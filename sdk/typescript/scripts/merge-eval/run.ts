import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { Codex } from "@openai/codex-sdk";
import { inlineToml } from "../../src/config.js";
import { validateScanMerge, scanMergePrompt } from "../../src/scan-merge.js";
import { mergeFixtures, parentId } from "./fixtures.js";
import { gradeMerge } from "./grade.js";
import { disabledMcpServers } from "../../src/scan-comparison.js";
import {
  executablePathForSpawn,
  resolveCodexCommand,
} from "../../src/runtime.js";

// Explicit developer invocation only; never part of unit tests or a scan.
const [destination, model, repetitions = "1"] = process.argv.slice(2);
if (
  !destination ||
  !model ||
  !Number.isSafeInteger(Number(repetitions)) ||
  Number(repetitions) < 1
)
  throw new Error(
    "Usage: bun scripts/merge-eval/run.ts OUTPUT_DIRECTORY MODEL [REPETITIONS]",
  );
const output = resolve(destination);
await mkdir(output, { recursive: true });
const environment = Object.fromEntries(
  Object.entries(process.env).filter(
    (entry): entry is [string, string] => entry[1] !== undefined,
  ),
);
const command = resolveCodexCommand(environment);
const codex = new Codex({
  codexPathOverride: executablePathForSpawn(command.command),
  env: environment,
  config: {
    project_doc_max_bytes: 0,
    features: {
      plugins: false,
      apps: false,
      multi_agent: false,
      multi_agent_v2: { enabled: false },
    },
  },
  configOverrides: [
    `mcp_servers=${inlineToml(
      await disabledMcpServers(command, undefined, environment, {
        workingDirectory: tmpdir(),
      }),
    )}`,
  ],
});
const results = [];
for (let iteration = 0; iteration < Number(repetitions); iteration++) {
  for (const fixture of mergeFixtures()) {
    // The oracle and other repository files are never put in the model's working directory.
    const scanDir = await mkdtemp(join(tmpdir(), "completed-merge-eval-"));
    const writer = {
      async restore(path: string, bytes: Uint8Array) {
        await mkdir(dirname(join(scanDir, path)), { recursive: true });
        await writeFile(join(scanDir, path), bytes);
      },
    };
    const prompt = await scanMergePrompt(
      parentId,
      fixture.inputs,
      fixture.previous,
      scanDir,
      writer,
    );
    const started = performance.now();
    const thread = codex.startThread({
      model,
      workingDirectory: scanDir,
      skipGitRepoCheck: true,
      sandboxMode: "read-only",
      approvalPolicy: "never",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
    });
    const record: Record<string, unknown> = {
      fixture: fixture.name,
      iteration,
      model,
      scanDir,
    };
    try {
      const turn = await thread.run(prompt);
      record["usage"] = turn.usage;
      record["output"] = turn.finalResponse;
      const raw: unknown = JSON.parse(turn.finalResponse);
      record["qualityErrors"] = gradeMerge(raw, fixture.expected);
      validateScanMerge(raw, fixture.inputs, fixture.previous);
      record["hostValid"] = true;
    } catch (error) {
      record["error"] = String(error);
    }
    record["milliseconds"] = performance.now() - started;
    record["threadId"] = thread.id;
    results.push(record);
    await writeFile(
      join(output, "results.json"),
      JSON.stringify(results, null, 2),
    );
    console.log(
      JSON.stringify({
        fixture: fixture.name,
        iteration,
        milliseconds: record["milliseconds"],
        hostValid: record["hostValid"],
        qualityErrors: record["qualityErrors"],
        error: record["error"],
      }),
    );
  }
}
if (
  results.some(
    (record) =>
      record["hostValid"] !== true ||
      (record["qualityErrors"] as string[]).length > 0,
  )
)
  process.exitCode = 1;

import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { Codex } from "@openai/codex-sdk";
import { definedEnvironment } from "../../src/execution-auth.js";
import {
  scanCompositionOverrides,
  codexConfigOverrides,
} from "../../src/config.js";
import {
  createScanMerger,
  saveScanMergeSources,
} from "../../src/scan-merge.js";
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
const pluginRoot = fileURLToPath(
  new URL("../../../../plugins/codex-security/", import.meta.url),
);
const merge = await createScanMerger(pluginRoot);
const environment = definedEnvironment(process.env);
const command = resolveCodexCommand(environment);
const config = scanCompositionOverrides(
  {
    project_doc_max_bytes: 0,
    features: { apps: false, multi_agent: false },
    mcp_servers: await disabledMcpServers(command, undefined, environment, {
      workingDirectory: tmpdir(),
    }),
  },
  0,
);
const codex = new Codex({
  codexPathOverride: executablePathForSpawn(command.command),
  env: environment,
  configOverrides: [...codexConfigOverrides(config), "features.plugins=false"],
});
const results = [];
for (let iteration = 0; iteration < Number(repetitions); iteration++) {
  for (const fixture of mergeFixtures()) {
    // The oracle and other repository files are never put in the model's working directory.
    const scanDir = await mkdtemp(join(tmpdir(), "completed-merge-eval-"));
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
      const turns: unknown[] = [];
      record["turns"] = turns;
      const restore = async (path: string, contents: string | Uint8Array) => {
        await mkdir(dirname(join(scanDir, path)), { recursive: true });
        await writeFile(join(scanDir, path), contents);
      };
      const contextPath = await saveScanMergeSources(
        fixture.inputs,
        {
          restore,
          async restoreMany(artifacts) {
            for (const artifact of artifacts)
              await restore(artifact.path, artifact.contents);
          },
        },
        fixture.previous,
      );
      const result = await merge(
        parentId,
        fixture.inputs,
        fixture.previous,
        new AbortController().signal,
        async (prompt, signal, outputSchema) => {
          const turn = await thread.run(prompt, { signal, outputSchema });
          turns.push({ usage: turn.usage, output: turn.finalResponse });
          return JSON.parse(turn.finalResponse);
        },
        { contextPath: join(scanDir, contextPath) },
      );
      const accepted = result.aggregate;
      record["output"] = {
        scanId: accepted.scanId,
        groups: accepted.findings.map(({ provenance }) => ({
          sourceFindingIds: provenance.sourceFindingIds!,
          representativeId: provenance.sourceFindingIds![0]!,
        })),
        scope: accepted.scope,
        threatModel: accepted.threatModel,
      };
      record["qualityErrors"] = gradeMerge(accepted, fixture.expected);
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

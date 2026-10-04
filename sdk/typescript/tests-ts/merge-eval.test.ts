import * as childProcess from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, spyOn, test } from "bun:test";
import { parse } from "smol-toml";
import { deepMerge, type JsonObject } from "../src/config.js";
import { reconcileScanMerge } from "../src/scan-merge.js";
import { executablePathForSpawn } from "../src/runtime.js";
import { mergeFixtures, parentId } from "../scripts/merge-eval/fixtures.js";
import { gradeMerge } from "../scripts/merge-eval/grade.js";
import { fixtureSpawn } from "./support/codex-process.js";

test("merge evaluation disables literal inherited MCP server names", async () => {
  const root = await mkdtemp(join(tmpdir(), "merge-eval-config-"));
  const executable = join(root, "synthetic-codex.exe");
  const script = join(root, "synthetic-codex.cjs");
  const capture = join(root, "arguments.jsonl");
  const codexHome = join(root, "codex-home");
  await mkdir(codexHome, { mode: 0o700 });
  await writeFile(
    join(codexHome, "config.toml"),
    `
[mcp_servers."synthetic.tools"]
command = "synthetic-unused"
args = ["--synthetic"]
enabled = true
`,
  );
  const nativeMcpList = (overrides: string[]) => {
    const node = Bun.which("node");
    if (node === null)
      throw new Error("The pinned Codex CLI requires Node.js.");
    const environment: NodeJS.ProcessEnv = {
      ...process.env,
      CODEX_HOME: codexHome,
    };
    delete environment["OPENAI_API_KEY"];
    delete environment["CODEX_API_KEY"];
    const result = Bun.spawnSync(
      [
        node,
        join(import.meta.dir, "../node_modules/@openai/codex/bin/codex.js"),
        "-C",
        root,
        ...overrides,
        "mcp",
        "list",
        "--json",
      ],
      { cwd: root, env: environment, stdout: "pipe", stderr: "pipe" },
    );
    if (result.exitCode !== 0)
      throw new Error(new TextDecoder().decode(result.stderr));
    return JSON.parse(new TextDecoder().decode(result.stdout)) as {
      name: string;
      enabled: boolean;
      transport: { type: string; command: string; args: string[] };
    }[];
  };
  await writeFile(
    script,
    `
const args = process.argv.slice(2);
const fs = require("node:fs");
if (args.includes("mcp")) {
  console.log(JSON.stringify([{ name: "synthetic.tools" }]));
  process.exit(0);
}
const index = fs.existsSync(${JSON.stringify(capture)}) ? fs.readFileSync(${JSON.stringify(capture)}, "utf8").trim().split("\\n").length : 0;
const answer = { matches: [], uncertain: [], related: [], request: null };
fs.appendFileSync(${JSON.stringify(capture)}, JSON.stringify(args) + "\\n");
process.stdin.resume();
process.stdin.on("end", () => {
  console.log(JSON.stringify({ type: "thread.started", thread_id: "synthetic-eval-thread" }));
  console.log(JSON.stringify({ type: "item.completed", item: { id: "answer", type: "agent_message", text: JSON.stringify(answer) } }));
  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }));
});
`,
  );
  const scanDirectories = new Set<string>();
  const spawning = spyOn(childProcess, "spawn").mockImplementation(
    fixtureSpawn(executablePathForSpawn(executable), script, (_child, args) => {
      const index = args.indexOf("--cd");
      if (index !== -1) scanDirectories.add(args[index + 1]!);
    }),
  );
  const logging = spyOn(console, "log").mockImplementation(() => {});
  const previous = {
    argv: process.argv,
    executable: process.env["CODEX_CLI_PATH"],
    exitCode: process.exitCode,
  };
  try {
    process.env["CODEX_CLI_PATH"] = executable;
    process.argv = [process.execPath, "run.ts", root, "synthetic-model"];
    await import("../scripts/merge-eval/run.js");
    expect(nativeMcpList([])).toMatchObject([
      {
        name: "synthetic.tools",
        enabled: true,
        transport: {
          type: "stdio",
          command: "synthetic-unused",
          args: ["--synthetic"],
        },
      },
    ]);
    const invocations = (await readFile(capture, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as string[]);
    expect(invocations.length).toBeGreaterThan(0);
    for (const args of invocations) {
      const overrides = args.flatMap((value, index) =>
        value === "--config" || value === "-c" ? [args[index + 1]!] : [],
      );
      const config = overrides.reduce<JsonObject>(
        (value, override) => deepMerge(value, parse(override) as JsonObject),
        {},
      );
      expect(config["mcp_servers"]).toEqual({
        "synthetic.tools": { enabled: false },
      });
      // Codex merges CLI overrides with inherited file-backed transport settings.
      const capturedOverrides = args.flatMap((value, index) =>
        value === "--config" || value === "-c" ? [value, args[index + 1]!] : [],
      );
      expect(nativeMcpList(capturedOverrides)).toMatchObject([
        {
          name: "synthetic.tools",
          enabled: false,
          transport: {
            type: "stdio",
            command: "synthetic-unused",
            args: ["--synthetic"],
          },
        },
      ]);
    }
  } finally {
    process.argv = previous.argv;
    process.exitCode = previous.exitCode;
    if (previous.executable === undefined) delete process.env["CODEX_CLI_PATH"];
    else process.env["CODEX_CLI_PATH"] = previous.executable;
    spawning.mockRestore();
    logging.mockRestore();
    await Promise.all(
      [root, ...scanDirectories].map((directory) =>
        rm(directory, { recursive: true, force: true }),
      ),
    );
  }
});

test.each(mergeFixtures())("merge quality oracle: $name", (fixture) => {
  expect(gradeMerge(fixture.reference, fixture.expected)).toEqual([]);
  const actual = reconcileScanMerge(
    parentId,
    fixture.groups,
    fixture.inputs,
    fixture.previous,
  ).aggregate;
  expect(gradeMerge(actual, fixture.expected)).toEqual([]);
  if (!fixture.reference.findings.length) return;
  for (const field of [
    "remediation",
    "remediationTests",
    "preventiveControls",
    "severity",
  ]) {
    const bad = structuredClone(fixture.reference);
    bad.findings[0]![field] = field === "severity" ? { level: "critical" } : [];
    // Full originals in provenance must not satisfy a canonical repair requirement.
    (bad.findings[0]!["provenance"] as Record<string, unknown>)[
      "sourceFindings"
    ] = fixture.reference.findings;
    expect(gradeMerge(bad, fixture.expected).length).toBeGreaterThan(0);
  }
  const omitted = structuredClone(fixture.reference);
  omitted.findings.pop();
  expect(gradeMerge(omitted, fixture.expected).length).toBeGreaterThan(0);
  const duplicate = structuredClone(fixture.reference);
  duplicate.findings.push(duplicate.findings[0]!);
  expect(gradeMerge(duplicate, fixture.expected).length).toBeGreaterThan(0);
});

test("accounting for every source does not excuse collapsing independent findings", () => {
  const fixture = mergeFixtures().find(
    (value) => value.name === "independent-similar-titles",
  )!;
  const collapsed = structuredClone(fixture.reference);
  collapsed.findings.splice(1);
  (collapsed.findings[0]!["provenance"] as Record<string, unknown>)[
    "sourceFindingIds"
  ] = fixture.expected.flatMap((group) => group.refs);
  const accepted = reconcileScanMerge(
    parentId,
    [fixture.expected.flatMap((group) => group.refs)],
    fixture.inputs,
    fixture.previous,
  ).aggregate;
  expect(gradeMerge(accepted, fixture.expected).length).toBeGreaterThan(0);
  expect(gradeMerge(collapsed, fixture.expected).length).toBeGreaterThan(0);
});

test("merge quality requires complete repair, test and control identifiers", () => {
  const fixture = mergeFixtures().find(
    (value) => value.name === "independent-similar-titles",
  )!;
  for (const [field, wrong] of [
    ["remediation", "Correct configuration repair-10."],
    ["remediationTests", ["Verify repair-1-test-other."]],
    ["preventiveControls", ["Maintain other-repair-1-control."]],
  ] as const) {
    const bad = structuredClone(fixture.reference);
    Object.assign(bad.findings[1]!, { [field]: wrong });
    expect(gradeMerge(bad, fixture.expected)).toEqual([
      `Missing canonical ${field} fact ${fixture.expected[1]!.facts[field]![0]}: ["wide:1"].`,
    ]);
  }
});

test("retained history requires every original repair in the quality oracle", () => {
  const fixture = mergeFixtures().find(
    (value) => value.name === "large-field-and-retained-sources",
  )!;
  const collapsed = structuredClone(fixture.reference);
  collapsed.findings[0]!.remediation = fixture.inputs[0]!.sourceFindings[0]![
    "remediation"
  ] as string;
  expect(gradeMerge(collapsed, fixture.expected).length).toBeGreaterThan(0);
});

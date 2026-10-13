import * as childProcess from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { Codex, type CodexOptions } from "@openai/codex-sdk";
import { afterEach, expect, spyOn, test } from "bun:test";
import { scanRuntimeCodexConfig } from "../src/api.js";
import { writeCodexConfig, type JsonObject } from "../src/config.js";
import { executablePathForSpawn } from "../src/runtime.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";
import { fixtureSpawn } from "./support/codex-process.js";

const { temporaryDirectory, copyCompletedScan, cleanup } =
  createApiTestFixtures();
afterEach(cleanup);

test("automatic matching retains read-only permissions through the scan session factory", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  await Promise.all([
    mkdir(repository),
    mkdir(codexHome, { mode: 0o700 }),
    mkdir(scanDir, { mode: 0o700 }),
  ]);
  const inheritedPermissions = {
    filesystem: {
      ":workspace_roots": "write",
      [join(repository, "scoped")]: { ".": "write", private: "deny" },
    },
    network: { enabled: true },
  };
  await writeCodexConfig(
    join(codexHome, "config.toml"),
    scanRuntimeCodexConfig({}, codexHome, inheritedPermissions),
  );
  const originalHome = await readFile(join(codexHome, "config.toml"));
  const executable = join(root, "synthetic-codex.exe");
  const script = join(root, "synthetic-codex.cjs");
  const capture = join(root, "matcher.json");
  await writeFile(
    script,
    `
const fs = require("node:fs");
const { parse } = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
const args = process.argv.slice(2);
if (args.includes("mcp")) { console.log("[]"); process.exit(0); }
const config = parse(fs.readFileSync(require("node:path").join(process.env.CODEX_HOME, "config.toml"), "utf8"));
const merge = (target, value) => { for (const [key, child] of Object.entries(value)) target[key] = child && typeof child === "object" && !Array.isArray(child) ? merge(target[key] ?? {}, child) : child; return target; };
for (let i = 0; i < args.length; i++) if (["-c", "--config"].includes(args[i])) merge(config, parse(args[++i]));
fs.writeFileSync(${JSON.stringify(capture)}, JSON.stringify({ args, config, apiKey: process.env.CODEX_API_KEY }));
process.stdin.resume();
process.stdin.on("end", () => {
  console.log(JSON.stringify({ type: "thread.started", thread_id: "matcher-thread" }));
  console.log(JSON.stringify({ type: "item.completed", item: { id: "answer", type: "agent_message", text: '{"matches":[],"uncertain":[]}' } }));
  console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }));
});
`,
  );
  const previous = {
    findingId: "previous",
    occurrenceId: "old",
    scanId: "prior",
    targetId: "target_sha256_example",
  };
  const current = {
    findingId: "csf_852f90d6e1177502ff113d4a",
    occurrenceId: "occ_e79cb19591e696572a1c22be",
  };
  let comparisonSaved = false;
  const warnings: string[] = [];
  const scanConfigurations: CodexOptions[] = [];
  const client = new TestClient(
    {},
    {
      environment: {
        PATH: process.env["PATH"],
        CODEX_CLI_PATH: executable,
        OPENAI_API_KEY: "synthetic-selected",
      },
      resolveCodexCommand: () => ({ command: executable }),
      prepareRuntime: async () => preparedRuntime(codexHome),
      resolvePluginPython: async () => "/managed/python",
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      runWorkbench: async (_options, args, input): Promise<JsonObject> => {
        if (args[0] === "list-global-findings") return { findings: [previous] };
        if (args[0] === "list-unmatched-scan-pairs")
          return {
            batches: [
              {
                afterScanId: "scan_example_001",
                afterFindings: [current],
                beforeScans: [{ scanId: "prior", findings: [previous] }],
              },
            ],
          };
        if (args[0] === "save-scan-comparison") comparisonSaved = true;
        return mockWorkbench(args, input);
      },
      createCodex: (options) => {
        if (
          (options.config?.["features"] as JsonObject)?.["shell_tool"] === false
        )
          return new Codex(options);
        scanConfigurations.push(options);
        return {
          startThread: () => ({
            id: null,
            async runStreamed() {
              await copyCompletedScan(root);
              return { events: completedEvents() };
            },
          }),
        };
      },
    },
  );
  const children: childProcess.ChildProcess[] = [];
  const spawning = spyOn(childProcess, "spawn").mockImplementation(
    fixtureSpawn(executablePathForSpawn(executable), script, (child) =>
      children.push(child),
    ),
  );
  try {
    await client.run(repository, {
      inheritedPermissions,
      onWarning: (message) => warnings.push(message),
    });
    expect(warnings).toEqual([]);
    expect(comparisonSaved).toBe(true);
    expect(scanConfigurations).toHaveLength(1);
    expect(
      scanConfigurations[0]!.configOverrides!.some((override) =>
        override.includes('"enabled"=true'),
      ),
    ).toBe(true);
    const observed = JSON.parse(await readFile(capture, "utf8"));
    const profile =
      observed.config.permissions[observed.config.default_permissions];
    expect(profile).toEqual({
      extends: ":read-only",
      filesystem: {
        ":workspace_roots": "read",
        [join(repository, "scoped")]: { ".": "read", private: "deny" },
      },
      network: { enabled: false },
    });
    expect(observed.apiKey).toBe("synthetic-selected");
    expect(await readFile(join(codexHome, "config.toml"))).toEqual(
      originalHome,
    );
  } finally {
    await client.close();
    for (const child of children)
      while (child.exitCode === null && child.signalCode === null)
        await new Promise<void>((resolve) => setImmediate(resolve));
    spawning.mockRestore();
  }
});

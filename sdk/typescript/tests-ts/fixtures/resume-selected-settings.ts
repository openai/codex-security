import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { nodeCommand, pythonExecutable } from "../support/shell.js";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { TestClient } from "../support/api-client.js";
import { preparedRuntime } from "../support/api-events.js";
import { runWorkbench, resolveScanSessionPaths } from "../../src/runtime.js";
import { main } from "../../src/cli.js";
import { dependencies, capture } from "../cli-fixtures.js";
import { parse as parseToml } from "smol-toml";
import { PLUGIN_ROOT as pluginRoot } from "../plugin-root.js";

process.umask(0o077);
const [root, stage, shape = "direct"] = process.argv.slice(2);
if (!root || !stage) throw new Error("root and stage required");
const python = pythonExecutable()!;
const repository = join(root, "repository"),
  scanDir = join(root, "scan"),
  codexHome = join(root, "state/codex-home");
const selectedHome = join(scanDir, " selected-state/nested");
const workerSnapshotPath = join(codexHome, "worker.toml");
const nativeChild = join(root, "synthetic-native.mjs");
const statePath = join(root, "state.json");
const nativeCommand = {
  ...nodeCommand(),
  args: ["--import", pathToFileURL(nativeChild).href, "--"],
};
const environment = {
  PATH: process.env["PATH"]!,
  HOME: root,
  USERPROFILE: root,
  SystemRoot: process.env["SystemRoot"],
  TEMP: process.env["TEMP"],
  TMP: process.env["TMP"],
  CODEX_HOME: codexHome,
  CODEX_SECURITY_STATE_DIR: join(root, "state"),
};
const command = (args: readonly string[], input?: string) =>
  runWorkbench({ python, pluginRoot, environment }, args, input);
const captures: any = { stage, shape, ownership: [], codex: [], workbench: [] };
const relevant = (config: any) =>
  Object.fromEntries(
    [
      "sqlite_home",
      "model_context_window",
      "model_auto_compact_token_limit",
    ].map((key) => [key, config?.[key] ?? null]),
  );
if (stage === "first") {
  for (const path of [repository, scanDir, join(codexHome, "sessions")])
    await mkdir(path, { recursive: true });
  await chmod(scanDir, 0o700);
  await chmod(root, 0o700);
  await writeFile(
    join(repository, "source.py"),
    "# Synthetic lifecycle fixture\n",
  );
  await writeFile(
    nativeChild,
    `import{createInterface}from'node:readline';import{appendFileSync}from'node:fs';const argv=process.argv.slice(1);const selected=argv.find(s=>s.startsWith('sqlite_home='));const home=selected?JSON.parse(selected.slice('sqlite_home='.length)):process.env.CODEX_HOME;for await(const line of createInterface({input:process.stdin})){const request=JSON.parse(line);appendFileSync(${JSON.stringify(join(root, "child-transcript.jsonl"))},JSON.stringify({argv,request,home})+'\\n');if(request.method==='initialize')process.stdout.write(JSON.stringify({id:request.id,result:{}})+'\\n');if(request.method==='config/read')process.stdout.write(JSON.stringify({id:request.id,result:{config:{sqlite_home:home}}})+'\\n');}\n`,
  );
  await chmod(nativeChild, 0o700);
}
const runtime = async () => ({
  ...preparedRuntime(codexHome),
  environment: Object.fromEntries(
    Object.entries(environment).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  ),
  configPath: join(root, "runtime.toml"),
  deepScanConfigPath: workerSnapshotPath,
});
let state: any =
  stage === "first"
    ? { threadId: randomUUID(), selectedHome, repository, scanDir }
    : JSON.parse(await readFile(statePath, "utf8"));
const clientDependencies = {
  environment,
  prepareRuntime: runtime,
  resolveCodexCommand: () => nativeCommand,
  resolvePluginPython: async () => python,
  runWorkbench: async (
    options: any,
    args: readonly string[],
    input?: string,
  ) => {
    captures.workbench.push(args[0]);
    const result = await runWorkbench(options, args, input);
    if (args[0] === "register-cli-scan") {
      state.scanId = result["scanId"];
      captures.registrationRecipe = JSON.parse(input!)["recipe"];
      await writeFile(statePath, JSON.stringify(state, null, 2));
    }
    return result;
  },
  resolveScanSessionPaths: async (
    ...args: Parameters<typeof resolveScanSessionPaths>
  ) => {
    const record: any = { config: relevant(args[3]?.config) };
    captures.ownership.push(record);
    try {
      const paths = await resolveScanSessionPaths(...args);
      record.paths = [...paths];
      return paths;
    } catch (error) {
      record.error = String(error);
      throw error;
    } finally {
      record.selectedSqliteHome = await args[3]?.sqliteHome;
    }
  },
  createCodex: (options: any) => {
    captures.codex.push({
      config: relevant(options.config),
      sqliteEnvironment: options.env?.CODEX_SQLITE_HOME ?? null,
    });
    const thread = {
      id: state.threadId,
      async runStreamed() {
        captures.workerSnapshot = relevant(
          parseToml(await readFile(workerSnapshotPath, "utf8"))[
            "worker_runtime"
          ],
        );
        if (stage !== "first")
          return {
            events: (async function* () {
              yield {
                type: "thread.started" as const,
                thread_id: state.threadId,
              };
              yield { type: "turn.started" as const };
              yield {
                type: "turn.completed" as const,
                usage: {
                  input_tokens: 100,
                  cached_input_tokens: 0,
                  cache_write_input_tokens: 0,
                  output_tokens: 10,
                  reasoning_output_tokens: 0,
                },
              };
            })(),
          };
        await mkdir(selectedHome, { recursive: true });
        const rollout = join(
          codexHome,
          "sessions",
          `rollout-${state.threadId}.jsonl`,
        );
        await writeFile(
          rollout,
          JSON.stringify({
            type: "session_meta",
            payload: { id: state.threadId, cwd: scanDir },
          }) + "\n",
        );
        execFileSync(python, [
          "-c",
          "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('CREATE TABLE threads (id TEXT PRIMARY KEY,rollout_path TEXT NOT NULL)'); c.execute('CREATE TABLE thread_spawn_edges (parent_thread_id TEXT NOT NULL,child_thread_id TEXT NOT NULL)'); c.execute('INSERT INTO threads VALUES (?,?)',(sys.argv[2],sys.argv[3])); c.commit()",
          join(selectedHome, "state_7.sqlite"),
          state.threadId,
          rollout,
        ]);
        // The unselected default database exists but deliberately has no owned thread.
        execFileSync(python, [
          "-c",
          "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('CREATE TABLE threads (id TEXT PRIMARY KEY,rollout_path TEXT NOT NULL)'); c.execute('CREATE TABLE thread_spawn_edges (parent_thread_id TEXT NOT NULL,child_thread_id TEXT NOT NULL)'); c.commit()",
          join(codexHome, "state_7.sqlite"),
        ]);
        return {
          events: (async function* () {
            yield {
              type: "thread.started" as const,
              thread_id: state.threadId,
            };
            await command([
              "begin-deep-scan",
              "--scan-id",
              state.scanId,
              "--thread-id",
              state.threadId,
              "--available-parallelism",
              "4",
              "--workflow-version",
              "deep-scan-mcp/v1",
            ]);
            captures.firstOwnershipControl = [
              ...(await clientDependencies.resolveScanSessionPaths(
                { python, pluginRoot, environment },
                state.scanId,
                state.threadId,
                {
                  command: nativeCommand,
                  config: options.config,
                  workingDirectory: scanDir,
                },
              )),
            ];
            yield { type: "turn.started" as const };
            captures.savedRecipe = (
              await command(["get-scan-recipe", "--scan-id", state.scanId])
            )["recipe"];
            captures.resumeContext = await command([
              "get-cli-scan-resume",
              "--scan-id",
              state.scanId,
            ]);
            await writeFile(
              join(root, "first.json"),
              JSON.stringify(captures, null, 2),
            );
            // Simulate the process disappearing after durable registration and session attachment.
            process.exit(86);
          })(),
        };
      },
    };
    return {
      startThread: () => thread,
      resumeThread: (id: string) => {
        captures.resumedThread = id;
        return thread;
      },
    };
  },
};
if (stage === "first") {
  const selected = {
    sqlite_home: " selected-state/nested",
    model_context_window: 96000,
    model_auto_compact_token_limit: 72000,
  };
  const codexOverrides =
    shape === "profile"
      ? {
          sqlite_home: "unselected-direct",
          model_context_window: 64000,
          model_auto_compact_token_limit: 48000,
          profile: "chosen",
          profiles: { chosen: selected },
        }
      : selected;
  const client = new TestClient({ codexOverrides }, clientDependencies);
  try {
    await client.run(repository, {
      mode: "deep",
      outputDir: scanDir,
      maxCostUsd: 1,
    });
  } catch (error) {
    captures.error = String(error);
    await writeFile(
      join(root, "first-failure.json"),
      JSON.stringify(captures, null, 2),
    );
    throw error;
  }
} else {
  const stdout = capture(),
    stderr = capture();
  const code = await main(
    ["scans", "resume", state.scanId, "--json"],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({ environment, currentDirectory: root }),
      runWorkbench: command,
      createSecurity: (config: any) => {
        captures.restoredConfig = relevant(config.codexOverrides);
        return new TestClient(config, clientDependencies);
      },
    },
  );
  captures.exitCode = code;
  captures.stdout = stdout.text();
  captures.stderr = stderr.text();
  if (!captures.workerSnapshot)
    captures.workerSnapshot = relevant(
      parseToml(await readFile(workerSnapshotPath, "utf8"))["worker_runtime"],
    );
  await writeFile(join(root, "resume.json"), JSON.stringify(captures, null, 2));
  console.log(
    JSON.stringify({
      exitCode: code,
      restoredConfig: captures.restoredConfig,
      workerSnapshot: captures.workerSnapshot,
      ownership: captures.ownership,
      stderr: captures.stderr,
    }),
  );
}

import { syntheticModelCatalog as catalog } from "./support/model-catalog.js";
import { createProviderProfile } from "../src/provider-profile.js";
import { CODEX_EXECUTABLE_VERSION } from "../src/version.js";
import * as childProcess from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { scanRuntimeCodexConfig } from "../src/api.js";
import {
  createExecutionCodex,
  nativeScanConfiguration,
  prepareDiscoveryExecution,
  prepareMergeExecution,
  prepareExecutionSource,
  resolveExecutionPaths,
  type PreparedExecution,
} from "../src/execution-preparation.js";
import { executablePathForSpawn } from "../src/runtime.js";
import {
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";
import { fixtureSpawn } from "./support/codex-process.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each(["home", "selected", "selected-profile", "recipe"] as const)(
  "native files keep their origin and explicit overrides across fresh/resumed workers, origin=%s",
  async (origin) => {
    const explicit = origin === "recipe";
    const root = await temporaryDirectory();
    const home = join(root, "home");
    const discovery = join(root, "discovery");
    const merge = join(root, "merge");
    await Promise.all([
      mkdir(home, { mode: 0o700 }),
      mkdir(discovery),
      mkdir(merge),
    ]);
    const original =
      'model_catalog_json = "models.json"\nmodel_instructions_file = "instructions.md"\nexperimental_compact_prompt_file = "compact.md"\nsqlite_home = "sqlite"\n';
    await writeFile(join(home, "config.toml"), original);
    await writeFile(join(home, "models.json"), JSON.stringify(catalog));
    await writeFile(
      join(home, "instructions.md"),
      "Synthetic home instructions.\n",
    );
    await writeFile(join(home, "compact.md"), "Synthetic home compact prompt.");
    await mkdir(join(home, "sqlite"));
    for (const cwd of [root]) {
      await writeFile(
        join(cwd, "caller-compact.md"),
        "Synthetic caller compact prompt.",
      );
      await mkdir(join(cwd, "caller-sqlite"));
      await writeFile(join(cwd, "caller-models.json"), JSON.stringify(catalog));
      await writeFile(
        join(cwd, "caller-instructions.md"),
        "Synthetic caller instructions.\n",
      );
    }
    const executable = join(root, "synthetic-codex.exe");
    const script = join(root, "synthetic-codex.cjs");
    const capture = join(root, "capture.jsonl");
    const codexEntry = join(
      import.meta.dirname,
      "..",
      "node_modules",
      "@openai",
      "codex",
      "bin",
      "codex.js",
    );
    const selectedDirectory = join(root, "selected");
    await mkdir(selectedDirectory);
    await writeFile(
      join(selectedDirectory, "selected-models.json"),
      JSON.stringify(catalog),
    );
    await writeFile(
      join(selectedDirectory, "selected-instructions.md"),
      "Synthetic selected instructions.\n",
    );
    await writeFile(
      join(selectedDirectory, "selected-compact.md"),
      "Synthetic selected compact prompt.",
    );
    await mkdir(join(selectedDirectory, "selected-sqlite"));
    const selectedPath = join(selectedDirectory, "settings.toml");
    await writeFile(
      selectedPath,
      `${origin === "selected-profile" ? 'profile = "selected"\n[profiles.selected]\n' : ""}model_catalog_json = "selected-models.json"\nmodel_instructions_file = "selected-instructions.md"\nexperimental_compact_prompt_file = "selected-compact.md"\nsqlite_home = "selected-sqlite"\n`,
    );
    const environment = {
      PATH: process.env["PATH"],
      CODEX_HOME: home,
      CODEX_CLI_PATH: executable,
      ...(origin.startsWith("selected")
        ? { CODEX_SECURITY_CONFIG_PATH: selectedPath }
        : {}),
    };
    const startup = (cwd: string, overrides: string[] = []) =>
      childProcess.spawnSync(
        process.execPath,
        [codexEntry, ...overrides, "mcp", "list", "--json"],
        {
          cwd,
          env: { PATH: process.env["PATH"], CODEX_HOME: home },
          encoding: "utf8",
          timeout: 15000,
        },
      );
    const version = childProcess.spawnSync(
      process.execPath,
      [codexEntry, "--version"],
      { encoding: "utf8" },
    );
    expect(version.status, version.stderr).toBe(0);
    expect(version.stdout).toContain(CODEX_EXECUTABLE_VERSION);
    // The same relative home setting succeeds in its original native file layer.
    for (const cwd of [discovery, merge]) {
      const control = startup(cwd);
      expect(control.status, control.stderr || control.error?.message).toBe(0);
    }
    const replaySettings = {
      analytics: { enabled: false },
      shell_environment_policy: {
        inherit: "all",
        set: { SYNTHETIC_REPLAY_SETTING: "selected" },
      },
      model_instructions_file: "caller-instructions.md",
      model_catalog_json: "caller-models.json",
      experimental_compact_prompt_file: "caller-compact.md",
      sqlite_home: "caller-sqlite",
    };
    const savedProfile = explicit
      ? await createProviderProfile(home, replaySettings)
      : undefined;
    const configuration = await nativeScanConfiguration(
      environment,
      explicit
        ? {
            recipe: {
              config: {},
              providerProfile: { name: savedProfile!.name, home: "ambient" },
            },
          }
        : {},
      2,
    );
    await writeFile(capture, "");
    await writeFile(
      script,
      `
const fs = require("node:fs"), path = require("node:path");
const {parse} = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
const args = process.argv.slice(2), config = parse(fs.readFileSync(path.join(process.env.CODEX_HOME, "config.toml"), "utf8"));
const merge=(target,value)=>{for(const [key,child] of Object.entries(value))target[key]=child&&typeof child==="object"&&!Array.isArray(child)?merge(target[key]??{},child):child;return target;};
if(args.includes("--profile"))merge(config,parse(fs.readFileSync(path.join(process.env.CODEX_HOME,args[args.indexOf("--profile")+1]+".config.toml"),"utf8")));
for(let i=0;i<args.length;i++)if(["-c","--config"].includes(args[i]))merge(config,parse(args[++i]));
fs.appendFileSync(${JSON.stringify(capture)},JSON.stringify({args,catalog:config.model_catalog_json,instructions:config.model_instructions_file,compact:config.experimental_compact_prompt_file,sqliteHome:config.sqlite_home,analytics:config.analytics,shellPolicy:config.shell_environment_policy})+"\\n");
if(args.includes("app-server"))require("node:readline").createInterface({input:process.stdin}).on("line",line=>{const request=JSON.parse(line);if(request.id===undefined)return;const result=request.method==="initialize"?{}:request.method==="config/read"?{config}:{data:[{id:config.default_permissions,allowed:true}],nextCursor:null};console.log(JSON.stringify({id:request.id,result}));});
else {process.stdin.resume();process.stdin.on("end",()=>{console.log(JSON.stringify({type:"thread.started",thread_id:"00000000-0000-4000-8000-000000000001"}));console.log(JSON.stringify({type:"turn.completed",usage:{input_tokens:0,cached_input_tokens:0,output_tokens:0}}));});}
`,
    );
    await writeFile(
      join(root, "compact.md"),
      "Synthetic parent compact prompt.",
    );
    await writeFile(
      join(root, "selected-compact.md"),
      "Synthetic selected parent compact prompt.",
    );
    await mkdir(join(root, "sqlite"));
    await mkdir(join(root, "selected-sqlite"));
    const workerConfiguration = resolveExecutionPaths(
      configuration,
      root,
      environment,
    );
    const source = prepareExecutionSource({
      command: { command: executable },
      configuration: workerConfiguration,
      environment,
      preserveProviderEnvironment: true,
    });
    const session: PreparedExecution = {
      policy: "ordinary",
      source,
      runtime: { ...preparedRuntime(home), preserveCodexHomeConfig: true },
      runtimeHome: home,
      effectiveConfig: workerConfiguration,
      preflightConfig: {},
      sessionConfig: scanRuntimeCodexConfig(workerConfiguration, home),
      authentication: source.authentication,
      approvalPolicy: "never",
      python: process.execPath,
      releaseCredentialHome: null,
    };
    let nativeChecks = 0;
    const nativeResults: Array<{ status: number | null; stderr: string }> = [];
    const spawn = spyOn(childProcess, "spawn").mockImplementation(
      fixtureSpawn(
        executablePathForSpawn(executable),
        script,
        (_child, args, options) => {
          const overrides: string[] = [];
          for (let i = 0; i < args.length; i++)
            if (["-c", "--config", "--profile"].includes(args[i]!))
              overrides.push(args[i]!, args[++i]!);
          const cwd = args.includes("--cd")
            ? args[args.indexOf("--cd") + 1]!
            : String(options?.cwd ?? root);
          const result = startup(cwd, overrides);
          nativeChecks++;
          nativeResults.push({
            status: result.status,
            stderr: result.stderr || result.error?.message || "",
          });
        },
      ),
    );
    try {
      for (const role of ["discovery", "merge"] as const) {
        const worker =
          role === "discovery"
            ? prepareDiscoveryExecution(session)
            : prepareMergeExecution(session, 2);
        const { codex } = await createExecutionCodex(
          { surface: "sdk", command: "scan", mode: "deep" },
          worker,
          {},
        );
        for (const resumed of [false, true]) {
          const options = {
            workingDirectory: role === "discovery" ? discovery : merge,
            skipGitRepoCheck: true,
          };
          const thread = resumed
            ? codex.resumeThread!(
                "00000000-0000-4000-8000-000000000001",
                options,
              )
            : codex.startThread(options);
          const { events } = await thread.runStreamed(
            "Synthetic catalog startup.",
            {},
          );
          for await (const _event of events) {
          }
        }
      }
      const rows = (await readFile(capture, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(nativeChecks).toBe(8);
      for (const result of nativeResults)
        expect(result.status, result.stderr).toBe(0);
      expect(rows).toHaveLength(8);
      for (const row of rows) {
        if (explicit) {
          expect(row.analytics).toEqual(replaySettings.analytics);
          expect(row.shellPolicy).toEqual(
            replaySettings.shell_environment_policy,
          );
        }
        expect(row.catalog).toBe(
          explicit
            ? join(root, "caller-models.json")
            : origin.startsWith("selected")
              ? join(selectedDirectory, "selected-models.json")
              : join(home, "models.json"),
        );
        expect(row.compact).toBe(
          explicit
            ? join(root, "caller-compact.md")
            : origin.startsWith("selected")
              ? join(selectedDirectory, "selected-compact.md")
              : join(home, "compact.md"),
        );
        expect(row.sqliteHome).toBe(
          explicit
            ? join(root, "caller-sqlite")
            : origin.startsWith("selected")
              ? join(selectedDirectory, "selected-sqlite")
              : join(home, "sqlite"),
        );
        expect(row.instructions).toBe(
          explicit
            ? join(root, "caller-instructions.md")
            : origin.startsWith("selected")
              ? join(selectedDirectory, "selected-instructions.md")
              : join(home, "instructions.md"),
        );
      }
      expect(await readFile(join(home, "config.toml"), "utf8")).toBe(original);
    } finally {
      spawn.mockRestore();
    }
  },
);

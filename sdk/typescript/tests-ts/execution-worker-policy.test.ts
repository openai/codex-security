import * as childProcess from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import {
  scanPreflightCodexConfig,
  scanRuntimeCodexConfig,
} from "../src/api.js";
import {
  EXTERNAL_CODEX_PROVIDERS,
  writeCodexConfig,
  type JsonObject,
} from "../src/config.js";
import {
  createExecutionCodex,
  prepareExecutionSource,
  prepareDiscoveryExecution,
  prepareMergeExecution,
  type PreparedExecution,
} from "../src/execution-preparation.js";
import { ScanPermissionError } from "../src/scan-execution.js";
import { executablePathForSpawn } from "../src/runtime.js";
import {
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";
import { fixtureSpawn } from "./support/codex-process.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each([
  ["ordinary", false, "ordinary"],
  ["ordinary", true, "ordinary"],
  ["discovery", false, "ordinary"],
  ["discovery", true, "ordinary"],
  ["merge", false, "ordinary"],
  ["merge", true, "ordinary"],
  ["discovery", true, "env_key"],
  ["discovery", true, "bearer"],
  ["merge", true, "env_key"],
  ["merge", true, "bearer"],
  ["discovery", false, "openrouter"],
  ["discovery", false, "fireworks"],
  ["merge", false, "openrouter"],
  ["merge", false, "fireworks"],
] as const)(
  "%s executions preserve selected inputs and enforce permissions and managed allowlists in initialized homes on fresh and resumed turns (preserve provider environment: %p, authentication: %s)",
  async (role, preserveProviderEnvironment, providerAuth) => {
    const profileId =
      role === "ordinary"
        ? "codex_security_scan_execution"
        : "codex_security_deep_scan_worker";
    const replayProvider =
      providerAuth === "openrouter" || providerAuth === "fireworks"
        ? providerAuth
        : undefined;
    const replayDefaults =
      replayProvider === undefined
        ? undefined
        : EXTERNAL_CODEX_PROVIDERS[replayProvider];
    for (const resumed of [false, true]) {
      for (const scenario of [
        "accepted",
        "managed",
        "rejected",
        "fallback",
        "transport",
      ] as const) {
        if (providerAuth !== "ordinary" && scenario !== "accepted") continue;
        const root = await temporaryDirectory();
        const home = join(root, "home");
        await mkdir(home);
        if (scenario === "managed")
          await writeFile(
            join(home, "requirements.toml"),
            `[allowed_permission_profiles]\n${profileId} = true\n`,
          );
        const executable = join(root, "synthetic-codex.exe");
        const script = join(root, "synthetic-codex.cjs");
        const capture = join(root, "observations.jsonl");
        await writeFile(capture, "");
        await writeFile(
          script,
          `
          const fs = require("node:fs");
          const {parse} = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
          const args = process.argv.slice(2);
          const config = parse(fs.readFileSync(require("node:path").join(process.env.CODEX_HOME,"config.toml"),"utf8"));
          const merge = (target,value) => { for (const [key,child] of Object.entries(value)) target[key] = child && typeof child === "object" && !Array.isArray(child) ? merge(target[key] ?? {},child) : child; return target; };
          for (let i = 0; i < args.length; i++) if (["-c","--config"].includes(args[i])) merge(config,parse(args[++i]));
          const allowed = ${JSON.stringify(scenario)} === "managed" ? parse(fs.readFileSync(require("node:path").join(process.env.CODEX_HOME,"requirements.toml"),"utf8")).allowed_permission_profiles : undefined;
          const record = value => fs.appendFileSync(${JSON.stringify(capture)},JSON.stringify(value)+"\\n");
          record({kind: args.includes("app-server") ? "preflight" : "exec",args,config,context:process.env.SYNTHETIC_CONTEXT,apiKey:process.env.CODEX_API_KEY,openAiKey:process.env.OPENAI_API_KEY,providerKey:process.env.SYNTHETIC_PROVIDER_KEY,replayProviderKey:process.env[${JSON.stringify(replayDefaults?.env_key ?? "UNUSED_SYNTHETIC_PROVIDER_KEY")}]});
          if (args.includes("app-server")) {
            require("node:readline").createInterface({input:process.stdin}).on("line",line => {
              const request=JSON.parse(line); if (!request.id) return;
              if (${JSON.stringify(scenario)} === "transport") { process.exit(1); }
              const result=request.method === "initialize" ? {} : request.method === "config/read" ? {config} : request.params.cursor ? {data:[{id:config.default_permissions,allowed:${scenario !== "rejected"} && (!allowed || allowed[config.default_permissions] === true)}],nextCursor:null} : {data:[],nextCursor:"selected"};
              console.log(JSON.stringify({id:request.id,result}));
            });
          } else {
            process.stdin.resume();
            process.stdin.on("end",() => {
              console.log(JSON.stringify({type:"thread.started",thread_id:"00000000-0000-4000-8000-000000000001"}));
              if (${JSON.stringify(scenario)} === "fallback") console.log(JSON.stringify({type:"error",message:"Configured value for \u0060permission_profile\u0060 is disallowed by requirements; falling back from \u0060"+config.default_permissions+"\u0060 to required value \u0060:read-only\u0060."}));
              else console.log(JSON.stringify({type:"turn.completed",usage:{input_tokens:0,cached_input_tokens:0,output_tokens:0}}));
            });
          }
        `,
        );
        const environment: NodeJS.ProcessEnv = {
          ...(replayDefaults === undefined
            ? {}
            : { [replayDefaults.env_key]: "synthetic-selected" }),
          PATH: process.env["PATH"],
          CODEX_CLI_PATH: executable,
          OPENAI_API_KEY:
            providerAuth === "ordinary" ? "synthetic-selected" : undefined,
          SYNTHETIC_PROVIDER_KEY: "synthetic-provider-selected",
          SYNTHETIC_CONTEXT: "selected",
        };
        const config: JsonObject = {
          ...(scenario === "managed"
            ? {
                permissions: {
                  [profileId]: {
                    filesystem: { ":root": "read" },
                    network: { enabled: false },
                  },
                },
              }
            : {}),
          model: "synthetic-model",
          ...(replayProvider !== undefined
            ? scanPreflightCodexConfig({
                model_provider: replayProvider,
                model_providers: {
                  [replayProvider]: {
                    ...replayDefaults!,
                    name: "Synthetic selected provider",
                  },
                },
              })
            : providerAuth === "ordinary"
              ? {}
              : {
                  model_provider: "synthetic",
                  model_providers: {
                    synthetic: {
                      base_url: "https://example.invalid/v1",
                      ...(providerAuth === "env_key"
                        ? { env_key: "SYNTHETIC_PROVIDER_KEY" }
                        : {
                            experimental_bearer_token:
                              "synthetic-bearer-selected",
                          }),
                    },
                  },
                }),
          mcp_servers: {
            synthetic: {
              command: "synthetic-mcp",
              env: { SETTING: "inherited" },
            },
          },
        };
        const configPath = join(home, "config.toml");
        await writeCodexConfig(
          configPath,
          scanRuntimeCodexConfig(config, home),
        );
        const savedConfig = await readFile(configPath, "utf8");
        const source = prepareExecutionSource({
          command: { command: executable },
          configuration: config,
          environment,
          preserveProviderEnvironment,
          ...(providerAuth === "ordinary" ? {} : { auth: "api-key" }),
        });
        const inheritedPermissions = {
          filesystem: { [join(root, "private")]: "deny" },
          network: { enabled: false },
        };
        const session: PreparedExecution = {
          policy: "ordinary",
          source,
          inheritedPermissions,
          runtime: preparedRuntime(home),
          runtimeHome: home,
          effectiveConfig: config,
          preflightConfig: {},
          sessionConfig: scanRuntimeCodexConfig(
            config,
            home,
            inheritedPermissions,
          ),
          authentication: source.authentication,
          approvalPolicy: "on-request",
          python: process.execPath,
          releaseCredentialHome: null,
        };
        if (replayDefaults !== undefined)
          environment[replayDefaults.env_key] = "synthetic-later";
        environment["SYNTHETIC_CONTEXT"] = "later";
        environment["OPENAI_API_KEY"] = "synthetic-later";
        environment["SYNTHETIC_PROVIDER_KEY"] = "synthetic-provider-later";
        const worker =
          role === "ordinary"
            ? session
            : role === "discovery"
              ? prepareDiscoveryExecution(session)
              : prepareMergeExecution(session, 2);
        const children: childProcess.ChildProcess[] = [];
        const spawning = spyOn(childProcess, "spawn").mockImplementation(
          fixtureSpawn(executablePathForSpawn(executable), script, (child) =>
            children.push(child),
          ),
        );
        try {
          const { codex } = createExecutionCodex(
            { surface: "sdk" },
            worker,
            {},
          );
          const thread = resumed
            ? codex.resumeThread!("00000000-0000-4000-8000-000000000001", {
                workingDirectory: root,
              })
            : codex.startThread({ workingDirectory: root });
          const run = async () => {
            const { events } = await thread.runStreamed("inert fixture", {});
            for await (const _event of events) {
            }
          };
          if (scenario === "accepted" || scenario === "managed") await run();
          else if (scenario === "transport") {
            try {
              await run();
              throw new Error("unexpected execution");
            } catch (error) {
              expect(error).not.toBeInstanceOf(ScanPermissionError);
              expect(String(error)).toContain("preflight");
            }
          } else
            await expect(run()).rejects.toBeInstanceOf(ScanPermissionError);
          const records = (await readFile(capture, "utf8"))
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line));
          const executions = records.filter((record) => record.kind === "exec");
          expect(executions).toHaveLength(
            scenario === "rejected" || scenario === "transport" ? 0 : 1,
          );
          for (const record of records) {
            if (scenario === "managed")
              expect(record.config.default_permissions).toBe(profileId);
            const profile =
              record.config.permissions[record.config.default_permissions];
            expect(record.context).toBe("selected");
            expect(record.apiKey).toBe(
              preserveProviderEnvironment || replayProvider !== undefined
                ? undefined
                : "synthetic-selected",
            );
            expect(record.openAiKey).toBe(
              preserveProviderEnvironment && providerAuth === "ordinary"
                ? "synthetic-selected"
                : undefined,
            );
            expect(record.providerKey).toBe("synthetic-provider-selected");
            if (providerAuth !== "ordinary") {
              expect(record.config.model_provider).toBe(
                replayProvider ?? "synthetic",
              );
              expect(record.config["model_providers"]).toEqual(
                replayProvider === undefined
                  ? config["model_providers"]
                  : { [replayProvider]: replayDefaults },
              );
              if (replayProvider !== undefined)
                expect(record.replayProviderKey).toBe("synthetic-selected");
            }
            expect(profile.filesystem[join(root, "private")]).toBe("deny");
            expect(profile.network.enabled).toBe(false);
            expect(profile.filesystem[":root"]).toBe("read");
            expect(profile.filesystem).not.toHaveProperty(":workspace_roots");
            expect(record.config.mcp_servers).toEqual({
              synthetic: {
                command: "synthetic-mcp",
                env: { SETTING: "inherited" },
              },
              ...(role === "ordinary"
                ? {}
                : { "codex-security": { command: "node", enabled: false } }),
            });
            if (role === "merge")
              expect(
                record.config.features.multi_agent_v2
                  .max_concurrent_threads_per_session,
              ).toBe(3);
          }
          if (executions.length)
            expect(executions[0].args.includes("resume")).toBe(resumed);
          expect(await readFile(configPath, "utf8")).toBe(savedConfig);
        } finally {
          for (const child of children)
            if (child.exitCode === null && child.signalCode === null)
              child.kill("SIGKILL");
          for (const child of children)
            while (child.exitCode === null && child.signalCode === null)
              await new Promise<void>((resolve) => setImmediate(resolve));
          spawning.mockRestore();
        }
      }
    }
  },
);

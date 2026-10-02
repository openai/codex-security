import * as childProcess from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { scanRuntimeCodexConfig } from "../src/api.js";
import { writeCodexConfig } from "../src/config.js";
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
  ["discovery", false],
  ["discovery", true],
  ["merge", false],
  ["merge", true],
] as const)(
  "%s workers preserve selected inputs and enforce permissions and managed allowlists in initialized homes on fresh and resumed turns (preserve provider environment: %p)",
  async (role, preserveProviderEnvironment) => {
    for (const resumed of [false, true]) {
      for (const scenario of [
        "accepted",
        "managed",
        "rejected",
        "fallback",
        "transport",
      ] as const) {
        const root = await temporaryDirectory();
        const home = join(root, "home");
        await mkdir(home);
        if (scenario === "managed")
          await writeFile(
            join(home, "requirements.toml"),
            "[allowed_permission_profiles]\ncodex_security_scan_execution = true\n",
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
          record({kind: args.includes("app-server") ? "preflight" : "exec",args,config,context:process.env.SYNTHETIC_CONTEXT,apiKey:process.env.CODEX_API_KEY,openAiKey:process.env.OPENAI_API_KEY});
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
        const environment = {
          PATH: process.env["PATH"],
          CODEX_CLI_PATH: executable,
          OPENAI_API_KEY: "synthetic-selected",
          SYNTHETIC_CONTEXT: "selected",
        };
        const config = {
          ...(scenario === "managed"
            ? {
                permissions: {
                  codex_security_scan_execution: {
                    filesystem: { ":root": "read" },
                    network: { enabled: false },
                  },
                },
              }
            : {}),
          model: "synthetic-model",
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
        environment.SYNTHETIC_CONTEXT = "later";
        environment.OPENAI_API_KEY = "synthetic-later";
        const worker =
          role === "discovery"
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
            const profile =
              record.config.permissions[record.config.default_permissions];
            expect(record.context).toBe("selected");
            expect(record.apiKey).toBe(
              preserveProviderEnvironment ? undefined : "synthetic-selected",
            );
            expect(record.openAiKey).toBe(
              preserveProviderEnvironment ? "synthetic-selected" : undefined,
            );
            expect(profile.filesystem[join(root, "private")]).toBe("deny");
            expect(profile.network.enabled).toBe(false);
            expect(profile.filesystem[":root"]).toBe("read");
            expect(profile.filesystem).not.toHaveProperty(":workspace_roots");
            expect(record.config.mcp_servers).toEqual({
              synthetic: {
                command: "synthetic-mcp",
                env: { SETTING: "inherited" },
              },
              "codex-security": { command: "node", enabled: false },
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

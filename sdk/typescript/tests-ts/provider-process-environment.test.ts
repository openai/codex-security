import * as childProcess from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { scanRuntimeCodexConfig } from "../src/api.js";
import {
  providerProcessConfiguration,
  type JsonObject,
} from "../src/config.js";
import { definedEnvironment } from "../src/execution-auth.js";
import {
  createExecutionCodex,
  prepareDiscoveryExecution,
  prepareMergeExecution,
  prepareExecutionSource,
  type PreparedExecution,
} from "../src/execution-preparation.js";
import { disabledMcpServers } from "../src/scan-comparison.js";
import { executablePathForSpawn } from "../src/runtime.js";
import {
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";
import { fixtureSpawn } from "./support/codex-process.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test("native provider credentials use private process environments across worker roles, resumes, and concurrent scans", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  await mkdir(home, { mode: 0o700 });
  const executable = join(root, "synthetic-codex.exe");
  const script = join(root, "synthetic-codex.cjs");
  const capture = join(root, "capture.jsonl");
  await writeFile(capture, "");
  await writeFile(
    script,
    `
const fs = require("node:fs");
const {parse} = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
const args = process.argv.slice(2), config = {};
const merge = (target,value) => { for(const [key,child] of Object.entries(value)) target[key] = child && typeof child === "object" && !Array.isArray(child) ? merge(target[key] ?? {},child) : child; return target; };
for(let i=0;i<args.length;i++) if(["-c","--config"].includes(args[i])) merge(config,parse(args[++i]));
if(args.includes("mcp")) { fs.appendFileSync(${JSON.stringify(capture)},JSON.stringify({args,privateEnvironment:Object.fromEntries(Object.entries(process.env).filter(([name])=>name.startsWith("CODEX_SECURITY_INTERNAL_")))})+"\\n"); console.log("[]"); process.exit(0); }
const provider = config["model_providers"].synthetic;
const headers = {...provider["http_headers"]};
for(const [key,name] of Object.entries(provider["env_http_headers"] ?? {})) { const value=process.env[name]; if(value?.trim()) headers[key]=value; }
fs.appendFileSync(${JSON.stringify(capture)},JSON.stringify({args,config,headers,bearer:process.env[provider["env_key"]],unused:process.env[config["model_providers"].unused["env_key"]],privateEnvironment:Object.fromEntries(Object.entries(process.env).filter(([name])=>name.startsWith("CODEX_SECURITY_INTERNAL_")))})+"\\n");
if(args.includes("app-server")) require("node:readline").createInterface({input:process.stdin}).on("line",line=>{
 const request=JSON.parse(line); if(request.id===undefined)return;
 const result=request.method==="initialize"?{}:request.method==="config/read"?{config}:{data:[{id:config.default_permissions,allowed:true}],nextCursor:null};
 console.log(JSON.stringify({id:request.id,result}));
}); else if(args.includes("mcp")) console.log("[]");
else { process.stdin.resume(); process.stdin.on("end",()=>{console.log(JSON.stringify({type:"thread.started",thread_id:"00000000-0000-4000-8000-000000000001"})); console.log(JSON.stringify({type:"turn.completed",usage:{input_tokens:0,cached_input_tokens:0,output_tokens:0}}));}); }
`,
  );
  const spawn = spyOn(childProcess, "spawn").mockImplementation(
    fixtureSpawn(executablePathForSpawn(executable), script, () => {}),
  );
  const snapshots: JsonObject[] = [];
  try {
    const sessions = ["first", "second"].map((name) => {
      const configuration: JsonObject = {
        model: "synthetic-model",
        model_provider: "synthetic",
        model_providers: {
          synthetic: {
            base_url: "https://example.invalid/v1",
            experimental_bearer_token: `synthetic-${name}-bearer`,
            http_headers: {
              "X-Synthetic": `synthetic-${name}-header`,
              "X-Fallback": `synthetic-${name}-fallback`,
              "X-Override": "synthetic-superseded",
              "X-Empty": "",
            },
            env_http_headers: {
              "X-Fallback": "SYNTHETIC_MISSING",
              "X-Override": "SYNTHETIC_OVERRIDE",
            },
          },
          unused: { experimental_bearer_token: `synthetic-${name}-unused` },
        },
      };
      snapshots.push(structuredClone(configuration));
      const environment = {
        PATH: process.env["PATH"],
        CODEX_CLI_PATH: executable,
        SYNTHETIC_OVERRIDE: `synthetic-${name}-override`,
      };
      const source = prepareExecutionSource({
        command: { command: executable },
        configuration,
        environment,
        preserveProviderEnvironment: true,
      });
      const permissions = {
        filesystem: { [join(root, name, "private")]: "deny" },
        network: { enabled: false },
      };
      const session: PreparedExecution = {
        policy: "ordinary",
        source,
        inheritedPermissions: permissions,
        runtime: { ...preparedRuntime(home), preserveCodexHomeConfig: true },
        runtimeHome: home,
        effectiveConfig: configuration,
        preflightConfig: {},
        sessionConfig: scanRuntimeCodexConfig(configuration, home, permissions),
        authentication: source.authentication,
        approvalPolicy: "never",
        python: process.execPath,
        releaseCredentialHome: null,
      };
      environment.SYNTHETIC_OVERRIDE = "synthetic-later-mutation";
      return session;
    });
    await Promise.all(
      sessions.map(async (session) => {
        const launch = providerProcessConfiguration(
          session.sessionConfig,
          session.source.environment,
        );
        await disabledMcpServers(
          session.source.command,
          launch.config,
          definedEnvironment(launch.environment),
          { workingDirectory: root },
        );
        for (const role of ["discovery", "merge"] as const) {
          const worker =
            role === "discovery"
              ? prepareDiscoveryExecution(session)
              : prepareMergeExecution(session, 2);
          const { codex } = createExecutionCodex(
            { surface: "sdk" },
            worker,
            {},
          );
          for (const resumed of [false, true]) {
            const options = { workingDirectory: root, skipGitRepoCheck: true };
            const thread = resumed
              ? codex.resumeThread!(
                  "00000000-0000-4000-8000-000000000001",
                  options,
                )
              : codex.startThread(options);
            const { events } = await thread.runStreamed(
              "Synthetic provider transport check.",
              {},
            );
            for await (const _event of events) {
            }
          }
        }
      }),
    );
    const rows = (await readFile(capture, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(rows).toHaveLength(18);
    for (const row of rows) {
      expect(row.args.join("\n")).not.toContain("synthetic-first-");
      expect(row.args.join("\n")).not.toContain("synthetic-second-");
    }
    for (const row of rows.filter((row) => row.args.includes("mcp"))) {
      expect(row.args.join("\n")).not.toContain("synthetic-first-");
      expect(row.args.join("\n")).not.toContain("synthetic-second-");
      expect(
        Object.values(row.privateEnvironment).some((value) =>
          String(value).includes("-bearer"),
        ),
      ).toBe(true);
    }
    for (const [index, name] of ["first", "second"].entries()) {
      const selected = rows.filter(
        (row) => row.bearer === `synthetic-${name}-bearer`,
      );
      expect(selected).toHaveLength(8);
      for (const row of selected) {
        expect(row.args.join("\n")).not.toContain("synthetic-first-");
        expect(row.args.join("\n")).not.toContain("synthetic-second-");
        expect(row.unused).toBe(`synthetic-${name}-unused`);
        expect(row.headers).toEqual({
          "X-Synthetic": `synthetic-${name}-header`,
          "X-Fallback": `synthetic-${name}-fallback`,
          "X-Override": `synthetic-${name}-override`,
          "X-Empty": "",
        });
        expect(
          Object.values(row.privateEnvironment).every((value) =>
            String(value).includes(`synthetic-${name}-`),
          ),
        ).toBe(true);
        if (!row.args.includes("mcp")) {
          const permissions =
            row.config.permissions[row.config.default_permissions];
          expect(permissions.filesystem[join(root, name, "private")]).toBe(
            "deny",
          );
          expect(permissions.network.enabled).toBe(false);
        }
      }
      expect(sessions[index]!.source.configuration["model_providers"]).toEqual(
        snapshots[index]!["model_providers"],
      );
      expect(
        Object.keys(sessions[index]!.source.environment).some((key) =>
          key.startsWith("CODEX_SECURITY_INTERNAL_"),
        ),
      ).toBe(false);
      expect(
        selected
          .filter((row) => row.args.includes("exec"))
          .map((row) => row.args.includes("resume")),
      ).toEqual([false, true, false, true]);
    }
  } finally {
    spawn.mockRestore();
  }
});

test("provider process transport preserves existing keys, blank literals, and environment-header fallback", () => {
  const original: JsonObject = {
    model_providers: {
      selected: {
        env_key: "EXISTING_KEY",
        experimental_bearer_token: "synthetic-unused-bearer",
        http_headers: {
          Authorization: "synthetic-literal",
          "X-Empty": "",
          "X-Blank": "  ",
        },
        env_http_headers: { authorization: "SELECTED_HEADER" },
      },
      blank: { experimental_bearer_token: "  " },
    },
    profiles: {
      inherited: {
        model_providers: {
          selected: { experimental_bearer_token: "synthetic-profile-bearer" },
        },
      },
    },
  };
  for (const selected of [
    undefined,
    "",
    "  ",
    "synthetic-environment",
    "synthetic-Ā",
    "synthetic-😀",
    "invalid\nheader",
  ]) {
    const environment = { SELECTED_HEADER: selected };
    const before = structuredClone(original);
    const launch = providerProcessConfiguration(original, environment);
    const provider = (launch.config["model_providers"] as JsonObject)[
      "selected"
    ] as JsonObject;
    expect(provider["env_key"]).toBe("EXISTING_KEY");
    expect(launch.environment["EXISTING_KEY"]).toBeUndefined();
    expect(provider["experimental_bearer_token"]).toBeUndefined();
    expect(provider["http_headers"]).toEqual({
      "X-Empty": "",
      "X-Blank": "  ",
    });
    const headers = provider["env_http_headers"] as JsonObject;
    if (selected?.startsWith("synthetic-"))
      expect(headers["Authorization"]).toBeUndefined();
    else
      expect(launch.environment[headers["Authorization"] as string]).toBe(
        "synthetic-literal",
      );
    expect((launch.config["model_providers"] as JsonObject)["blank"]).toEqual({
      experimental_bearer_token: "  ",
    });
    expect(JSON.stringify(launch.config)).not.toContain(
      "synthetic-profile-bearer",
    );
    expect(original).toEqual(before);
    expect(environment).toEqual({ SELECTED_HEADER: selected });
  }
});

test.each(["amazon-bedrock", "amazon-bedrock-runtime"])(
  "%s retains its supported literal-header configuration",
  (name) => {
    const config: JsonObject = {
      model_provider: name,
      model_providers: {
        [name]: {
          http_headers: { "X-Synthetic": "synthetic-header" },
          aws: { region: "us-east-1" },
        },
      },
    };
    expect(providerProcessConfiguration(config, {}).config).toEqual(config);
  },
);

import * as childProcess from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  readlink,
  symlink,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { stringify } from "smol-toml";
import { scanRuntimeCodexConfig } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import { definedEnvironment } from "../src/execution-auth.js";
import {
  createExecutionCodex,
  prepareDiscoveryExecution,
  prepareMergeExecution,
  prepareExecutionSource,
  nativeScanConfiguration,
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

test.each([
  { entry: "regular", mode: 0o700, configMode: 0o600 },
  { entry: "regular", mode: 0o700, configMode: 0o600, replay: true },
  { entry: "regular", mode: 0o700, configMode: 0o400 },
  { entry: "regular", mode: 0o755, configMode: 0o600 },
  ...(process.platform === "win32"
    ? []
    : [{ entry: "linked", mode: 0o700, configMode: 0o600 }]),
])(
  "native credentials retain private transport across worker roles, resumes, and concurrent scans: %j",
  async ({ entry, mode, configMode, replay = false }) => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home, { mode });
    if (process.platform !== "win32") await chmod(home, mode);
    const mcpSettings = (name: string): JsonObject => ({
      "synthetic.stdio": {
        command: "synthetic-mcp",
        env: { SHARED_TOKEN: `synthetic-${name}-stdio` },
      },
      "synthetic.other": {
        command: "synthetic-other-mcp",
        env: { SHARED_TOKEN: `synthetic-${name}-other` },
      },
      "synthetic.http": {
        url: "https://example.invalid/mcp",
        http_headers: { Authorization: `synthetic-${name}-http` },
      },
    });
    const originalContents = `# Preserve the caller's original config bytes.\n${stringify({ mcp_servers: mcpSettings("first") })}\n`;
    const configEntry = join(home, "config.toml");
    const configTarget = join(root, "linked-config.toml");
    await writeFile(
      entry === "linked" ? configTarget : configEntry,
      originalContents,
      { mode: configMode },
    );
    if (entry === "linked") await symlink(configTarget, configEntry);
    const originalMetadata = await lstat(configEntry);
    const inheritedConfiguration = await nativeScanConfiguration(
      { CODEX_HOME: home },
      {},
      2,
    );
    const executable = join(root, "synthetic-codex.exe");
    const script = join(root, "synthetic-codex.cjs");
    const capture = join(root, "capture.jsonl");
    await writeFile(capture, "");
    await writeFile(
      script,
      `
const fs = require("node:fs");
const {parse} = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
const args = process.argv.slice(2), config = parse(fs.readFileSync(require("node:path").join(process.env.CODEX_HOME,"config.toml"),"utf8"));
const merge = (target,value) => { for(const [key,child] of Object.entries(value)) target[key] = child && typeof child === "object" && !Array.isArray(child) ? merge(target[key] ?? {},child) : child; return target; };
if(args.includes("--profile")) merge(config,parse(fs.readFileSync(require("node:path").join(process.env.CODEX_HOME,args[args.indexOf("--profile")+1]+".config.toml"),"utf8")));
for(let i=0;i<args.length;i++) if(["-c","--config"].includes(args[i])) merge(config,parse(args[++i]));
if(args.includes("mcp")) { fs.appendFileSync(${JSON.stringify(capture)},JSON.stringify({args,privateEnvironment:Object.fromEntries(Object.entries(process.env).filter(([name])=>name.startsWith("CODEX_SECURITY_INTERNAL_")))})+"\\n"); console.log("[]"); process.exit(0); }
const provider = config["model_providers"].synthetic;
const headers = {...provider["http_headers"]};
for(const [key,name] of Object.entries(provider["env_http_headers"] ?? {})) { const value=process.env[name]; if(value?.trim()) headers[key]=value; }
fs.appendFileSync(${JSON.stringify(capture)},JSON.stringify({args,ambientContents:fs.readFileSync(${JSON.stringify(configEntry)},"utf8"),config,headers,auth:provider.auth,role:process.env.SYNTHETIC_ROLE,mcpServers:config.mcp_servers,bearer:provider.experimental_bearer_token ?? process.env[provider["env_key"]],unused:config["model_providers"].unused.experimental_bearer_token,ambientOverride:process.env.SYNTHETIC_OVERRIDE,literalCredentialInEnvironment:[provider.experimental_bearer_token,provider.http_headers?.["X-Synthetic"],...Object.values(provider.auth?.env ?? {})].some(value=>typeof value==="string"&&Object.values(process.env).includes(value)),privateEnvironment:Object.fromEntries(Object.entries(process.env).filter(([name])=>name.startsWith("CODEX_SECURITY_INTERNAL_")))})+"\\n");
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
    const managedHome = join(root, "managed-home");
    if (replay) await mkdir(managedHome, { mode: 0o700 });
    const runtimeHome = replay ? managedHome : home;
    const snapshots: JsonObject[] = [];
    try {
      const sessions = ["first", "second"].map((name) => {
        const configuration: JsonObject = {
          ...(name === "first" ? inheritedConfiguration : {}),
          mcp_servers:
            name === "first"
              ? inheritedConfiguration["mcp_servers"]!
              : mcpSettings(name),
          model: "synthetic-model",
          shell_environment_policy: {
            inherit: "all",
            ignore_default_excludes: true,
          },
          model_provider: "synthetic",
          model_providers: {
            synthetic: {
              base_url: "https://example.invalid/v1",
              auth: {
                command: "synthetic-auth",
                args: [],
                env: { CLIENT_SECRET: `synthetic-${name}-command` },
              },
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
          CODEX_HOME: home,
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
          runtime: {
            ...preparedRuntime(runtimeHome),
            preserveCodexHomeConfig: !replay,
          },
          runtimeConfig: replay ? {} : undefined,
          runtimeHome,
          effectiveConfig: configuration,
          preflightConfig: {},
          sessionConfig: scanRuntimeCodexConfig(
            configuration,
            runtimeHome,
            permissions,
          ),
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
          await disabledMcpServers(
            session.source.command,
            session.sessionConfig,
            definedEnvironment(session.source.environment),
            { workingDirectory: root },
          );
          for (const role of ["ordinary", "discovery", "merge"] as const) {
            const worker =
              role === "discovery"
                ? prepareDiscoveryExecution(session)
                : role === "merge"
                  ? prepareMergeExecution(session, 2)
                  : session;
            const { codex } = createExecutionCodex({ surface: "sdk" }, worker, {
              SYNTHETIC_ROLE: role,
            });
            for (const resumed of [false, true]) {
              const options = {
                workingDirectory: root,
                skipGitRepoCheck: true,
              };
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
      expect(rows).toHaveLength(26);
      for (const row of rows) {
        expect(row.args.join("\n")).not.toContain("synthetic-first-");
        expect(row.args.join("\n")).not.toContain("synthetic-second-");
      }
      const enumerations = rows.filter((row) => row.args.includes("mcp"));
      expect(enumerations).toHaveLength(2);
      for (const row of enumerations) {
        expect(row.args.join("\n")).not.toContain("synthetic-first-");
        expect(row.args.join("\n")).not.toContain("synthetic-second-");
        expect(row.privateEnvironment).toEqual({});
      }
      const preflights = rows.filter((row) => row.args.includes("app-server"));
      expect(preflights).toHaveLength(12);
      for (const row of preflights) {
        const name = ["first", "second"].find(
          (name) => row.ambientOverride === `synthetic-${name}-override`,
        );
        expect(name).toBeDefined();
        expect(row.privateEnvironment).toEqual({});
        expect(row.literalCredentialInEnvironment).toBe(false);
        const permissions =
          row.config.permissions[row.config.default_permissions];
        expect(permissions.filesystem[join(root, name!, "private")]).toBe(
          "deny",
        );
        expect(permissions.network.enabled).toBe(false);
      }
      for (const [index, name] of ["first", "second"].entries()) {
        const selected = rows.filter(
          (row) =>
            row.args.includes("exec") &&
            row.bearer === `synthetic-${name}-bearer`,
        );
        expect(selected).toHaveLength(6);
        for (const row of selected) {
          expect(row.ambientContents).toBe(originalContents);
          expect(row.args.join("\n")).not.toContain("synthetic-first-");
          expect(row.args.join("\n")).not.toContain("synthetic-second-");
          expect(row.unused).toBe(`synthetic-${name}-unused`);
          expect(row.mcpServers).toMatchObject(mcpSettings(name));
          if (row.role !== "ordinary")
            expect(row.mcpServers["codex-security"].enabled).toBe(false);
          expect(row.auth).toEqual({
            command: "synthetic-auth",
            args: [],
            env: { CLIENT_SECRET: `synthetic-${name}-command` },
          });
          expect(row.headers).toEqual({
            "X-Synthetic": `synthetic-${name}-header`,
            "X-Fallback": `synthetic-${name}-fallback`,
            "X-Override": `synthetic-${name}-override`,
            "X-Empty": "",
          });
          expect(row.privateEnvironment).toEqual({});
          expect(row.literalCredentialInEnvironment).toBe(false);
          expect(row.ambientOverride).toBe(`synthetic-${name}-override`);
          expect(row.config.shell_environment_policy).toEqual({
            inherit: "all",
            ignore_default_excludes: true,
          });
          if (!row.args.includes("mcp")) {
            const permissions =
              row.config.permissions[row.config.default_permissions];
            expect(permissions.filesystem[join(root, name, "private")]).toBe(
              "deny",
            );
            expect(permissions.network.enabled).toBe(false);
          }
        }
        expect(sessions[index]!.source.configuration["mcp_servers"]).toEqual(
          snapshots[index]!["mcp_servers"],
        );
        expect(
          sessions[index]!.source.configuration["model_providers"],
        ).toEqual(snapshots[index]!["model_providers"]);
        expect(
          Object.keys(sessions[index]!.source.environment).some((key) =>
            key.startsWith("CODEX_SECURITY_INTERNAL_"),
          ),
        ).toBe(false);
        expect(
          selected
            .filter((row) => row.args.includes("exec"))
            .map((row) => row.args.includes("resume")),
        ).toEqual([false, true, false, true, false, true]);
      }
      expect(await readFile(configEntry, "utf8")).toBe(originalContents);
      const restoredMetadata = await lstat(configEntry);
      expect(restoredMetadata.ino).toBe(originalMetadata.ino);
      expect(restoredMetadata.dev).toBe(originalMetadata.dev);
      expect((await lstat(home)).mode & 0o777).toBe(
        process.platform === "win32" ? (await lstat(home)).mode & 0o777 : mode,
      );
      if (entry === "linked") {
        expect((await lstat(configEntry)).isSymbolicLink()).toBe(true);
        expect(await readlink(configEntry)).toBe(configTarget);
        expect(await readFile(configTarget, "utf8")).toBe(originalContents);
      } else {
        expect((await lstat(configEntry)).mode).toBe(originalMetadata.mode);
      }
    } finally {
      spawn.mockRestore();
    }
  },
);

test.each(["amazon-bedrock", "amazon-bedrock-runtime"])(
  "%s keeps literal headers in config at fresh and resumed worker boundaries",
  async (name) => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home, { mode: 0o700 });
    const configuration: JsonObject = {
      model: "synthetic-model",
      model_provider: name,
      model_providers: {
        [name]: {
          aws: { region: "us-east-1" },
          http_headers: { "X-Synthetic": "synthetic-bedrock-file-header" },
        },
      },
    };
    const contents = stringify(configuration);
    await writeFile(join(home, "config.toml"), contents, { mode: 0o600 });
    const executable = join(root, "synthetic-bedrock-codex.exe");
    const script = join(root, "synthetic-bedrock-codex.cjs");
    const capture = join(root, "capture.jsonl");
    await writeFile(capture, "");
    await writeFile(
      script,
      `
const fs=require("node:fs"), {parse}=require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
const args=process.argv.slice(2), config=parse(fs.readFileSync(require("node:path").join(process.env.CODEX_HOME,"config.toml"),"utf8"));
const merge=(target,value)=>{for(const [key,child]of Object.entries(value)) target[key]=child&&typeof child==="object"&&!Array.isArray(child)?merge(target[key]??{},child):child;return target;};
if(args.includes("--profile")) merge(config,parse(fs.readFileSync(require("node:path").join(process.env.CODEX_HOME,args[args.indexOf("--profile")+1]+".config.toml"),"utf8")));
for(let i=0;i<args.length;i++) if(["-c","--config"].includes(args[i])) merge(config,parse(args[++i]));
fs.appendFileSync(${JSON.stringify(capture)},JSON.stringify({args,provider:config.model_providers[config.model_provider]})+"\\n");
if(args.includes("app-server")) require("node:readline").createInterface({input:process.stdin}).on("line",line=>{const request=JSON.parse(line);if(request.id===undefined)return; const result=request.method==="initialize"?{}:request.method==="config/read"?{config}:{data:[{id:config.default_permissions,allowed:true}],nextCursor:null}; console.log(JSON.stringify({id:request.id,result}));});
else { process.stdin.resume();process.stdin.on("end",()=>{console.log(JSON.stringify({type:"thread.started",thread_id:"00000000-0000-4000-8000-000000000001"}));console.log(JSON.stringify({type:"turn.completed",usage:{input_tokens:0,cached_input_tokens:0,output_tokens:0}}));});}
`,
    );
    const spawn = spyOn(childProcess, "spawn").mockImplementation(
      fixtureSpawn(executablePathForSpawn(executable), script, () => {}),
    );
    try {
      const source = prepareExecutionSource({
        command: { command: executable },
        configuration,
        environment: {
          PATH: process.env["PATH"],
          CODEX_HOME: home,
          CODEX_CLI_PATH: executable,
        },
        preserveProviderEnvironment: true,
      });
      const permissions = {
        filesystem: { [join(root, "private")]: "deny" },
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
      for (const role of ["discovery", "merge"] as const) {
        const worker =
          role === "discovery"
            ? prepareDiscoveryExecution(session)
            : prepareMergeExecution(session, 2);
        const { codex } = createExecutionCodex({ surface: "sdk" }, worker, {});
        for (const resumed of [false, true]) {
          const options = { workingDirectory: root, skipGitRepoCheck: true };
          const thread = resumed
            ? codex.resumeThread!(
                "00000000-0000-4000-8000-000000000001",
                options,
              )
            : codex.startThread(options);
          const { events } = await thread.runStreamed(
            "Synthetic Bedrock credential boundary.",
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
      expect(rows).toHaveLength(8);
      for (const row of rows) {
        expect(row.args.join("\n")).not.toContain(
          "synthetic-bedrock-file-header",
        );
        expect(row.provider.http_headers).toEqual({
          "X-Synthetic": "synthetic-bedrock-file-header",
        });
        expect(row.provider.aws).toEqual({ region: "us-east-1" });
        expect(row.provider.env_http_headers).toBeUndefined();
      }
      expect(await readFile(join(home, "config.toml"), "utf8")).toBe(contents);
    } finally {
      spawn.mockRestore();
    }
  },
);

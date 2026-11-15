import { expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { join } from "node:path";
import { parse as parseToml } from "smol-toml";
import { readSkillCommandOutput, runCodexSkillCommand } from "../src/cli.js";
import { modelProviderConfigOverride, type JsonObject } from "../src/config.js";
import {
  openDependencyGraph,
  type DependencyGraphTools,
} from "../src/dependency-graph-tools.js";
import { createDependencyInventory } from "../src/dependency-inventory.js";
import { createDependencyNativeSession } from "../src/dependency-native-session.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";

type AppServer = NonNullable<Parameters<typeof readSkillCommandOutput>[1]>;
type Recovery = NonNullable<AppServer["recovery"]>;

const fakeServer = String.raw`
const readline = require("node:readline");
const mode = process.argv[2];
const send = value => process.stdout.write(JSON.stringify(value) + "\n");
const tool = (id, namespace, name, args) => send({id,method:"item/tool/call",params:{threadId:"check",turnId:mode,namespace,tool:name,arguments:args}});
readline.createInterface({input:process.stdin}).on("line", line => {
  const message = JSON.parse(line);
  if (message.method === "initialize") send({id:message.id,result:{}});
  if (message.method === "config/read") send({id:message.id,result:{config:{},layers:[]}});
  if (message.method === "thread/start" || message.method === "thread/resume") {
    if (mode === "second" && (message.method !== "thread/resume" || "dynamicTools" in message.params)) process.exit(10);
    send({id:message.id,result:{thread:{id:"check",ephemeral:false,path:"/synthetic/check.jsonl"},activePermissionProfile:{id:"restricted"},model:"synthetic",modelProvider:"openai"}});
  }
  if (message.method === "turn/start") {
    send({id:message.id,result:{turn:{id:mode}}});
    send({method:"thread/tokenUsage/updated",params:{threadId:"check",turnId:mode,tokenUsage:{total:{inputTokens:mode==="first"?10:20,cachedInputTokens:0,outputTokens:1}}}});
    if (mode === "first") {
      send({method:"turn/plan/updated",params:{threadId:"check",turnId:mode,plan:[{step:"L1 selected parser copy",status:"inProgress"}]}});
      send({method:"item/completed",params:{threadId:"check",turnId:mode,item:{id:"runtime-receipt",type:"mcpToolCall",server:"runtime",tool:"lookup",arguments:{artifact:"synthetic"},status:"completed",result:{structuredContent:{artifact:"synthetic",copy:"patched"}}}}});
      tool("save", "codex_security_dependency", "record_codex_security_evidence", {question:"L1 selected parser copy",scope:"parser",claim:"The guard returns early.",evidence:[{path:"parser.js",startLine:1,endLine:1}]});
    } else tool("list", "codex_security_dependency", "query_codex_security_graph", {evidence:{}});
  }
  if (message.id === "save") {
    if (!message.result.success) process.exit(11);
    tool("pending", "codex_security_dependency", "lookup_codex_security_inventory", {});
  }
  if (message.method === "mcpServer/tool/call") {
    process.exit(9);
  }
  if (message.id === "list") {
    const data = JSON.parse(message.result.contentItems[0].text);
    if (data.source_evidence.length !== 1) process.exit(12);
    tool("read", "codex_security_dependency", "query_codex_security_graph", {evidence:{id:data.source_evidence[0].id}});
  }
  if (message.id === "read") {
    const data = JSON.parse(message.result.contentItems[0].text);
    if (data.source_evidence.excerpts[0].text !== "return [];") process.exit(13);
    tool("status", "codex_security_reports", "get_codex_security_review_status", {inventoryReceipts:true});
  }
  if (message.id === "status") {
    const data = JSON.parse(message.result.contentItems[0].text);
    if (data.inventoryReceipts.length !== 1 || data.inventoryReceipts[0].id !== "inventory-1") process.exit(14);
    tool("submit", "codex_security_reports", "produce_codex_security_exploit_report", {synthetic:true});
  }
  if (message.id === "submit") {
    if (!message.result.success) process.exit(15);
    send({method:"turn/completed",params:{threadId:"check",turn:{id:mode,status:"completed"}}});
  }
}).on("close", () => process.exit(0));
`;

test("a replacement app-server resumes the same plan, graph notes, receipts, and usage", async () => {
  const repository = await realpath(
    await mkdtemp(join(tmpdir(), "native-recovery-")),
  );
  const children: ReturnType<typeof spawn>[] = [];
  try {
    await mkdir(join(repository, "mcp"));
    await writeFile(
      join(repository, "mcp/helpers.mjs"),
      `export default {createDependencyGraphSession(){return {tools:[{name:"query_codex_security_graph",description:"Query",inputSchema:{type:"object",properties:{},additionalProperties:false}}],close:async()=>{},call:async()=>({code_paths_found:0,service_resolution:{catalog_configured:false}})}}};`,
    );
    await writeFile(join(repository, "parser.js"), "return [];\n");
    const script = join(repository, "server.cjs");
    await writeFile(script, fakeServer);
    const sourceGraph = await openDependencyGraph(repository, repository);
    let pendingLookups = 0;
    const graph: DependencyGraphTools = {
      ...sourceGraph,
      call: async (name, args, rpc) => {
        if (name === "lookup_codex_security_inventory") {
          pendingLookups++;
          return (await rpc!.call(
            "runtime",
            "pending_lookup",
            {},
          )) as JsonObject;
        }
        return sourceGraph.call(name, args, rpc);
      },
    };
    const inventory = createDependencyInventory();
    let submits = 0;
    const report: AppServer["dependencyReport"] = {
      recordInventory: inventory.record,
      recordGraphEvent() {},
      status: () => ({ inventoryReceipts: inventory.snapshot() }),
      continuationPrompt: () => undefined,
      submit: async () => {
        submits++;
        return { accepted: true, feedback: "Accepted" };
      },
    };
    const recovery: Recovery = {
      session: createDependencyNativeSession(),
      usage: new Map(),
      finishedTurns: new Set(),
      completedTurnNotifications: new Set(),
    };
    for (const mode of ["first", "second"]) {
      const child = spawn(process.execPath, [script, mode], {
        stdio: ["pipe", "pipe", "pipe"],
      });
      children.push(child);
      const closed = once(child, "close");
      const result = await readSkillCommandOutput(
        child.stdout!,
        {
          directory: repository,
          prompt: "Synthetic advisory and caller scope",
          sandbox: "read-only",
          permissionProfile: "restricted",
          modelProvider: "openai",
          cyberAccessProgram: "standard",
          threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
          dependencyGraph: graph,
          dependencyReport: report,
          allowedMcpServers: ["runtime"],
          recovery,
          input: child.stdin!,
        },
        () => {},
      );
      const [status] = await closed;
      expect(status).toBe(mode === "first" ? 9 : 0);
      expect(result.completed).toBe(mode === "second");
      if (mode === "first") {
        expect(recovery.threadId).toBe("check");
        expect(recovery.plan).toEqual([
          { step: "L1 selected parser copy", status: "inProgress" },
        ]);
        recovery.session.resetTurns();
      }
    }
    expect(submits).toBe(1);
    expect(pendingLookups).toBe(1);
    expect(inventory.snapshot()).toHaveLength(1);
    expect(recovery.usage.size).toBe(1);
    expect(recovery.usage.get("check")?.input_tokens).toBe(20);
    await graph.close();
  } finally {
    for (const child of children)
      if (child.exitCode === null) child.kill("SIGKILL");
    await rm(repository, { recursive: true, force: true });
  }
}, 10000);

test("preserves selected access and permissions across concurrent native resumes", async () => {
  const { spyOn } = await import("bun:test");
  const profile = await import("../src/provider-profile.js");
  const { Writable } = await import("node:stream");
  const preflight = spyOn(
    profile,
    "preflightReadOnlyProfileCodex",
  ).mockResolvedValue({
    permissionProfileId: "restricted",
    configOverrides: [],
  });
  const server = String.raw`
const fs = require("node:fs");
const readline = require("node:readline");
const path = process.env.ACCESS_RECORD;
const records = fs.existsSync(path) ? JSON.parse(fs.readFileSync(path, "utf8")) : [];
const mode = records.length ? "second" : "first";
const argv = process.argv.slice(2);
const {parse} = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
let daybreak = false;
const flags = {api_key_cyber_access_programs:true};
for (let index=0;index<argv.length;index++) {
  if (argv[index] !== "--config") continue;
  const override = parse(argv[++index]);
  if ("daybreak" in override) daybreak = override.daybreak;
  Object.assign(flags,override.features);
}
const entry = {mode,home:process.env.CODEX_HOME,argv};
records.push(entry);
const save = () => fs.writeFileSync(path, JSON.stringify(records));
const send = value => process.stdout.write(JSON.stringify(value) + "\n");
save();
readline.createInterface({input:process.stdin}).on("line", line => {
  const message = JSON.parse(line);
  if (message.method === "initialize" || message.method === "account/login/start") send({id:message.id,result:{}});
  if (message.method === "config/read") send({id:message.id,result:{config:{daybreak,features:flags},layers:[]}});
  if (message.method === "experimentalFeature/list") send({id:message.id,result:{data:Object.entries(flags).map(([name,enabled])=>({name,enabled}))}});
  if (message.method === "account/read") send({id:message.id,result:{account:{type:"apiKey"}}});
  if (message.method === "model/list") send({id:message.id,result:{data:[{model:"synthetic",availableAccessPrograms:{cyber:["standard","daybreakBlue"]}}]}});
  if (message.method === "thread/start" || message.method === "thread/resume") {
    entry.thread = {method:message.method,approvalPolicy:message.params.approvalPolicy,permissions:message.params.permissions,excludeTurns:message.params.excludeTurns,hasDynamicTools:"dynamicTools" in message.params};
    save();
    send({id:message.id,result:{thread:{id:"check",ephemeral:false,path:"/synthetic/check.jsonl"},activePermissionProfile:{id:"restricted"},model:"synthetic",modelProvider:"openai"}});
  }
  if (message.method === "turn/start") {
    entry.program = message.params.cyberAccessProgram;
    save();
    send({id:message.id,result:{turn:{id:mode}}});
    if (mode === "first") process.stdout.write("", () => process.exit(9));
    else send({id:"submit",method:"item/tool/call",params:{threadId:"check",turnId:mode,namespace:"codex_security_reports",tool:"produce_codex_security_exploit_report",arguments:{}}});
  }
  if (message.id === "submit") {
    if (!message.result.success) process.exit(12);
    send({method:"turn/completed",params:{threadId:"check",turn:{id:mode,status:"completed"}}});
  }
}).on("close",()=>process.exit(0));
`;
  try {
    const homes = await Promise.all(
      [true, false].map(async (enabled) => {
        const repository = await realpath(
          await mkdtemp(join(tmpdir(), "native-access-")),
        );
        try {
          const home = join(repository, "home");
          await mkdir(home);
          const script = join(repository, "server.cjs");
          const record = join(repository, "launches.json");
          await writeFile(script, server);
          const codexOverrides = {
            daybreak: enabled,
            features: {
              cli_daybreak: true,
              multi_agent_v2: { max_concurrent_threads_per_session: 49 },
            },
          };
          const bindings: Array<{ config: JsonObject; program: unknown }> = [];
          const status = await runCodexSkillCommand(
            [
              script,
              "app-server",
              "--config",
              `daybreak=${enabled}`,
              "--config",
              "features.cli_daybreak=true",
              "--config",
              "features.multi_agent_v2.max_concurrent_threads_per_session=49",
            ],
            {
              command: "exploitability check",
              auth: "api-key",
              modelProvider: "openai",
              codexOverrides,
              directory: repository,
              readOnlySkillRoot: repository,
              stdout: new Writable({
                write(_chunk, _encoding, done) {
                  done();
                },
              }),
              stderr: new Writable({
                write(_chunk, _encoding, done) {
                  done();
                },
              }),
              appServer: {
                directory: repository,
                prompt: "Synthetic advisory",
                sandbox: "read-only",
                threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
                dependencyReport: {
                  bindReviewer(_environment, config, program) {
                    bindings.push({ config, program });
                  },
                  recordInventory: () => undefined,
                  recordGraphEvent() {},
                  continuationPrompt: () => undefined,
                  submit: async () => ({
                    accepted: true,
                    feedback: "Accepted",
                  }),
                },
              },
            },
            { command: process.execPath },
            {
              ...process.env,
              CODEX_HOME: home,
              ACCESS_RECORD: record,
              CODEX_API_KEY: "synthetic-access-key",
              OPENAI_API_KEY: "synthetic-access-key",
            },
          );
          expect(status).toBe(0);
          const launches = JSON.parse(await readFile(record, "utf8")) as Array<{
            home: string;
            argv: string[];
            program: string;
            thread: {
              method: string;
              approvalPolicy: string;
              permissions: string;
              excludeTurns?: boolean;
              hasDynamicTools: boolean;
            };
          }>;
          expect(launches).toHaveLength(2);
          expect(new Set(launches.map((x) => x.home)).size).toBe(1);
          for (const launch of launches) {
            expect(launch.argv).toContain(`daybreak=${enabled}`);
            expect(launch.argv).toContain("features.cli_daybreak=true");
            expect(launch.argv).toContain(
              "features.multi_agent_v2.max_concurrent_threads_per_session=49",
            );
            expect(launch.program).toBe(enabled ? "daybreakBlue" : "standard");
            expect(launch.thread).toMatchObject({
              approvalPolicy: "never",
              permissions: "restricted",
            });
          }
          expect(launches[0]?.thread).toMatchObject({
            method: "thread/start",
            hasDynamicTools: true,
          });
          expect(launches[1]?.thread).toMatchObject({
            method: "thread/resume",
            excludeTurns: true,
            hasDynamicTools: false,
          });
          expect(bindings).toHaveLength(2);
          for (const binding of bindings) {
            expect(binding.config["model_provider"]).toBe("openai");
            expect(binding.program).toBe(enabled ? "daybreak_blue" : undefined);
            if (enabled)
              expect(binding.config).toMatchObject({
                daybreak: true,
                features: { cli_daybreak: true },
              });
          }
          return launches[0]!.home;
        } finally {
          await rm(repository, { recursive: true, force: true });
        }
      }),
    );
    expect(new Set(homes).size).toBe(2);
  } finally {
    preflight.mockRestore();
  }
}, 10000);

test("the CLI resumes with its provider and preserves model errors and cancellation", async () => {
  const { spyOn } = await import("bun:test");
  const profile = await import("../src/provider-profile.js");
  const { runCodexSkillCommand } = await import("../src/cli.js");
  const preflight = spyOn(
    profile,
    "preflightReadOnlyProfileCodex",
  ).mockResolvedValue({
    permissionProfileId: "restricted",
    configOverrides: [],
  });
  const { readFile } = await import("node:fs/promises");
  const { Writable } = await import("node:stream");
  const provider = "recovery-provider";
  const providerConfiguration = {
    name: "Recovery gateway",
    base_url: "https://recovery.example.test/v1",
    wire_api: "responses",
    env_key: "RECOVERY_PROVIDER_KEY",
  };
  const codexOverrides = {
    model_provider: provider,
    model_providers: { [provider]: providerConfiguration },
    features: { multi_agent_v2: { max_concurrent_threads_per_session: 49 } },
  };
  try {
    for (const scenario of [
      "recover",
      "receipt-routing-recover",
      "receipt-ancestry-recover",
      "second-failure",
      "model-error",
      "cancel",
    ]) {
      const repository = await realpath(
        await mkdtemp(join(tmpdir(), "native-auto-recovery-")),
      );
      try {
        await mkdir(join(repository, "mcp"));
        await mkdir(join(repository, "home"));
        await writeFile(
          join(repository, "mcp/helpers.mjs"),
          `export default {createDependencyGraphSession(){return {tools:[],close:async()=>{},call:async()=>({code_paths_found:0,service_resolution:{catalog_configured:false}})}}};`,
        );
        await writeFile(join(repository, "parser.js"), "return [];\n");
        const script = join(repository, "server.cjs");
        const launchesPath = join(repository, "launches.json");
        const server = fakeServer
          .replace(
            "const mode = process.argv[2];",
            String.raw`
const fs = require("node:fs");
const launchesPath = process.env.RECOVERY_LAUNCHES;
const launches = fs.existsSync(launchesPath) ? JSON.parse(fs.readFileSync(launchesPath, "utf8")) : [];
const mode = launches.length === 0 ? "first" : "second";
launches.push({
  home: process.env.CODEX_HOME,
  argv: process.argv.slice(2),
  providerEnv: process.env.RECOVERY_PROVIDER_KEY,
  providerConfig: fs.readFileSync(
    require("node:path").join(process.env.CODEX_HOME, "config.toml"), "utf8"
  ),
});
fs.writeFileSync(launchesPath, JSON.stringify(launches));
if (mode === "second" && process.env.RECOVERY_SCENARIO === "second-failure") {
  process.stderr.write("second process failure diagnostic\n");
  process.exit(17);
}
`,
          )
          .replace(
            'modelProvider:"openai"',
            `modelProvider:${JSON.stringify(provider)}`,
          )
          .replace(
            'if (message.id === "save") {',
            String.raw`
if (message.method === "thread/read" && mode === "second" && process.env.RECOVERY_SCENARIO === "receipt-ancestry-recover") {
  send({id:message.id,result:{thread:{id:message.params.threadId,parentThreadId:"check",status:{type:"idle"}}}});
  return;
}
if (message.method === "thread/read" && mode === "first" && process.env.RECOVERY_SCENARIO === "receipt-ancestry-recover") {
  process.stdout.write(JSON.stringify({method:"item/completed",params:{threadId:"check",turnId:"first",item:{type:"subAgentActivity",kind:"started",agentThreadId:"child"}}}) + "\n", () => process.exit(9));
  return;
}
if (message.method === "thread/read" && mode === "first" && process.env.RECOVERY_SCENARIO === "receipt-routing-recover") {
  process.exit(9);
}
if (message.id === "save" && ["receipt-routing-recover", "receipt-ancestry-recover"].includes(process.env.RECOVERY_SCENARIO)) {
  if (!message.result.success) process.exit(11);
  send({method:"thread/status/changed",params:{threadId:"child",status:{type:"active"}}});
  send({method:"turn/started",params:{threadId:"child",turn:{id:"child-turn"}}});
  send({method:"item/completed",params:{threadId:"child",turnId:"child-turn",item:{id:"unverified-child",type:"mcpToolCall",server:"runtime",tool:"lookup",arguments:{artifact:"unverified"},status:"completed",result:{structuredContent:{artifact:"unverified"}}}}});
  return;
}
if (message.id === "save") {
`,
          )
          .replace(
            "if (data.inventoryReceipts.length !== 1 ||",
            'if (data.inventoryReceipts.length !== (process.env.RECOVERY_SCENARIO === "receipt-ancestry-recover" ? 2 : 1) ||',
          )
          .replace(
            'if (message.method === "turn/start") {',
            String.raw`
if (message.method === "turn/start" && process.env.RECOVERY_SCENARIO === "model-error") {
  send({id:message.id,result:{turn:{id:mode}}});
  send({method:"turn/completed",params:{threadId:"check",turn:{id:mode,status:"failed",error:{message:"model request failed"}}}});
  return;
}
if (message.method === "turn/start") {
`,
          );
        await writeFile(script, server);
        const sourceGraph = await openDependencyGraph(repository, repository);
        const graph: DependencyGraphTools = {
          ...sourceGraph,
          call: async (name, args, rpc) => {
            if (name === "lookup_codex_security_inventory")
              return (await rpc!.call(
                "runtime",
                "pending_lookup",
                {},
              )) as JsonObject;
            return sourceGraph.call(name, args, rpc);
          },
        };
        const inventory = createDependencyInventory();
        let submits = 0;
        let stderr = "";
        const controller = new AbortController();
        const status = await runCodexSkillCommand(
          [
            script,
            "--config",
            `model_provider=${JSON.stringify(provider)}`,
            "--config",
            "features.multi_agent_v2.max_concurrent_threads_per_session=49",
            ...modelProviderConfigOverride(codexOverrides).flatMap((value) => [
              "--config",
              value,
            ]),
          ],
          {
            command: "exploitability check",
            auth: "api-key",
            modelProvider: provider,
            codexOverrides,
            directory: repository,
            readOnlySkillRoot: repository,
            allowedMcpServers: ["runtime"],
            signal: controller.signal,
            stdout: new Writable({
              write(_chunk, _encoding, callback) {
                callback();
              },
            }),
            stderr: new Writable({
              write(chunk, _encoding, callback) {
                stderr += String(chunk);
                callback();
              },
            }),
            appServer: {
              directory: repository,
              prompt: "Synthetic advisory and caller scope",
              sandbox: "read-only",
              cyberAccessProgram: "standard",
              threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
              dependencyGraph: graph,
              onEvent(event) {
                if (
                  scenario === "cancel" &&
                  event["method"] === "turn/plan/updated"
                )
                  controller.abort("SIGTERM");
              },
              dependencyReport: {
                recordInventory: inventory.record,
                recordGraphEvent() {},
                status: () => ({ inventoryReceipts: inventory.snapshot() }),
                continuationPrompt: () => undefined,
                submit: async () => {
                  submits++;
                  return { accepted: true, feedback: "Accepted" };
                },
              },
            },
          },
          { command: process.execPath },
          {
            ...process.env,
            CODEX_HOME: join(repository, "home"),
            RECOVERY_LAUNCHES: launchesPath,
            RECOVERY_SCENARIO: scenario,
            RECOVERY_PROVIDER_KEY: "synthetic-provider-value",
          },
        );
        const launches = JSON.parse(await readFile(launchesPath, "utf8"));
        expect(launches).toHaveLength(
          scenario === "model-error" || scenario === "cancel" ? 1 : 2,
        );
        expect(
          new Set(launches.map((item: { home: string }) => item.home)).size,
        ).toBe(1);
        for (const launch of launches as {
          argv: string[];
          providerEnv: string;
          providerConfig: string;
        }[]) {
          expect(launch.argv).toContain(
            `model_provider=${JSON.stringify(provider)}`,
          );
          expect(launch.argv).toContain(
            "features.multi_agent_v2.max_concurrent_threads_per_session=49",
          );
          const overrides = launch.argv.flatMap((argument, index) =>
            argument === "--config" ? [launch.argv[index + 1]!] : [],
          );
          expect(
            parseToml(
              overrides
                .filter((value) => !value.startsWith("features."))
                .join("\n"),
            ),
          ).toMatchObject({
            model_provider: provider,
            model_providers: { [provider]: providerConfiguration },
          });
          expect(parseToml(launch.providerConfig)).toEqual({
            model_provider: provider,
            model_providers: { [provider]: providerConfiguration },
          });
          expect(launch.providerEnv).toBe("synthetic-provider-value");
        }
        if (
          scenario === "recover" ||
          scenario === "receipt-routing-recover" ||
          scenario === "receipt-ancestry-recover"
        ) {
          expect(status).toBe(0);
          expect(submits).toBe(1);
          expect(inventory.snapshot()).toHaveLength(
            scenario === "receipt-ancestry-recover" ? 2 : 1,
          );
          expect(stderr).toContain("Resuming the investigation");
        } else if (scenario === "second-failure") {
          expect(status).toBe(17);
          expect(stderr).toContain("second process failure diagnostic");
        } else if (scenario === "model-error") {
          expect(status).toBe(1);
          expect(stderr).toContain("model request failed");
          expect(stderr).not.toContain("Resuming the investigation");
        } else {
          expect(status).toBe(143);
          expect(submits).toBe(0);
          expect(stderr).not.toContain("Resuming the investigation");
        }
        await graph.close();
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    }
  } finally {
    preflight.mockRestore();
  }
}, 10000);

import { expect, spyOn, test } from "bun:test";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { stringify } from "smol-toml";
import { runCodexSkillCommand } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import * as profile from "../src/provider-profile.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";

const native = (count: number): JsonObject => ({
  features: { multi_agent_v2: { max_concurrent_threads_per_session: count } },
});
const legacy = (count: number): JsonObject => ({
  agents: { max_concurrent_threads_per_session: count },
});
const server = String.raw`
const fs = require("node:fs");
const readline = require("node:readline");
const path = process.env.CAPACITY_RECORD;
const records = fs.existsSync(path) ? JSON.parse(fs.readFileSync(path, "utf8")) : [];
const entry = {home:process.env.CODEX_HOME,argv:process.argv.slice(2),config:fs.readFileSync(require("node:path").join(process.env.CODEX_HOME,"config.toml"),"utf8")};
const first = records.length === 0;
const flags = {cli_daybreak:false,api_key_cyber_access_programs:true};
records.push(entry);
const save = () => fs.writeFileSync(path, JSON.stringify(records));
const send = value => process.stdout.write(JSON.stringify(value) + "\n");
save();
readline.createInterface({input:process.stdin}).on("line", line => {
  const message = JSON.parse(line);
  if (message.method === "initialize" || message.method === "account/login/start") send({id:message.id,result:{}});
  if (message.method === "config/read") send({id:message.id,result:{config:{daybreak:false,features:flags},layers:[]}});
  if (message.method === "experimentalFeature/list") send({id:message.id,result:{data:Object.entries(flags).map(([name,enabled])=>({name,enabled}))}});
  if (message.method === "account/read") send({id:message.id,result:{account:{type:"apiKey"}}});
  if (message.method === "model/list") send({id:message.id,result:{data:[{model:"synthetic",availableAccessPrograms:{cyber:["standard"]}}]}});
  if (message.method === "thread/start" || message.method === "thread/resume") {
    entry.method=message.method;save();
    send({id:message.id,result:{thread:{id:"capacity",ephemeral:false,path:"/synthetic/capacity.jsonl"},activePermissionProfile:{id:"restricted"},model:"synthetic",modelProvider:"openai"}});
  }
  if (message.method === "turn/start") {
    send({id:message.id,result:{turn:{id:first?"first":"second"}}});
    if (first) {
      fs.writeFileSync(process.env.CAPACITY_SOURCE_CONFIG,"[features.multi_agent_v2]\nmax_concurrent_threads_per_session=1\n");
      process.stdout.write("",()=>process.exit(9));
    } else send({id:"submit",method:"item/tool/call",params:{threadId:"capacity",turnId:"second",namespace:"codex_security_reports",tool:"produce_codex_security_exploit_report",arguments:{}}});
  }
  if (message.id === "submit") {
    if (!message.result.success) process.exit(10);
    send({method:"turn/completed",params:{threadId:"capacity",turn:{id:"second",status:"completed"}}});
  }
}).on("close",()=>process.exit(0));
`;

test("selects native home capacity before isolation and preserves it across concurrent resumes", async () => {
  const preflight = spyOn(
    profile,
    "preflightReadOnlyProfileCodex",
  ).mockResolvedValue({
    permissionProfileId: "restricted",
    configOverrides: [],
  });
  const cases: Array<{
    home: JsonObject;
    selected: JsonObject;
    expected: string;
  }> = [
    {
      home: {},
      selected: {},
      expected: "features.multi_agent_v2.max_concurrent_threads_per_session=16",
    },
    {
      home: native(49),
      selected: {},
      expected: "features.multi_agent_v2.max_concurrent_threads_per_session=49",
    },
    {
      home: native(49),
      selected: native(7),
      expected: "features.multi_agent_v2.max_concurrent_threads_per_session=7",
    },
    {
      home: native(7),
      selected: native(49),
      expected: "features.multi_agent_v2.max_concurrent_threads_per_session=49",
    },
    {
      home: legacy(48),
      selected: {},
      expected: "agents.max_concurrent_threads_per_session=48",
    },
    {
      home: native(7),
      selected: legacy(48),
      expected: "features.multi_agent_v2.max_concurrent_threads_per_session=7",
    },
    {
      home: legacy(48),
      selected: native(49),
      expected: "features.multi_agent_v2.max_concurrent_threads_per_session=49",
    },
  ];
  try {
    const homes = await Promise.all(
      cases.map(async ({ home: settings, selected, expected }) => {
        const root = await realpath(
          await mkdtemp(join(tmpdir(), "native-capacity-")),
        );
        try {
          const repository = join(root, "repository");
          const home = join(root, "home");
          await mkdir(repository);
          await mkdir(home);
          const sourceConfig = join(home, "config.toml");
          await writeFile(
            sourceConfig,
            stringify({
              ...settings,
              developer_instructions: "Unrelated native home guidance.",
            }),
          );
          const script = join(root, "server.cjs");
          const record = join(root, "launches.json");
          await writeFile(script, server);
          const diagnostics: string[] = [];
          const sink = () =>
            new Writable({
              write(chunk, _encoding, done) {
                diagnostics.push(String(chunk));
                done();
              },
            });
          const status = await runCodexSkillCommand(
            [script, "app-server"],
            {
              command: "exploitability check",
              auth: "api-key",
              modelProvider: "openai",
              codexOverrides: selected,
              directory: repository,
              readOnlySkillRoot: repository,
              stdout: sink(),
              stderr: sink(),
              appServer: {
                directory: repository,
                prompt: "Synthetic advisory",
                sandbox: "read-only",
                threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
                dependencyReport: {
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
              CODEX_SECURITY_STATE_DIR: join(root, "state"),
              CAPACITY_RECORD: record,
              CAPACITY_SOURCE_CONFIG: sourceConfig,
              CODEX_API_KEY: "synthetic-capacity-key",
              OPENAI_API_KEY: "synthetic-capacity-key",
            },
          );
          expect(status, diagnostics.join("")).toBe(0);
          const launches = JSON.parse(await readFile(record, "utf8")) as Array<{
            home: string;
            argv: string[];
            config: string;
            method: string;
          }>;
          expect(launches.map((x) => x.method)).toEqual([
            "thread/start",
            "thread/resume",
          ]);
          expect(new Set(launches.map((x) => x.home)).size).toBe(1);
          for (const launch of launches) {
            expect(launch.argv).toContain(expected);
            expect(launch.argv.join(" ")).not.toContain(
              "Unrelated native home guidance",
            );
            expect(launch.config).not.toContain(
              "Unrelated native home guidance",
            );
          }
          return launches[0]!.home;
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      }),
    );
    expect(new Set(homes).size).toBe(cases.length);
  } finally {
    preflight.mockRestore();
  }
});

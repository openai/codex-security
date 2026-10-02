import * as childProcess from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { writeCodexConfig, type JsonObject } from "../src/config.js";
import { executablePathForSpawn } from "../src/runtime.js";
import {
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";
import { fixtureSpawn } from "./support/codex-process.js";
import { InternalSecurity } from "./support/internal-security.js";
import { POLICY, PYTHON, stageResult } from "./support/security-policy.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test("policy generation retains prepared command authentication after shared configuration changes", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const home = join(root, "home");
  await mkdir(repository);
  await mkdir(home, { mode: 0o700 });
  const executable = join(root, "synthetic-policy.exe");
  const script = join(root, "synthetic-policy.cjs");
  const capture = join(root, "capture.jsonl");
  await writeFile(capture, "");
  const results = ["architecture", "threat_model", "policy"].map((stage) =>
    stageResult(stage as "architecture" | "threat_model" | "policy"),
  );
  await writeFile(
    script,
    `
const fs = require("node:fs"), path = require("node:path");
const {parse} = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
const args = process.argv.slice(2), config = parse(fs.readFileSync(path.join(process.env.CODEX_HOME,"config.toml"),"utf8"));
const merge = (target,value) => { for(const [key,child] of Object.entries(value)) target[key] = child && typeof child === "object" && !Array.isArray(child) ? merge(target[key] ?? {},child) : child; return target; };
for(let i=0;i<args.length;i++) if(["-c","--config"].includes(args[i])) merge(config,parse(args[++i]));
const prior = fs.readFileSync(${JSON.stringify(capture)},"utf8").trim().split("\\n").filter(Boolean);
fs.appendFileSync(${JSON.stringify(capture)},JSON.stringify({auth:config.model_providers[config.model_provider].auth,args})+"\\n");
process.stdin.resume(); process.stdin.on("end",()=>{
 console.log(JSON.stringify({type:"thread.started",thread_id:"00000000-0000-4000-8000-000000000001"}));
 console.log(JSON.stringify({type:"item.completed",item:{id:"result",type:"agent_message",text:JSON.stringify(${JSON.stringify(results)}[prior.length])}}));
 console.log(JSON.stringify({type:"turn.completed",usage:{input_tokens:0,cached_input_tokens:0,output_tokens:0}}));
});
`,
  );
  const authentication = {
    command: process.execPath,
    args: ["synthetic-selected-account"],
  };
  const configuration: JsonObject = {
    model: "gpt-5.6-sol",
    model_provider: "synthetic.provider",
    model_providers: {
      "synthetic.provider": {
        name: "Synthetic provider",
        base_url: "https://example.invalid/v1",
        auth: authentication,
      },
    },
  };
  const original = structuredClone(configuration);
  await writeCodexConfig(join(home, "config.toml"), configuration);
  let replacement = Buffer.alloc(0);
  const security = new InternalSecurity(
    { codexOverrides: configuration },
    {
      environment: {
        PATH: process.env["PATH"],
        CODEX_CLI_PATH: executable,
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      },
      prepareRuntime: async () => preparedRuntime(home),
      resolvePluginPython: async () => {
        await writeCodexConfig(join(home, "config.toml"), {
          model_providers: {
            "synthetic.provider": {
              auth: {
                command: process.execPath,
                args: ["synthetic-other-account"],
              },
            },
          },
        });
        replacement = await readFile(join(home, "config.toml"));
        return PYTHON;
      },
    },
  );
  const spawn = spyOn(childProcess, "spawn").mockImplementation(
    fixtureSpawn(executablePathForSpawn(executable), script, () => {}),
  );
  try {
    const policy = await security.generatePolicy(repository, {
      outputDir: join(root, "output"),
    });
    expect(await readFile(policy.draftPath, "utf8")).toBe(POLICY);
    const rows = (await readFile(capture, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(rows).toHaveLength(3);
    for (const row of rows) {
      expect(row.auth.command).toBe(authentication.command);
      expect(row.auth.args).toEqual(authentication.args);
      expect(row.args.join("\n")).not.toContain("synthetic-other-account");
    }
    expect(configuration).toEqual(original);
    expect(await readFile(join(home, "config.toml"))).toEqual(replacement);
  } finally {
    spawn.mockRestore();
    await security.close();
  }
});

import { expect, spyOn, test } from "bun:test";
import * as childProcess from "node:child_process";
import {
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { parse } from "smol-toml";
import { readSkillCommandOutput } from "../src/cli.js";
import { deepMerge, type JsonObject } from "../src/config.js";
import { createDependencyNativeSession } from "../src/dependency-native-session.js";
import { executablePathForSpawn } from "../src/runtime.js";
import { runReadOnlyCodex } from "../src/scan-comparison.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";

type AppServer = NonNullable<Parameters<typeof readSkillCommandOutput>[1]>;

test("reviewer exec retains selected access settings across automatic root treatment and resume", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "native-helper-access-")),
  );
  const script = join(root, "helper.cjs");
  await writeFile(
    script,
    String.raw`
const fs = require("node:fs");
const argv = process.argv.slice(2);
if (argv.includes("mcp") && argv.includes("list")) {
  process.stdout.write("[]");
} else if (argv.includes("exec")) {
  fs.writeFileSync(process.env.HELPER_ARGV, JSON.stringify(argv));
  process.stdin.resume();
  process.stdin.on("end", () => {
    for (const value of [
      {type:"thread.started",thread_id:"synthetic-reviewer"},
      {type:"item.completed",item:{id:"answer",type:"agent_message",text:'{"ok":true}'}},
      {type:"turn.completed",usage:{input_tokens:0,cached_input_tokens:0,output_tokens:0}},
    ]) console.log(JSON.stringify(value));
  });
} else process.exitCode = 4;
`,
  );
  const spawn = childProcess.spawn;
  const intercepted = spyOn(childProcess, "spawn").mockImplementation(((
    command: string,
    args: readonly string[],
    options: childProcess.SpawnOptions,
  ) =>
    spawn(
      command,
      command === executablePathForSpawn(process.execPath)
        ? [script, ...args]
        : args,
      options,
    )) as typeof childProcess.spawn);
  const variants = [
    {
      name: "catalog-error",
      daybreak: true,
      cli: true,
      api: true,
      discovery: false,
      catalog: "error",
    },
    {
      name: "empty-programs",
      daybreak: true,
      cli: true,
      api: false,
      discovery: false,
      catalog: "empty",
    },
    {
      name: "unlisted-model",
      daybreak: true,
      cli: true,
      api: true,
      discovery: true,
      catalog: "unlisted",
    },
    {
      name: "feature-off",
      daybreak: true,
      cli: false,
      api: false,
      discovery: true,
      catalog: "available",
    },
    {
      name: "opt-out",
      daybreak: false,
      cli: true,
      api: true,
      discovery: false,
      catalog: "error",
    },
    {
      name: "explicit-standard",
      daybreak: true,
      cli: true,
      api: true,
      discovery: true,
      catalog: "error",
      program: "standard",
    },
    {
      name: "blue",
      daybreak: true,
      cli: true,
      api: true,
      discovery: false,
      catalog: "available",
    },
    {
      name: "explicit-red",
      daybreak: false,
      cli: false,
      api: false,
      discovery: false,
      catalog: "error",
      program: "daybreak_red",
    },
  ] as const;
  try {
    const results = await Promise.allSettled(
      variants.map(async (variant) => {
        const home = join(root, variant.name);
        await mkdir(home);
        await writeFile(join(home, "config.toml"), "");
        const config = {
          daybreak: variant.daybreak,
          features: {
            cli_daybreak: variant.cli,
            api_key_cyber_access_programs: variant.api,
            api_key_model_discovery: variant.discovery,
            shell_tool: true,
          },
        };
        const recovery: NonNullable<AppServer["recovery"]> = {
          session: createDependencyNativeSession(),
          usage: new Map(),
          finishedTurns: new Set(),
          completedTurnNotifications: new Set(),
        };
        for (const resumed of [false, true]) {
          let binding:
            | {
                provider: string;
                config: JsonObject;
                program?: AppServer["cyberAccessProgram"];
              }
            | undefined;
          const requests: JsonObject[] = [];
          const output = new PassThrough();
          const send = (value: unknown) =>
            queueMicrotask(() => output.write(JSON.stringify(value) + "\n"));
          const input = new Writable({
            write(chunk, _encoding, done) {
              for (const line of chunk.toString().trim().split("\n")) {
                const request = JSON.parse(line) as JsonObject;
                requests.push(request);
                const id = request["id"];
                switch (request["method"]) {
                  case "initialize":
                    send({ id, result: {} });
                    break;
                  case "config/read":
                    send({ id, result: { config, layers: [] } });
                    break;
                  case "thread/start":
                  case "thread/resume":
                    send({
                      id,
                      result: {
                        thread: {
                          id: variant.name,
                          ephemeral: false,
                          path: join(home, "thread.jsonl"),
                        },
                        activePermissionProfile: { id: "restricted" },
                        model: "synthetic",
                        modelProvider: "openai",
                      },
                    });
                    break;
                  case "experimentalFeature/list":
                    send({
                      id,
                      result: {
                        data: Object.entries(config.features).map(
                          ([name, enabled]) => ({ name, enabled }),
                        ),
                      },
                    });
                    break;
                  case "account/read":
                    send({ id, result: { account: { type: "chatgpt" } } });
                    break;
                  case "model/list":
                    send(
                      variant.catalog === "error"
                        ? {
                            id,
                            error: {
                              code: -32000,
                              message: "Synthetic catalog unavailable",
                            },
                          }
                        : {
                            id,
                            result: {
                              data:
                                variant.catalog === "unlisted"
                                  ? []
                                  : [
                                      {
                                        model: "synthetic",
                                        availableAccessPrograms: {
                                          cyber:
                                            variant.catalog === "empty"
                                              ? []
                                              : ["standard", "daybreakBlue"],
                                        },
                                      },
                                    ],
                              nextCursor: null,
                            },
                          },
                    );
                    break;
                  case "turn/start":
                    send({
                      id,
                      result: { turn: { id: resumed ? "resumed" : "initial" } },
                    });
                    if (resumed)
                      send({
                        method: "turn/completed",
                        params: {
                          threadId: variant.name,
                          turn: { id: "resumed", status: "completed" },
                        },
                      });
                    else queueMicrotask(() => output.end());
                    break;
                }
              }
              done();
            },
            final(done) {
              output.end();
              done();
            },
          });
          const result = await readSkillCommandOutput(output, {
            input,
            recovery,
            directory: root,
            prompt: "Synthetic advisory",
            permissionProfile: "restricted",
            threadSource: CODEX_SECURITY_THREAD_SOURCES.validation,
            ...("program" in variant
              ? { cyberAccessProgram: variant.program }
              : {}),
            dependencyReport: {
              recordInventory: () => undefined,
              recordGraphEvent() {},
              continuationPrompt: () => undefined,
            },
            bindReviewer(provider, selected, program) {
              binding = { provider, config: selected ?? {}, program };
            },
          });
          expect(result.completed).toBe(resumed);
          expect(recovery.threadId).toBe(variant.name);
          expect(
            requests.some(
              (request) =>
                request["method"] ===
                (resumed ? "thread/resume" : "thread/start"),
            ),
          ).toBe(true);
          expect(binding).toBeDefined();
          const selected = binding!;
          const argvPath = join(home, `argv-${resumed}.json`);
          await runReadOnlyCodex(
            "Synthetic reviewer",
            {},
            {
              selectedEnvironment: {
                CODEX_CLI_PATH: process.execPath,
                CODEX_HOME: home,
                HOME: home,
                HELPER_ARGV: argvPath,
              },
              config: {
                codexOverrides: {
                  model_provider: selected.provider,
                  ...selected.config,
                },
              },
              cyberAccessProgram: selected.program,
              workingDirectory: root,
            },
            {
              surface: "cli",
              command: "exploitability",
              threadSource: CODEX_SECURITY_THREAD_SOURCES.scanComparison,
            },
          );
          const argv = JSON.parse(await readFile(argvPath, "utf8")) as string[];
          let actual: JsonObject = {};
          for (let index = 0; index < argv.length; index++)
            if (argv[index] === "-c" || argv[index] === "--config")
              actual = deepMerge(actual, parse(argv[++index]!) as JsonObject);
          const explicitRed =
            "program" in variant && variant.program === "daybreak_red";
          expect(actual["daybreak"]).toBe(
            explicitRed ? true : variant.daybreak,
          );
          expect(actual["features"]).toMatchObject({
            cli_daybreak: explicitRed ? true : variant.cli,
            api_key_cyber_access_programs: variant.api,
            api_key_model_discovery: variant.discovery,
            shell_tool: false,
          });
          expect(actual["model_provider"]).toBe("openai");
          expect(argv).toContain("read-only");
          expect(actual["approval_policy"]).toBe("never");
          const turn = requests.find(
            (request) => request["method"] === "turn/start",
          )!["params"] as JsonObject;
          const expectedProgram =
            "program" in variant
              ? variant.program
              : variant.name === "blue"
                ? "daybreak_blue"
                : undefined;
          expect(selected.program).toBe(expectedProgram);
          expect(turn["cyberAccessProgram"]).toBe(
            expectedProgram === "daybreak_blue"
              ? "daybreakBlue"
              : expectedProgram === "daybreak_red"
                ? "daybreakRed"
                : expectedProgram,
          );
          if (expectedProgram !== undefined)
            expect(argv[argv.indexOf("--cyber-access-program") + 1]).toBe(
              expectedProgram,
            );
          else expect(argv).not.toContain("--cyber-access-program");
          recovery.session.resetTurns();
        }
      }),
    );
    for (const result of results)
      if (result.status === "rejected") throw result.reason;
  } finally {
    intercepted.mockRestore();
    await rm(root, { recursive: true, force: true });
  }
}, 30000);

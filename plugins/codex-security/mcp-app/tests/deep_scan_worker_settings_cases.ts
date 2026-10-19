import assert from "node:assert/strict";
import childProcess, { type SpawnOptions } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import { stringify as stringifyToml } from "smol-toml";
import type { CodexSdkWorkerExecutor as Executor } from "../src/deep-scan/executor.js";
import type { DeepWorkerParentSandbox } from "../src/deep-scan/parent-sandbox.js";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import { assertFlagPair } from "./assertions.ts";
import { readJson } from "./support/json.ts";

export async function testWorkerCyberAccessSettings({
  CodexSdkWorkerExecutor,
  fakeCodexFixture,
  parentSandbox,
  workerRequest,
  assertConfigOverrides,
  assertReadOnlyWorkerPolicy,
  assertWorkerSubagentPolicy,
  restoreEnv,
}: {
  CodexSdkWorkerExecutor: typeof Executor;
  fakeCodexFixture: () => Promise<{ root: string; executablePath: string }>;
  parentSandbox: DeepWorkerParentSandbox;
  workerRequest: (
    promptPath: string,
    workingDirectory: string,
    options: Partial<CodexWorkerRequest>,
  ) => CodexWorkerRequest;
  assertConfigOverrides: (
    args: readonly string[],
    values: Record<string, string | number | boolean | undefined>,
  ) => void;
  assertReadOnlyWorkerPolicy: (args: readonly string[]) => void;
  assertWorkerSubagentPolicy: (
    args: readonly string[],
    subagents: number,
  ) => void;
  restoreEnv: (name: string, value: string | undefined) => void;
}) {
  const cases: {
    name: string;
    configuration?: string;
    workerFeatures?: Record<string, boolean>;
    daybreak?: boolean;
    workerDaybreak?: boolean;
    nativeProfile?: string;
    program?: string;
    parentProgram?: string;
    parentTurn?: { threadId: string; turnId: string };
    missingParentTurn?: boolean;
    failParentReadOnce?: boolean;
    serviceTier?: string;
    features?: Record<string, boolean>;
    configPath?: string;
    workerConfigPath?: string;
    executor?: import("../src/deep-scan/executor.js").CodexSdkWorkerExecutor;
  }[] = [
    { name: "unset", configuration: "" },
    {
      name: "blue",
      configuration:
        'daybreak = true\nservice_tier = "fast"\n[codex_security]\ncyber_access_program = "daybreak_blue"\n[features]\ncli_daybreak = true\napi_key_cyber_access_programs = true\napi_key_model_discovery = true\n',
      daybreak: true,
      serviceTier: "fast",
      program: "daybreak_blue",
      features: {
        cli_daybreak: true,
        api_key_cyber_access_programs: true,
        api_key_model_discovery: true,
      },
    },
    {
      name: "explicit-false",
      configuration:
        'daybreak = false\nservice_tier = "flex"\n[codex_security]\ncyber_access_program = "daybreak_blue"\n[features]\ncli_daybreak = false\napi_key_cyber_access_programs = false\napi_key_model_discovery = false\n',
      daybreak: false,
      serviceTier: "flex",
      program: "daybreak_blue",
      features: {
        cli_daybreak: false,
        api_key_cyber_access_programs: false,
        api_key_model_discovery: false,
      },
    },
    {
      name: "other-program",
      configuration:
        'daybreak = true\nservice_tier = "flex"\nprofile = "cloud.production"\n[profiles."cloud.production"]\ndaybreak = false\nservice_tier = "fast"\n[codex_security]\ncyber_access_program = "standard"\n[features]\napi_key_cyber_access_programs = true\napi_key_model_discovery = false\n',
      daybreak: false,
      serviceTier: "fast",
      program: "standard",
      features: {
        api_key_cyber_access_programs: true,
        api_key_model_discovery: false,
      },
    },
    {
      name: "features-only",
      configuration:
        'daybreak = true\nservice_tier = "fast"\nprofile = "selected"\n[profiles.selected]\nmodel = "fixture-model"\n[features]\ncli_daybreak = false\napi_key_cyber_access_programs = false\napi_key_model_discovery = true\n',
      daybreak: true,
      serviceTier: "fast",
      features: {
        cli_daybreak: false,
        api_key_cyber_access_programs: false,
        api_key_model_discovery: true,
      },
    },
    {
      name: "parent-standard",
      configuration:
        'daybreak = true\n[codex_security]\ncyber_access_program = "daybreak_blue"\n',
      daybreak: true,
      program: "standard",
      parentProgram: "standard",
      parentTurn: { threadId: "parent-standard", turnId: "active-standard" },
      features: { api_key_cyber_access_programs: true },
    },
    {
      name: "parent-blue",
      configuration:
        'daybreak = false\n[codex_security]\ncyber_access_program = "daybreak_red"\n',
      daybreak: false,
      program: "daybreak_blue",
      parentProgram: "daybreak_blue",
      parentTurn: { threadId: "parent-blue", turnId: "active-blue" },
      features: { api_key_cyber_access_programs: true },
      failParentReadOnce: true,
    },
    {
      name: "parent-red",
      configuration:
        'daybreak = false\n[codex_security]\ncyber_access_program = "standard"\n',
      daybreak: false,
      workerDaybreak: false,
      nativeProfile: "parent_profile_fixture",
      program: "daybreak_red",
      parentProgram: "daybreak_red",
      parentTurn: { threadId: "parent-red", turnId: "active-red" },
      features: { api_key_cyber_access_programs: true },
    },
    {
      name: "parent-native-home",
      program: "standard",
      parentProgram: "standard",
      parentTurn: { threadId: "parent-native-home", turnId: "active-native" },
      features: { api_key_cyber_access_programs: true },
    },
    {
      name: "parent-gate-disabled",
      configuration: "[features]\napi_key_cyber_access_programs = false\n",
      program: "daybreak_blue",
      parentProgram: "daybreak_blue",
      parentTurn: { threadId: "parent-disabled", turnId: "active-disabled" },
      features: { api_key_cyber_access_programs: false },
    },
    ...[true, false].map((enabled) => ({
      name: `parent-snapshot-gate-${enabled}`,
      configuration: `[features]\napi_key_cyber_access_programs = ${!enabled}\n`,
      workerFeatures: { api_key_cyber_access_programs: enabled },
      program: "daybreak_red",
      parentProgram: "daybreak_red",
      parentTurn: {
        threadId: `parent-snapshot-${enabled}`,
        turnId: `active-snapshot-${enabled}`,
      },
      features: { api_key_cyber_access_programs: enabled },
    })),
    {
      name: "parent-turn-unavailable",
      configuration:
        'daybreak = false\n[codex_security]\ncyber_access_program = "daybreak_blue"\n',
      daybreak: false,
      program: "daybreak_blue",
      parentProgram: "daybreak_red",
      parentTurn: { threadId: "parent-unavailable", turnId: "active-missing" },
      missingParentTurn: true,
    },
    {
      name: "snapshot-enabled",
      configuration: "daybreak = false\n",
      daybreak: true,
      workerDaybreak: true,
    },
    {
      name: "snapshot-disabled",
      configuration: "daybreak = true\n",
      daybreak: false,
      workerDaybreak: false,
      nativeProfile: "daybreak_fixture",
    },
  ];
  const saved = [
    "CODEX_CLI_PATH",
    "CODEX_HOME",
    "CODEX_SECURITY_CONFIG_PATH",
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    "OPENAI_API_KEY",
    "CODEX_API_KEY",
  ].map((name) => [name, process.env[name]] as const);
  const originalSpawn = childProcess.spawn;
  const fixture = await fakeCodexFixture();
  const writeParentTurn = (threadId: string, turnId: string, program: string) =>
    writeFile(
      path.join(fixture.root, `${threadId}.jsonl`),
      [
        { type: "session_meta", payload: { id: threadId } },
        {
          type: "turn_context",
          payload: { turn_id: turnId, cyber_access_program: program },
        },
      ]
        .map((record) => JSON.stringify(record))
        .join("\n") + "\n",
    );
  const promptPath = path.join(fixture.root, "prompt.md");
  const launches: {
    args: readonly string[];
    markerPath: string;
    configPath: string | undefined;
  }[] = [];
  try {
    delete process.env.OPENAI_API_KEY;
    process.env.CODEX_API_KEY = "synthetic-worker-api-key";
    process.env.CODEX_CLI_PATH = process.execPath;
    process.env.CODEX_HOME = fixture.root;
    await writeFile(promptPath, "CAPTURE_SYNTHETIC_OPENAI_AUTH");
    await writeFile(
      path.join(fixture.root, "config.toml"),
      "[features]\napi_key_cyber_access_programs = false\n",
    );
    childProcess.spawn = ((
      command: string,
      args: readonly string[],
      options: SpawnOptions,
    ) => {
      const markerPath = path.join(
        fixture.root,
        `cyber-${launches.length}.json`,
      );
      const environment = {
        ...options!.env,
        FAKE_CODEX_MARKER: markerPath,
        FAKE_CODEX_PREFLIGHT_MARKER: markerPath,
      };
      launches.push({
        args,
        markerPath,
        configPath: options.env?.CODEX_SECURITY_CONFIG_PATH,
      });
      return originalSpawn(command, [fixture.executablePath, ...args], {
        ...options,
        env: environment,
      });
    }) as typeof childProcess.spawn;
    syncBuiltinESMExports();
    for (const testCase of cases) {
      if (testCase.configuration !== undefined) {
        testCase.configPath = path.join(fixture.root, `${testCase.name}.toml`);
        await writeFile(testCase.configPath, testCase.configuration);
      }
      if (
        testCase.workerDaybreak !== undefined ||
        testCase.workerFeatures !== undefined
      ) {
        testCase.workerConfigPath = `${testCase.configPath}.deep`;
        await writeFile(
          testCase.workerConfigPath,
          stringifyToml({
            worker_runtime: {
              ...(testCase.workerDaybreak === undefined
                ? {}
                : { daybreak: testCase.workerDaybreak }),
              ...(testCase.workerFeatures === undefined
                ? {}
                : { features: testCase.workerFeatures }),
              ...(testCase.nativeProfile === undefined
                ? {}
                : { native_profile: testCase.nativeProfile }),
            },
          }),
        );
      }
      if (testCase.nativeProfile !== undefined) {
        await writeFile(
          path.join(fixture.root, `${testCase.nativeProfile}.config.toml`),
          "",
        );
      }
      if (testCase.parentTurn !== undefined) {
        await writeParentTurn(
          testCase.parentTurn.threadId,
          testCase.missingParentTurn
            ? "different-turn"
            : testCase.parentTurn.turnId,
          testCase.parentProgram!,
        );
      }
      testCase.executor = new CodexSdkWorkerExecutor({
        model: testCase.name,
        parentSandbox,
        parentTurn: testCase.parentTurn,
      });
    }
    for (const testCase of cases.filter(
      ({ failParentReadOnce }) => failParentReadOnce,
    )) {
      await writeFile(
        path.join(
          fixture.root,
          `${testCase.parentTurn!.threadId}.read-fails-once`,
        ),
        "",
      );
      restoreEnv("CODEX_SECURITY_CONFIG_PATH", testCase.configPath);
      restoreEnv(
        "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
        testCase.workerConfigPath,
      );
      await assert.rejects(
        testCase.executor!.run(workerRequest(promptPath, fixture.root, {})),
        /synthetic parent read temporary failure/,
      );
      assert.equal(
        launches.some(({ args }) => args[0] === "exec"),
        false,
      );
      const failedParentReads = (
        await Promise.all(
          launches.map(({ markerPath }) => readJson(markerPath)),
        )
      ).flatMap((launch) =>
        launch.requests.filter(
          (request: { method: string }) => request.method === "thread/read",
        ),
      );
      assert.deepEqual(failedParentReads, [
        { method: "thread/read", threadId: testCase.parentTurn!.threadId },
      ]);
    }
    for (const kind of ["discovery", "dedup"] as const) {
      for (const resumeThreadId of [undefined, "fixture-resumed-thread"]) {
        launches.length = 0;
        await Promise.all(
          cases.map((testCase) => {
            // Each scan captures its own config before its asynchronous launch.
            restoreEnv("CODEX_SECURITY_CONFIG_PATH", testCase.configPath);
            restoreEnv(
              "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
              testCase.workerConfigPath,
            );
            return testCase.executor!.run(
              workerRequest(promptPath, fixture.root, { kind, resumeThreadId }),
            );
          }),
        );
        const workerLaunches = launches.filter(
          ({ args }) => args[0] === "exec",
        );
        assert.equal(workerLaunches.length, cases.length);
        const preflights = await Promise.all(
          launches
            .filter(({ args }) => args.includes("app-server"))
            .map(async (launch) => ({
              ...launch,
              invocation: await readJson(launch.markerPath),
            })),
        );
        for (const {
          name,
          daybreak,
          program,
          serviceTier,
          features = {},
          configPath,
        } of cases) {
          const preflight = preflights.find(
            (entry) =>
              entry.configPath === configPath &&
              entry.invocation.requests.some(
                (request: { method: string }) =>
                  request.method === "config/read",
              ),
          );
          assert.ok(preflight);
          assertConfigOverrides(preflight.args, {
            daybreak,
            "features.cli_daybreak": features.cli_daybreak,
            "features.api_key_cyber_access_programs":
              features.api_key_cyber_access_programs,
            "features.api_key_model_discovery":
              features.api_key_model_discovery,
          });
          const launch = workerLaunches.find(
            ({ args }) => args[args.indexOf("--model") + 1] === name,
          );
          const invocation = await readJson(launch!.markerPath);
          assert.deepEqual(
            invocation.argv.filter((arg: string) =>
              arg.startsWith("service_tier="),
            ),
            serviceTier === undefined
              ? []
              : [`service_tier=${JSON.stringify(serviceTier)}`],
          );
          if (program === undefined) {
            assert.equal(
              invocation.argv.includes("--cyber-access-program"),
              false,
            );
          } else {
            assertFlagPair(invocation.argv, "--cyber-access-program", program);
          }
          assertConfigOverrides(invocation.argv, {
            daybreak,
            "features.cli_daybreak": features.cli_daybreak,
            "features.api_key_cyber_access_programs":
              features.api_key_cyber_access_programs,
            "features.api_key_model_discovery":
              features.api_key_model_discovery,
          });
          assert.equal(
            invocation.openaiAuthentication.CODEX_API_KEY,
            "synthetic-worker-api-key",
          );
          assert.equal(
            invocation.argv.includes("resume"),
            resumeThreadId !== undefined,
          );
          assertReadOnlyWorkerPolicy(invocation.argv);
          assertWorkerSubagentPolicy(invocation.argv, 0);
        }
        const parentReads = preflights.flatMap(({ invocation }) =>
          invocation.requests.filter(
            (request: { method: string }) => request.method === "thread/read",
          ),
        );
        assert.deepEqual(
          parentReads
            .map((request: { threadId: string }) => request.threadId)
            .sort(),
          kind === "discovery" && resumeThreadId === undefined
            ? cases
                .flatMap(({ parentTurn }) =>
                  parentTurn ? [parentTurn.threadId] : [],
                )
                .sort()
            : [],
        );
        // Running coordinators and their resumed workers retain their own settings.
        for (const {
          configPath,
          workerConfigPath,
          daybreak,
          features,
          parentTurn,
          parentProgram,
        } of cases) {
          if (parentTurn !== undefined) {
            await writeParentTurn(
              parentTurn.threadId,
              parentTurn.turnId,
              parentProgram === "standard" ? "daybreak_blue" : "standard",
            );
          }
          if (configPath !== undefined) {
            await writeFile(
              configPath,
              `daybreak = ${!daybreak}\n[codex_security]\ncyber_access_program = "daybreak_red"\n[features]\ncli_daybreak = ${!features?.cli_daybreak}\napi_key_cyber_access_programs = false\napi_key_model_discovery = false\n`,
            );
          }
          if (workerConfigPath !== undefined) {
            await writeFile(
              workerConfigPath,
              stringifyToml({ worker_runtime: { daybreak: !daybreak } }),
            );
          }
        }
      }
    }
  } finally {
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
    for (const [name, value] of saved) restoreEnv(name, value);
  }
}

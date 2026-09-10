import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve, sep, win32 } from "node:path";
import { parse, stringify } from "smol-toml";
import { fileURLToPath } from "node:url";
import { expect, mock, test } from "bun:test";
import { CodexReviewRunner } from "../src/deduplication/codex-review.js";
import { CheckpointedReviewRunner } from "../src/deduplication/checkpointed-review.js";
import { FindingWorkflow } from "../src/finding-workflow.js";
import { checkpointWorkbench } from "./support/workbench-fakes.js";
import {
  codexSecurityCredentialHome,
  codexSecurityStateDirectory,
  resolveCodexCommand,
} from "../src/runtime.js";
import { environmentEntry } from "../src/scan-comparison.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { workflowFixture } from "./support/workflow-fixture.js";
import { DeduplicationReviewError } from "../src/errors.js";

const fixture = fileURLToPath(
  new URL("fixtures/codex-review.mjs", import.meta.url),
);

const failureReasons: Record<string, string> = {
  "text-only": "Codex did not submit a validated review",
  "failed-turn": "Rate limit exceeded",
  "request-error": "Authentication required",
  "credential-error": "[redacted]",
  "invalid-json": "Codex returned malformed JSON",
  "invalid-submission": "Review validation failed: Invalid decision",
  "required-source-error":
    "Required review check could not be completed: Required source revision could not be read.",
  "required-source-error-after-verdict":
    "Required review check could not be completed: Required source revision could not be read.",
  "required-source-error-after-text":
    "Required review check could not be completed: Required source revision could not be read.",
  "invalid-review-error":
    "Required review check could not be completed: Required source revision could not be read.",
  exit: "Codex exited before completing the review",
};

test("managed state rejects links even when Windows path comparison considers their names equal", async () => {
  const name =
    "managed state rejects links even when Windows path comparison considers their names equal";
  if (runTestInSubprocess(import.meta.path, name)) return;
  await using saved = await workflowFixture();
  const state = saved.environment.CODEX_SECURITY_STATE_DIR;
  const target = join(state, "alternate");
  const linked = join(state, "dedupe");
  await mkdir(target, { recursive: true });
  await symlink(
    target,
    linked,
    process.platform === "win32" ? "junction" : "dir",
  );
  const paths = { ...(await import("node:path")) };
  // Reproduce case-sensitive Windows directory names without requiring a
  // privileged volume setting on the host running this real link fixture.
  mock.module("node:path", () => ({
    ...paths,
    relative: (from: string, to: string) =>
      from === linked && to === target
        ? paths.win32.relative("C:\\state\\dedupe", "C:\\state\\DEDUPE")
        : paths.relative(from, to),
  }));
  const { prepareCodexSecurityStateSubdirectory } = await import(
    "../src/runtime.js"
  );
  await expect(
    prepareCodexSecurityStateSubdirectory(linked, saved.environment),
  ).rejects.toThrow("linked state directory");
  expect(await readdir(target)).toEqual([]);
});

test.each(["dedupe", "operation", "managed-sibling", "configured-root"])(
  "native failure diagnostics honor the configured root without following a linked managed directory (%s)",
  async (linked) => {
    await using saved = await workflowFixture();
    const { root, scanDir, repository, environment } = saved;
    await mkdir(environment.CODEX_HOME);
    await writeFile(
      join(environment.CODEX_HOME, "config.toml"),
      '[mcp_servers.synthetic]\ncommand="unused"\n',
    );
    environment.CODEX_SECURITY_STATE_DIR = join(repository, "local-state");
    const state = environment.CODEX_SECURITY_STATE_DIR;
    const actualState = join(root, "actual-state");
    await mkdir(actualState);
    const diagnostics = join(state, "dedupe", "operation");
    const link =
      linked === "configured-root"
        ? state
        : linked === "dedupe"
          ? join(state, "dedupe")
          : diagnostics;
    if (linked !== "configured-root") {
      await mkdir(linked === "dedupe" ? state : join(state, "dedupe"), {
        recursive: true,
      });
    }
    const target =
      linked === "managed-sibling" ? join(state, "codex-home") : scanDir;
    if (linked === "managed-sibling") await mkdir(target);
    await symlink(
      linked === "configured-root" ? actualState : target,
      link,
      process.platform === "win32" ? "junction" : "dir",
    );
    const before = await readdir(target, { recursive: true });
    const runner = new CodexReviewRunner(
      { ...environment, OPENAI_API_KEY: "synthetic-review-key" },
      (_command, _args, options) =>
        spawn(
          process.execPath,
          [fixture, "exit", join(root, "messages.jsonl"), repository],
          options,
        ),
      undefined,
      repository,
      diagnostics,
    );
    const error: unknown = await runner
      .run({
        stage: "pair-review",
        model: "gpt-5.6-sol",
        effort: "high",
        prompt: "Synthetic review",
        schema: {},
        validate(value) {
          return value;
        },
      })
      .catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(DeduplicationReviewError);
    expect((error as Error).message).toContain(failureReasons["exit"]!);
    expect(await readdir(target, { recursive: true })).toEqual(before);
    const path = (error as DeduplicationReviewError).metadata.diagnosticsPath;
    if (linked === "configured-root") {
      expect(typeof path).toBe("string");
      expect(await readFile(path!, "utf8")).toContain(
        "Synthetic native process failure",
      );
    } else {
      expect(path).toBeUndefined();
    }
  },
);

test.each(["api-key", "stored-default-state"])(
  "later reviews cannot read retained diagnostics from another operation (%s)",
  async (authentication) => {
    const name = `later reviews cannot read retained diagnostics from another operation (${authentication})`;
    if (runTestInSubprocess(import.meta.path, name)) return;
    const comparison = { ...(await import("../src/scan-comparison.js")) };
    mock.module("../src/scan-comparison.js", () => ({
      ...comparison,
      comparisonEnvironment: (environment: NodeJS.ProcessEnv) =>
        comparison.comparisonEnvironment(environment, async () => ({
          authenticated: true,
          details: "Synthetic stored sign-in",
        })),
    }));
    const root = await mkdtemp(join(tmpdir(), "codex-review-diagnostics-"));
    const home = join(root, "home");
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_HOME: home,
      ...(authentication === "api-key"
        ? {
            CODEX_SECURITY_STATE_DIR: join(root, "state"),
            OPENAI_API_KEY: "synthetic-review-key",
          }
        : {}),
    };
    const state = codexSecurityStateDirectory(environment);
    const credentialHome = codexSecurityCredentialHome(environment);
    const checkout = join(root, "repository");
    const policies: Record<string, string>[] = [];
    const diagnostics: string[] = [];
    try {
      await Promise.all([mkdir(home), mkdir(checkout)]);
      await writeFile(
        join(home, "config.toml"),
        '[mcp_servers.synthetic]\ncommand="unused"\n',
      );
      if (authentication === "stored-default-state") {
        await mkdir(credentialHome, { recursive: true, mode: 0o700 });
        await writeFile(
          join(credentialHome, "config.toml"),
          '[mcp_servers.synthetic]\ncommand="unused"\n',
        );
      }
      for (const operation of ["first", "second"]) {
        const runner = new CodexReviewRunner(
          environment,
          (_command, args, options) => {
            expect(options.env?.["CODEX_HOME"]).toBe(
              authentication === "api-key" ? home : credentialHome,
            );
            const config = parse(
              args.find((arg) =>
                arg.startsWith("permissions.codex_security_review="),
              )!,
            );
            policies.push(
              (
                config["permissions"] as {
                  codex_security_review: { filesystem: Record<string, string> };
                }
              ).codex_security_review.filesystem,
            );
            return spawn(
              process.execPath,
              [fixture, "exit", join(root, `${operation}.jsonl`), checkout],
              options,
            );
          },
          undefined,
          checkout,
          join(state, "dedupe", operation),
        );
        const error: unknown = await runner
          .run({
            stage: "pair-review",
            model: "gpt-5.6-sol",
            effort: "high",
            prompt: "Synthetic review",
            schema: {},
            validate: (value) => value,
          })
          .catch((failure: unknown) => failure);
        expect(error).toBeInstanceOf(DeduplicationReviewError);
        const path = (error as DeduplicationReviewError).metadata
          .diagnosticsPath!;
        expect(await readFile(path, "utf8")).toContain(
          "Synthetic native process failure",
        );
        diagnostics.push(path);
      }
      for (const path of diagnostics) {
        const denied = Object.entries(policies[1]!).some(
          ([root, permission]) => {
            const within = relative(root, path);
            return (
              permission === "deny" &&
              (within === "" ||
                (!isAbsolute(within) &&
                  within !== ".." &&
                  !within.startsWith(`..${sep}`)))
            );
          },
        );
        expect(denied).toBe(true);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

const transportCases: {
  scenario: string;
  name?: string;
  environmentNames?: readonly [string, string, string];
  extraEnvironment?: Record<string, string>;
  windowsOnly?: boolean;
  commandAuth?: "direct" | "ambient";
  retainDiagnostics?: boolean;
  diagnosticsWritable?: boolean;
}[] = [
  {
    scenario: "exit",
    name: "diagnostic write failure preserves native failure",
    retainDiagnostics: true,
    diagnosticsWritable: false,
  },
  {
    scenario: "exit",
    name: "retained native process diagnostics",
    retainDiagnostics: true,
  },
  {
    scenario: "credential-error",
    name: "credential-safe retained diagnostics",
    retainDiagnostics: true,
  },
  {
    scenario: "correction",
    name: "command auth without an API key",
    commandAuth: "direct",
  },
  {
    scenario: "correction",
    name: "command auth with ambient API key and relative home",
    commandAuth: "ambient",
  },
  { scenario: "retry-correction" },
  { scenario: "text-only-correction" },
  { scenario: "cancel-continuation" },
  { scenario: "accepted-no-replay" },
  ...[
    "correction",
    "incomplete-content",
    "optional-lookup-failure",
    ...Object.keys(failureReasons),
    "cancel",
  ].map((scenario) => ({ scenario })),
  {
    scenario: "correction",
    name: "lowercase Windows environment",
    environmentNames: ["codex_home", "openai_api_key", "gh_config_dir"],
    windowsOnly: true,
  },
  {
    scenario: "correction",
    name: "mixed-case Windows environment",
    environmentNames: ["Codex_Home", "Codex_Api_Key", "Gh_Config_Dir"],
    windowsOnly: true,
  },
  ...["", " \t"].map((value) => ({
    scenario: "correction",
    name: `${value === "" ? "empty" : "blank"} OpenAI key uses Codex key`,
    environmentNames: ["CODEX_HOME", "CODEX_API_KEY", "GH_CONFIG_DIR"] as const,
    extraEnvironment: { OPENAI_API_KEY: value },
  })),
  {
    scenario: "correction",
    name: "empty Windows OpenAI alias uses Codex key",
    environmentNames: ["Codex_Home", "Codex_Api_Key", "Gh_Config_Dir"],
    extraEnvironment: { openai_api_key: "" },
    windowsOnly: true,
  },
];

for (const {
  scenario,
  name = scenario,
  environmentNames = ["CODEX_HOME", "OPENAI_API_KEY", "GH_CONFIG_DIR"],
  extraEnvironment,
  windowsOnly = false,
  commandAuth,
  retainDiagnostics = false,
  diagnosticsWritable = true,
} of transportCases) {
  const runCase = test.skipIf(windowsOnly && process.platform !== "win32");
  runCase(`Codex review transport: ${name}`, async () => {
    const modelHome = await mkdtemp(join(tmpdir(), "codex-review-test-"));
    const checkout = await realpath(
      await mkdtemp(join(tmpdir(), "codex-review-source-")),
    );
    const ghConfig = await mkdtemp(join(tmpdir(), "codex-review-gh-"));
    const transcript = join(modelHome, "messages.jsonl");
    let child: ChildProcessWithoutNullStreams | undefined;
    let starts = 0;
    let directory: string | undefined;
    let args: readonly string[] = [];
    const controller = new AbortController();
    try {
      const auth = {
        command: "./synthetic-auth",
        args: ["token"],
        refresh_interval_ms: 1234,
        ...(commandAuth === "ambient" ? { cwd: modelHome } : {}),
      };
      const configuration = stringify({
        mcp_servers: { synthetic: { command: "synthetic-unused-command" } },
        ...(commandAuth
          ? {
              model_provider: "synthetic.provider",
              model_providers: {
                "synthetic.provider": {
                  name: "Synthetic",
                  wire_api: "responses",
                  base_url: "https://provider.example/v1",
                  auth,
                },
              },
            }
          : {}),
      });
      await writeFile(join(modelHome, "config.toml"), configuration);
      await mkdir(join(modelHome, "state", "codex-home"), { recursive: true });
      if (retainDiagnostics && !diagnosticsWritable)
        await writeFile(join(modelHome, "state", "config.toml"), configuration);
      const [homeName, keyName, ghName] = environmentNames;
      const runner = new CodexReviewRunner(
        {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          TEMP: process.env["TEMP"],
          TMP: process.env["TMP"],
          [homeName]:
            commandAuth === "ambient"
              ? relative(process.cwd(), modelHome)
              : modelHome,
          ...(commandAuth === "direct"
            ? {}
            : { [keyName]: "synthetic-review-key" }),
          CODEX_SECURITY_STATE_DIR: join(modelHome, "state"),
          [ghName]: ghConfig,
          ...extraEnvironment,
        },
        (command, commandArgs, options) => {
          starts++;
          const selected = resolveCodexCommand({}).command;
          expect(command).toBe(
            process.platform === "win32"
              ? win32.toNamespacedPath(selected)
              : selected,
          );
          args = commandArgs;
          directory = options.env!["CODEX_SQLITE_HOME"];
          expect(options.cwd).toBe(directory);
          expect(environmentEntry(options.env!, "CODEX_HOME")).toBe(modelHome);
          child = spawn(
            process.execPath,
            [fixture, scenario, transcript, checkout],
            options,
          );
          if (scenario === "cancel")
            child.once("spawn", () =>
              controller.abort("synthetic cancellation"),
            );
          if (scenario === "cancel-continuation")
            child.stderr.once("data", () =>
              controller.abort("synthetic cancellation"),
            );
          return child;
        },
        controller.signal,
        checkout,
        retainDiagnostics
          ? join(
              modelHome,
              "state",
              diagnosticsWritable ? "diagnostics" : "config.toml",
              "reviews",
            )
          : undefined,
      );
      let validations = 0;
      const checkpoints = checkpointWorkbench("blocked-review", {
        repository: checkout,
      });
      const reportsBlocker =
        scenario.startsWith("required-source-error") ||
        scenario === "invalid-review-error";
      const reviewRunner = reportsBlocker
        ? new CheckpointedReviewRunner(
            new FindingWorkflow("blocked-review", process.env, checkpoints.run),
            runner,
            checkpoints.source,
            { allRepositories: true },
          )
        : runner;
      const result = reviewRunner.run({
        stage: "pair-review",
        model: "gpt-5.6-sol",
        effort: "ultra",
        prompt: "Review the supplied synthetic reports.",
        schema: {
          type: "object",
          properties: { decision: { enum: ["SAME", "DISTINCT"] } },
          required: ["decision"],
          additionalProperties: false,
        },
        validate(value: unknown) {
          validations++;
          if (
            typeof value !== "object" ||
            value === null ||
            !("decision" in value) ||
            value.decision !==
              (scenario === "incomplete-content" ? "DISTINCT" : "SAME")
          )
            throw new Error("Invalid decision");
          return { decision: value.decision };
        },
      });
      if (
        [
          "correction",
          "retry-correction",
          "text-only-correction",
          "accepted-no-replay",
        ].includes(scenario)
      ) {
        expect(await result).toEqual({ decision: "SAME" });
        expect(validations).toBe(
          ["text-only-correction", "accepted-no-replay"].includes(scenario)
            ? 1
            : 2,
        );
      } else if (
        ["incomplete-content", "optional-lookup-failure"].includes(scenario)
      ) {
        expect(await result).toEqual({
          decision: scenario === "incomplete-content" ? "DISTINCT" : "SAME",
        });
        expect(validations).toBe(1);
      } else if (["cancel", "cancel-continuation"].includes(scenario)) {
        await expect(result).rejects.toBe("synthetic cancellation");
      } else {
        const failure = await result.catch((error: unknown) => error);
        expect(failure).toMatchObject({
          name: "DeduplicationReviewError",
          message: `Codex did not complete a validated deduplication review. Findings are unchanged; retry the command. Reason: ${failureReasons[scenario]}`,
        });
        const reviewFailure = failure as Error & {
          cause?: unknown;
          metadata: {
            stage: string;
            model: string;
            category: string;
            attempts: number;
            reason: string;
          };
        };
        expect(reviewFailure.cause).toBeUndefined();
        expect(reviewFailure.metadata).toEqual({
          stage: "pair-review",
          model: "gpt-5.6-sol",
          category:
            scenario === "invalid-submission"
              ? "validation"
              : scenario === "text-only"
                ? "no-submission"
                : scenario === "failed-turn" || reportsBlocker
                  ? "model"
                  : "transport",
          attempts: [
            "invalid-submission",
            "text-only",
            "required-source-error-after-text",
          ].includes(scenario)
            ? 2
            : 1,
          reason:
            scenario === "credential-error"
              ? "[redacted]"
              : scenario === "invalid-submission"
                ? "The submitted review failed semantic validation."
                : scenario === "text-only"
                  ? "Codex did not submit a validated review."
                  : scenario === "failed-turn"
                    ? "Codex review turn failed."
                    : reportsBlocker
                      ? "A required review check could not be completed."
                      : scenario === "request-error"
                        ? "Codex rejected the review request."
                        : "Codex review transport failed.",
          ...(retainDiagnostics && diagnosticsWritable
            ? { diagnosticsPath: expect.any(String) }
            : {}),
        });
        if (retainDiagnostics && diagnosticsWritable) {
          const diagnosticsPath = (
            reviewFailure.metadata as { diagnosticsPath?: string }
          ).diagnosticsPath!;
          const saved = await readFile(diagnosticsPath, "utf8");
          expect(saved).not.toContain("synthetic-review-key");
          const details = JSON.parse(saved);
          expect(details).toMatchObject({
            stage: "pair-review",
            model: "gpt-5.6-sol",
            attempts: 1,
          });
          if (scenario === "exit")
            expect(details).toMatchObject({
              threadId: "review-thread",
              turnId: "review-turn-1",
              exitCode: 1,
              stderr: "Synthetic native process failure\n",
            });
          else
            expect(details).toMatchObject({
              reason: "[redacted]",
              rpcCode: -32000,
              stderr: "[redacted]",
            });
        }
        const supportBundle = JSON.stringify(reviewFailure.metadata);
        expect(supportBundle).not.toContain("synthetic-review-key");
        expect(supportBundle).not.toContain(checkout);
        expect(supportBundle).not.toContain("review-thread");
        expect(validations).toBe(
          scenario === "invalid-submission"
            ? 2
            : ["failed-turn", "required-source-error-after-verdict"].includes(
                  scenario,
                )
              ? 1
              : 0,
        );
        if (reportsBlocker) expect(checkpoints.saved).toHaveLength(0);
      }
      expect(starts).toBe(1);
      if (commandAuth) {
        expect(args).not.toContain('cli_auth_credentials_store="ephemeral"');
        const providers = parse(
          args.find((value) => value.startsWith("model_providers="))!,
        );
        expect(providers).toMatchObject({
          model_providers: {
            "synthetic.provider": { auth: { ...auth, cwd: modelHome } },
          },
        });
      } else {
        expect(args).toContain('cli_auth_credentials_store="ephemeral"');
      }
      expect(args.join(" ")).not.toContain("synthetic-review-key");
      const permissions = args.find((argument) =>
        argument.startsWith("permissions.codex_security_review="),
      );
      expect(permissions).toContain(
        `${JSON.stringify(resolve(modelHome))}="deny"`,
      );
      expect(permissions).toContain(
        `${JSON.stringify(resolve(ghConfig))}="deny"`,
      );
      if (scenario !== "cancel") {
        const messages = (await readFile(transcript, "utf8"))
          .trim()
          .split("\n")
          .map(
            (line) =>
              JSON.parse(line) as {
                method?: string;
                params?: { apiKey?: string };
              },
          );
        const loginRequest = messages.find(
          (message) => message.method === "account/login/start",
        );
        expect(
          messages.filter((message) => message.method === "thread/start"),
        ).toHaveLength(1);
        expect(
          messages.filter((message) => message.method === "turn/start"),
        ).toHaveLength(
          [
            "invalid-submission",
            "text-only",
            "retry-correction",
            "text-only-correction",
            "cancel-continuation",
            "required-source-error-after-text",
          ].includes(scenario)
            ? 2
            : ["request-error", "credential-error"].includes(scenario)
              ? 0
              : 1,
        );
        expect(loginRequest?.params?.apiKey).toBe(
          commandAuth ? undefined : "synthetic-review-key",
        );
      }
      expect(await readFile(join(modelHome, "config.toml"), "utf8")).toBe(
        configuration,
      );
      expect(existsSync(join(modelHome, "auth.json"))).toBe(false);
      expect(child!.exitCode !== null || child!.signalCode !== null).toBe(true);
      expect(existsSync(directory!)).toBe(false);
      expect(existsSync(checkout)).toBe(true);
    } finally {
      await rm(modelHome, { recursive: true, force: true });
      await rm(checkout, { recursive: true, force: true });
      await rm(ghConfig, { recursive: true, force: true });
    }
  });
}

test("empty credential paths use default directories without denying cwd", async () => {
  if (
    runTestInSubprocess(
      import.meta.path,
      "empty credential paths use default directories without denying cwd",
    )
  ) {
    return;
  }
  const comparison = { ...(await import("../src/scan-comparison.js")) };
  const root = await mkdtemp(join(tmpdir(), "codex-review-empty-paths-"));
  const checkout = await mkdtemp(join(tmpdir(), "codex-review-source-"));
  // An empty CODEX_HOME makes native Codex use the real user profile.
  mock.module("../src/scan-comparison.js", () => ({
    ...comparison,
    disabledMcpServers: async () => ({}),
  }));
  try {
    const names: [string, string][] = [["CODEX_HOME", "GH_CONFIG_DIR"]];
    if (process.platform === "win32")
      names.push(["codex_home", "Gh_Config_Dir"]);
    for (const [homeName, ghName] of names) {
      let args: readonly string[] = [];
      const runner = new CodexReviewRunner(
        {
          CODEX_CLI_PATH: process.execPath,
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          OPENAI_API_KEY: "synthetic-review-key",
          [homeName]: "",
          [ghName]: "",
        },
        (_command, commandArgs) => {
          args = commandArgs;
          throw new Error("Synthetic stop after permission configuration");
        },
        undefined,
        checkout,
      );
      await expect(
        runner.run({
          stage: "pair-review",
          model: "gpt-5.6-sol",
          effort: "ultra",
          prompt: "Review the supplied synthetic reports.",
          schema: {},
          validate: (value) => value,
        }),
      ).rejects.toThrow(
        "Codex did not complete a validated deduplication review",
      );
      const permissions = args.find((argument) =>
        argument.startsWith("permissions.codex_security_review="),
      );
      for (const path of [
        join(homedir(), ".codex"),
        join(homedir(), ".config", "gh"),
      ]) {
        expect(permissions).toContain(
          `${JSON.stringify(resolve(path))}="deny"`,
        );
      }
      expect(permissions).not.toContain(
        `${JSON.stringify(resolve(""))}="deny"`,
      );
    }
  } finally {
    mock.module("../src/scan-comparison.js", () => comparison);
    await rm(root, { recursive: true, force: true });
    await rm(checkout, { recursive: true, force: true });
  }
});

test("environment lookups preserve platform case rules and exact-key precedence", () => {
  const aliases = { codex_home: "synthetic-alias" };
  expect(environmentEntry(aliases, "CODEX_HOME")).toBe(
    process.platform === "win32" ? "synthetic-alias" : undefined,
  );
  expect(
    environmentEntry(
      { ...aliases, CODEX_HOME: "synthetic-exact" },
      "CODEX_HOME",
    ),
  ).toBe("synthetic-exact");
  expect(environmentEntry({ ...aliases, CODEX_HOME: "" }, "CODEX_HOME")).toBe(
    "",
  );
});

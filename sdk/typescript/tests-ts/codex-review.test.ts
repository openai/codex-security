import {
  execFileSync,
  spawn,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { existsSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, relative, resolve, win32 } from "node:path";
import { parse, stringify } from "smol-toml";
import { fileURLToPath } from "node:url";
import { expect, mock, test } from "bun:test";
import { CodexReviewRunner } from "../src/deduplication/codex-review.js";
import { CheckpointedReviewRunner } from "../src/deduplication/checkpointed-review.js";
import { FindingWorkflow } from "../src/finding-workflow.js";
import { checkpointWorkbench } from "./support/workbench-fakes.js";
import { resolveCodexCommand } from "../src/runtime.js";
import { environmentEntry } from "../src/scan-comparison.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { retryDelay, waitForRetry } from "../src/deduplication/retry.js";
import { isReviewRefusal } from "../src/deduplication/refusal.js";

const fixture = fileURLToPath(
  new URL("fixtures/codex-review.mjs", import.meta.url),
);

const failureReasons: Record<string, string> = {
  "policy-turn-code": "Request blocked.",
  "policy-request-code": "Request blocked.",
  "policy-turn": "Request flagged for possible cybersecurity risk.",
  "policy-request": "Request rejected: cyber_policy.",
  "refusal-text": "I'm sorry, but I can't assist with that request.",
  "policy-reported-error":
    "Required review check could not be completed: Request refused due to cybersecurity policy violation.",
  "text-only": "Codex did not submit a validated review",
  "failed-turn": "Rate limit exceeded",
  "server-error": "Provider temporarily unavailable",
  "connection-error": "Provider stream disconnected",
  "unauthorized-turn": "Authentication required",
  "bad-request-turn": "Invalid model configuration",
  "unknown-turn": "Unknown model failure",
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
  "model-policy-override":
    "Required review check could not be completed: Approval reviewer unavailable.",
  "source-missing-revision":
    "Required review check could not be completed: Required source revision could not be read.",
  "source-missing-file":
    "Required review check could not be completed: Required source revision could not be read.",
  exit: "Codex exited before completing the review",
};
const retriedFailures = new Set([
  "text-only",
  "failed-turn",
  "server-error",
  "connection-error",
  "invalid-json",
  "invalid-submission",
  "exit",
]);
const recoveredScenarios: Record<string, string> = {
  "recover-rate-limit": "failed-turn",
  "recover-server-error": "server-error",
  "recover-connection-error": "connection-error",
  "recover-process-exit": "exit",
  "recover-invalid-json": "invalid-json",
  "recover-invalid-submission": "invalid-submission",
  "recover-no-submission": "text-only",
};
const modelFailures = new Set([
  "policy-turn-code",
  "policy-turn",
  "failed-turn",
  "server-error",
  "connection-error",
  "unauthorized-turn",
  "bad-request-turn",
  "unknown-turn",
]);

const transportCases: {
  scenario: string;
  name?: string;
  environmentNames?: readonly [string, string, string];
  extraEnvironment?: Record<string, string>;
  windowsOnly?: boolean;
  commandAuth?: "direct" | "ambient";
  model?: string;
}[] = [
  {
    scenario: "correction",
    name: "Daybreak review without approval escalation",
    model: "gpt-daybreak-blue-latest",
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
  { scenario: "source-read-success" },
  ...[
    "correction",
    "incomplete-content",
    "optional-lookup-failure",
    ...Object.keys(recoveredScenarios),
    ...Object.keys(failureReasons),
    "cancel-backoff",
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
  model = "gpt-5.6-sol",
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
    const delays: number[] = [];
    const recovery = recoveredScenarios[scenario];
    const sessions = retriedFailures.has(scenario) ? 3 : recovery ? 2 : 1;
    const controller = new AbortController();
    try {
      let sourceRevision = "";
      if (scenario.startsWith("source-")) {
        const git = (...args: string[]) =>
          execFileSync("git", args, {
            cwd: checkout,
            encoding: "utf8",
          }).trim();
        git("init", "--quiet");
        await mkdir(join(checkout, "src"));
        await writeFile(join(checkout, "src", "app.ts"), "synthetic source\n");
        git("add", ".");
        git(
          "-c",
          "user.name=Example",
          "-c",
          "user.email=example@example.test",
          "commit",
          "--quiet",
          "-m",
          "Synthetic source",
        );
        sourceRevision = git("rev-parse", "HEAD");
      }
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
            [
              fixture,
              recovery
                ? starts === 1
                  ? recovery
                  : "accepted-no-replay"
                : scenario === "cancel-backoff"
                  ? "exit"
                  : scenario,
              transcript,
              checkout,
              sourceRevision,
            ],
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
        {
          random: () => 0,
          wait: async (delay, signal) => {
            delays.push(delay);
            if (scenario === "cancel-backoff") {
              controller.abort("synthetic cancellation");
              await waitForRetry(delay, signal);
            }
          },
        },
      );
      let validations = 0;
      const checkpoints = checkpointWorkbench("blocked-review", {
        repository: checkout,
      });
      const reportsBlocker =
        scenario.startsWith("required-source-error") ||
        scenario.startsWith("source-missing-") ||
        scenario === "policy-reported-error" ||
        scenario === "invalid-review-error" ||
        scenario === "model-policy-override";
      const checkpointedFailure =
        reportsBlocker && scenario !== "model-policy-override";
      const refused =
        scenario.startsWith("policy-") || scenario === "refusal-text";
      const reviewRunner =
        checkpointedFailure || refused
          ? new CheckpointedReviewRunner(
              new FindingWorkflow(
                "blocked-review",
                process.env,
                checkpoints.run,
              ),
              runner,
              checkpoints.source,
              { allRepositories: true },
            )
          : runner;
      const result = reviewRunner.run({
        stage: "pair-review",
        model,
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
        recovery ||
        [
          "correction",
          "retry-correction",
          "text-only-correction",
          "accepted-no-replay",
          "source-read-success",
        ].includes(scenario)
      ) {
        expect(await result).toEqual({ decision: "SAME" });
        expect(validations).toBe(
          recovery
            ? recovery === "invalid-submission"
              ? 3
              : modelFailures.has(recovery)
                ? 2
                : 1
            : [
                  "text-only-correction",
                  "accepted-no-replay",
                  "source-read-success",
                ].includes(scenario)
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
      } else if (
        ["cancel", "cancel-continuation", "cancel-backoff"].includes(scenario)
      ) {
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
            failureCode: string;
            retryable: boolean;
          };
        };
        expect(reviewFailure.cause).toBeUndefined();
        expect(reviewFailure.metadata).toEqual({
          stage: "pair-review",
          model,
          category: refused
            ? "refusal"
            : scenario === "invalid-submission"
              ? "validation"
              : scenario === "text-only"
                ? "no-submission"
                : modelFailures.has(scenario) || reportsBlocker
                  ? scenario.startsWith("source-missing-")
                    ? "transport"
                    : "model"
                  : "transport",
          attempts:
            ([
              "invalid-submission",
              "text-only",
              "required-source-error-after-text",
            ].includes(scenario)
              ? 2
              : 1) * sessions,
          reason: refused
            ? "The model refused the deduplication review."
            : scenario === "credential-error"
              ? "[redacted]"
              : scenario === "invalid-submission"
                ? "The submitted review failed semantic validation."
                : scenario === "text-only"
                  ? "Codex did not submit a validated review."
                  : modelFailures.has(scenario)
                    ? "Codex review turn failed."
                    : reportsBlocker
                      ? scenario === "source-missing-revision"
                        ? "The required source revision was unavailable."
                        : scenario === "source-missing-file"
                          ? "The required source could not be read."
                          : "A required review check could not be completed."
                      : scenario === "request-error"
                        ? "Codex rejected the review request."
                        : "Codex review transport failed.",
          failureCode: refused
            ? ["policy-turn-code", "policy-request-code"].includes(scenario)
              ? "review_model_refused"
              : scenario === "policy-turn"
                ? "review_transport_unavailable"
                : "review_unknown"
            : ["invalid-submission", "text-only"].includes(scenario)
              ? "review_validation_exhausted"
              : [
                    "failed-turn",
                    "server-error",
                    "connection-error",
                    "invalid-json",
                    "exit",
                  ].includes(scenario)
                ? "review_transport_unavailable"
                : scenario === "source-missing-revision"
                  ? "review_source_revision_unavailable"
                  : scenario === "source-missing-file"
                    ? "review_source_access_unavailable"
                    : "review_unknown",
          retryable: [
            "policy-turn",
            "invalid-submission",
            "text-only",
            "failed-turn",
            "server-error",
            "connection-error",
            "invalid-json",
            "exit",
          ].includes(scenario),
        });
        const supportBundle = JSON.stringify(reviewFailure.metadata);
        expect(supportBundle).not.toContain("synthetic-review-key");
        expect(supportBundle).not.toContain(checkout);
        expect(supportBundle).not.toContain("review-thread");
        expect(validations).toBe(
          scenario === "invalid-submission"
            ? 2 * sessions
            : modelFailures.has(scenario) ||
                scenario === "required-source-error-after-verdict"
              ? sessions
              : 0,
        );
        if (checkpointedFailure || refused)
          expect(checkpoints.saved).toHaveLength(0);
      }
      expect(starts).toBe(sessions);
      expect(delays).toEqual(
        scenario === "cancel-backoff"
          ? [1000]
          : sessions === 3
            ? [1000, 2000]
            : sessions === 2
              ? [1000]
              : [],
      );
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
        const threadRequest = messages.find(
          (message) => message.method === "thread/start",
        );
        expect(
          (threadRequest?.params as { model?: string } | undefined)?.model,
        ).toBe(model);
        expect(
          messages.some(
            (message) =>
              typeof message.method === "string" &&
              message.method.toLowerCase().includes("approval"),
          ),
        ).toBe(false);
        expect(
          messages.filter((message) => message.method === "thread/start"),
        ).toHaveLength(sessions);
        expect(
          messages.filter((message) => message.method === "turn/start"),
        ).toHaveLength(
          recovery
            ? ["invalid-submission", "text-only"].includes(recovery)
              ? 3
              : 2
            : ([
                "invalid-submission",
                "text-only",
                "retry-correction",
                "text-only-correction",
                "cancel-continuation",
                "required-source-error-after-text",
              ].includes(scenario)
                ? 2
                : [
                      "request-error",
                      "credential-error",
                      "policy-request",
                      "policy-request-code",
                    ].includes(scenario)
                  ? 0
                  : 1) * sessions,
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

test.each([
  "cyber_policy",
  "Request blocked by a safety policy violation.",
  "Request flagged for potentially high-risk cyber activity.",
  "I cannot help with this request.",
  "I’m sorry, but I can’t assist with your request.",
  "I can't help analyze or merge these vulnerability reports.",
  "I'm unable to assist with this comparison.",
])("recognizes explicit review refusals: %s", (message) => {
  expect(isReviewRefusal(message)).toBe(true);
});

test.each(["cyberPolicy", "misalignmentPolicyViolation"])(
  "recognizes structured policy refusal codes independently of message wording: %s",
  (code) => {
    expect(isReviewRefusal("Request blocked.", code)).toBe(true);
    expect(isReviewRefusal("Request blocked.", "unauthorized")).toBe(false);
  },
);

test.each([
  "Rate limit exceeded",
  "Authentication required",
  "Required source revision could not be read.",
  "I cannot complete the review because the source is unavailable.",
  "Connection refused",
  "Here is the review JSON.",
])("does not turn other failures into refused reviews: %s", (message) => {
  expect(isReviewRefusal(message)).toBe(false);
});

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

test("retry backoff grows exponentially with jitter and preserves cancellation", async () => {
  expect(retryDelay(1, () => 0.25)).toBe(1250);
  expect(retryDelay(2, () => 0.75)).toBe(3500);
  const controller = new AbortController();
  const waiting = waitForRetry(60_000, controller.signal);
  controller.abort("synthetic backoff cancellation");
  await expect(waiting).rejects.toBe("synthetic backoff cancellation");
});

test("a missing Codex executable is not retried", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-review-missing-command-"));
  let starts = 0;
  const delays: number[] = [];
  try {
    await writeFile(join(root, "config.toml"), "");
    const runner = new CodexReviewRunner(
      { CODEX_HOME: root, OPENAI_API_KEY: "synthetic-review-key" },
      (_command, args, options) => {
        starts++;
        return spawn(join(root, "missing-executable"), args, options);
      },
      undefined,
      root,
      {
        wait: async (delay) => {
          delays.push(delay);
        },
      },
    );
    await expect(
      runner.run({
        stage: "pair-review",
        model: "gpt-5.6-sol",
        effort: "high",
        prompt: "Review synthetic reports",
        schema: {},
        validate: (value) => value,
      }),
    ).rejects.toThrow("ENOENT");
    expect(starts).toBe(1);
    expect(delays).toEqual([]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

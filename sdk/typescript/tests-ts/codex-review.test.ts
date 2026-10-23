import { parseJsonLines } from "./support/json.js";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, relative, resolve, win32 } from "node:path";
import { parse, stringify } from "smol-toml";
import { fileURLToPath } from "node:url";
import { expect, mock, test } from "bun:test";
import { CodexReviewRunner } from "../src/deduplication/codex-review.js";
import { DEFAULT_CODEX_CONFIG, type JsonObject } from "../src/config.js";
import { CheckpointedReviewRunner } from "../src/deduplication/checkpointed-review.js";
import { FindingWorkflow } from "../src/finding-workflow.js";
import { checkpointWorkbench } from "./support/workbench-fakes.js";
import { resolveCodexCommand } from "../src/runtime.js";
import { environmentEntry } from "../src/scan-comparison.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { retryDelay, waitForRetry } from "../src/deduplication/retry.js";
import { isReviewRefusal } from "../src/deduplication/refusal.js";
import { temporaryDirectory } from "./support/temporary-directories.js";
import type { CodexSecuritySurface } from "../src/api.js";
import { VERSION } from "../src/version.js";
import { workflowFixture } from "./support/workflow-fixture.js";
import { readCodexHomeConfig } from "../src/auth.js";
import { CodexDeduplicationReviewer } from "../src/deduplication/deduplication-reviewer.js";

const fixture = fileURLToPath(
  new URL("fixtures/codex-review.mjs", import.meta.url),
);

test.each(["defaults", "configured", "luna-model", "legacy-profile"] as const)(
  "dedupe respects %s configuration and keeps review policy attached to stage",
  async (selection) => {
    await using f = await workflowFixture();
    await mkdir(f.environment.CODEX_HOME);
    const config = {
      mcp_servers: { synthetic: { command: "synthetic-unused-command" } },
      ...(selection === "defaults"
        ? {}
        : {
            model:
              selection === "luna-model"
                ? "gpt-5.6-luna"
                : "synthetic-review-model",
            model_reasoning_effort: "medium",
          }),
      ...(selection === "legacy-profile"
        ? {
            profile: "review",
            profiles: {
              review: { model: "gpt-5.6-luna", model_reasoning_effort: "low" },
            },
          }
        : {}),
    };
    await writeFile(
      join(f.environment.CODEX_HOME, "config.toml"),
      stringify(config),
    );
    const environment = {
      ...f.environment,
      OPENAI_API_KEY: "synthetic-review-key",
    };
    const findings = [f.document.findings[0]!, f.document.findings[0]!];
    for (const stage of ["screening", "pair-review"] as const) {
      const transcript = join(f.root, `${stage}.jsonl`);
      const runner = new CodexReviewRunner(
        environment,
        (_command, _args, options) =>
          spawn(
            process.execPath,
            [fixture, "configured-model", transcript, f.repository, stage],
            options,
          ),
        undefined,
        f.repository,
      );
      const reviewer = new CodexDeduplicationReviewer(
        runner,
        await readCodexHomeConfig(environment),
      );
      if (selection === "legacy-profile") {
        await expect(reviewer.screen(findings)).rejects.toThrow(
          "legacy `profile =",
        );
        expect(existsSync(transcript)).toBe(false);
        break;
      }
      if (stage === "screening") await reviewer.screen(findings);
      else await reviewer.reviewPair(findings);
      const messages = parseJsonLines<{
        method?: string;
        params?: Record<string, unknown>;
      }>(await readFile(transcript, "utf8"));
      const model =
        selection === "defaults"
          ? stage === "screening"
            ? "gpt-5.6-luna"
            : "gpt-5.6-sol"
          : selection === "luna-model"
            ? "gpt-5.6-luna"
            : "synthetic-review-model";
      const effort =
        selection === "defaults"
          ? stage === "screening"
            ? "xhigh"
            : "high"
          : "medium";
      expect(
        messages.find((m) => m.method === "thread/start")?.params,
      ).toMatchObject({
        model,
        approvalPolicy: stage === "screening" ? "never" : "on-request",
      });
      expect(
        messages.find((m) => m.method === "turn/start")?.params,
      ).toMatchObject({ model, effort });
    }
  },
);

const transportStatusScenarios = [408, 429, 500, 502, 503, 504, 401].flatMap(
  (status) =>
    ["request", "turn"].map((phase) => ({
      scenario: `transport-${phase}-${status}`,
      message: `Safety policy: request refused by upstream with ${status}`,
      phase,
      retryable: status !== 401,
    })),
);
const failureReasons: Record<string, string> = {
  ...Object.fromEntries(
    transportStatusScenarios.map(({ scenario, message }) => [
      scenario,
      message,
    ]),
  ),
  "transport-null-turn": "Request flagged for possible cybersecurity risk.",
  "transport-wording-request":
    "Request flagged for possible cybersecurity risk.",
  "transport-timeout-turn":
    "Safety policy: request refused because the service timed out",
  "service-timeout-text": "Codex did not submit a validated review",
  "policy-turn-code": "Request blocked.",
  "policy-request-code": "Request blocked.",
  "policy-turn": "Request flagged for possible cybersecurity risk.",
  "policy-accordance-turn":
    "This request was refused in accordance with the safety policy.",
  "policy-terse-turn": "Refused due to the safety policy",
  "policy-request": "Request rejected: cyber_policy.",
  "refusal-text": "I'm sorry, but I can't assist with that request.",
  "policy-colon-refusal-text": "Request refused: safety policy.",
  "policy-colon-explanation-text":
    "Safety policy: request refused due to disallowed content.",
  "policy-harmful-content-text":
    "Safety policy: this request is refused due to harmful content.",
  "policy-bare-harmful-content-text":
    "Safety policy: request refused due to harmful content.",
  "policy-restrictions-text":
    "Safety policy: this request is refused due to policy restrictions.",
  "policy-bare-restrictions-text":
    "Safety policy: request refused due to policy restrictions.",
  "policy-service-impact-text":
    "Safety policy: this request is refused because it would make the service unavailable.",
  "policy-multiline-explanation-text":
    "Safety policy: this request is refused.\nI can offer a defensive alternative.",
  "policy-prefix-text": "Safety policy: request refused.",
  "policy-review-text": "Review refused: safety policy.",
  "policy-intro-text":
    "Review cannot proceed. Safety policy: this request is refused.",
  "policy-prefix-due-text":
    "Safety policy: this request is refused due to disallowed content.",
  "policy-prefix-unsafe-text":
    "Safety policy: this request is refused due to unsafe content.",
  "policy-prefix-under-text":
    "Safety policy: your request was blocked under the applicable restrictions.",
  "policy-suffix-text": "Request refused: safety policy.",
  "policy-suffix-explanation-text":
    "Request refused: safety policy. I can offer a defensive alternative.",
  "policy-causal-refusal-text":
    "This request was refused because it violates the safety policy.",
  "policy-refusal-text":
    "This request was refused because of the safety policy.",
  "policy-first-refusal-text":
    "Cybersecurity policy: this request is refused because it would facilitate unauthorized access.",
  "policy-reported-error":
    "Required review check could not be completed: Request refusal due to the safety policy.",
  "text-only": "Codex did not submit a validated review",
  "failed-turn": "Rate limit exceeded",
  "rate-limit-turn": "Rate limit reached",
  "server-error": "Provider temporarily unavailable",
  "service-unavailable":
    "Connection refused: safety policy service unavailable",
  "network-request-error":
    "Network request refused: safety policy service unavailable",
  "http-request-error":
    "HTTP request blocked: safety policy service unavailable",
  "prefix-network-error":
    "Failed to contact safety policy: request refused by upstream with 503",
  "prefix-service-error": "Safety policy: request refused: service unavailable",
  "sentence-service-error":
    "Safety policy: request refused. Service unavailable.",
  "determiner-service-error":
    "Safety policy: this request is refused because the upstream service is unavailable.",
  "sentence-service-request-error":
    "Safety policy: request refused. Service unavailable.",
  "prefix-because-error":
    "Safety policy: request refused because the upstream service is unavailable.",
  "prefix-as-error":
    "Safety policy: request refused as the upstream service is unavailable.",
  "prefix-upstream-error":
    "Safety policy: request refused by upstream with 503",
  "connection-error": "Provider stream disconnected",
  "unauthorized-turn": "Authentication required",
  "bad-request-turn": "Invalid model configuration",
  "unknown-turn": "Unknown model failure",
  "request-error": "Authentication required",
  "credential-error": "Authentication failed: Bearer synthetic-review-key",
  "invalid-json": "Codex returned malformed JSON",
  "invalid-submission": "Review validation failed: Invalid decision",
  "required-source-error-policy-file":
    "Required review check could not be completed: Connection refused while fetching content-policy.ts",
  "required-source-error-upload-policy":
    "Required review check could not be completed: Artifact upload was blocked by the content policy.",
  "required-source-error-upload-content-policy-violation":
    "Required review check could not be completed: Artifact upload failed due to content policy violation",
  "required-source-error-upload-safety-policy-violation":
    "Required review check could not be completed: Artifact upload failed due to safety policy violation",
  "required-source-error-publication-policy":
    "Required review check could not be completed: Artifact publication was refused due to the content policy.",
  "required-source-error-publication-refusal":
    "Required review check could not be completed: Artifact publication refusal due to the content policy.",
  "required-source-error-policy-requires-refusal":
    "Required review check could not be completed: Artifact upload failed because the content policy requires refusal of unsupported media",
  "required-source-error":
    "Required review check could not be completed: Required source revision could not be read.",
  "required-source-error-after-verdict":
    "Required review check could not be completed: Required source revision could not be read.",
  "required-source-error-after-text":
    "Required review check could not be completed: Required source revision could not be read.",
  "invalid-review-error":
    "Required review check could not be completed: Required source revision could not be read.",
  exit: "Codex exited before completing the review",
  "exit-diagnostic":
    "Permission profile synthetic_profile was rejected: café 🔒\n",
};
const retriedFailures = new Set([
  ...transportStatusScenarios
    .filter(({ retryable }) => retryable)
    .map(({ scenario }) => scenario),
  "transport-null-turn",
  "transport-wording-request",
  "transport-timeout-turn",
  "service-timeout-text",
  "text-only",
  "failed-turn",
  "rate-limit-turn",
  "server-error",
  "service-unavailable",
  "network-request-error",
  "http-request-error",
  "prefix-network-error",
  "prefix-service-error",
  "sentence-service-error",
  "determiner-service-error",
  "sentence-service-request-error",
  "prefix-upstream-error",
  "prefix-because-error",
  "prefix-as-error",
  "connection-error",
  "invalid-json",
  "invalid-submission",
  "exit",
  "exit-diagnostic",
]);
const recoveredScenarios: Record<string, string> = {
  "recover-rate-limit": "failed-turn",
  "recover-rate-limit-code": "rate-limit-turn",
  "recover-server-error": "server-error",
  "recover-service-unavailable": "service-unavailable",
  "recover-network-request-error": "network-request-error",
  "recover-http-request-error": "http-request-error",
  "recover-prefix-network-error": "prefix-network-error",
  "recover-prefix-service-error": "prefix-service-error",
  "recover-sentence-service-error": "sentence-service-error",
  "recover-determiner-service-error": "determiner-service-error",
  "recover-sentence-service-request-error": "sentence-service-request-error",
  "recover-prefix-upstream-error": "prefix-upstream-error",
  "recover-prefix-because-error": "prefix-because-error",
  "recover-prefix-as-error": "prefix-as-error",
  "recover-connection-error": "connection-error",
  "recover-process-exit": "exit",
  "recover-invalid-json": "invalid-json",
  "recover-invalid-submission": "invalid-submission",
  "recover-no-submission": "text-only",
};
const modelFailures = new Set([
  ...transportStatusScenarios
    .filter(({ phase }) => phase === "turn")
    .map(({ scenario }) => scenario),
  "transport-null-turn",
  "transport-timeout-turn",
  "policy-turn-code",
  "policy-turn",
  "policy-accordance-turn",
  "policy-terse-turn",
  "failed-turn",
  "rate-limit-turn",
  "server-error",
  "service-unavailable",
  "network-request-error",
  "http-request-error",
  "prefix-network-error",
  "prefix-service-error",
  "sentence-service-error",
  "determiner-service-error",
  "prefix-upstream-error",
  "prefix-because-error",
  "prefix-as-error",
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
  windowsConfig?: JsonObject;
  expectedWindowsSandbox?: string;
  surface?: CodexSecuritySurface;
  permissionPathSuffix?: string;
}[] = [
  {
    scenario: "correction",
    name: "literal permission paths",
    permissionPathSuffix: "literal.path-雪\u007f-",
  },
  {
    scenario: "recover-server-error",
    name: "CLI attribution survives a retried review session",
    surface: "cli",
  },
  {
    scenario: "correction",
    name: "command auth without an API key",
    commandAuth: "direct",
    windowsConfig: { features: { elevated_windows_sandbox: false } },
    expectedWindowsSandbox: "unelevated",
  },
  {
    scenario: "correction",
    name: "command auth with ambient API key and relative home",
    commandAuth: "ambient",
    windowsConfig: { windows: { sandbox: "unelevated" } },
    expectedWindowsSandbox: "unelevated",
  },
  {
    scenario: "retry-correction",
    windowsConfig: { features: { elevated_windows_sandbox: true } },
    expectedWindowsSandbox: "elevated",
  },
  { scenario: "text-only-correction" },
  { scenario: "cancel-continuation" },
  { scenario: "accepted-no-replay" },
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
  windowsConfig,
  expectedWindowsSandbox,
  surface,
  permissionPathSuffix = "",
} of transportCases) {
  const runCase = test.skipIf(windowsOnly && process.platform !== "win32");
  runCase(`Codex review transport: ${name}`, async () => {
    const modelHome = await mkdtemp(join(tmpdir(), "codex-review-test-"));
    const checkout = await temporaryDirectory("codex-review-source-", true);
    const ghConfig = await mkdtemp(
      join(tmpdir(), `codex-review-gh-${permissionPathSuffix}`),
    );
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
      const auth = {
        command: "./synthetic-auth",
        args: ["token"],
        refresh_interval_ms: 1234,
        ...(commandAuth === "ambient" ? { cwd: modelHome } : {}),
      };
      const configuration = stringify({
        mcp_servers: { synthetic: { command: "synthetic-unused-command" } },
        responses_api_metadata: {
          synthetic_caller: "preserved",
          codex_security_surface: "previous",
          codex_security_command: "previous",
        },
        ...windowsConfig,
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
          directory = options.cwd as string;
          expect(options.env!["CODEX_SQLITE_HOME"]).toBeUndefined();
          expect(
            commandArgs.some((arg) => arg.startsWith("sqlite_home=")),
          ).toBe(false);
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
        undefined,
        surface,
      );
      const validate = mock((value: unknown) => {
        if (
          typeof value !== "object" ||
          value === null ||
          !("decision" in value) ||
          value.decision !==
            (scenario === "incomplete-content" ? "DISTINCT" : "SAME")
        )
          throw new Error("Invalid decision");
        return { decision: value.decision };
      });
      const checkpoints = checkpointWorkbench("blocked-review", {
        repository: checkout,
      });
      const reportsBlocker =
        scenario.startsWith("required-source-error") ||
        scenario === "policy-reported-error" ||
        scenario === "invalid-review-error";
      const refused =
        scenario.startsWith("policy-") || scenario === "refusal-text";
      const reviewRunner =
        reportsBlocker || refused
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
        model: "gpt-5.6-sol",
        effort: "ultra",
        prompt: "Review the supplied synthetic reports.",
        schema: {
          type: "object",
          properties: { decision: { enum: ["SAME", "DISTINCT"] } },
          required: ["decision"],
          additionalProperties: false,
        },
        validate,
      });
      if (
        recovery ||
        [
          "correction",
          "retry-correction",
          "text-only-correction",
          "accepted-no-replay",
        ].includes(scenario)
      ) {
        expect(await result).toEqual({ decision: "SAME" });
        expect(validate).toHaveBeenCalledTimes(
          recovery
            ? recovery === "invalid-submission"
              ? 3
              : modelFailures.has(recovery)
                ? 2
                : 1
            : ["text-only-correction", "accepted-no-replay"].includes(scenario)
              ? 1
              : 2,
        );
      } else if (
        ["incomplete-content", "optional-lookup-failure"].includes(scenario)
      ) {
        expect(await result).toEqual({
          decision: scenario === "incomplete-content" ? "DISTINCT" : "SAME",
        });
        expect(validate).toHaveBeenCalledTimes(1);
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
          };
        };
        expect(reviewFailure.cause).toBeUndefined();
        expect(reviewFailure.metadata).toEqual({
          stage: "pair-review",
          model: "gpt-5.6-sol",
          category: refused
            ? "refusal"
            : scenario === "invalid-submission"
              ? "validation"
              : ["text-only", "service-timeout-text"].includes(scenario)
                ? "no-submission"
                : modelFailures.has(scenario) || reportsBlocker
                  ? "model"
                  : "transport",
          attempts:
            ([
              "invalid-submission",
              "text-only",
              "service-timeout-text",
              "required-source-error-after-text",
            ].includes(scenario)
              ? 2
              : 1) * sessions,
          reason: refused
            ? "The model refused the deduplication review."
            : scenario === "invalid-submission"
              ? "The submitted review failed semantic validation."
              : ["text-only", "service-timeout-text"].includes(scenario)
                ? "Codex did not submit a validated review."
                : modelFailures.has(scenario)
                  ? "Codex review turn failed."
                  : reportsBlocker
                    ? "A required review check could not be completed."
                    : scenario.startsWith("transport-request-") ||
                        scenario === "transport-wording-request" ||
                        [
                          "request-error",
                          "credential-error",
                          "sentence-service-request-error",
                        ].includes(scenario)
                      ? "Codex rejected the review request."
                      : "Codex review transport failed.",
        });
        const supportBundle = JSON.stringify(reviewFailure.metadata);
        expect(supportBundle).not.toContain("synthetic-review-key");
        expect(supportBundle).not.toContain(checkout);
        expect(supportBundle).not.toContain("review-thread");
        expect(validate).toHaveBeenCalledTimes(
          scenario === "invalid-submission"
            ? 2 * sessions
            : modelFailures.has(scenario) ||
                scenario === "required-source-error-after-verdict"
              ? sessions
              : 0,
        );
        if (reportsBlocker || refused)
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
      expect(
        parse(args.find((value) => value.startsWith("windows="))!)["windows"],
      ).toEqual({
        sandbox:
          expectedWindowsSandbox ??
          (DEFAULT_CODEX_CONFIG["windows"] as { sandbox: string }).sandbox,
      });
      const permissions = args.find((argument) =>
        argument.startsWith("permissions.codex_security_review="),
      );
      expect(parse(permissions!)).toMatchObject({
        permissions: {
          codex_security_review: {
            extends: ":read-only",
            filesystem: {
              [resolve(modelHome)]: "deny",
              [resolve(ghConfig)]: "deny",
            },
          },
        },
      });
      if (scenario !== "cancel") {
        const messages = parseJsonLines<{
          method?: string;
          params?: {
            apiKey?: string;
            config?: { responses_api_metadata?: Record<string, string> };
          };
        }>(await readFile(transcript, "utf8"));
        const loginRequest = messages.find(
          (message) => message.method === "account/login/start",
        );
        expect(
          messages.filter((message) => message.method === "thread/start"),
        ).toHaveLength(sessions);
        for (const message of messages.filter(
          (message) => message.method === "thread/start",
        )) {
          expect(message.params?.config?.responses_api_metadata).toEqual({
            synthetic_caller: "preserved",
            codex_security_surface: surface ?? "sdk",
            codex_security_command: "dedupe",
            codex_security_package_version: VERSION,
          });
        }
        expect(
          messages.filter((message) => message.method === "turn/start"),
        ).toHaveLength(
          recovery
            ? recovery === "sentence-service-request-error"
              ? 1
              : ["invalid-submission", "text-only"].includes(recovery)
                ? 3
                : 2
            : ([
                "invalid-submission",
                "text-only",
                "service-timeout-text",
                "retry-correction",
                "text-only-correction",
                "cancel-continuation",
                "required-source-error-after-text",
              ].includes(scenario)
                ? 2
                : [
                      ...transportStatusScenarios
                        .filter(({ phase }) => phase === "request")
                        .map(({ scenario }) => scenario),
                      "transport-wording-request",
                      "request-error",
                      "sentence-service-request-error",
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
  "default",
  "environment",
  "configuration",
  "relative-environment",
  "relative-configuration",
  "configuration-over-environment",
])(
  "concurrent ephemeral reviews reuse %s native SQLite without deleting it",
  async (selection) => {
    await using f = await workflowFixture();
    await mkdir(f.environment.CODEX_HOME, { recursive: true });
    const sqliteHome =
      selection === "default"
        ? f.environment.CODEX_HOME
        : join(f.root, "native-sqlite");
    await mkdir(sqliteHome, { recursive: true });
    const marker = join(sqliteHome, "existing-state");
    const configured = selection.includes("configuration");
    const inherited = selection.endsWith("environment");
    const environmentHome =
      selection === "configuration-over-environment"
        ? join(f.root, "ignored-environment-state")
        : sqliteHome;
    await writeFile(marker, "Existing native state");
    await writeFile(
      join(f.environment.CODEX_HOME, "config.toml"),
      stringify({
        mcp_servers: { synthetic: { command: "synthetic-unused-command" } },
        ...(configured
          ? {
              sqlite_home: selection.startsWith("relative")
                ? relative(f.environment.CODEX_HOME, sqliteHome)
                : sqliteHome,
            }
          : {}),
      }),
    );
    const environment = {
      ...f.environment,
      OPENAI_API_KEY: "synthetic-review-key",
      ...(inherited
        ? {
            CODEX_SQLITE_HOME: selection.startsWith("relative")
              ? relative(process.cwd(), sqliteHome)
              : environmentHome,
          }
        : {}),
    };
    const originalEnvironment = { ...environment };
    const scratch: string[] = [];
    let starts = 0;
    const runner = new CodexReviewRunner(
      environment,
      (_command, args, options) => {
        scratch.push(options.cwd as string);
        expect(args.some((arg) => arg.startsWith("sqlite_home="))).toBe(false);
        expect(
          args.find((arg) =>
            arg.startsWith("permissions.codex_security_review="),
          ),
        ).toContain(`${JSON.stringify(sqliteHome)}="deny"`);
        expect(options.env!["CODEX_HOME"]).toBe(f.environment.CODEX_HOME);
        expect(options.env!["CODEX_SQLITE_HOME"]).toBe(
          inherited ? environmentHome : undefined,
        );
        return spawn(
          process.execPath,
          [
            fixture,
            "accepted-no-replay",
            join(f.root, `sqlite-${starts++}.jsonl`),
            f.repository,
          ],
          options,
        );
      },
      undefined,
      f.repository,
    );
    const review = {
      stage: "pair-review" as const,
      model: "synthetic-model",
      effort: "high",
      prompt: "Compare synthetic findings",
      schema: {},
      validate: () => ({ decision: "SAME" }),
    };
    await Promise.all([runner.run(review), runner.run(review)]);
    expect(environment).toEqual(originalEnvironment);
    expect(new Set(scratch).size).toBe(2);
    expect(scratch.every((path) => !existsSync(path))).toBe(true);
    expect(await readFile(marker, "utf8")).toBe("Existing native state");
  },
);

test.each(["capture", "throw", "reject", "pending"])(
  "native review diagnostics preserve messages and IDs without blocking on %s observers",
  async (behavior) => {
    await using f = await workflowFixture();
    await mkdir(f.environment.CODEX_HOME);
    await writeFile(
      join(f.environment.CODEX_HOME, "config.toml"),
      stringify({
        mcp_servers: { synthetic: { command: "synthetic-unused-command" } },
      }),
    );
    const events: import("../src/deduplication/diagnostics.js").DeduplicationDiagnostic[] =
      [];
    const runner = new CodexReviewRunner(
      { ...f.environment, OPENAI_API_KEY: "synthetic-review-key" },
      (_command, _args, options) =>
        spawn(
          process.execPath,
          [
            fixture,
            "diagnostics",
            join(f.root, "diagnostics.jsonl"),
            f.repository,
          ],
          options,
        ),
      undefined,
      f.repository,
      undefined,
      (event) => {
        events.push(event);
        if (behavior === "throw") throw new Error("Observer failed");
        if (behavior === "reject")
          return Promise.reject(new Error("Observer rejected"));
        if (behavior === "pending") return new Promise<void>(() => {});
      },
    );
    expect(
      await runner.run({
        stage: "pair-review",
        model: "synthetic-model",
        effort: "high",
        prompt: "Compare synthetic findings",
        schema: {},
        validate: () => ({ decision: "SAME" }),
      }),
    ).toEqual({ decision: "SAME" });
    expect(events[0]).toMatchObject({
      event: "review.started",
      stage: "pair-review",
      model: "synthetic-model",
      effort: "high",
      attempt: 1,
    });
    expect(events.at(-1)?.event).toBe("review.completed");
    expect(new Set(events.map((event) => event.reviewId)).size).toBe(1);
    expect(
      events
        .filter((event) => event.event === "review.stderr")
        .map((event) => event.message)
        .join(""),
    ).toBe("Native diagnostic: Bearer synthetic-review-key\n");
    expect(
      events
        .filter((event) => event.event === "review.warning")
        .map((event) => event.details),
    ).toEqual([
      {
        method: "configWarning",
        message: "Configured model fallback: synthetic-review-key",
      },
      {
        method: "warning",
        message: "Source lookup warning",
        threadId: "review-thread",
      },
    ]);
    expect(events).toContainEqual(
      expect.objectContaining({
        event: "review.event",
        details: {
          method: "item/completed",
          threadId: "review-thread",
          turnId: "review-turn-1",
          item: {
            id: "command-1",
            type: "commandExecution",
            status: "completed",
            exitCode: 7,
            aggregatedOutput: "Source lookup failed: synthetic-review-key",
          },
        },
      }),
    );
    expect(
      events
        .filter(
          (event) => event.details?.["method"] === "thread/tokenUsage/updated",
        )
        .map((event) => event.details?.["threadId"]),
    ).toEqual(["nested-review", "review-thread"]);
    expect(events).toContainEqual(
      expect.objectContaining({
        event: "review.submission",
        details: expect.objectContaining({
          threadId: "review-thread",
          turnId: "review-turn-1",
          accepted: true,
        }),
      }),
    );
  },
);

test.each([
  "cyber_policy",
  "Review cannot proceed. Safety policy: this request is refused.",
  "Error: Safety policy: this request is refused.",
  "Request blocked by a safety policy violation.",
  "This request was blocked by the content policy.",
  "The review has been blocked under the safety policy.",
  "Review blocked because it violates the safety policy.",
  "The review was refused due to the content policy.",
  "This request was refused under the safety policy",
  "This request was refused under the content policy",
  "Request flagged for potentially high-risk cyber activity.",
  "I cannot help with this request.",
  "I’m sorry, but I can’t assist with your request.",
  "Request refused by cybersecurity policy.",
  "Request refusal due to the safety policy.",
  "Request was refused because of the safety policy.",
  "Request was refused: safety policy.",
  "Review refused: safety policy.",
  "Safety policy: review refused.",
  "Request refused: safety policy. I can offer a defensive alternative.",
  "Request refused: safety policy! Please ask for defensive guidance instead.",
  "Safety policy: request was refused.",
  "Safety policy: request refused.",
  "Safety policy: request refused due to disallowed content.",
  "Safety policy: request refused due to potentially harmful content.",
  "Safety policy: request refused due to harmful assistance.",
  "Safety policy: this review is refused because complying would violate applicable restrictions.",
  "Safety policy: request refused under the applicable policy restrictions. I can offer a defensive alternative.",
  "Safety policy: request blocked under the applicable restrictions.",
  "Safety policy: request refused because it would facilitate unauthorized access.",
  "Review refusal due to the content policy.",
  "Refusal due to the content policy.",
  "Refused due to the safety policy",
  "This request was refused because of the safety policy.",
  "This request was refused in accordance with the safety policy.",
  "This request was refused because it violates the safety policy.",
  "The content policy requires refusal of this request.",
  "The content policy requires refusal of review.",
  "The safety policy requires a refusal of your review.",
  "Under the safety policy, this request is refused.",
  "Cybersecurity policy: this request is refused.",
  "Safety policy: this request is refused because it would facilitate harm.",
  "Safety policy: this request is refused due to unsafe content.",
  "Safety policy: this request is refused due to harmful content.",
  "Safety policy: this request is refused due to potentially harmful content. I can offer a defensive alternative.",
  "Content policy: your review has been blocked due to harmful assistance.",
  "Safety policy: this request is refused due to unsafe content. I can offer a defensive alternative.",
  "Content policy: your review has been blocked due to unsafe assistance.",
  "Content policy: your request has been blocked because it contains disallowed content.",
  "Cybersecurity policy: this request is refused as it requests disallowed assistance.",
  "Cybersecurity policy: this request is refused. I can offer a defensive alternative.",
  "Cybersecurity policy: this request is refused. Please ask for defensive guidance instead.",
  "Content policy: your request has been blocked.",
  "Safety policy: the request was refused.",
  "Request refused: safety policy.",
  "Safety policy: request refused under the applicable restrictions.",
  "Safety policy: request refused because it would facilitate harm.",
  "This request was refused for violating the content policy.",
  "I can't help analyze or merge these vulnerability reports.",
  "I'm unable to assist with this comparison.",
  "I'm not able to help with that.",
  "Safety policy: this request is refused because it would make the service time out.",
])("recognizes explicit review refusals: %s", (message) => {
  expect(isReviewRefusal(message)).toBe(true);
});

test.each([
  "httpConnectionFailed",
  "responseStreamConnectionFailed",
  "responseStreamDisconnected",
  "responseTooManyFailedAttempts",
])("preserves structured transport failure semantics: %s", (variant) => {
  for (const status of [null, 401, 502]) {
    const info = { [variant]: { httpStatusCode: status } };
    expect(
      isReviewRefusal("Request flagged for possible cybersecurity risk.", info),
    ).toBe(false);
    expect(
      isReviewRefusal(
        "Safety policy: request refused because the service timed out",
        info,
      ),
    ).toBe(false);
  }
});

test.each(["cyberPolicy", "misalignmentPolicyViolation"])(
  "recognizes structured policy refusal codes independently of message wording: %s",
  (code) => {
    expect(isReviewRefusal("Request blocked.", code)).toBe(true);
    expect(
      isReviewRefusal(
        "Safety policy: request refused because the service timed out",
        code,
      ),
    ).toBe(true);
    expect(isReviewRefusal("Request blocked.", "unauthorized")).toBe(false);
  },
);

test.each([
  "Rate limit exceeded",
  "Authentication required",
  "Required source revision could not be read.",
  "I cannot complete the review because the source is unavailable.",
  "Connection refused",
  "Connection refused: safety policy service unavailable",
  "Network request refused: safety policy service unavailable",
  "HTTP request blocked: safety policy service unavailable",
  "Request refused: safety policy service unavailable",
  "Review refused: safety policy service unavailable",
  "Request refused: safety policy. Service unavailable.",
  "Review refused: safety policy. Service unavailable.",
  "Safety policy: request refused: service unavailable",
  "Safety policy: request refused because the service timed out",
  "Safety policy: request refused due to upstream service timeout.",
  "Safety policy: request refused by upstream with 401",
  "Safety policy: request refused by upstream with 502",
  "Safety policy: request refused by upstream with 504",
  "Safety policy: request refused. Service unavailable.",
  "Safety policy: this request is refused.\nService unavailable.",
  "Safety policy: request refused due to upstream service unavailability.",
  "Safety policy: request refused due to upstream service unavailability for content processing.",
  "Safety policy: request refused due to upstream service unavailability while fetching content.",
  "Safety policy: this request is refused due to upstream service unavailability while fetching content.",
  "Safety policy: this request is refused because the upstream service is unavailable.",
  "Safety policy: this request is refused. Service unavailable.",
  "Safety policy: request refused because the upstream service is unavailable.",
  "Safety policy: request refused as the upstream service is unavailable.",
  "Safety policy: request refused by upstream with 503",
  "Failed to contact safety policy: request refused by upstream with 503",
  "Ordinary safety policy documentation",
  "Network request failed due to connectivity policy.",
  "Connection refused while fetching content-policy.ts",
  "Artifact upload was blocked by the content policy.",
  "Artifact upload failed due to content policy violation",
  "Artifact upload failed due to safety policy violation",
  "Artifact publication was refused due to the content policy.",
  "Artifact publication refusal due to the content policy.",
  "Artifact upload failed because the content policy requires refusal of unsupported media",
  "The review failed because the content policy requires refusal of unsupported media",
  "git fetch was refused by the remote for the cybersecurity-platform repository",
  "Cybersecurity policy: this request is invalid.",
  "Content policy: connection refused while fetching the source.",
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
  const delays = mock(async (_delay: number) => {});
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
        wait: delays,
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
    expect(delays).not.toHaveBeenCalled();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

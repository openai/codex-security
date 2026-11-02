import { requestMetadata } from "./support/request-metadata.js";
import { afterEach, describe, expect, test, mock } from "bun:test";
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { stripVTControlCharacters } from "node:util";
import { main, runCodexSkillCommand } from "../src/cli.js";
import {
  MAX_VERIFICATION_INPUT_CHARS,
  planVerificationRequests,
  remediationPrompt,
} from "../src/remediation.js";
import { VERSION } from "../src/version.js";
import type { Finding, JsonObject } from "../src/index.js";
import type { LinearClientFactory } from "../src/linear.js";
import {
  capture,
  dependencies,
  FakeSignals,
  fakeResult,
} from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createCliTest, captureCli } from "./support/cli-run.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures("verify-fix-");
afterEach(cleanup);

const CODEX_INPUT_LIMIT = 1_048_576;

function turnStartTextCharacters(prompt: string): number {
  const request = JSON.stringify({
    id: 3,
    method: "turn/start",
    params: {
      threadId: "synthetic-thread",
      input: [{ type: "text", text: prompt, text_elements: [] }],
    },
  });
  const decoded = JSON.parse(request) as {
    params: { input: [{ text: string }] };
  };
  return [...decoded.params.input[0].text].length;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

async function runLinuxPtyInterruption(signal: "SIGINT" | "SIGTERM") {
  const fixture = join(
    import.meta.dirname,
    "fixtures",
    "verify-fix-signal-gap.ts",
  );
  const child = spawn(
    "script",
    [
      "-q",
      "-e",
      "-c",
      `${shellQuote(process.execPath)} ${shellQuote(fixture)} ${signal}`,
      "/dev/null",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => {
    output += chunk;
  });
  child.stderr.setEncoding("utf8").on("data", (chunk) => {
    output += chunk;
  });
  const status = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  return { output, status };
}

async function runLinuxStoredAuthInterruption(
  mode: "git" | "helper-unresponsive" | "helper-responsive",
  signal: "SIGINT" | "SIGTERM",
) {
  const fixture = join(
    import.meta.dirname,
    "fixtures",
    "verify-fix-stored-auth-process-signal.ts",
  );
  const child = spawn(
    "script",
    [
      "-q",
      "-e",
      "-c",
      `${shellQuote(process.execPath)} ${shellQuote(fixture)} ${mode} ${signal}`,
      "/dev/null",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => {
    output += chunk;
  });
  child.stderr.setEncoding("utf8").on("data", (chunk) => {
    output += chunk;
  });
  const status = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  return { output, status };
}

async function runCredentialPreparationInterruption(
  signal: "SIGINT" | "SIGTERM",
) {
  const fixture = join(
    import.meta.dirname,
    "fixtures",
    "verify-fix-auth-signal.ts",
  );
  const child = spawn(process.execPath, [fixture, signal], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => {
    output += chunk;
  });
  child.stderr.setEncoding("utf8").on("data", (chunk) => {
    output += chunk;
  });
  const status = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  return { output, status };
}

async function linearIssue(identifier: string) {
  return {
    identifier,
    title: `Verify ${identifier}`,
    description: `Synthetic security evidence for ${identifier}`,
    url: `https://linear.app/example/issue/${identifier}`,
    comments: async () => ({
      nodes: [
        {
          body: `Additional verification evidence for ${identifier}`,
          url: `https://linear.app/example/issue/${identifier}#comment-evidence`,
        },
      ],
      pageInfo: { hasNextPage: false },
    }),
  };
}

const linearClient = () =>
  ({ issue: linearIssue }) as ReturnType<LinearClientFactory>;

function savedScanWithEvidence(
  severities: readonly ("critical" | "high" | "medium" | "low")[],
  evidence: string | ((index: number) => string),
) {
  const result = fakeResult(severities);
  const findings = result.findings.findings as Finding[];
  findings.forEach((finding, index) => {
    Object.assign(finding, {
      findingId: `csf_${index + 1}`,
      occurrenceId: `occ_${index + 1}`,
      title: `Finding ${index + 1}`,
      codeEvidence: [
        {
          code: typeof evidence === "string" ? evidence : evidence(index),
          path: `src/finding-${index + 1}.ts`,
        },
      ],
    });
  });
  return { result, findings };
}

describe("read-only finding verification", () => {
  test("verifies imported Linear issues in a read-only sandbox without exposing credentials", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    let prompt = "";
    let environment: NodeJS.ProcessEnv | undefined;

    expect(
      await runCli(
        ["verify-fix", "--linear-issue", "SEC-123", "--json"],
        dependencies({
          environment: {
            CODEX_SECURITY_LINEAR_API_KEY: "lin_api_SYNTHETIC_SECRET",
            LINEAR_ACCESS_TOKEN: "SYNTHETIC_OAUTH_SECRET",
            OPENAI_API_KEY: "sk-proj-SYNTHETIC_MODEL_KEY",
          },
          linearClient,
          onCodex: (args, output, processEnvironment, input) => {
            expect(requestMetadata(args)).toMatchObject({
              codex_security_command: "verify-fix",
              codex_security_package_version: VERSION,
            });
            expect(args[0]).toBe("app-server");
            expect(input).toBeUndefined();
            expect(args).toContain('approval_policy="on-request"');
            expect(args).toContain('approvals_reviewer="auto_review"');
            expect(args).not.toContain('approval_policy="never"');
            expect(output?.command).toBe("verify-fix");
            expect(output?.appServer?.sandbox).toBe("read-only");
            prompt = output!.appServer!.prompt;
            environment = processEnvironment;
            output?.stdout.write(
              JSON.stringify({
                results: [
                  {
                    id: "SEC-123",
                    status: "fixed",
                    evidence:
                      "The authorization check rejects the original request and the legitimate request succeeds.",
                  },
                ],
              }),
            );
            return 0;
          },
        }),
      ),
    ).toBe(0);

    expect(JSON.parse(stdout.text())).toEqual({
      repository: "/current/repository",
      results: [
        {
          id: "SEC-123",
          status: "fixed",
          evidence:
            "The authorization check rejects the original request and the legitimate request succeeds.",
        },
      ],
    });
    expect(stderr.text()).not.toContain("lin_api_SYNTHETIC_SECRET");
    expect(prompt).toContain("standalone verification-only mode");
    expect(prompt).toContain("$codex-security:verify-fix");
    expect(prompt).toContain("Additional verification evidence for SEC-123");
    expect(prompt).toContain(
      await readFile(
        join(PLUGIN_ROOT, "skills", "verify-fix", "SKILL.md"),
        "utf8",
      ),
    );
    expect(prompt).toContain(
      await readFile(
        join(PLUGIN_ROOT, "references", "static-finding-assessment.md"),
        "utf8",
      ),
    );
    expect(prompt).not.toContain("$codex-security:fix-finding");
    expect(prompt).not.toContain("$codex-security:validation");
    expect(prompt).toContain("Synthetic security evidence for SEC-123");
    expect(prompt).not.toContain("lin_api_SYNTHETIC_SECRET");
    expect(environment?.["OPENAI_API_KEY"]).toBe("sk-proj-SYNTHETIC_MODEL_KEY");
    expect(environment).not.toHaveProperty("CODEX_SECURITY_LINEAR_API_KEY");
    expect(environment).not.toHaveProperty("LINEAR_ACCESS_TOKEN");
  });

  test("shows live agent progress in the verification dashboard while keeping JSON clean", async () => {
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

    expect(
      await runCli(
        ["verify-fix", "A previously reported authorization bypass", "--json"],
        dependencies({
          onCodex: (_args, output) => {
            const emit = output?.appServer?.onEvent;
            emit?.({
              method: "item/started",
              params: {
                item: {
                  id: "command-1",
                  type: "commandExecution",
                  command: "rg authorization src/guard.ts",
                },
              },
            });
            emit?.({
              method: "item/reasoning/summaryTextDelta",
              params: {
                itemId: "reasoning-1",
                delta: "Checking the original authorization guard.",
              },
            });
            emit?.({
              method: "item/started",
              params: {
                item: {
                  id: "tool-1",
                  type: "mcpToolCall",
                  tool: "read_file",
                  arguments: { path: "src/guard.ts" },
                },
              },
            });
            emit?.({
              method: "item/completed",
              params: {
                item: {
                  id: "commentary-1",
                  type: "agentMessage",
                  phase: "commentary",
                  text: "The bypass now reaches the shared guard.",
                },
              },
            });
            output?.stdout.write(
              JSON.stringify({
                results: [
                  {
                    id: "finding-1",
                    status: "fixed",
                    evidence: "The original authorization bypass is rejected.",
                  },
                ],
              }),
            );
            return 0;
          },
        }),
      ),
    ).toBe(0);

    const activity = stripVTControlCharacters(stderr.text());
    expect(activity).toContain("VERIFY-FIX");
    expect(activity).toContain("rg authorization src/guard.ts");
    expect(activity).toContain("Checking the original authorization guard.");
    expect(activity).toContain("read_file");
    expect(activity).toContain("The bypass now reaches the shared guard.");
    expect(activity).not.toContain("FILES");
    expect(stderr.text()).toContain("\u001B[?1049h\u001B[?25l");
    expect(stderr.text()).toContain("\u001B[?25h\u001B[?1049l");
    expect(JSON.parse(stdout.text())).toMatchObject({
      results: [{ id: "finding-1", status: "fixed" }],
    });
    expect(stdout.text()).not.toContain("\u001B");
  });

  test("uses plain verification progress in CI and dumb terminals", async () => {
    for (const environment of [{ CI: "1" }, { TERM: "dumb" }]) {
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

      expect(
        await runCli(
          [
            "verify-fix",
            "A previously reported authorization bypass",
            "--json",
          ],
          dependencies({
            environment,
            onCodex: (_args, output) => {
              output?.appServer?.onEvent?.({
                method: "item/completed",
                params: {
                  item: {
                    id: "reasoning-1",
                    type: "reasoning",
                    summary: ["Checking the original authorization guard."],
                  },
                },
              });
              output?.stdout.write(
                JSON.stringify({
                  results: [
                    {
                      id: "finding-1",
                      status: "fixed",
                      evidence:
                        "The original authorization bypass is rejected.",
                    },
                  ],
                }),
              );
              return 0;
            },
          }),
        ),
      ).toBe(0);

      expect(stderr.text()).toContain("Verifying");
      expect(stderr.text()).toContain(
        "Codex: Checking the original authorization guard.",
      );
      expect(stderr.text()).not.toContain("\u001B");
      expect(JSON.parse(stdout.text())).toMatchObject({
        results: [{ id: "finding-1", status: "fixed" }],
      });
    }
  });

  test("verifies repeated Linear issues together in one agent invocation", async () => {
    const stdout = captureCli(main, "stdout");
    let agentCalls = 0;
    let prompt = "";

    expect(
      await stdout.run(
        [
          "verify-fix",
          "--linear-issue",
          "SEC-123",
          "--linear-issue",
          "SEC-456",
          "--json",
        ],
        dependencies({
          environment: { LINEAR_ACCESS_TOKEN: "SYNTHETIC_OAUTH_TOKEN" },
          linearClient,
          onCodex: (_args, output) => {
            agentCalls += 1;
            prompt = output!.appServer!.prompt;
            output?.stdout.write(
              JSON.stringify({
                results: [
                  {
                    id: "SEC-123",
                    status: "fixed",
                    evidence: "The original exploit is rejected.",
                  },
                  {
                    id: "SEC-456",
                    status: "still_vulnerable",
                    evidence:
                      "The original unauthenticated route remains reachable.",
                  },
                ],
              }),
            );
            return 0;
          },
        }),
      ),
    ).toBe(1);

    expect(agentCalls).toBe(1);
    const suppliedFindings = JSON.parse(prompt.split("\n").at(-1)!) as string[];
    expect(suppliedFindings).toHaveLength(2);
    expect(suppliedFindings[0]).toContain("SEC-123");
    expect(suppliedFindings[1]).toContain("SEC-456");
    expect(JSON.parse(stdout.text())).toMatchObject({
      results: [
        { id: "SEC-123", status: "fixed" },
        { id: "SEC-456", status: "still_vulnerable" },
      ],
    });
  });

  test("verifies saved findings in their original repository with static mode", async () => {
    const evidence =
      "Source review confirms the guard; runtime checks were not performed.";
    const result = fakeResult(["high", "medium"]);
    result.findings.findings.forEach((finding, index) => {
      Object.assign(finding, {
        findingId: `csf_${index + 1}`,
        occurrenceId: `occ_${index + 1}`,
        title: `Finding ${index + 1}`,
      });
    });
    const stdout = captureCli(main, "stdout");

    expect(
      await stdout.run(
        [
          "verify-fix",
          "--scan",
          "scan-1",
          "--severity",
          "high",
          "--verification-mode",
          "static",
          "--model",
          "gpt-6-astra",
          "--effort",
          "max",
          "--json",
        ],
        dependencies({
          result,
          onWorkbench: (args) => {
            expect(args).toEqual(["get-scan", "--scan-id", "scan-1"]);
            return {
              scan: {
                scanId: "scan-1",
                targetPath: "/saved/repository",
                findings: result.findings.findings as unknown as JsonObject[],
              },
            };
          },
          onCodex: (args, output) => {
            expect(args).toContain('model="gpt-6-astra"');
            expect(args).toContain('model_reasoning_effort="max"');
            expect(output?.appServer?.directory).toBe("/saved/repository");
            expect(output?.appServer?.sandbox).toBe("read-only");
            expect(output?.appServer?.prompt).toContain(
              "Verification mode: static",
            );
            const findings = JSON.parse(
              output!.appServer!.prompt.split("\n").at(-1)!,
            ) as Finding[];
            expect(findings.map(({ occurrenceId }) => occurrenceId)).toEqual([
              "occ_1",
            ]);
            output?.stdout.write(
              JSON.stringify({
                results: [
                  {
                    id: "occ_1",
                    status: "fixed",
                    evidence,
                  },
                ],
              }),
            );
            return 0;
          },
        }),
      ),
    ).toBe(0);

    expect(JSON.parse(stdout.text())).toMatchObject({
      repository: "/saved/repository",
      scanId: "scan-1",
      results: [{ id: "occ_1", status: "fixed", evidence }],
    });
  });

  test("preserves every selected saved finding across bounded verification requests", async () => {
    const evidence = `${'"quoted evidence"\n'.repeat(22_000)}🚀`;
    const { result, findings } = savedScanWithEvidence(
      ["high", "high", "high", "low"],
      evidence,
    );
    const expected = [
      {
        id: "occ_1",
        status: "fixed",
        evidence: "The original exploit is rejected.",
      },
      {
        id: "occ_2",
        status: "still_vulnerable",
        evidence: "The vulnerable path remains reachable.",
      },
      {
        id: "occ_3",
        status: "inconclusive",
        evidence: "A required runtime dependency is unavailable.",
      },
    ];
    const prompts: string[] = [];
    const suppliedIds: string[] = [];
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["verify-fix", "--scan", "scan-large", "--severity", "high", "--json"],
        dependencies({
          result,
          onWorkbench: () => ({
            scan: {
              scanId: "scan-large",
              targetPath: "/saved/repository",
              findings: findings as unknown as JsonObject[],
            },
          }),
          onCodex: (_args, output) => {
            const prompt = output!.appServer!.prompt;
            prompts.push(prompt);
            const actualCharacters = turnStartTextCharacters(prompt);
            if (actualCharacters > CODEX_INPUT_LIMIT) {
              output!.stderr.write(
                `Input exceeds the maximum length of ${CODEX_INPUT_LIMIT} characters.\n`,
              );
              return 1;
            }
            const supplied = JSON.parse(
              prompt.split("\n").at(-1)!,
            ) as Finding[];
            expect(
              supplied.every(
                (finding) => finding.codeEvidence?.[0]?.code === evidence,
              ),
            ).toBe(true);
            suppliedIds.push(
              ...supplied.map(({ occurrenceId }) => occurrenceId),
            );
            output!.stdout.write(
              JSON.stringify({
                results: supplied.map(({ occurrenceId }) =>
                  expected.find(({ id }) => id === occurrenceId),
                ),
              }),
            );
            return 0;
          },
        }),
      ),
    ).toBe(2);

    expect(prompts.length).toBeGreaterThan(1);
    expect(
      prompts.every(
        (prompt) => turnStartTextCharacters(prompt) <= CODEX_INPUT_LIMIT,
      ),
    ).toBe(true);
    expect(suppliedIds).toEqual(["occ_1", "occ_2", "occ_3"]);
    expect(JSON.parse(stdout.text()).results).toEqual(expected);
    expect(prompts.join("\n")).not.toContain("src/finding-4.ts");
    expect(stderr.text()).not.toContain("quoted evidence");
    expect(stderr.text()).not.toContain(
      `Input exceeds the maximum length of ${CODEX_INPUT_LIMIT} characters.`,
    );
  });

  test.skipIf(process.platform !== "linux").each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const)(
    "restores a real Linux PTY when %s arrives between verification requests",
    async (signal, expectedStatus) => {
      const { output, status } = await runLinuxPtyInterruption(signal);

      expect(status).toBe(expectedStatus);
      expect(output).toContain("\u001B[?1049h\u001B[?25l");
      expect(output).toContain("PTY_WORKER_1");
      expect(output).toContain("PTY_SIGNAL_BETWEEN_BATCHES");
      expect(output).not.toContain("PTY_WORKER_2");
      expect(output).toContain("\u001B[?25h\u001B[?1049l");
      expect(output).toContain(`PTY_EXIT_${expectedStatus}`);
      expect(output).not.toContain('"results"');
    },
  );

  test.skipIf(process.platform !== "linux").each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const)(
    "cancels a delayed stored-auth Git probe with one PID-targeted %s",
    async (signal, expectedStatus) => {
      const { output, status } = await runLinuxStoredAuthInterruption(
        "git",
        signal,
      );

      expect(status).toBe(expectedStatus);
      expect(output).toContain("PTY_CAPABLE_true");
      expect(output).toContain("\u001B[?1049h\u001B[?25l");
      expect(output).toContain("\u001B[?25h\u001B[?1049l");
      expect(output).toContain("PID_TARGET_ONLY_true");
      expect(output).toContain("SIGNAL_SENT_COUNT_1");
      expect(output).toContain("WORKER_STARTED_false");
      expect(output).toContain("SIGNAL_LISTENERS_0_0");
      expect(output).toContain(`STORED_AUTH_EXIT_${expectedStatus}`);
      expect(output).not.toContain('"results"');
    },
  );

  test.skipIf(process.platform !== "linux").each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const)(
    "forces an unresponsive login-status helper down after PID-targeted %s",
    async (signal, expectedStatus) => {
      const { output, status } = await runLinuxStoredAuthInterruption(
        "helper-unresponsive",
        signal,
      );

      expect(status).toBe(expectedStatus);
      expect(output).toContain("PTY_CAPABLE_true");
      expect(output).toContain("\u001B[?1049h\u001B[?25l");
      expect(output).toContain("\u001B[?25h\u001B[?1049l");
      expect(output).toContain("PID_TARGET_ONLY_true");
      expect(output).toContain("SIGNAL_SENT_COUNT_1");
      expect(output).toContain("SIGTERM_RECEIVED");
      expect(output).not.toContain("GRACEFUL_EXIT");
      expect(output).toContain("HELPER_ALIVE_false");
      expect(output).toContain("LOCK_REACQUIRED");
      expect(output).toContain("WORKER_STARTED_false");
      expect(output).toContain("SIGNAL_LISTENERS_0_0");
      expect(output).toContain(`STORED_AUTH_EXIT_${expectedStatus}`);
      expect(output).not.toContain('"results"');
    },
  );

  test.skipIf(process.platform !== "linux")(
    "lets a login-status helper honor SIGTERM without forced termination",
    async () => {
      const { output, status } = await runLinuxStoredAuthInterruption(
        "helper-responsive",
        "SIGTERM",
      );

      expect(status).toBe(143);
      expect(output).toContain("PTY_CAPABLE_true");
      expect(output).toContain("SIGTERM_RECEIVED");
      expect(output).toContain("GRACEFUL_EXIT");
      expect(output).toContain("HELPER_ALIVE_false");
      expect(output).toContain("LOCK_REACQUIRED");
      expect(output).toContain("WORKER_STARTED_false");
      expect(output).toContain("SIGNAL_LISTENERS_0_0");
      expect(output).toContain("STORED_AUTH_EXIT_143");
      expect(output).not.toContain('"results"');
    },
  );

  test.each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const)(
    "restores the dashboard when %s arrives during request planning",
    async (signal, expectedStatus) => {
      const signals = new FakeSignals();
      const onCodex = mock(() => 0);
      const { result, findings } = savedScanWithEvidence(
        ["high", "high", "high"],
        "x".repeat(525_000),
      );
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });
      const deps = dependencies({
        result,
        signals,
        onWorkbench: () => ({
          scan: {
            scanId: "scan-planning-interruption",
            targetPath: "/saved/repository",
            findings: findings as unknown as JsonObject[],
          },
        }),
        onCodex,
      });
      deps.setInterval = () => {
        queueMicrotask(() => signals.emit(signal));
        return {} as NodeJS.Timeout;
      };

      expect(
        await runCli(
          ["verify-fix", "--scan", "scan-planning-interruption", "--json"],
          deps,
        ),
      ).toBe(expectedStatus);
      expect(onCodex).not.toHaveBeenCalled();
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain("\u001B[?1049h\u001B[?25l");
      expect(stderr.text()).toContain("\u001B[?25h\u001B[?1049l");
      expect(signals.listeners.get("SIGINT")?.size ?? 0).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size ?? 0).toBe(0);
    },
  );

  test.skipIf(process.platform === "win32").each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const)(
    "cancels an active Codex child through %s without duplicate process listeners",
    async (signal, expectedStatus) => {
      const controller = new AbortController();
      const stdout = capture();
      const stderr = capture();
      const interruptListeners = process.listenerCount("SIGINT");
      const terminateListeners = process.listenerCount("SIGTERM");
      const status = runCodexSkillCommand(
        ["-e", "setInterval(() => {}, 1000)"],
        {
          command: "verify-fix",
          stdout: stdout.stream,
          stderr: stderr.stream,
          signal: controller.signal,
        },
        { command: process.execPath },
        {},
      );

      expect(process.listenerCount("SIGINT")).toBe(interruptListeners);
      expect(process.listenerCount("SIGTERM")).toBe(terminateListeners);
      controller.abort(signal);
      expect(await status).toBe(expectedStatus);
      expect(process.listenerCount("SIGINT")).toBe(interruptListeners);
      expect(process.listenerCount("SIGTERM")).toBe(terminateListeners);
    },
  );

  test.each(["SIGINT", "SIGTERM"] as const)(
    "cancels stored-auth preparation waiting for the credential lock on %s",
    async (signal) => {
      const { output, status } =
        await runCredentialPreparationInterruption(signal);

      expect(status).toBe(0);
      expect(output).toContain(`PREPARATION_ABORT_${signal}`);
    },
  );

  test.each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const)(
    "restores the dashboard when %s arrives during an active verification",
    async (signal, expectedStatus) => {
      const signals = new FakeSignals();
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });
      let calls = 0;

      expect(
        await runCli(
          ["verify-fix", "Synthetic finding", "--json"],
          dependencies({
            signals,
            onCodex: (_arguments, output) => {
              calls += 1;
              signals.emit(signal);
              expect(output?.signal?.aborted).toBe(true);
              return 0;
            },
          }),
        ),
      ).toBe(expectedStatus);
      expect(calls).toBe(1);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain("\u001B[?1049h\u001B[?25l");
      expect(stderr.text()).toContain("\u001B[?25h\u001B[?1049l");
      expect(signals.listeners.get("SIGINT")?.size ?? 0).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size ?? 0).toBe(0);
    },
  );

  test("uses the real prompt size at the Codex input boundary", async () => {
    const contents = [
      { occurrenceId: "occ_1", evidence: "small" },
      { occurrenceId: "occ_2", evidence: "" },
    ];
    const verificationIds = ["occ_1", "occ_2"];
    const base = await remediationPrompt({
      operation: "verify",
      pluginRoot: PLUGIN_ROOT,
      contents,
      verificationIds,
    });
    const padding =
      MAX_VERIFICATION_INPUT_CHARS - 1 - turnStartTextCharacters(base);
    expect(padding).toBeGreaterThan(0);
    contents[1]!.evidence = "x".repeat(padding);

    const below = await planVerificationRequests({
      pluginRoot: PLUGIN_ROOT,
      contents,
      verificationIds,
    });
    expect(below).toHaveLength(1);
    expect(below[0]!.inputCharacters).toBe(MAX_VERIFICATION_INPUT_CHARS - 1);
    const belowPrompt = await remediationPrompt({
      operation: "verify",
      pluginRoot: PLUGIN_ROOT,
      contents: below[0]!.contents,
      verificationIds: below[0]!.identifiers,
    });
    expect(turnStartTextCharacters(belowPrompt)).toBe(
      MAX_VERIFICATION_INPUT_CHARS - 1,
    );

    contents[1]!.evidence += "xx";
    const combined = await remediationPrompt({
      operation: "verify",
      pluginRoot: PLUGIN_ROOT,
      contents,
      verificationIds,
    });
    expect(turnStartTextCharacters(combined)).toBe(
      MAX_VERIFICATION_INPUT_CHARS + 1,
    );
    const above = await planVerificationRequests({
      pluginRoot: PLUGIN_ROOT,
      contents,
      verificationIds,
    });
    expect(above).toHaveLength(2);
    const abovePrompts = await Promise.all(
      above.map(({ contents, identifiers }) =>
        remediationPrompt({
          operation: "verify",
          pluginRoot: PLUGIN_ROOT,
          contents,
          verificationIds: identifiers,
        }),
      ),
    );
    expect(
      above.every(
        ({ inputCharacters }, index) =>
          inputCharacters === turnStartTextCharacters(abovePrompts[index]!) &&
          inputCharacters <= MAX_VERIFICATION_INPUT_CHARS,
      ),
    ).toBe(true);
  });

  test("rejects one oversized saved finding without exposing its evidence", async () => {
    const sensitiveMarker = "SENSITIVE_FINDING_BODY";
    const { result, findings } = savedScanWithEvidence(
      ["high"],
      sensitiveMarker.repeat(55_000),
    );
    const onCodex = mock(() => 0);
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["verify-fix", "--scan", "scan-oversized", "--json"],
        dependencies({
          result,
          onWorkbench: () => ({
            scan: {
              scanId: "scan-oversized",
              targetPath: "/saved/repository",
              findings: findings as unknown as JsonObject[],
            },
          }),
          onCodex,
        }),
      ),
    ).toBe(2);

    expect(onCodex).not.toHaveBeenCalled();
    expect(JSON.parse(stdout.text())).toMatchObject({
      status: "failed",
      code: "VERIFICATION_FAILED",
      message: expect.stringContaining(
        "cannot fit in one complete Codex verification request",
      ),
    });
    expect(stderr.text()).not.toContain(sensitiveMarker);
    expect(stdout.text()).not.toContain(sensitiveMarker);
  });

  test.each([
    ["transport failure", "Synthetic middle transport failure."],
    [
      "wrong identifier",
      "Codex did not return an evidence-backed verification result for every finding.",
    ],
  ])(
    "fails atomically on a middle verification %s",
    async (failure, message) => {
      const { result, findings } = savedScanWithEvidence(
        ["high", "high", "high"],
        "x".repeat(525_000),
      );
      let calls = 0;
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["verify-fix", "--scan", "scan-failure", "--json"],
          dependencies({
            result,
            onWorkbench: () => ({
              scan: {
                scanId: "scan-failure",
                targetPath: "/saved/repository",
                findings: findings as unknown as JsonObject[],
              },
            }),
            onCodex: (_args, output) => {
              calls += 1;
              expect(
                turnStartTextCharacters(output!.appServer!.prompt),
              ).toBeLessThanOrEqual(CODEX_INPUT_LIMIT);
              if (calls === 2 && failure === "transport failure") {
                output!.stderr.write(`${message}\n`);
                return 1;
              }
              const supplied = JSON.parse(
                output!.appServer!.prompt.split("\n").at(-1)!,
              ) as Finding[];
              output!.stdout.write(
                JSON.stringify({
                  results: supplied.map(({ occurrenceId }) => ({
                    id: calls === 2 ? "occ_wrong" : occurrenceId,
                    status: "fixed",
                    evidence: "Synthetic verification passed.",
                  })),
                }),
              );
              return 0;
            },
          }),
        ),
      ).toBe(2);

      expect(calls).toBe(2);
      expect(JSON.parse(stdout.text())).toMatchObject({
        status: "failed",
        code: "VERIFICATION_FAILED",
        message,
      });
      expect(JSON.parse(stdout.text())).not.toHaveProperty("results");
      expect(stderr.text()).toContain(message);
    },
  );

  test.each([130, 143] as const)(
    "preserves interrupted status %i from a middle verification request",
    async (status) => {
      const { result, findings } = savedScanWithEvidence(
        ["high", "high", "high"],
        "x".repeat(525_000),
      );
      let calls = 0;
      const { stdout, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["verify-fix", "--scan", "scan-interrupted", "--json"],
          dependencies({
            result,
            onWorkbench: () => ({
              scan: {
                scanId: "scan-interrupted",
                targetPath: "/saved/repository",
                findings: findings as unknown as JsonObject[],
              },
            }),
            onCodex: (_args, output) => {
              calls += 1;
              if (calls === 2) return status;
              const supplied = JSON.parse(
                output!.appServer!.prompt.split("\n").at(-1)!,
              ) as Finding[];
              output!.stdout.write(
                JSON.stringify({
                  results: supplied.map(({ occurrenceId }) => ({
                    id: occurrenceId,
                    status: "fixed",
                    evidence: "Synthetic verification passed.",
                  })),
                }),
              );
              return 0;
            },
          }),
        ),
      ).toBe(status);
      expect(calls).toBe(2);
      expect(stdout.text()).toBe("");
    },
  );

  test("reports inconclusive findings without treating them as fixed", async () => {
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(
        ["verify-fix", "A previously reported authorization bypass"],
        dependencies({
          onCodex: (_args, output) => {
            output?.stdout.write(
              JSON.stringify({
                results: [
                  {
                    id: "finding-1",
                    status: "inconclusive",
                    evidence: "The original entrypoint cannot be identified.",
                  },
                ],
              }),
            );
            return 0;
          },
        }),
      ),
    ).toBe(2);

    expect(stdout.text()).toContain(
      "INCONCLUSIVE finding-1: The original entrypoint cannot be identified.",
    );
  });

  test.each([
    [1, 2],
    [7, 2],
    [130, 130],
    [143, 143],
  ] as const)(
    "maps Codex exit %i to verification exit %i",
    async (codexStatus, expectedStatus) => {
      for (const flags of [
        ["--json"],
        ["--json", "--full-output"],
        ["--format", "yaml", "--full-output"],
        ["--token-count"],
      ]) {
        const { stdout, stderr, runCli } = createCliTest(main);
        expect(
          await runCli(
            ["verify-fix", "Synthetic finding", ...flags],
            dependencies({ onCodex: () => codexStatus }),
          ),
        ).toBe(expectedStatus);
        const message = `Codex verification failed with exit code ${codexStatus}.`;
        if (expectedStatus === 2) {
          expect(stderr.text()).toContain(`codex-security: ${message}\n`);
          expect(stderr.text().split(message)).toHaveLength(2);
        } else expect(stderr.text()).not.toContain(message);
        if (expectedStatus === 2 && flags[0] === "--json") {
          const failure = JSON.parse(stdout.text());
          if (flags.includes("--full-output")) {
            expect(failure.ok).toBe(false);
            expect(failure.error).toMatchObject({
              code: "VERIFICATION_FAILED",
              message,
            });
          } else {
            expect(failure).toMatchObject({
              status: "failed",
              code: "VERIFICATION_FAILED",
              message,
            });
          }
        } else expect(stdout.text()).toBe("");
      }
    },
  );

  test.each(["exit", "throw"] as const)(
    "reports ChatGPT authentication diagnostics after a Codex %s failure",
    async (transport) => {
      const message =
        "401 Unauthorized: stored ChatGPT credentials expired. Run codex-security login --auth chatgpt.";
      for (const flags of [
        [],
        ["--json"],
        ["--json", "--full-output"],
        ["--format", "jsonl"],
      ]) {
        const { stdout, stderr, runCli } = createCliTest(main);
        expect(
          await runCli(
            ["verify-fix", "Synthetic finding", "--auth", "chatgpt", ...flags],
            dependencies({
              onCodex: (_args, output) => {
                if (transport === "throw") throw new Error(message);
                output!.stderr.write(`${message}\n`);
                return 1;
              },
            }),
          ),
        ).toBe(2);
        if (flags.length === 0) expect(stdout.text()).toBe("");
        else {
          const failure = JSON.parse(stdout.text());
          const details = flags.includes("--full-output")
            ? failure.error
            : failure;
          expect(details).toMatchObject({
            code: "VERIFICATION_FAILED",
            message,
          });
          expect(failure.results).toBeUndefined();
        }
        expect(stderr.text()).toContain(message);
        expect(stderr.text().split(message)).toHaveLength(2);
      }
    },
  );

  test("reports an authentication protocol error from a successfully exited Codex child", async () => {
    const directory = await temporaryDirectory();
    const message = "401 Unauthorized: synthetic ChatGPT token expired";
    const source = `
const lines = require("node:readline").createInterface({ input: process.stdin });
lines.once("line", () => process.stdout.write(JSON.stringify({
  id: 1, error: { code: -32001, message: ${JSON.stringify(message)} }
}) + "\\n"));
`;
    const { stdout, stderr, runCli } = createCliTest(main);
    expect(
      await runCli(
        ["verify-fix", "Synthetic finding", "--auth", "chatgpt", "--json"],
        dependencies({
          currentDirectory: directory,
          onCodex: (_args, output) =>
            runCodexSkillCommand(
              ["-e", source],
              { ...output!, auth: undefined },
              { command: process.execPath },
              {},
            ),
        }),
      ),
    ).toBe(2);
    expect(JSON.parse(stdout.text())).toMatchObject({
      status: "failed",
      code: "VERIFICATION_FAILED",
      message: expect.stringContaining(message),
    });
    expect(stderr.text()).toContain(message);
  });

  test.each([
    ["fixed", 0],
    ["still_vulnerable", 1],
    ["inconclusive", 2],
  ] as const)(
    "retains completed %s results with full output",
    async (status, code) => {
      const { stdout, runCli } = createCliTest(main);
      const results = [
        {
          id: "finding-1",
          status,
          evidence: "Synthetic verification evidence.",
        },
      ];
      expect(
        await runCli(
          ["verify-fix", "Synthetic finding", "--json", "--full-output"],
          dependencies({
            onCodex: (_args, output) => {
              output?.stdout.write(JSON.stringify({ results }));
              return 0;
            },
          }),
        ),
      ).toBe(code);
      expect(JSON.parse(stdout.text()).data.results).toEqual(results);
    },
  );

  test.each([130, 143])(
    "preserves interrupted status %i without writing a success envelope",
    async (status) => {
      const { stderr } = createCliTest(main);
      const write = mock(() => {
        throw new Error("Unexpected stdout write.");
      });
      expect(
        await main(
          ["verify-fix", "Synthetic finding", "--json", "--full-output"],
          { write },
          stderr.stream,
          dependencies({ onCodex: () => status }),
        ),
      ).toBe(status);
      expect(write).not.toHaveBeenCalled();
    },
  );

  test("sanitizes model-controlled evidence in human-readable output", async () => {
    const stdout = captureCli(main, "stdout");

    expect(
      await stdout.run(
        ["verify-fix", "A previously reported authorization bypass"],
        dependencies({
          onCodex: (_args, output) => {
            output?.stdout.write(
              JSON.stringify({
                results: [
                  {
                    id: "finding-1",
                    status: "fixed",
                    evidence:
                      "\u001b[31mOriginal exploit rejected.\nForged result.",
                  },
                ],
              }),
            );
            return 0;
          },
        }),
      ),
    ).toBe(0);

    expect(stdout.text()).toBe(
      "FIXED finding-1: Original exploit rejected. Forged result.\n",
    );
  });

  test.each(["fixed", "still_vulnerable", "inconclusive"])(
    "reports required output failure for a %s verification",
    async (status) => {
      const failure = new Error("Synthetic verification output failure");
      const stdout = new Writable({
        write(_chunk, _encoding, callback) {
          queueMicrotask(() => callback(failure));
        },
      });
      const emitted = new Promise<Error>((resolve) =>
        stdout.once("error", resolve),
      );
      const stderr = capture();
      const [exitCode, error] = await Promise.all([
        main(
          ["verify-fix", "Synthetic finding"],
          stdout,
          stderr.stream,
          dependencies({
            onCodex: (_args, output) => {
              output?.stdout.write(
                JSON.stringify({
                  results: [
                    {
                      id: "finding-1",
                      status,
                      evidence: "Synthetic evidence.",
                    },
                  ],
                }),
              );
              return 0;
            },
          }),
        ),
        emitted,
      ]);
      expect(error).toBe(failure);
      expect(exitCode).toBe(2);
      expect(stderr.text()).toContain(failure.message);
      expect(stdout.listenerCount("error")).toBe(0);
    },
  );

  test("waits for each verification result before writing the next", async () => {
    const writes = [
      Promise.withResolvers<() => void>(),
      Promise.withResolvers<() => void>(),
    ];
    const chunks: string[] = [];
    const stdout = new Writable({
      highWaterMark: 1,
      write(chunk, _encoding, callback) {
        chunks.push(chunk.toString());
        writes[chunks.length - 1]!.resolve(callback);
      },
    });
    const operation = main(
      ["verify-fix", "First finding", "Second finding"],
      stdout,
      capture().stream,
      dependencies({
        onCodex: (_args, output) => {
          output?.stdout.write(
            JSON.stringify({
              results: [
                {
                  id: "finding-1",
                  status: "fixed",
                  evidence: "Café evidence.",
                },
                {
                  id: "finding-2",
                  status: "still_vulnerable",
                  evidence: "Exploit still succeeds.",
                },
              ],
            }),
          );
          return 0;
        },
      }),
    );
    const first = await writes[0]!.promise;
    const firstBufferedBytes = stdout.writableLength;
    first();
    const second = await writes[1]!.promise;
    second();
    expect(await operation).toBe(1);
    expect(chunks).toEqual([
      "FIXED finding-1: Café evidence.\n",
      "STILL_VULNERABLE finding-2: Exploit still succeeds.\n",
    ]);
    expect(firstBufferedBytes).toBe(Buffer.byteLength(chunks[0]!));
    expect(stdout.writableEnded).toBe(false);
    expect(stdout.listenerCount("error")).toBe(0);
    stdout.destroy();
  });

  test.each([
    ["missing result", { results: [] }],
    [
      "wrong finding",
      {
        results: [
          { id: "SEC-124", status: "fixed", evidence: "Different finding." },
        ],
      },
    ],
    [
      "missing evidence",
      { results: [{ id: "SEC-123", status: "fixed", evidence: "   " }] },
    ],
    [
      "unsupported outcome",
      { results: [{ id: "SEC-123", status: "no_change", evidence: "Safe." }] },
    ],
  ] as const)(
    "rejects %s instead of reporting an unverified fix",
    async (_name, result) => {
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["verify-fix", "--linear-issue", "SEC-123", "--json"],
          dependencies({
            environment: { CODEX_SECURITY_LINEAR_API_KEY: "synthetic-key" },
            linearClient,
            onCodex: (_args, output) => {
              output?.stdout.write(JSON.stringify(result));
              return 0;
            },
          }),
        ),
      ).toBe(2);

      expect(JSON.parse(stdout.text())).toMatchObject({
        status: "failed",
        code: "VERIFICATION_FAILED",
      });
      expect(stderr.text()).toContain(
        "an evidence-backed verification result for every finding",
      );
    },
  );

  test.each([
    [["verify-fix"], "Verify-fix requires a finding"],
    [
      ["verify-fix", "--scan", "scan-1", "--linear-issue", "SEC-123"],
      "Saved findings cannot be combined with Linear issues or projects",
    ],
  ] as const)(
    "rejects invalid verification selection %j",
    async (args, expected) => {
      const stderr = captureCli(main, "stderr");
      const onCodex = mock<() => number>().mockReturnValue(0);

      expect(
        await stderr.run(
          args,
          dependencies({
            environment: { CODEX_SECURITY_LINEAR_API_KEY: "synthetic-key" },
            onCodex,
          }),
        ),
      ).toBe(2);
      expect(stderr.text()).toContain(expected);
      expect(onCodex).not.toHaveBeenCalled();
    },
  );
});

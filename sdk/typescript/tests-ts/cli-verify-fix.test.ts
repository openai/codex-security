import { requestMetadata } from "./support/request-metadata.js";
import { afterEach, describe, expect, test, mock, spyOn } from "bun:test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { stripVTControlCharacters } from "node:util";
import { writeArtifactOutput } from "../src/artifact-export.js";
import { main, runCodexSkillCommand } from "../src/cli.js";
import { remediationPrompt, verificationBatches } from "../src/remediation.js";
import * as runtime from "../src/runtime.js";
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

  test("reports missing verification instructions on stderr for a small saved finding", async () => {
    const pluginRoot = await temporaryDirectory();
    using plugin = spyOn(runtime, "bundledPluginRoot").mockResolvedValue(
      pluginRoot,
    );
    const result = fakeResult(["high"]);
    result.findings.findings[0]!.occurrenceId = "occ_0";
    const onCodex = mock(() => 0);
    const { stdout, stderr, runCli } = createCliTest(main);
    expect(
      await runCli(
        ["verify-fix", "--scan", "scan", "--json"],
        dependencies({
          result,
          onWorkbench: () => ({
            scan: {
              scanId: "scan",
              targetPath: "/saved/repository",
              findings: result.findings.findings as unknown as JsonObject[],
            },
          }),
          onCodex,
        }),
      ),
    ).toBe(2);
    const failure = JSON.parse(stdout.text());
    expect(failure.code).toBe("VERIFICATION_FAILED");
    expect(failure.message).toContain("SKILL.md");
    expect(stderr.text()).toBe(`codex-security: ${failure.message}\n`);
    expect(plugin).toHaveBeenCalled();
    expect(onCodex).not.toHaveBeenCalled();
  });

  test.each([530_000, 1 << 20])(
    "retains a saved verification worker failure with %i-character findings and token-limited stdout",
    async (size) => {
      const result = fakeResult(["high", "high"]);
      for (const [index, finding] of result.findings.findings.entries()) {
        finding.occurrenceId = `occ_${index}`;
        finding.title = "x".repeat(size);
      }
      const workerMessage = "Synthetic verification worker failed.";
      const message = workerMessage;
      const deps = dependencies({
        result,
        onWorkbench: () => ({
          scan: {
            scanId: "scan",
            targetPath: "/saved/repository",
            findings: result.findings.findings as unknown as JsonObject[],
          },
        }),
        onCodex: (_args, output) => {
          output!.stderr.write(`${workerMessage}\n`);
          return 1;
        },
      });
      for (const flags of [
        ["--json", "--token-count"],
        ["--format=jsonl", "--full-output", "--token-count"],
        ["--format", "jsonl", "--token-limit=1"],
        [
          "--json",
          "--filter-output=results",
          "--token-offset",
          "20",
          "--token-limit",
          "1",
        ],
      ]) {
        const { stdout, stderr, runCli } = createCliTest(main);
        expect(
          await runCli(["verify-fix", "--scan", "scan", ...flags], deps),
        ).toBe(2);
        const value = JSON.parse(stdout.text());
        if (flags.includes("--full-output")) {
          expect(value).toMatchObject({ ok: false, error: { message } });
        } else if (flags.includes("--token-count")) {
          expect(typeof value).toBe("number");
        } else {
          expect(typeof value).toBe("string");
          expect(value).toContain("[truncated:");
          expect(value).not.toContain(message);
        }
        expect(stderr.text().split(message)).toHaveLength(2);
      }
    },
  );

  test.each([
    ["complete", 1],
    ["redirected output", 1],
    ["wrong ID", 2],
    ["missing result", 2],
    ["transport failure", 2],
    ["closed stderr", 2],
    ["SIGINT", 130],
    ["SIGTERM", 143],
    ["repeated signal", 130],
    ["interrupted worker", 143],
    ["oversized finding", 1],
  ] as const)(
    "handles %s across saved verification batches",
    async (scenario, expectedExit) => {
      const result = fakeResult(["high", "high", "high", "low"]);
      const evidence = '"quoted"\n'.repeat(60_000);
      result.findings.findings.forEach((finding, i) => {
        Object.assign(finding, {
          occurrenceId: `occ_${i}`,
          findingId: `csf_${i}`,
          codeEvidence: [
            {
              path: "src/check.ts",
              code:
                scenario === "oversized finding" && i === 1
                  ? evidence.repeat(2)
                  : evidence,
            },
          ],
        });
      });
      const signals = new FakeSignals();
      const { stdout, stderr } = createCliTest(main, {
        stdout: scenario !== "redirected output",
        stderr: true,
      });
      const seen: string[] = [];
      const forceExit = mock(() => {});
      const deps = dependencies({
        result,
        signals,
        onWorkbench: () => ({
          scan: {
            scanId: "scan",
            targetPath: "/saved/repository",
            findings: result.findings.findings as unknown as JsonObject[],
          },
        }),
        onCodex: async (_args, output) => {
          const prompt = output!.appServer!.prompt;
          expect([...prompt].length).toBeLessThanOrEqual(1 << 20);
          const file = prompt.match(/^".*finding\.json"$/m)?.[0];
          const batch = JSON.parse(
            file === undefined
              ? prompt.split("\n").at(-1)!
              : await readFile(JSON.parse(file), "utf8"),
          ) as Finding[];
          expect(batch).toHaveLength(1);
          expect(batch[0]!.codeEvidence![0]!.code).toBe(
            scenario === "oversized finding" && seen.length === 1
              ? evidence.repeat(2)
              : evidence,
          );
          const id = batch[0]!.occurrenceId;
          seen.push(id);
          expect(output!.appServer!.onEvent).toBeUndefined();
          output!.appServer!.onEvent?.({
            method: "item/reasoning/summaryTextDelta",
            params: { itemId: "reason_0", delta: `Checked ${id}.` },
          });
          output!.appServer!.onEvent?.({
            method: "item/completed",
            params: {
              item: {
                type: "reasoning",
                id: "reason_0",
                summary: [`Checked ${id}.`],
              },
            },
          });
          if (seen.length === 2 && scenario === "missing result") {
            output!.stdout.write(JSON.stringify({ results: [] }));
            return 0;
          }
          if (seen.length === 1 && scenario === "transport failure")
            output!.stderr.write("First batch diagnostic.\n");
          if (seen.length === 2 && scenario === "transport failure") return 1;
          if (seen.length === 2 && scenario === "interrupted worker") {
            signals.emit("SIGINT");
            signals.emit("SIGTERM");
            return 143;
          }
          if (seen.length === 2 && scenario === "closed stderr") {
            output!.stderr.write("Second worker failed.\n");
            return 1;
          }
          if (
            seen.length === 1 &&
            (scenario === "SIGINT" || scenario === "SIGTERM")
          )
            queueMicrotask(() => signals.emit(scenario));
          if (seen.length === 1 && scenario === "repeated signal")
            queueMicrotask(() => {
              signals.emit("SIGINT");
              signals.emit("SIGTERM");
            });
          output!.stdout.write(
            JSON.stringify({
              results: [
                {
                  id:
                    seen.length === 2 && scenario === "wrong ID" ? "occ_0" : id,
                  status: seen.length === 1 ? "still_vulnerable" : "fixed",
                  evidence: "Verified against source.",
                },
              ],
            }),
          );
          return 0;
        },
      });
      const errorOutput =
        scenario === "closed stderr"
          ? new Writable({
              write(chunk, _encoding, done) {
                done(
                  chunk.includes("Second worker")
                    ? new Error("EPIPE")
                    : undefined,
                );
              },
            })
          : stderr.stream;
      const exit = await main(
        ["verify-fix", "--scan", "scan", "--severity", "high", "--json"],
        stdout.stream,
        errorOutput,
        { ...deps, forceExit },
      );
      expect(forceExit).not.toHaveBeenCalled();
      expect(exit).toBe(expectedExit);
      expect(
        [...signals.listeners.values()].every(
          (listeners) => listeners.size === 0,
        ),
      ).toBe(true);
      if (scenario === "closed stderr")
        expect((errorOutput as Writable).listenerCount("error")).toBe(0);
      if (
        scenario === "complete" ||
        scenario === "redirected output" ||
        scenario === "oversized finding"
      ) {
        expect(seen).toEqual(["occ_0", "occ_1", "occ_2"]);
        expect(stderr.text()).toBe("");
        expect(
          JSON.parse(stdout.text()).results.map(({ id }: { id: string }) => id),
        ).toEqual(seen);
      } else if (
        scenario === "SIGINT" ||
        scenario === "SIGTERM" ||
        scenario === "repeated signal" ||
        scenario === "interrupted worker"
      ) {
        expect(seen).toEqual(
          scenario === "interrupted worker" ? ["occ_0", "occ_1"] : ["occ_0"],
        );
        expect(stdout.text()).toBe("");
        expect(stderr.text()).toBe("");
      } else {
        expect(seen).toEqual(["occ_0", "occ_1"]);
        const failure = JSON.parse(stdout.text());
        expect(failure.code).toBe("VERIFICATION_FAILED");
        expect(failure.results).toBeUndefined();
        if (scenario === "transport failure")
          expect(failure.message).toBe(
            "Codex verification failed with exit code 1.",
          );
        if (scenario === "closed stderr")
          expect(failure.message).toBe("Second worker failed.");
      }
    },
  );

  test("verifies a historical occurrence directly in the selected scan", async () => {
    const result = fakeResult(["high"]);
    Object.assign(result.findings.findings[0]!, {
      occurrenceId: "occ_earlier",
      findingId: "csf_guard",
    });
    const verdict = {
      id: "occ_earlier",
      status: "fixed",
      evidence: "The guard rejects the original input.",
    };
    const stdout = captureCli(main, "stdout");
    const status = await stdout.run(
      ["verify-fix", "--scan", "earlier", "occ_earlier", "--json"],
      dependencies({
        result,
        onWorkbench: (args) => {
          expect(args).toEqual([
            "get-scan",
            "--scan-id",
            "earlier",
            "--occurrence-id",
            "occ_earlier",
          ]);
          return {
            scan: {
              scanId: "earlier",
              targetPath: "/saved/repository",
              findings: result.findings.findings as unknown as JsonObject[],
            },
          };
        },
        onCodex: (_args, output) => {
          output!.stdout.write(JSON.stringify({ results: [verdict] }));
          return 0;
        },
      }),
    );
    expect(status).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({
      scanId: "earlier",
      results: [verdict],
    });
  });

  test("batches at the exact decoded prompt limit and isolates an oversized finding", async () => {
    const findings = fakeResult(["high", "high"]).findings.findings.map(
      (finding, i) => ({
        ...finding,
        occurrenceId: `occ_${i}`,
        title: "",
      }),
    );
    const prompt = await remediationPrompt({
      operation: "verify",
      contents: findings,
      verificationIds: findings.map(({ occurrenceId }) => occurrenceId),
      pluginRoot: PLUGIN_ROOT,
      verificationMode: "static",
    });
    const batches = () => verificationBatches(findings, PLUGIN_ROOT, "static");
    findings[1]!.title = "🚀".repeat((1 << 20) - [...prompt].length);
    expect((await batches()).map((batch) => batch.length)).toEqual([2]);
    findings[1]!.title += "x";
    expect((await batches()).map((batch) => batch.length)).toEqual([1, 1]);
    findings[1]!.title += "x".repeat(1024);
    expect(await batches()).toEqual([[findings[0]!], [findings[1]!]]);
  });

  test("rejects an unfinished output slice before starting a verification", async () => {
    const cli = createCliTest(main);
    const deps = dependencies({
      onCodex: () => {
        throw new Error("Unexpected verification");
      },
    });
    expect(
      await cli.runCli(
        ["verify-fix", "Example", "--filter-output=results[0"],
        deps,
      ),
    ).toBe(2);
    expect(cli.stderr.text()).toContain(
      "--filter-output requires matching brackets",
    );
  });

  test("formats a verification result before applying output controls", async () => {
    const result = {
      id: "finding-1",
      status: "fixed",
      evidence: "Synthetic evidence.",
    };
    const deps = dependencies({
      onCodex: (_args, output) => {
        output?.stdout.write(JSON.stringify({ results: [result] }));
        return 0;
      },
    });
    const yaml = captureCli(main, "stdout");
    expect(
      await yaml.run(
        [
          "verify-fix",
          "Example",
          "--format=yaml",
          "--filter-output",
          "results",
        ],
        deps,
      ),
    ).toBe(0);
    const { parse } = await import("yaml");
    expect(parse(yaml.text())).toEqual({ results: [result] });

    const tokens = captureCli(main, "stdout");
    expect(
      await tokens.run(["verify-fix", "Example", "--token-count"], deps),
    ).toBe(0);
    expect(tokens.text().trim()).toMatch(/^[1-9][0-9]*$/u);
  });

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

  test.each(["JSON", "token count", "failed stderr"])(
    "writes a structured selection failure before stderr drains (%s)",
    async (scenario) => {
      const tokenCount = scenario === "token count";
      const stdout = capture();
      const output = new Writable({
        write(chunk, _encoding, callback) {
          stdout.stream.write(chunk);
          setImmediate(callback);
        },
      });
      const writeStarted = Promise.withResolvers<(error?: Error) => void>();
      let diagnostic = "";
      const stderr = new Writable({
        highWaterMark: 1,
        write(chunk, _encoding, callback) {
          const first = diagnostic.length === 0;
          diagnostic += chunk.toString();
          if (first) writeStarted.resolve(callback);
          else callback();
        },
      });
      let finished = false;
      const operation = main(
        [
          "verify-fix",
          "--scan",
          "latest",
          "--json",
          ...(tokenCount ? ["--token-count"] : []),
        ],
        output,
        stderr,
        dependencies({ onWorkbench: () => ({ scans: [] }) }),
      ).then((code) => {
        finished = true;
        return code;
      });

      const finishWrite = await writeStarted.promise;
      await new Promise<void>((resolve) => setImmediate(resolve));
      const beforeDrain = stdout.text();
      const finishedBeforeDrain = finished;
      if (scenario === "JSON") {
        const repeated = await main(
          ["verify-fix", "--scan", "missing", "--json"],
          output,
          stderr,
          dependencies({ onWorkbench: () => ({ scans: [] }) }),
        );
        expect(repeated).toBe(2);
        expect(stderr.listenerCount("error")).toBe(0);
        expect(
          JSON.parse(stdout.text().slice(beforeDrain.length)).message,
        ).toBe("Could not read the selected scan and repository.");
      }
      finishWrite(
        scenario === "failed stderr"
          ? new Error("Synthetic stderr failure.")
          : undefined,
      );
      expect(await operation).toBe(2);
      if (scenario === "JSON") {
        await new Promise<void>((resolve) => stderr.end(resolve));
        expect(diagnostic).toBe(
          "codex-security: No saved scan was found for this repository.\n" +
            "codex-security: Could not read the selected scan and repository.\n",
        );
      }
      expect(finishedBeforeDrain).toBe(!tokenCount);
      expect(diagnostic).toContain("No saved scan was found");
      if (tokenCount) expect(beforeDrain).toMatch(/^\d+\n$/u);
      else
        expect(JSON.parse(beforeDrain).message).toContain(
          "No saved scan was found",
        );
    },
  );

  test("releases batch signal listeners before waiting for a worker's text diagnostic", async () => {
    const result = fakeResult(["high", "high"]);
    for (const [index, finding] of result.findings.findings.entries()) {
      finding.occurrenceId = `occ_${index}`;
      finding.title = "x".repeat(530_000);
    }
    const signals = new FakeSignals();
    const message = "Synthetic worker failure.\n";
    let diagnostic = "";
    let listenerCounts: number[] = [];
    const stderr = new Writable({
      write(chunk, _encoding, callback) {
        diagnostic += chunk.toString();
        setImmediate(() => {
          listenerCounts = Array.from(
            signals.listeners.values(),
            (listeners) => listeners.size,
          );
          signals.emit("SIGTERM");
          signals.emit("SIGINT");
          callback();
        });
      },
    });
    const exit = await main(
      ["verify-fix", "--scan", "scan"],
      capture().stream,
      stderr,
      dependencies({
        result,
        signals,
        onWorkbench: () => ({
          scan: {
            scanId: "scan",
            targetPath: "/saved/repository",
            findings: result.findings.findings as unknown as JsonObject[],
          },
        }),
        onCodex: (_args, output) => {
          output!.stderr.write(message);
          return 1;
        },
      }),
    );
    expect(listenerCounts).toEqual([0, 0]);
    expect(exit).toBe(2);
    expect(diagnostic).toBe(message);
  });

  test("waits for a single worker's stderr diagnostic", async () => {
    const message = "One worker failed.\n";
    const writeStarted = Promise.withResolvers<() => void>();
    const stderr = new Writable({
      write(chunk, _encoding, callback) {
        if (chunk.toString() === message) writeStarted.resolve(callback);
        else callback();
      },
    });
    let workerFinished = false;
    const operation = main(
      ["verify-fix", "Finding"],
      capture().stream,
      stderr,
      dependencies({
        onCodex: async (_args, output) => {
          await writeArtifactOutput(output!.stderr, message);
          workerFinished = true;
          return 1;
        },
      }),
    );
    const finishWrite = await writeStarted.promise;
    await new Promise<void>((resolve) => setImmediate(resolve));
    const finishedBeforeWrite = workerFinished;
    finishWrite();
    expect(await operation).toBe(2);
    expect(finishedBeforeWrite).toBe(false);
    expect(workerFinished).toBe(true);
    expect(stderr.writableEnded).toBe(false);
  });
});

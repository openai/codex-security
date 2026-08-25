import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { stripVTControlCharacters } from "node:util";
import { main } from "../src/cli.js";
import type { Finding, JsonObject } from "../src/index.js";
import type { LinearClientFactory } from "../src/linear.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";

function linearIssue(identifier: string) {
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

describe("read-only finding verification", () => {
  test("verifies imported Linear issues in a read-only sandbox without exposing credentials", async () => {
    const stdout = capture();
    const stderr = capture();
    let prompt = "";
    let environment: NodeJS.ProcessEnv | undefined;

    expect(
      await main(
        ["verify-fix", "--linear-issue", "SEC-123", "--json"],
        stdout.stream,
        stderr.stream,
        dependencies({
          environment: {
            CODEX_SECURITY_LINEAR_API_KEY: "lin_api_SYNTHETIC_SECRET",
            LINEAR_ACCESS_TOKEN: "SYNTHETIC_OAUTH_SECRET",
            OPENAI_API_KEY: "sk-proj-SYNTHETIC_MODEL_KEY",
          },
          linearClient: () =>
            ({
              issue: async (id: string) => linearIssue(id),
            }) as ReturnType<LinearClientFactory>,
          onCodex: (args, output, processEnvironment, input) => {
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
        new URL(
          "../_bundled_plugin/skills/verify-fix/SKILL.md",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    expect(prompt).toContain(
      await readFile(
        new URL(
          "../_bundled_plugin/references/static-finding-assessment.md",
          import.meta.url,
        ),
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
    const stdout = capture();
    const stderr = capture(true);

    expect(
      await main(
        ["verify-fix", "A previously reported authorization bypass", "--json"],
        stdout.stream,
        stderr.stream,
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
      const stdout = capture();
      const stderr = capture(true);

      expect(
        await main(
          [
            "verify-fix",
            "A previously reported authorization bypass",
            "--json",
          ],
          stdout.stream,
          stderr.stream,
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
    const stdout = capture();
    let agentCalls = 0;
    let prompt = "";

    expect(
      await main(
        [
          "verify-fix",
          "--linear-issue",
          "SEC-123",
          "--linear-issue",
          "SEC-456",
          "--json",
        ],
        stdout.stream,
        capture().stream,
        dependencies({
          environment: { LINEAR_ACCESS_TOKEN: "SYNTHETIC_OAUTH_TOKEN" },
          linearClient: () =>
            ({
              issue: async (id: string) => linearIssue(id),
            }) as ReturnType<LinearClientFactory>,
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

  test("verifies saved findings in their original repository", async () => {
    const result = fakeResult(["high", "medium"]);
    result.findings.findings.forEach((finding, index) => {
      Object.assign(finding, {
        findingId: `csf_${index + 1}`,
        occurrenceId: `occ_${index + 1}`,
        title: `Finding ${index + 1}`,
      });
    });
    const stdout = capture();

    expect(
      await main(
        ["verify-fix", "--scan", "scan-1", "--severity", "high", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({
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
          onCodex: (_args, output) => {
            expect(output?.appServer?.directory).toBe("/saved/repository");
            expect(output?.appServer?.sandbox).toBe("read-only");
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
                    evidence:
                      "The original exploit fails and regression checks pass.",
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
      results: [{ id: "occ_1", status: "fixed" }],
    });
  });

  test("reports inconclusive findings without treating them as fixed", async () => {
    const stdout = capture();
    expect(
      await main(
        ["verify-fix", "A previously reported authorization bypass"],
        stdout.stream,
        capture().stream,
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
      const stdout = capture();

      expect(
        await main(
          [
            "verify-fix",
            "A previously reported authorization bypass",
            "--json",
          ],
          stdout.stream,
          capture().stream,
          dependencies({ onCodex: () => codexStatus }),
        ),
      ).toBe(expectedStatus);
      expect(stdout.text()).toBe("");
    },
  );

  test("sanitizes model-controlled evidence in human-readable output", async () => {
    const stdout = capture();

    expect(
      await main(
        ["verify-fix", "A previously reported authorization bypass"],
        stdout.stream,
        capture().stream,
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
      const stdout = capture();
      const stderr = capture();

      expect(
        await main(
          ["verify-fix", "--linear-issue", "SEC-123", "--json"],
          stdout.stream,
          stderr.stream,
          dependencies({
            environment: { CODEX_SECURITY_LINEAR_API_KEY: "synthetic-key" },
            linearClient: () =>
              ({
                issue: async (id: string) => linearIssue(id),
              }) as ReturnType<LinearClientFactory>,
            onCodex: (_args, output) => {
              output?.stdout.write(JSON.stringify(result));
              return 0;
            },
          }),
        ),
      ).toBe(2);

      expect(stdout.text()).toBe("");
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
      const stderr = capture();
      let started = false;

      expect(
        await main(
          args,
          capture().stream,
          stderr.stream,
          dependencies({
            environment: { CODEX_SECURITY_LINEAR_API_KEY: "synthetic-key" },
            onCodex: () => {
              started = true;
              return 0;
            },
          }),
        ),
      ).toBe(2);
      expect(stderr.text()).toContain(expected);
      expect(started).toBe(false);
    },
  );
});

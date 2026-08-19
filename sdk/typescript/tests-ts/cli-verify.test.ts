import { describe, expect, test } from "bun:test";
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
        ["verify", "--linear-issue", "SEC-123", "--json"],
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
          onCodex: (args, output, processEnvironment) => {
            expect(args[0]).toBe("app-server");
            expect(output?.command).toBe("verify");
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
    expect(stderr.text()).toBe("");
    expect(prompt).toContain("standalone verification-only mode");
    expect(prompt).toContain(
      "Do not create, modify, or delete repository files",
    );
    expect(prompt).toContain(
      'Expected result identifiers (JSON array): ["SEC-123"]',
    );
    expect(prompt).toContain("Synthetic security evidence for SEC-123");
    expect(prompt).not.toContain("lin_api_SYNTHETIC_SECRET");
    expect(environment).toEqual({
      OPENAI_API_KEY: "sk-proj-SYNTHETIC_MODEL_KEY",
    });
  });

  test("verifies completed Linear project issues when explicitly selected", async () => {
    const stdout = capture();
    let selectedFilter: unknown;

    expect(
      await main(
        [
          "verify",
          "--linear-project",
          "Security backlog",
          "--linear-filter",
          '{"state":{"type":{"eq":"completed"}}}',
          "--json",
        ],
        stdout.stream,
        capture().stream,
        dependencies({
          environment: { LINEAR_ACCESS_TOKEN: "SYNTHETIC_OAUTH_TOKEN" },
          linearClient: () =>
            ({
              projects: async () => ({
                nodes: [
                  {
                    issues: async ({ filter }: { filter: unknown }) => {
                      selectedFilter = filter;
                      return {
                        nodes: [linearIssue("SEC-123"), linearIssue("SEC-124")],
                        pageInfo: { hasNextPage: false },
                      };
                    },
                  },
                ],
              }),
            }) as unknown as ReturnType<LinearClientFactory>,
          onCodex: (_args, output) => {
            output?.stdout.write(
              JSON.stringify({
                results: [
                  {
                    id: "SEC-123",
                    status: "fixed",
                    evidence: "The original exploit is rejected.",
                  },
                  {
                    id: "SEC-124",
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

    expect(selectedFilter).toEqual({ state: { type: { eq: "completed" } } });
    expect(JSON.parse(stdout.text())).toMatchObject({
      results: [
        { id: "SEC-123", status: "fixed" },
        { id: "SEC-124", status: "still_vulnerable" },
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
        ["verify", "--scan", "scan-1", "--severity", "high", "--json"],
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
        ["verify", "A previously reported authorization bypass"],
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

  test("sanitizes model-controlled evidence in human-readable output", async () => {
    const stdout = capture();

    expect(
      await main(
        ["verify", "A previously reported authorization bypass"],
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
          ["verify", "--linear-issue", "SEC-123", "--json"],
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
    [["verify"], "Verify requires a finding"],
    [
      ["verify", "--linear-issue", "SEC-123", "--linear-project", "Backlog"],
      "Use either --linear-issue or --linear-project",
    ],
    [
      ["verify", "--linear-issue", "SEC-123", "--linear-filter", "{}"],
      "--linear-filter requires --linear-project",
    ],
    [
      ["verify", "finding", "--linear-api-key", "synthetic-key"],
      "--linear-api-key requires --linear-issue or --linear-project",
    ],
    [
      ["verify", "finding", "--severity", "high"],
      "--severity requires a saved finding identifier or --scan",
    ],
    [
      ["verify", "--scan", "scan-1", "--linear-issue", "SEC-123"],
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

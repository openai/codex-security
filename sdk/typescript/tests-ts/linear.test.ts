import { AuthenticationLinearError, RatelimitedLinearError } from "@linear/sdk";
import { describe, expect, test } from "bun:test";
import { importLinearIssues, type LinearClientFactory } from "../src/linear.js";

type LinearImportClient = ReturnType<LinearClientFactory>;

function projectClient(
  count: number,
  issues: unknown[] = [],
  onFilter?: (filter: unknown) => void,
): LinearImportClient {
  return {
    projects: async () => ({
      nodes: Array.from({ length: count }, () => ({
        issues: async ({ filter }: { filter: unknown }) => {
          onFilter?.(filter);
          return { nodes: issues, pageInfo: { hasNextPage: false } };
        },
      })),
    }),
  } as unknown as LinearImportClient;
}

describe("Linear issue intake", () => {
  test("allows a supplied state filter to select completed issues", async () => {
    let filter: unknown;
    const issues = await importLinearIssues({
      issues: [],
      project: "Security backlog",
      filter: '{"state":{"type":{"eq":"completed"}}}',
      environment: { LINEAR_API_KEY: "lin_api_SYNTHETIC_SECRET" },
      linearClient: ({ apiKey }) => {
        expect(apiKey).toBe("lin_api_SYNTHETIC_SECRET");
        return projectClient(
          1,
          [
            {
              identifier: "SEC-123",
              title: "Recheck a completed issue",
              description: null,
              url: "https://linear.app/example/issue/SEC-123",
            },
          ],
          (value) => (filter = value),
        );
      },
    });

    expect(filter).toEqual({ state: { type: { eq: "completed" } } });
    expect(issues).toHaveLength(1);
    expect(issues[0]).toContain("Recheck a completed issue");
  });

  test("reports missing, ambiguous, and empty Linear projects", async () => {
    for (const [count, message] of [
      [0, 'Linear project "Security backlog" was not found'],
      [2, 'Linear project "Security backlog" is ambiguous.'],
      [1, 'No open Linear issues matched project "Security backlog"'],
    ] as const) {
      await expect(
        importLinearIssues({
          issues: [],
          project: "Security backlog",
          environment: {
            CODEX_SECURITY_LINEAR_API_KEY: "lin_api_SYNTHETIC_SECRET",
          },
          linearClient: () => projectClient(count),
        }),
      ).rejects.toThrow(message);
    }
  });

  test("reports SDK failures without exposing credentials", async () => {
    for (const [error, message] of [
      [new AuthenticationLinearError(), "Linear authentication failed."],
      [new RatelimitedLinearError(), "Linear request was rate limited."],
      [
        new Error("Invalid lin_api_SYNTHETIC_SECRET"),
        "Linear request failed: [redacted]",
      ],
    ] as const) {
      await expect(
        importLinearIssues({
          issues: ["SEC-123"],
          environment: {
            CODEX_SECURITY_LINEAR_API_KEY: "lin_api_SYNTHETIC_SECRET",
          },
          linearClient: () =>
            ({
              issue: async () => {
                throw error;
              },
            }) as unknown as LinearImportClient,
        }),
      ).rejects.toThrow(message);
    }
  });
});

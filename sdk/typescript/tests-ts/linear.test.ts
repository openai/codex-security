import { AuthenticationLinearError, RatelimitedLinearError } from "@linear/sdk";
import { describe, expect, test } from "bun:test";
import {
  createLinearClient,
  importLinearIssues,
  resolveLinearApiKey,
  type LinearClientFactory,
} from "../src/linear.js";

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
  test("shares API-key precedence and redirect-safe client setup", () => {
    const environment = { CODEX_SECURITY_LINEAR_API_KEY: " environment-key " };
    expect(resolveLinearApiKey(environment, " explicit-key ")).toBe(
      "explicit-key",
    );
    expect(resolveLinearApiKey(environment)).toBe("environment-key");
    expect(resolveLinearApiKey({})).toBeUndefined();
    expect(
      resolveLinearApiKey({
        LINEAR_API_KEY: "intake-key",
        LINEAR_ACCESS_TOKEN: "intake-token",
      }),
    ).toBeUndefined();
    const signal = new AbortController().signal;
    const client = projectClient(1);
    expect(
      createLinearClient(
        { apiKey: "synthetic-key", redirect: "follow", signal },
        (options) => {
          expect(options).toEqual({
            apiKey: "synthetic-key",
            redirect: "error",
            signal,
          });
          return client;
        },
      ),
    ).toBe(client);
  });

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
              comments: async () => ({
                nodes: [],
                pageInfo: { hasNextPage: false },
              }),
            },
          ],
          (value) => (filter = value),
        );
      },
    });

    expect(filter).toEqual({ state: { type: { eq: "completed" } } });
    expect(issues).toEqual([
      {
        source: "linear",
        id: "SEC-123",
        url: "https://linear.app/example/issue/SEC-123",
        text: "Title: Recheck a completed issue\n\n<description>\n\n</description>",
      },
    ]);
  });

  test("preserves the workspace selected by an issue URL", async () => {
    const selected = "https://linear.app/selected/issue/SEC-123/old-title";
    for (const workspace of ["selected", "different"]) {
      const url = `https://linear.app/${workspace}/issue/SEC-123/new-title`;
      const importing = importLinearIssues({
        issues: [selected],
        environment: { CODEX_SECURITY_LINEAR_API_KEY: "synthetic-key" },
        linearClient: () =>
          ({
            issue: async (id: string) => {
              expect(id).toBe("SEC-123");
              return {
                identifier: id,
                title: "Synthetic finding",
                description: "Synthetic evidence",
                url,
                comments: async () => ({
                  nodes: [],
                  pageInfo: { hasNextPage: false },
                }),
              };
            },
          }) as unknown as LinearImportClient,
      });
      if (workspace === "selected") {
        await expect(importing).resolves.toEqual([
          {
            source: "linear",
            id: "SEC-123",
            url,
            text: "Title: Synthetic finding\n\n<description>\nSynthetic evidence\n</description>",
          },
        ]);
      } else {
        await expect(importing).rejects.toThrow(
          "does not match the workspace in the selected URL",
        );
      }
    }
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
              issue: async () => ({
                comments: async () => ({
                  nodes: [],
                  pageInfo: { hasNextPage: true },
                  fetchNext: async () => {
                    throw error;
                  },
                }),
              }),
            }) as unknown as LinearImportClient,
        }),
      ).rejects.toThrow(message);
    }
  });
});

import { AuthenticationLinearError, RatelimitedLinearError } from "@linear/sdk";
import { describe, expect, test } from "bun:test";
import {
  createLinearClient,
  importLinearIssues,
  loadLinearPublicationContext,
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
        text: "Title: Recheck a completed issue\n\n",
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
            text: "Title: Synthetic finding\n\nSynthetic evidence",
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
        "Linear request failed: Invalid [redacted]",
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

describe("Linear publication context", () => {
  test("validates the destination and returns every active non-group team label", async () => {
    const labels = {
      nodes: [
        {
          id: "label-zeta",
          name: "Zeta",
          parentId: "label-group",
          isGroup: false,
          archivedAt: undefined as Date | undefined,
          retiredById: undefined as string | undefined,
        },
        {
          id: "label-group",
          name: "Escalation",
          isGroup: true,
          archivedAt: undefined as Date | undefined,
          retiredById: undefined as string | undefined,
        },
      ],
      pageInfo: { hasNextPage: true },
      async fetchNext() {
        this.nodes.push({
          id: "label-alpha",
          name: "Alpha",
          isGroup: false,
          archivedAt: undefined,
          retiredById: undefined,
        });
        this.nodes.push({
          id: "label-archived",
          name: "Archived",
          isGroup: false,
          archivedAt: new Date(),
          retiredById: undefined,
        });
        this.nodes.push({
          id: "label-retired",
          name: "Retired",
          isGroup: false,
          archivedAt: undefined,
          retiredById: "user-example",
        });
        this.pageInfo.hasNextPage = false;
      },
    };
    const projectTeams = {
      nodes: [{ id: "another-team" }],
      pageInfo: { hasNextPage: true },
      async fetchNext() {
        this.nodes.push({ id: "team-example" });
        this.pageInfo.hasNextPage = false;
      },
    };
    let workspaceFilter: unknown;
    const workspaceLabels = {
      nodes: [
        {
          id: "label-workspace-group",
          name: "Workspace impact",
          isGroup: true,
          teamId: undefined,
          archivedAt: undefined as Date | undefined,
          retiredById: undefined as string | undefined,
        },
        {
          id: "label-workspace",
          name: "Workspace label",
          parentId: "label-workspace-group",
          isGroup: false,
          teamId: undefined,
          archivedAt: undefined as Date | undefined,
          retiredById: undefined as string | undefined,
        },
        {
          id: "label-other-team",
          name: "Other team",
          isGroup: false,
          teamId: "another-team",
          archivedAt: undefined as Date | undefined,
          retiredById: undefined as string | undefined,
        },
      ],
      pageInfo: { hasNextPage: false },
    };
    const context = await loadLinearPublicationContext(
      {
        team: async (id: string) => ({
          id,
          labels: async () => labels,
        }),
        project: async (id: string) => ({
          id,
          teams: async () => projectTeams,
        }),
        issueLabels: async ({ filter }: { filter: unknown }) => {
          workspaceFilter = filter;
          return workspaceLabels;
        },
      } as never,
      "team-example",
      "project-example",
    );

    expect(context).toEqual({
      labels: [
        { id: "label-alpha", name: "Alpha" },
        {
          id: "label-workspace",
          name: "Workspace label",
          groupId: "label-workspace-group",
          groupName: "Workspace impact",
        },
        {
          id: "label-zeta",
          name: "Zeta",
          groupId: "label-group",
          groupName: "Escalation",
        },
      ],
    });
    expect(workspaceFilter).toEqual({ team: { null: true } });
  });

  test("rejects a project outside the selected team", async () => {
    await expect(
      loadLinearPublicationContext(
        {
          team: async () => ({
            id: "team-example",
            labels: async () => ({
              nodes: [],
              pageInfo: { hasNextPage: false },
            }),
          }),
          project: async () => ({
            id: "project-example",
            teams: async () => ({
              nodes: [{ id: "another-team" }],
              pageInfo: { hasNextPage: false },
            }),
          }),
        } as never,
        "team-example",
        "project-example",
      ),
    ).rejects.toThrow("does not belong to the selected team");
  });
});

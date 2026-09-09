import { expect, test } from "bun:test";
import {
  importLinearIssues,
  type LinearClientFactory,
} from "../src/linear.js";

type LinearImportClient = ReturnType<LinearClientFactory>;

function issue(identifier: string) {
  return {
    identifier,
    title: `Finding ${identifier}`,
    description: `Evidence for ${identifier}`,
    url: `https://linear.app/example/issue/${identifier}`,
  };
}

test("imports every page of issues from a Linear project", async () => {
  let fetchNextCalls = 0;
  const secondPage = {
    nodes: [issue("SEC-102")],
    pageInfo: { hasNextPage: false },
  };
  const firstPage = {
    nodes: [issue("SEC-101")],
    pageInfo: { hasNextPage: true },
    fetchNext: async () => {
      fetchNextCalls += 1;
      return secondPage;
    },
  };

  const imported = await importLinearIssues({
    issues: [],
    project: "Security backlog",
    environment: { CODEX_SECURITY_LINEAR_API_KEY: "synthetic-key" },
    linearClient: () =>
      ({
        projects: async () => ({
          nodes: [
            {
              issues: async (options: { first: number }) => {
                expect(options.first).toBe(50);
                return firstPage;
              },
            },
          ],
        }),
      }) as unknown as LinearImportClient,
  });

  expect(fetchNextCalls).toBe(1);
  expect(imported.map(({ id }) => id)).toEqual(["SEC-101", "SEC-102"]);
});

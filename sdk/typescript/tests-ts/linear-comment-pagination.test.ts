import { expect, test } from "bun:test";
import { importLinearIssues, type LinearClientFactory } from "../src/linear.js";
import { paginated } from "./support/linear-pagination.js";

test.each([
  [0, []],
  [1, []],
  [51, ["50"]],
  [101, ["50", "100"]],
] as const)(
  "imports %i issue comments exactly once",
  async (count, expectedCursors) => {
    const comments = Array.from({ length: count }, (_, index) => ({
      body: `Synthetic comment ${index + 1}`,
      url: `https://linear.app/example/issue/DEMO-1#comment-${index + 1}`,
    }));
    const { connection, cursors } = paginated(comments);

    const imported = await importLinearIssues({
      issues: ["DEMO-1"],
      environment: { CODEX_SECURITY_LINEAR_API_KEY: "synthetic-key" },
      linearClient: () =>
        ({
          issue: async () => ({
            identifier: "DEMO-1",
            title: "Synthetic issue",
            description: "Synthetic evidence.",
            url: "https://linear.app/example/issue/DEMO-1",
            comments: async () => connection,
          }),
        }) as unknown as ReturnType<LinearClientFactory>,
    });

    expect(imported).toHaveLength(1);
    const importedComments: string[] =
      imported[0]!.text.match(/Synthetic comment \d+/gu) ?? [];
    expect(importedComments).toEqual(comments.map(({ body }) => body));
    expect(cursors).toEqual([...expectedCursors]);
  },
);

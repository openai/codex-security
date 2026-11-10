import { expect, test } from "bun:test";
import { importLinearIssues, type LinearClientFactory } from "../src/linear.js";
import { emptyPage, paginated } from "./support/linear-pagination.js";

test("imports all project issues once across three SDK pages", async () => {
  const issues = Array.from({ length: 101 }, (_, index) => ({
    identifier: `DEMO-${index + 1}`,
    title: `Synthetic issue ${index + 1}`,
    description: "Synthetic evidence.",
    url: `https://linear.app/example/issue/DEMO-${index + 1}`,
    comments: emptyPage,
  }));
  const { connection, cursors } = paginated(issues);
  const imported = await importLinearIssues({
    issues: [],
    project: "Example project",
    environment: { CODEX_SECURITY_LINEAR_API_KEY: "synthetic-key" },
    linearClient: () =>
      ({
        projects: async () => ({
          nodes: [{ issues: async () => connection }],
        }),
      }) as unknown as ReturnType<LinearClientFactory>,
  });
  expect(imported.map(({ id }) => id)).toEqual(
    issues.map(({ identifier }) => identifier),
  );
  expect(cursors).toEqual(["50", "100"]);
});

test.each([
  [1, []],
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

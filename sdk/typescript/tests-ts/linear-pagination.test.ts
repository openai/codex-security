import { expect, test } from "bun:test";
import { importLinearIssues, type LinearClientFactory } from "../src/linear.js";
import { paginated } from "./support/linear-pagination.js";

test.each([
  [1, []],
  [51, ["50"]],
  [101, ["50", "100"]],
] as const)(
  "imports %i project issues exactly once",
  async (count, expectedCursors) => {
    const issues = Array.from({ length: count }, (_, index) => ({
      identifier: `DEMO-${index + 1}`,
      title: `Synthetic issue ${index + 1}`,
      description: "Synthetic evidence.",
      url: `https://linear.app/example/issue/DEMO-${index + 1}`,
      comments: async () => paginated([]).connection,
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
    expect(cursors).toEqual([...expectedCursors]);
  },
);

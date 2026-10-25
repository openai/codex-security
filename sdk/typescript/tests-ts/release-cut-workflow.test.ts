import { readFileSync } from "node:fs";
import { expect, test } from "bun:test";

test("checks out the same revision used to cut tags after main CI or a manual dispatch", () => {
  const workflow = Bun.YAML.parse(
    readFileSync(
      new URL(
        "../../../.github/workflows/node-release-cut.yml",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as {
    on: Record<string, unknown>;
    jobs: {
      cut: {
        env: { RELEASE_SHA: string };
        steps: { uses?: string; with?: { ref?: string } }[];
      };
    };
  };
  expect(workflow.on).toEqual({
    workflow_run: {
      workflows: ["node-ci"],
      types: ["completed"],
      branches: ["main"],
    },
    workflow_dispatch: null,
  });
  const { env, steps } = workflow.jobs.cut;
  const verifiedSha = "${{ github.event.workflow_run.head_sha || github.sha }}";
  expect(env.RELEASE_SHA).toBe(verifiedSha);
  expect(
    steps.find(({ uses }) => uses?.startsWith("actions/checkout@"))?.with?.ref,
  ).toBe(verifiedSha);
});

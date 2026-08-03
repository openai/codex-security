import { readFileSync } from "node:fs";
import { expect, test } from "bun:test";

const releaseCutWorkflow = readFileSync(
  new URL("../../../.github/workflows/node-release-cut.yml", import.meta.url),
  "utf8",
);

test("starts npm publication only after node-ci succeeds on main", () => {
  expect(releaseCutWorkflow).toContain("workflow_run:");
  expect(releaseCutWorkflow).toContain('workflows: ["node-ci"]');
  expect(releaseCutWorkflow).toContain("types: [completed]");
  expect(releaseCutWorkflow).toContain(
    "github.event.workflow_run.conclusion == 'success'",
  );
  expect(releaseCutWorkflow).toContain(
    "github.event.workflow_run.head_branch == 'main'",
  );
  expect(releaseCutWorkflow).not.toContain("  push:\n");
});

test("cuts the protected release tag from the exact successful CI commit", () => {
  expect(releaseCutWorkflow).toContain(
    "RELEASE_SHA: ${{ github.event.workflow_run.head_sha || github.sha }}",
  );
  expect(releaseCutWorkflow).toContain(
    "ref: ${{ github.event.workflow_run.head_sha || github.sha }}",
  );
  expect(releaseCutWorkflow).toContain(
    'git merge-base --is-ancestor "$RELEASE_SHA" origin/main',
  );
  expect(releaseCutWorkflow).toContain('git rev-parse "$RELEASE_SHA^"');
  expect(releaseCutWorkflow).toContain('-f "sha=$RELEASE_SHA"');
});

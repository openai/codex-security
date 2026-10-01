import assert from "node:assert/strict";
import test from "node:test";
import { resolveScanTargets } from "./invoice-desk-target.mjs";

const repository = "example/invoices";
const sourceSha = "1".repeat(40);
const mainSha = "2".repeat(40);
const context = {
  eventName: "workflow_dispatch",
  repository,
  sha: mainSha,
  event: { inputs: { pr_number: "7", source_sha: sourceSha } },
};
function pullRequest(overrides = {}) {
  return {
    number: 7,
    state: "open",
    draft: false,
    base: { ref: "main", repo: { full_name: repository } },
    head: { sha: sourceSha, repo: { full_name: repository } },
    ...overrides,
  };
}

test("selects the requested PR head rather than the trusted workflow commit", async () => {
  assert.deepEqual(
    await resolveScanTargets(context, async (number) => {
      assert.equal(number, "7");
      return pullRequest();
    }),
    [{ pr: 7, sha: sourceSha }],
  );
});

test("includes fork and draft PRs without depending on a PR workflow run", async () => {
  assert.deepEqual(
    await resolveScanTargets(context, async () =>
      pullRequest({
        draft: true,
        head: { sha: sourceSha, repo: { full_name: "contributor/invoices" } },
      }),
    ),
    [{ pr: 7, sha: sourceSha }],
  );
});

test("rechecking after approval excludes closed, retargeted, and superseded PRs", async () => {
  assert.deepEqual(
    await resolveScanTargets(context, async () => pullRequest()),
    [{ pr: 7, sha: sourceSha }],
  );
  for (const changed of [
    { state: "closed" },
    { base: { ref: "release", repo: { full_name: repository } } },
    { base: { ref: "main", repo: { full_name: "other/invoices" } } },
    { head: { sha: "3".repeat(40) } },
  ]) {
    assert.deepEqual(
      await resolveScanTargets(context, async () => pullRequest(changed)),
      [],
    );
  }
});

test("manual baseline scans use the trusted workflow commit", async () => {
  assert.deepEqual(
    await resolveScanTargets({ ...context, event: { inputs: {} } }, () =>
      assert.fail("unexpected API call"),
    ),
    [{ pr: 0, sha: mainSha }],
  );
});

test("incomplete or invalid PR inputs fail instead of falling back to a baseline", async () => {
  for (const inputs of [
    { pr_number: "7" },
    { source_sha: sourceSha },
    { pr_number: "-1", source_sha: sourceSha },
    { pr_number: "7", source_sha: "main" },
  ]) {
    await assert.rejects(
      resolveScanTargets({ ...context, event: { inputs } }, () =>
        assert.fail("unexpected API call"),
      ),
      /require both/,
    );
  }
});

test("ignores unexpected events without querying GitHub", async () => {
  assert.deepEqual(
    await resolveScanTargets({ ...context, eventName: "pull_request" }, () =>
      assert.fail("unexpected API call"),
    ),
    [],
  );
});

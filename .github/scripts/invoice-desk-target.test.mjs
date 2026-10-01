import assert from "node:assert/strict";
import test from "node:test";
import { resolveScanTargets } from "./invoice-desk-target.mjs";

const repository = "example/invoices";
const sourceSha = "1".repeat(40);
const mainSha = "2".repeat(40);
const context = {
  eventName: "workflow_run",
  repository,
  sha: mainSha,
  event: {
    workflow_run: {
      event: "pull_request",
      conclusion: "success",
      head_sha: sourceSha,
      pull_requests: [{ number: 7 }],
    },
  },
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

test("selects the PR head rather than the downstream workflow's main commit", async () => {
  const targets = await resolveScanTargets(context, async (sha) => {
    assert.equal(sha, sourceSha);
    return [pullRequest()];
  });
  assert.deepEqual(targets, [{ pr: 7, sha: sourceSha }]);
});

test("finds fork and draft PRs when the workflow payload omits associations", async () => {
  const forkContext = structuredClone(context);
  forkContext.event.workflow_run.pull_requests = [];
  const targets = await resolveScanTargets(forkContext, async () => [
    pullRequest({
      draft: true,
      head: { sha: sourceSha, repo: { full_name: "contributor/invoices" } },
    }),
  ]);
  assert.deepEqual(targets, [{ pr: 7, sha: sourceSha }]);
});

test("excludes closed, retargeted, superseded, and unrelated PRs", async () => {
  const targets = await resolveScanTargets(context, async () => [
    pullRequest({ state: "closed" }),
    pullRequest({ base: { ref: "release", repo: { full_name: repository } } }),
    pullRequest({ head: { sha: "3".repeat(40) } }),
    pullRequest({
      base: { ref: "main", repo: { full_name: "other/invoices" } },
    }),
    pullRequest({ number: 8 }),
  ]);
  assert.deepEqual(targets, []);
});

test("a failed behavior check still queues the source scan", async () => {
  const failedContext = structuredClone(context);
  failedContext.event.workflow_run.conclusion = "failure";
  assert.deepEqual(
    await resolveScanTargets(failedContext, async () => [pullRequest()]),
    [{ pr: 7, sha: sourceSha }],
  );
});

test("ignores cancelled runs and non-PR events without querying associations", async () => {
  const cancelled = structuredClone(context);
  cancelled.event.workflow_run.conclusion = "cancelled";
  const pushed = structuredClone(context);
  pushed.event.workflow_run.event = "push";
  const unexpected = { ...context, eventName: "push" };
  for (const skipped of [cancelled, pushed, unexpected]) {
    assert.deepEqual(
      await resolveScanTargets(skipped, () =>
        assert.fail("unexpected API call"),
      ),
      [],
    );
  }
});

test("manual baseline scans use the protected workflow commit", async () => {
  assert.deepEqual(
    await resolveScanTargets(
      { ...context, eventName: "workflow_dispatch" },
      () => assert.fail("unexpected API call"),
    ),
    [{ pr: 0, sha: mainSha }],
  );
});

test("retains each matching PR when a fork run has no association metadata", async () => {
  const forkContext = structuredClone(context);
  forkContext.event.workflow_run.pull_requests = [];
  assert.deepEqual(
    await resolveScanTargets(forkContext, async () => [
      pullRequest(),
      pullRequest({ number: 8 }),
    ]),
    [
      { pr: 7, sha: sourceSha },
      { pr: 8, sha: sourceSha },
    ],
  );
});

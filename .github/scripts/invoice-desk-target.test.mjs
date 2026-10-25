import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
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

test("scheduled baseline scans use the trusted workflow commit", async () => {
  assert.deepEqual(
    await resolveScanTargets(
      { ...context, eventName: "schedule", event: { schedule: "17 3 * * 1" } },
      () => assert.fail("unexpected API call"),
    ),
    [{ pr: 0, sha: mainSha }],
  );
});

test("completed behavior workflows no longer queue inference", async () => {
  assert.deepEqual(
    await resolveScanTargets(
      {
        ...context,
        eventName: "workflow_run",
        event: {
          workflow_run: {
            event: "pull_request",
            conclusion: "success",
            head_sha: sourceSha,
            pull_requests: [{ number: 7 }],
          },
        },
      },
      () => assert.fail("unexpected API call"),
    ),
    [],
  );
});

test("approval recheck stays bound to its matrix PR and source revision", async () => {
  const run = { ...context, target: { pr: 7, sha: sourceSha } };
  for (const changed of [
    { state: "closed" },
    { base: { ref: "release", repo: { full_name: repository } } },
    { head: { sha: mainSha } },
  ]) {
    assert.deepEqual(
      await resolveScanTargets(run, async (number) => {
        assert.equal(number, "7");
        return pullRequest(changed);
      }),
      [],
    );
  }
  assert.deepEqual(await resolveScanTargets(run, async () => pullRequest()), [
    { pr: 7, sha: sourceSha },
  ]);
});

test("baseline approval recheck retains the original trusted workflow commit", async () => {
  for (const eventName of ["workflow_dispatch", "schedule"]) {
    assert.deepEqual(
      await resolveScanTargets(
        { ...context, eventName, target: { pr: 0, sha: mainSha } },
        () => assert.fail("unexpected API call"),
      ),
      [{ pr: 0, sha: mainSha }],
    );
  }
});

test("resolver CLI emits the requested target without dispatching another workflow", (t) => {
  const root = mkdtempSync(join(tmpdir(), "invoice-desk-target-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const eventPath = join(root, "event.json");
  const outputPath = join(root, "output.txt");
  writeFileSync(eventPath, JSON.stringify(context.event));
  const scriptUrl = new URL("./invoice-desk-target.mjs", import.meta.url);
  const script = `
    import assert from "node:assert/strict";
    import childProcess from "node:child_process";
    import { syncBuiltinESMExports } from "node:module";
    childProcess.execFileSync = (command, args) => {
      assert.equal(command, "gh");
      assert.deepEqual(args, ["api", ${JSON.stringify(`repos/${repository}/pulls/7`)}]);
      return JSON.stringify(${JSON.stringify(pullRequest())});
    };
    syncBuiltinESMExports();
    process.argv[1] = ${JSON.stringify(fileURLToPath(scriptUrl))};
    await import(${JSON.stringify(scriptUrl.href)});
  `;
  const result = execFileSync(
    process.execPath,
    ["--input-type=module", "--eval", script],
    {
      encoding: "utf8",
      env: {
        GITHUB_REPOSITORY: repository,
        GITHUB_SHA: mainSha,
        GITHUB_EVENT_NAME: "workflow_dispatch",
        GITHUB_EVENT_PATH: eventPath,
        GITHUB_OUTPUT: outputPath,
      },
    },
  );
  assert.match(result, /PR #7/);
  assert.equal(
    readFileSync(outputPath, "utf8"),
    `targets=${JSON.stringify([{ pr: 7, sha: sourceSha }])}\n`,
  );
});

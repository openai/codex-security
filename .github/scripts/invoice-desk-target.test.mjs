import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { resolveScanTarget } from "./invoice-desk-target.mjs";

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

test("initial selection and approval recheck require the selected PR and revision to remain eligible", async () => {
  const target = { pr: 7, sha: sourceSha };
  // The approval step must use its original target even if dispatch inputs differ.
  const recheck = {
    ...context,
    target: { ...target },
    event: { inputs: { pr_number: "9", source_sha: mainSha } },
  };
  for (const request of [context, recheck]) {
    for (const [overrides, expected] of [
      [{}, target],
      [
        {
          draft: true,
          head: { sha: sourceSha, repo: { full_name: "contributor/invoices" } },
        },
        target,
      ],
      [{ state: "closed" }, null],
      [{ base: { ref: "release", repo: { full_name: repository } } }, null],
      [{ base: { ref: "main", repo: { full_name: "other/invoices" } } }, null],
      [{ head: { sha: mainSha } }, null],
      [{ head: { sha: "3".repeat(40) } }, null],
    ]) {
      const actual = await resolveScanTarget(request, async (number) => {
        assert.equal(number, "7");
        return pullRequest(overrides);
      });
      assert.deepEqual(actual, expected);
    }
  }
});

test("manual and scheduled baselines use the trusted workflow commit before and after approval", async () => {
  const target = { pr: 0, sha: mainSha };
  const scheduled = {
    ...context,
    eventName: "schedule",
    event: { schedule: "17 3 * * 1" },
  };
  for (const request of [
    { ...context, event: { inputs: {} } },
    scheduled,
    { ...context, target: { ...target } },
    { ...scheduled, target: { ...target } },
  ]) {
    assert.deepEqual(
      await resolveScanTarget(request, () =>
        assert.fail("unexpected API call"),
      ),
      target,
    );
  }
});

test("incomplete or invalid PR inputs fail instead of falling back to a baseline", async () => {
  for (const inputs of [
    { pr_number: "7" },
    { source_sha: sourceSha },
    { pr_number: "-1", source_sha: sourceSha },
    { pr_number: "7", source_sha: "main" },
  ]) {
    await assert.rejects(
      resolveScanTarget({ ...context, event: { inputs } }, () =>
        assert.fail("unexpected API call"),
      ),
      /require both/,
    );
  }
});

test("PR events and completed PR workflows do not queue inference or query GitHub", async () => {
  for (const trigger of [
    { eventName: "pull_request", event: { pull_request: pullRequest() } },
    {
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
  ]) {
    assert.deepEqual(
      await resolveScanTarget({ ...context, ...trigger }, () =>
        assert.fail("unexpected API call"),
      ),
      null,
      trigger.eventName,
    );
  }
});

test("resolver CLI emits the requested target without dispatching another workflow", (t) => {
  const root = mkdtempSync(join(tmpdir(), "invoice-desk-target-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const eventPath = join(root, "event.json");
  const outputPath = join(root, "output.txt");
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
  writeFileSync(eventPath, JSON.stringify(context.event));
  for (const [eventName, message, output] of [
    ["workflow_dispatch", /PR #7/, `sha=${sourceSha}\npr=7\n`],
    ["schedule", /Main baseline/, `sha=${mainSha}\npr=\n`],
    ["pull_request", /Skipped/, "sha=\npr=\n"],
  ]) {
    writeFileSync(outputPath, "");
    const result = execFileSync(
      process.execPath,
      ["--input-type=module", "--eval", script],
      {
        encoding: "utf8",
        env: {
          GITHUB_REPOSITORY: repository,
          GITHUB_SHA: mainSha,
          GITHUB_EVENT_NAME: eventName,
          GITHUB_EVENT_PATH: eventPath,
          GITHUB_OUTPUT: outputPath,
        },
      },
    );
    assert.match(result, message);
    assert.equal(readFileSync(outputPath, "utf8"), output);
  }
});

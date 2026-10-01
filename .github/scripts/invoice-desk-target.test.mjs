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

const automationContext = {
  ...context,
  eventName: "workflow_run",
  event: {
    workflow_run: {
      event: "pull_request",
      actor: { login: "github-actions[bot]" },
      conclusion: "success",
      head_sha: sourceSha,
      pull_requests: [{ number: 7 }],
    },
  },
};

test("falls back to completed behavior runs for GITHUB_TOKEN-created PRs", async () => {
  for (const conclusion of ["success", "failure"]) {
    const run = structuredClone(automationContext);
    run.event.workflow_run.conclusion = conclusion;
    assert.deepEqual(
      await resolveScanTargets(
        run,
        () => assert.fail("unexpected direct lookup"),
        async (sha) => {
          assert.equal(sha, sourceSha);
          return [
            pullRequest(),
            pullRequest({ number: 8 }),
            pullRequest({ state: "closed" }),
          ];
        },
        async (sha) => {
          assert.equal(sha, mainSha);
          return [];
        },
      ),
      [{ pr: 7, sha: sourceSha }],
    );
  }
});

test("fallback rechecks current heads and handles empty association metadata", async () => {
  const run = structuredClone(automationContext);
  run.event.workflow_run.pull_requests = [];
  const lookup = async () => [
    pullRequest(),
    pullRequest({ head: { sha: mainSha } }),
  ];
  assert.deepEqual(
    await resolveScanTargets(run, null, lookup, async () => []),
    [{ pr: 7, sha: sourceSha }],
  );
  assert.deepEqual(
    await resolveScanTargets(run, null, async () => [
      pullRequest({ state: "closed" }),
    ]),
    [],
  );
});

test("target events and cancelled runs do not queue fallback scans", async () => {
  for (const changed of [
    { event: "pull_request_target" },
    { conclusion: "cancelled" },
  ]) {
    const run = structuredClone(automationContext);
    Object.assign(run.event.workflow_run, changed);
    assert.deepEqual(
      await resolveScanTargets(run, null, () =>
        assert.fail("unexpected association lookup"),
      ),
      [],
    );
  }
});

test("approval recheck stays bound to its matrix PR even when another PR shares the commit", async () => {
  const run = { ...automationContext, target: { pr: 7, sha: sourceSha } };
  assert.deepEqual(
    await resolveScanTargets(
      run,
      async (number) => {
        assert.equal(number, "7");
        return pullRequest({ state: "closed" });
      },
      () => assert.fail("must not select another associated PR"),
    ),
    [],
  );
  assert.deepEqual(await resolveScanTargets(run, async () => pullRequest()), [
    { pr: 7, sha: sourceSha },
  ]);
});

test("fallback covers human PRs when GitHub suppresses a target event", async () => {
  const run = structuredClone(automationContext);
  run.event.workflow_run.actor.login = "contributor";
  run.event.workflow_run.head_branch = sourceSha;
  assert.deepEqual(
    await resolveScanTargets(
      run,
      null,
      async () => [pullRequest()],
      async () => [],
    ),
    [{ pr: 7, sha: sourceSha }],
  );
});

test("fallback skips only the PR and head already dispatched from the same workflow revision", async () => {
  const run = structuredClone(automationContext);
  run.event.workflow_run.pull_requests = [];
  assert.deepEqual(
    await resolveScanTargets(
      run,
      null,
      async () => [pullRequest(), pullRequest({ number: 8 })],
      async (sha) => {
        assert.equal(sha, mainSha);
        return [
          `Invoice Desk scan — PR #7 @ ${sourceSha}`,
          `Invoice Desk scan — PR #8 @ ${mainSha}`,
        ];
      },
    ),
    [{ pr: 8, sha: sourceSha }],
  );
});

test("fallback CLI dispatches a keyed run once and leaves inference to that run", (t) => {
  const root = mkdtempSync(join(tmpdir(), "invoice-desk-dispatch-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const statePath = join(root, "dispatches.json");
  const eventPath = join(root, "event.json");
  const outputPath = join(root, "output.txt");
  writeFileSync(statePath, "[]");
  writeFileSync(eventPath, JSON.stringify(automationContext.event));
  const scriptUrl = new URL("./invoice-desk-target.mjs", import.meta.url);
  const script = `
    import assert from "node:assert/strict";
    import childProcess from "node:child_process";
    import { readFileSync, writeFileSync } from "node:fs";
    import { syncBuiltinESMExports } from "node:module";
    const statePath = ${JSON.stringify(statePath)};
    const dispatches = JSON.parse(readFileSync(statePath, "utf8"));
    childProcess.execFileSync = (command, args) => {
      assert.equal(command, "gh");
      if (args[0] === "workflow") {
        assert.deepEqual(args, [
          "workflow", "run", "invoice-desk-scan.yml", "--repo", ${JSON.stringify(repository)},
          "--ref", "main", "-f", "pr_number=7", "-f", ${JSON.stringify(`source_sha=${sourceSha}`)}
        ]);
        dispatches.push(${JSON.stringify(`Invoice Desk scan — PR #7 @ ${sourceSha}`)});
        writeFileSync(statePath, JSON.stringify(dispatches));
        return "";
      }
      assert.equal(args[0], "api");
      const endpoint = args.at(-1);
      if (endpoint === ${JSON.stringify(`repos/${repository}/pulls/7`)})
        return JSON.stringify(${JSON.stringify(pullRequest())});
      if (endpoint === ${JSON.stringify(`repos/${repository}/commits/${sourceSha}/pulls?per_page=100`)})
        return JSON.stringify([[${JSON.stringify(pullRequest())}]]);
      assert.equal(endpoint, ${JSON.stringify(`repos/${repository}/actions/workflows/invoice-desk-scan.yml/runs?event=workflow_dispatch&branch=main&head_sha=${mainSha}&per_page=100`)});
      return JSON.stringify([{ workflow_runs: dispatches.map(display_title => ({ display_title })) }]);
    };
    syncBuiltinESMExports();
    process.argv[1] = ${JSON.stringify(fileURLToPath(scriptUrl))};
    await import(${JSON.stringify(scriptUrl.href)});
  `;
  const run = (eventName) =>
    execFileSync(process.execPath, ["--input-type=module", "--eval", script], {
      encoding: "utf8",
      env: {
        GITHUB_REPOSITORY: repository,
        GITHUB_SHA: mainSha,
        GITHUB_EVENT_NAME: eventName,
        GITHUB_EVENT_PATH: eventPath,
        GITHUB_OUTPUT: outputPath,
      },
    });
  assert.match(run("workflow_run"), /Queued PR #7/);
  assert.match(run("workflow_run"), /Skipped/);
  assert.deepEqual(JSON.parse(readFileSync(statePath, "utf8")), [
    `Invoice Desk scan — PR #7 @ ${sourceSha}`,
  ]);
  assert.equal(readFileSync(outputPath, "utf8"), "targets=[]\ntargets=[]\n");

  writeFileSync(eventPath, JSON.stringify(context.event));
  run("workflow_dispatch");
  assert.equal(
    readFileSync(outputPath, "utf8").trim().split("\n").at(-1),
    `targets=${JSON.stringify([{ pr: 7, sha: sourceSha }])}`,
  );
});

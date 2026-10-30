import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import {
  checkoutBase,
  confirmEdit,
  realSource,
  verifyEdit,
} from "./verify-pr-source.mjs";

const pr = {
  number: 42,
  base: { ref: "main", sha: "base", repo: { id: 1 } },
  head: { ref: "feature", sha: "head", repo: { id: 2 } },
};
const sha = "merge",
  target = { ...pr, merge_commit_sha: sha };
const passed = { status: "completed", conclusion: "success" };
function run(id, changes = {}) {
  return {
    id,
    html_url: `https://github.com/example/repo/actions/runs/${id}`,
    run_number: id,
    run_attempt: 1,
    run_started_at: id,
    updated_at: id + 1,
    event: "pull_request",
    head_sha: "head",
    pull_requests: [pr],
    referenced_workflows: [{ ref: "refs/pull/42/merge", sha }],
    display_title: "Source CI · PR #42 → main",
    ...passed,
    ...changes,
  };
}
const edit = (id, changes) =>
  run(id, { display_title: "PR edit CI · PR #42 → main", ...changes });
function evidence(id, selected = "success") {
  const names = ["ci", "classify changes"];
  const selection = {
    name: "Select required checks",
    status: "completed",
    conclusion: selected,
  };
  const jobs = names.map((name) => ({
    name,
    run_id: id,
    run_attempt: 1,
    ...passed,
    steps: [selection],
  }));
  return { total_count: jobs.length, jobs };
}
function fixture(
  history,
  {
    jobs = evidence,
    targets = [target],
    wait = false,
    runAttempt = 1,
    base = pr.base.sha,
    comparisons = [],
  } = {},
) {
  let current = [],
    live = target;
  const api = async (path) => {
    if (path.startsWith("pulls/")) {
      live = targets.shift() ?? live;
      if (live instanceof Error) throw live;
      return live;
    }
    if (path.startsWith("compare/")) {
      assert.equal(path, "compare/refs%2Fheads%2Fmain...base?per_page=1");
      const result = comparisons.shift();
      if (result instanceof Error) throw result;
      return result;
    }
    const runId = path.match(/runs\/(\d+)\/jobs/);
    if (runId) return jobs(Number(runId[1]));
    current = history.shift() ?? current;
    if (current instanceof Error) throw current;
    if (!Array.isArray(current)) return current;
    const runs = [edit(99, { run_attempt: runAttempt }), ...current];
    return { total_count: runs.length, workflow_runs: runs };
  };
  const input = { pr, sha, base, runId: 99, runAttempt, api };
  return {
    check: () => verifyEdit(input, () => wait),
    finish: (id, classifierAttempt = runAttempt) =>
      confirmEdit(input, id, classifierAttempt),
  };
}

test("the usual source and repeated metadata edits verify a single actual source job list", async () => {
  const source = run(2),
    edits = [edit(8), edit(5), source];
  const inspected = [];
  const result = await fixture([edits], {
    jobs: (id) => {
      inspected.push(id);
      return evidence(id);
    },
  }).check();
  assert.equal(result, 2);
  assert.deepEqual(inspected, [2]);
});

test("full qualification covers missing, ambiguous, ineligible and retargeted histories", async () => {
  for (const invalid of [
    { event: "workflow_dispatch" },
    { head_sha: "another" },
    { pull_requests: [] },
    { display_title: "Source CI · PR #42 → another-target" },
    { pull_requests: [{ ...pr, base: { ...pr.base, sha: "old" } }] },
    { pull_requests: [{ ...pr, head: { ...pr.head, repo: { id: 9 } } }] },
    { referenced_workflows: [] },
    { referenced_workflows: [{ ref: "refs/pull/3/merge", sha }] },
    { referenced_workflows: [{ ref: "refs/pull/42/merge", sha: "old" }] },
    { run_attempt: 2 },
    { conclusion: "cancelled" },
  ])
    assert.equal(await fixture([[run(2, invalid)]]).check(), "full");
  for (const history of [
    [],
    [run(99)],
    [run(5), run(2)],
    [run(2), edit(5, { conclusion: "failure" }), edit(8)],
    [run(2), edit(5, { conclusion: "cancelled" }), edit(8)],
    { total_count: 1, workflow_runs: [run(2)] }, // Snapshot predates this edit.
    { total_count: 2, workflow_runs: [run(2)] },
  ]) {
    assert.equal(await fixture([history]).check(), "full");
  }
});

test("only fresh canonical source jobs and genuine selection can qualify a source", () => {
  const source = run(2),
    page = evidence(2);
  assert.ok(realSource(page, source));
  for (const change of [
    { total_count: 99 },
    { total_count: 1, jobs: page.jobs.slice(1) },
    { total_count: 1, jobs: page.jobs.slice(0, 1) },
    { total_count: 3, jobs: [...page.jobs, page.jobs[0]] },
    { jobs: page.jobs.map((j) => ({ ...j, run_id: 1 })) },
    { jobs: page.jobs.map((j) => ({ ...j, run_attempt: 2 })) },
    {
      jobs: page.jobs.map((j) =>
        j.name === "ci" ? { ...j, conclusion: "failure" } : j,
      ),
    },
    evidence(2, "skipped"),
  ])
    assert.ok(!realSource({ ...page, ...change }, source));
});

test("pending sources settle, genuine red remains red, and newer attempts cannot be masked", async (t) => {
  const green = run(3),
    red = run(3, { conclusion: "failure" }),
    pending = run(3, { status: "in_progress" });
  assert.equal(await fixture([[pending], [green]], { wait: true }).check(), 3);
  assert.equal(
    await fixture([[pending], [red]], { wait: true }).check(),
    "failed",
  );
  assert.equal(await fixture([[pending]]).check(), "full");
  assert.equal(await fixture([[green], [red]]).check(), "failed");
  assert.equal(
    await fixture([[green, run(1, { run_attempt: 2 })]]).check(),
    "full",
  );
  const log = t.mock.method(console, "log", () => {});
  assert.equal(
    await fixture([[edit(8, { conclusion: "failure" }), red]]).check(),
    "failed",
  );
  assert.deepEqual(log.mock.calls[0]?.arguments, [
    `Failed source CI: ${red.html_url}/attempts/1`,
  ]);
  for (const changed of [
    [run(3, { run_attempt: 2 })],
    [run(5, { conclusion: "failure" }), green],
  ]) {
    await assert.rejects(
      fixture([changed]).finish(3),
      /source qualification changed/,
    );
  }
});

test("retrying a failed edit cannot replace its full checks with older green results", async () => {
  const retry = fixture([[run(2)]], { runAttempt: 2 });
  assert.equal(await retry.check(), "full");
  await assert.rejects(retry.finish(2, 1), /Re-run all jobs/);
  await assert.rejects(retry.finish(undefined, 1), /Re-run all jobs/);
  await assert.rejects(retry.finish(2), /source qualification changed/);
  await retry.finish();
});

test("even full fallback needs a current target when the CI gate finishes", async () => {
  const stale = { ...target, base: { ...pr.base, ref: "other" } },
    unavailable = new Error("target unavailable");
  for (const history of [
    [],
    [run(3, { status: "in_progress" })],
    new Error("history unavailable"),
  ]) {
    await assert.rejects(
      fixture([history], { targets: [target, stale] }).check(),
      /target changed/,
    );
    await assert.rejects(
      fixture([history], { targets: [target, unavailable] }).check(),
      /target unavailable/,
    );
  }
  assert.equal(
    await fixture([new Error("history unavailable")]).check(),
    "full",
  );
  await assert.rejects(
    fixture([], { targets: [stale] }).finish(),
    /target changed/,
  );
  await assert.rejects(
    fixture([], { targets: [unavailable] }).finish(),
    /target unavailable/,
  );
});

test("an edit can use a newer test-merge base only while its named branch still proves that advance", async () => {
  const base = "new-base";
  const current = { base_commit: { sha: base }, status: "behind" };
  const changed = { base_commit: { sha: "moved" }, status: "behind" };
  const check = (comparisons, history = [[run(2)]]) =>
    fixture(history, { base, comparisons });
  const updated = { ...target, base: { ...pr.base, sha: base } };
  const source = run(2, { pull_requests: [updated] });
  const caughtUp = fixture([[run(2)], [source]], {
    base,
    comparisons: [current, current, current],
    targets: [target, updated],
  });
  assert.equal(await caughtUp.check(), 2);
  await caughtUp.finish(2);
  await assert.rejects(
    fixture([[source]], {
      base,
      targets: [{ ...updated, base: { ...pr.base, sha: "unrelated" } }],
    }).finish(2),
    /target changed/,
  );
  assert.equal(await check([current, current], [[]]).check(), "full");
  for (const invalid of [
    changed,
    { ...current, status: "ahead" },
    { ...current, status: "diverged" },
    { ...current, status: "identical" },
    new Error("comparison unavailable"),
  ]) {
    const error =
      invalid instanceof Error ? /comparison unavailable/ : /Stale test merge/;
    await assert.rejects(check([invalid]).check(), error);
    await assert.rejects(check([current, invalid]).check(), error);
    await assert.rejects(check([invalid]).finish(2), error);
    await assert.rejects(check([invalid]).finish(), error);
  }
});

test("the final gate reads both actual merge parents from a depth-one checkout", (t) => {
  const root = mkdtempSync(join(tmpdir(), "ci-source-parents-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repo = join(root, "source"),
    checkout = join(root, "checkout");
  function git(cwd, ...args) {
    return execFileSync(
      "git",
      [
        "-c",
        "user.name=CI Fixture",
        "-c",
        "user.email=fixture@example.com",
        ...args,
      ],
      { cwd, encoding: "utf8", input: "" },
    ).trim();
  }
  git(root, "init", "--quiet", "-b", "main", repo);
  const tree = git(repo, "mktree"),
    base = git(repo, "commit-tree", tree, "-m", "base"),
    head = git(repo, "commit-tree", tree, "-m", "head");
  const merge = git(
    repo,
    "commit-tree",
    tree,
    "-p",
    base,
    "-p",
    head,
    "-m",
    "merge",
  );
  git(repo, "update-ref", "refs/heads/main", merge);
  git(
    root,
    "clone",
    "--quiet",
    "--depth=1",
    pathToFileURL(repo).href,
    checkout,
  );
  assert.equal(git(checkout, "rev-parse", "--is-shallow-repository"), "true");
  const pull = { base: { sha: base }, head: { sha: head } };
  assert.equal(checkoutBase(pull, merge, checkout), base);
  assert.throws(
    () => checkoutBase({ ...pull, head: { sha: base } }, merge, checkout),
    /Stale test merge/,
  );
  assert.throws(() => checkoutBase(pull, base, checkout), /Stale test merge/);
});

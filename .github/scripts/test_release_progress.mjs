import assert from "node:assert/strict";
import { test } from "node:test";
import {
  renderProgress,
  updateReleaseProgress,
  watchReleaseProgress,
} from "./release-progress.mjs";
const sha = "a".repeat(40);
const automationSha = "b".repeat(40);
const marker = "<!-- codex-security-release-progress -->";
const pull = {
  number: 42,
  title: "chore(release): 99.1.2",
  merged_at: "2026-01-01T00:00:00Z",
  base: { ref: "main" },
};

function run(id, name, extra = {}) {
  return {
    id,
    name: name === "node-github-release" ? "Publish npm-v99.1.2" : name,
    path: `.github/workflows/${name}.yml`,
    head_sha: sha,
    head_branch: name === "node-release" ? "npm-v99.1.2" : "main",
    event: name === "node-ci" ? "push" : "workflow_dispatch",
    display_title:
      name === "node-github-release" ? "Publish npm-v99.1.2" : name,
    html_url: `https://github.com/example/security-tool/actions/runs/${id}`,
    created_at: `2026-01-01T00:${String(id).padStart(2, "0")}:00Z`,
    status: "in_progress",
    conclusion: null,
    ...extra,
  };
}

function job(name, conclusion = "success") {
  return {
    name,
    status: conclusion ? "completed" : "in_progress",
    conclusion,
  };
}

function fixture() {
  const runs = new Map();
  const jobs = new Map();
  const deployments = new Map();
  const comments = [];
  const requests = [];
  const pulls = [structuredClone(pull)];
  let annotated = false;
  const github = {
    async list(path) {
      requests.push({ method: "GET", path });
      if (path === `commits/${sha}/pulls?per_page=100`) return pulls;
      if (path === "issues/42/comments?per_page=100") return comments;
      throw new Error(`Unexpected list: ${path}`);
    },
    async request(method, path, body) {
      requests.push({ method, path, body });
      if (
        method === "POST" &&
        path === "actions/workflows/release-progress.yml/dispatches"
      )
        return;
      if (method === "POST" && path === "issues/42/comments") {
        comments.push({
          id: 101,
          user: { login: "github-actions[bot]" },
          ...body,
        });
        return comments.at(-1);
      }
      if (method === "PATCH" && path === "issues/comments/101") {
        Object.assign(
          comments.find((comment) => comment.id === 101),
          body,
        );
        return comments.find((comment) => comment.id === 101);
      }
      assert.equal(method, "GET");
      if (path === "git/ref/tags/npm-v99.1.2")
        return {
          object: {
            type: annotated ? "tag" : "commit",
            sha: annotated ? "tag-object" : sha,
          },
        };
      if (path === "git/tags/tag-object") return { object: { sha } };
      const match = /^actions\/runs\/(\d+)(.*)$/u.exec(path);
      assert.ok(match, `Unexpected request: ${path}`);
      const id = Number(match[1]);
      if (!match[2]) {
        assert.ok(runs.has(id), `Missing fixture run ${id}`);
        return structuredClone(runs.get(id));
      }
      if (match[2] === "/pending_deployments") return deployments.get(id) ?? [];
      const page = /^\/jobs\?filter=latest&per_page=100&page=(\d+)$/u.exec(
        match[2],
      );
      assert.ok(page, `Unexpected request: ${path}`);
      const all = jobs.get(id) ?? [];
      const start = (Number(page[1]) - 1) * 100;
      return { total_count: all.length, jobs: all.slice(start, start + 100) };
    },
  };
  return {
    runs,
    jobs,
    deployments,
    comments,
    requests,
    pulls,
    annotate() {
      annotated = true;
    },
    update: (id) => updateReleaseProgress(github, id),
    watch: (id, wait) => watchReleaseProgress(github, id, wait),
    writes: () => requests.filter((request) => request.method !== "GET"),
    body: () => comments.find((comment) => comment.id === 101)?.body,
  };
}

test("ignores pull-request CI and unrelated or unmerged commits", async () => {
  for (const scenario of [
    "pull-request",
    "ordinary",
    "release-maintenance",
    "unmerged",
    "unassociated",
  ]) {
    const f = fixture();
    f.runs.set(1, run(1, "node-ci"));
    if (scenario === "pull-request") f.runs.get(1).event = "pull_request";
    if (scenario === "ordinary") f.pulls[0].title = "fix: improve reporting";
    if (scenario === "release-maintenance")
      f.pulls[0].title = "chore(release): improve automation";
    if (scenario === "unmerged") f.pulls[0].merged_at = null;
    if (scenario === "unassociated") f.pulls.length = 0;
    assert.equal((await f.update(1)).action, "ignored");
    assert.equal(f.writes().length, 0);
  }
});

test("accepts stable version-bump titles with breaking-change markers", async () => {
  for (const title of [
    "chore(release)!: 99.1.2",
    "release!: 99.1.2",
    "release(npm): 99.1.2",
  ]) {
    const f = fixture();
    f.pulls[0].title = title;
    f.runs.set(1, run(1, "node-ci"));
    assert.equal((await f.update(1)).action, "created");
  }
});

test("queued or cancelled duplicates cannot hide an active protected approval", async () => {
  for (const [workflow, environment, jobName] of [
    ["node-release", "npm", "verify"],
    ["node-github-release", "container", "publish matching container / source"],
  ]) {
    for (const [queuedState, queuedArrivesFirst] of [
      ["queued", false],
      ["queued", true],
      ["pending", false],
      ["pending", true],
    ]) {
      const f = fixture();
      f.runs.set(
        1,
        run(1, workflow, {
          status: environment === "npm" ? "waiting" : "in_progress",
        }),
      );
      f.runs.set(
        2,
        run(2, workflow, {
          status: queuedState,
          ...(queuedArrivesFirst
            ? { run_started_at: "2026-01-01T00:03:00Z" }
            : {}),
        }),
      );
      f.jobs.set(1, [job(jobName)]);
      f.deployments.set(1, [{ environment: { name: environment } }]);
      if (queuedArrivesFirst) await f.update(2);
      await f.update(1);
      await f.update(2);
      assert.match(
        f.body(),
        new RegExp(`Waiting for ${environment} approval`, "u"),
      );
      assert.ok(f.body().includes(`"${workflow}":1`));
      assert.ok(
        f
          .body()
          .includes(
            "[View run](https://github.com/example/security-tool/actions/runs/1)",
          ),
      );
      Object.assign(f.runs.get(2), {
        status: "completed",
        conclusion: "cancelled",
      });
      await f.update(2);
      assert.ok(f.body().includes(`"${workflow}":1`));
      Object.assign(f.runs.get(1), {
        status: "completed",
        conclusion: "success",
      });
      f.deployments.set(1, []);
      Object.assign(f.runs.get(2), { status: "in_progress", conclusion: null });
      f.jobs.set(2, [job(jobName, null)]);
      await f.update(2);
      assert.ok(f.body().includes(`"${workflow}":2`));
    }
  }
});

test("a new attempt of an older run supersedes a newer cancelled run", async () => {
  const f = fixture();
  f.runs.set(
    1,
    run(1, "node-release", { status: "completed", conclusion: "failure" }),
  );
  f.runs.set(
    2,
    run(2, "node-release", { status: "completed", conclusion: "cancelled" }),
  );
  await f.update(2);
  Object.assign(f.runs.get(1), {
    run_attempt: 2,
    run_started_at: "2026-01-01T00:03:00Z",
    status: "completed",
    conclusion: "success",
  });
  f.jobs.set(1, [job("verify"), job("publish")]);
  await f.update(1);
  assert.match(f.body(), /"node-release":1/u);
  assert.match(f.body(), /Protected npm publication \| Passed/u);
  await f.update(2);
  assert.match(f.body(), /"node-release":1/u);
});

test("successful verified recovery completes despite a failed npm retry", async () => {
  const f = fixture();
  f.runs.set(
    2,
    run(2, "node-release", { status: "completed", conclusion: "failure" }),
  );
  f.jobs.set(2, [job("verify", "failure")]);
  await f.update(2);
  f.runs.set(
    3,
    run(3, "node-github-release", {
      status: "completed",
      conclusion: "success",
    }),
  );
  f.jobs.set(3, [job("release status")]);
  await f.update(3);
  assert.match(f.body(), /## Automated release complete/u);
  assert.match(f.body(), /Release verification \| Failed/u);
});

test("completed prerequisites do not claim that later checks or Action publication passed", () => {
  const body = renderProgress(
    {
      "node-release": run(2, "node-release"),
      "node-github-release": run(3, "node-github-release"),
    },
    {
      "node-release": [job("native / bundle")],
      "node-github-release": [
        job("verify matching Action"),
        job("publish matching container / source"),
      ],
    },
    false,
  );
  assert.match(body, /Release verification \| Running/u);
  assert.match(body, /GitHub Action \| Waiting to publish/u);
  assert.match(body, /Container image \| Running/u);
});

test("observer follows protected approval through completion without workflow events", async () => {
  const f = fixture();
  f.runs.set(2, run(2, "node-release"));
  f.jobs.set(2, [job("verify", null)]);
  let waits = 0;
  await f.watch(2, async (milliseconds) => {
    assert.equal(milliseconds, 30_000);
    waits += 1;
    if (waits === 2) {
      f.jobs.set(2, [job("verify")]);
      f.deployments.set(2, [{ environment: { name: "npm" } }]);
    }
    if (waits === 4) {
      f.deployments.set(2, []);
      Object.assign(f.runs.get(2), {
        status: "completed",
        conclusion: "success",
      });
      f.jobs.set(2, [
        job("verify"),
        job("publish"),
        job("dispatch GitHub release"),
      ]);
    }
  });
  assert.equal(waits, 4);
  assert.equal(f.writes().length, 3);
  for (const request of f.writes()) {
    assert.equal(
      request.path,
      "actions/workflows/release-progress.yml/dispatches",
    );
    assert.deepEqual(request.body, {
      ref: "main",
      inputs: { "run-id": "2" },
    });
  }
  assert.equal(f.comments.length, 0);
});

test("observer refreshes final failures and ignores unrelated runs", async () => {
  const f = fixture();
  f.runs.set(3, run(3, "node-github-release"));
  await f.watch(3, async () => {
    Object.assign(f.runs.get(3), {
      status: "completed",
      conclusion: "failure",
    });
    f.jobs.set(3, [job("release status", "failure")]);
  });
  assert.equal(f.writes().length, 2);
  f.runs.set(1, run(1, "node-ci"));
  f.runs.set(4, run(4, "unrelated"));
  for (const id of [1, 4])
    await f.watch(id, () => assert.fail("must not poll"));
  assert.equal(f.writes().length, 2);
});

test("tracks protected container approval and failed reusable workflow jobs", async () => {
  const f = fixture();
  f.runs.set(3, run(3, "node-github-release"));
  f.jobs.set(3, [job("publish matching container / source")]);
  f.deployments.set(3, [{ environment: { name: "container" } }]);
  await f.update(3);
  assert.match(f.body(), /Container image \| Waiting for container approval/u);
  await f.watch(3, async () => {
    f.deployments.set(3, []);
    Object.assign(f.runs.get(3), {
      status: "completed",
      conclusion: "failure",
    });
    f.jobs.set(3, [
      job("publish matching container / source"),
      job("publish matching container / publish-linux-amd64", "failure"),
      job("release status", "failure"),
    ]);
  });
  await f.update(3);
  assert.match(f.body(), /Container image \| Failed/u);
  assert.match(f.body(), /Final release status \| Failed/u);
  assert.doesNotMatch(f.body(), /## Automated release complete/u);
});

test("keeps one comment across CI, verification, and protected approval", async () => {
  const f = fixture();
  f.runs.set(1, run(1, "node-ci"));
  assert.equal((await f.update(1)).action, "created");
  f.runs.get(1).status = "completed";
  f.runs.get(1).conclusion = "success";
  f.runs.set(2, run(2, "node-release", { status: "waiting" }));
  f.jobs.set(2, [
    job("native / bundle"),
    job("verify"),
    ...[1, 2, 3, "mcp"].map((suite) => job(`release tests / ${suite}`)),
  ]);
  f.deployments.set(2, [{ environment: { name: "npm" } }]);
  assert.equal((await f.update(2)).action, "updated");
  assert.equal(f.comments.length, 1);
  assert.match(f.body(), /Post-merge CI \| Passed/u);
  assert.match(f.body(), /Release verification \| Passed/u);
  assert.match(
    f.body(),
    /Protected npm publication \| Waiting for npm approval/u,
  );
  assert.match(f.body(), /runs\/2/u);
  assert.deepEqual(
    f.writes().map((request) => request.method),
    ["POST", "PATCH"],
  );
  assert.equal((await f.update(2)).action, "unchanged");
  assert.equal(f.writes().length, 2);
});

test("workflow results remain visible when no jobs start or every job is skipped", async () => {
  for (const [workflow, stage, firstJob] of [
    ["node-release", "npm release status", "verify"],
    [
      "node-github-release",
      "Final release status",
      "publish verified GitHub release",
    ],
  ]) {
    for (const skipped of [false, true]) {
      for (const [conclusion, label] of [
        ["cancelled", "Cancelled"],
        ["failure", "Failed"],
        ["timed_out", "Timed out"],
        ["startup_failure", "startup_failure"],
      ]) {
        const f = fixture();
        f.runs.set(1, run(1, workflow));
        f.jobs.set(
          1,
          skipped
            ? [
                job(firstJob, "skipped"),
                ...(workflow === "node-github-release"
                  ? [job("release status", "skipped")]
                  : []),
              ]
            : [],
        );
        let waits = 0;
        await f.watch(1, async () => {
          waits += 1;
          Object.assign(f.runs.get(1), { status: "completed", conclusion });
        });
        assert.equal(waits, 1);
        assert.equal(
          f.requests.filter(({ path }) => path.endsWith("/dispatches")).length,
          2,
        );
        await f.update(1);
        assert.ok(f.body().includes(`| ${stage} | ${label} |`));
        assert.doesNotMatch(f.body(), /Automated release complete/u);
      }
    }
  }
});

test("reports failed shards and cancelled publication without declaring completion", async () => {
  for (const conclusion of ["failure", "cancelled"]) {
    const f = fixture();
    f.runs.set(2, run(2, "node-release", { status: "completed", conclusion }));
    f.jobs.set(2, [
      job("verify"),
      job("release tests / 2", conclusion),
      job("publish", "skipped"),
    ]);
    await f.update(2);
    assert.match(f.body(), conclusion === "failure" ? /Failed/u : /Cancelled/u);
    assert.doesNotMatch(f.body(), /## Automated release complete/u);
  }
});

test("reports a failed handoff after npm publication succeeds", async () => {
  for (const conclusion of ["failure", "cancelled"]) {
    const f = fixture();
    f.runs.set(2, run(2, "node-release", { status: "completed", conclusion }));
    f.jobs.set(2, [
      job("verify"),
      job("publish"),
      job("dispatch GitHub release", conclusion),
    ]);
    await f.update(2);
    assert.match(f.body(), /Protected npm publication \| Passed/u);
    assert.match(
      f.body(),
      conclusion === "failure"
        ? /Start GitHub publication \| Failed/u
        : /Start GitHub publication \| Cancelled/u,
    );
    assert.doesNotMatch(f.body(), /## Automated release complete/u);
  }
});

test("Action verification failures take precedence over skipped publication", async () => {
  const f = fixture();
  f.runs.set(
    3,
    run(3, "node-github-release", {
      status: "completed",
      conclusion: "failure",
    }),
  );
  f.jobs.set(3, [
    job("verify matching Action", "failure"),
    job("publish matching Action", "skipped"),
    job("release status", "failure"),
  ]);
  await f.update(3);
  assert.match(f.body(), /GitHub Action \| Failed/u);
  assert.doesNotMatch(f.body(), /GitHub Action \| Skipped/u);
});

test("resolves GitHub publication to the release tag, including annotated tags", async () => {
  for (const annotated of [false, true]) {
    const f = fixture();
    if (annotated) f.annotate();
    f.runs.set(
      3,
      run(3, "node-github-release", {
        head_sha: automationSha,
        status: "completed",
        conclusion: "success",
      }),
    );
    f.jobs.set(3, [
      job("publish verified GitHub release"),
      job("verify published installation / linux"),
      job("verify matching Action"),
      job("publish matching Action"),
      job("release status"),
    ]);
    await f.update(3);
    assert.match(f.body(), /## Automated release complete/u);
    assert.match(f.body(), /Post-merge CI \| Not recorded/u);
    assert.match(f.body(), /Release verification \| Not recorded/u);
    assert.match(f.body(), /Protected npm publication \| Not recorded/u);
    assert.match(f.body(), /GitHub Action \| Passed/u);
    assert.ok(
      f.requests.some(
        (request) => request.path === `commits/${sha}/pulls?per_page=100`,
      ),
    );
    assert.ok(
      !f.requests.some((request) =>
        request.path.includes(`commits/${automationSha}`),
      ),
    );
  }
});

test("shows partial publication failures and installation failures beyond the first page", async () => {
  const f = fixture();
  f.runs.set(
    3,
    run(3, "node-github-release", {
      status: "completed",
      conclusion: "failure",
    }),
  );
  f.jobs.set(3, [
    job("publish verified GitHub release"),
    ...Array.from({ length: 100 }, (_, i) =>
      job(`verify published installation / ${i}`),
    ),
    job("verify published installation / windows", "failure"),
    job("publish matching Action", "skipped"),
    job("release status", "failure"),
  ]);
  await f.update(3);
  assert.match(f.body(), /Public npm package and provenance \| Passed/u);
  assert.match(f.body(), /Published installation checks \| Failed/u);
  assert.match(f.body(), /GitHub Action \| Skipped/u);
  assert.doesNotMatch(f.body(), /## Automated release complete/u);
});

test("late events cannot replace a newer run and reruns refresh the latest attempt", async () => {
  const f = fixture();
  f.runs.set(
    1,
    run(1, "node-ci", { status: "completed", conclusion: "failure" }),
  );
  f.runs.set(
    2,
    run(2, "node-ci", { status: "completed", conclusion: "success" }),
  );
  await f.update(2);
  await f.update(1);
  assert.match(f.body(), /Post-merge CI \| Passed/u);
  assert.match(f.body(), /"node-ci":2/u);
  f.runs.get(2).status = "in_progress";
  f.runs.get(2).conclusion = null;
  await f.update(2);
  assert.match(f.body(), /Post-merge CI \| Running/u);
});

test("does not overwrite human comments containing the marker", async () => {
  const f = fixture();
  const human = {
    id: 99,
    user: { login: "maintainer" },
    body: `${marker}\nMy notes`,
  };
  f.comments.push(human);
  f.runs.set(1, run(1, "node-ci"));
  await f.update(1);
  assert.equal(f.comments.length, 2);
  assert.equal(human.body, `${marker}\nMy notes`);
});

test("rejects workflow lookalikes and publication runs outside main or stable tags", async () => {
  for (const input of [
    run(1, "node-ci", { path: ".github/workflows/unrelated.yml" }),
    run(2, "node-release", { event: "pull_request", head_branch: "feature" }),
    run(2, "node-release", { head_branch: "main" }),
    run(3, "node-github-release", { head_branch: "feature" }),
    run(3, "node-github-release", { display_title: "Publish arbitrary-ref" }),
  ]) {
    const f = fixture();
    f.runs.set(input.id, input);
    assert.equal((await f.update(input.id)).action, "ignored");
    assert.equal(f.writes().length, 0);
  }
});

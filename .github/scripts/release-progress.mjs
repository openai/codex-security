import { appendFile } from "node:fs/promises";
import { setTimeout } from "node:timers/promises";
import {
  createGitHubClient,
  createGitRepository,
  readVersionHistory,
} from "../../sdk/typescript/scripts/release-pr.mjs";
import { isMain } from "../../sdk/typescript/scripts/is-main.mjs";

const marker = "<!-- codex-security-release-progress -->";
const workflows = ["node-ci", "node-release", "node-github-release"];
const npmDeploymentJobs = {
  "Publish npm and container images": {
    stage: "Release approval and npm publication",
    prompt:
      "Approve the **npm** deployment to publish the npm package and its matching container images.",
  },
  "Verify existing npm release": {
    stage: "Existing npm release verification",
    prompt:
      "Approve the **npm** deployment to verify the existing npm package and its signed provenance.",
  },
  publish: {
    stage: "Protected npm publication",
    prompt:
      "Approve the protected **npm** deployment in the linked release run.",
  },
};

function status(value) {
  if (!value) return "Not started";
  const current = value.conclusion ?? value.status;
  return (
    {
      success: "Passed",
      failure: "Failed",
      cancelled: "Cancelled",
      timed_out: "Timed out",
      action_required: "Needs attention",
      skipped: "Skipped",
      neutral: "Neutral",
      waiting: "Waiting for approval",
      queued: "Queued",
      pending: "Queued",
      requested: "Queued",
      in_progress: "Running",
    }[current] ?? current
  );
}

function jobStatus(jobs, run) {
  const failed = jobs.find((job) =>
    ["failure", "cancelled", "timed_out", "action_required"].includes(
      job.conclusion,
    ),
  );
  if (failed) return status(failed);
  if (jobs.length === 0)
    return run?.status === "completed" ? "Not reached" : "Not started";
  const unfinished = jobs.find((job) => job.status !== "completed");
  if (unfinished) return status(unfinished);
  return jobs.every((job) => job.conclusion === "skipped")
    ? "Skipped"
    : "Passed";
}

export function renderProgress(
  runs,
  jobs,
  awaitingApproval,
  awaitingContainerApproval = false,
) {
  const ci = runs["node-ci"];
  const npm = runs["node-release"];
  const github = runs["node-github-release"];
  const npmJobs = jobs["node-release"] ?? [];
  const githubJobs = jobs["node-github-release"] ?? [];
  const row = (name, state, run, unrecorded = false) =>
    `| ${name} | ${unrecorded ? "Not recorded" : state} | ${run ? `[View run](${run.html_url})` : "—"} |`;
  const verification = npmJobs.filter(
    (job) =>
      job.name === "verify" ||
      job.name.startsWith("native /") ||
      job.name.startsWith("release tests /"),
  );
  const npmDeploymentJob = npmJobs.find((job) =>
    Object.hasOwn(npmDeploymentJobs, job.name),
  );
  const npmDeployment = npmDeploymentJobs[npmDeploymentJob?.name] ?? {
    stage: "npm deployment",
    prompt:
      "Open the linked release run to see what the waiting job will do before approving the **npm** deployment.",
  };
  const verified = jobStatus(verification, npm);
  const actionPublisher = githubJobs.find(
    (job) => job.name === "publish matching Action",
  );
  const actionVerifier = githubJobs.find(
    (job) => job.name === "verify matching Action",
  );
  const containerJobs = githubJobs.filter(
    (job) =>
      job.name === "publish matching container" ||
      job.name.startsWith("publish matching container /"),
  );
  const containerState = jobStatus(containerJobs, github);
  const containerJob = (name) =>
    containerJobs.find(
      (job) => job.name === `publish matching container / ${name}`,
    );
  const containerVerification = containerJob(
    "verify required container publications",
  );
  // Historical runs skipped promotion after verifying an existing image.
  const containerFinished =
    github?.conclusion === "success" ||
    (containerVerification
      ? containerVerification.conclusion === "success"
      : github?.status === "completed" &&
        containerJob("source")?.conclusion === "success" &&
        containerJob("promote-verified-and-attested-release")?.status ===
          "completed");
  const complete = github?.conclusion === "success";
  return [
    marker,
    `<!-- release-progress-runs: ${JSON.stringify(
      Object.fromEntries(
        Object.entries(runs).map(([name, run]) => [name, run.id]),
      ),
    )} -->`,
    complete ? "## Automated release complete" : "## Release progress",
    "",
    "| Stage | Status | Details |",
    "| --- | --- | --- |",
    row("Post-merge CI", status(ci), ci, !ci && Boolean(npm || github)),
    row("npm release status", status(npm), npm, !npm && Boolean(github)),
    row(
      "Release verification",
      verified === "Passed" && !npmDeploymentJob && !awaitingApproval
        ? status(npm)
        : verified,
      npm,
      !npm && Boolean(github),
    ),
    row(
      npmDeployment.stage,
      awaitingApproval ? "Waiting for npm approval" : status(npmDeploymentJob),
      npm,
      !npm && Boolean(github),
    ),
    row(
      "Start GitHub publication",
      status(npmJobs.find((job) => job.name === "dispatch GitHub release")),
      npm,
      !npm && Boolean(github),
    ),
    row(
      "Public npm package and provenance",
      jobStatus(
        githubJobs.filter(
          (job) => job.name === "publish verified GitHub release",
        ),
        github,
      ),
      github,
    ),
    row(
      "Published installation checks",
      jobStatus(
        githubJobs.filter((job) =>
          job.name.startsWith("verify published installation /"),
        ),
        github,
      ),
      github,
    ),
    row(
      "GitHub Action",
      actionVerifier?.conclusion &&
        !["success", "skipped"].includes(actionVerifier.conclusion)
        ? status(actionVerifier)
        : actionPublisher
          ? status(actionPublisher)
          : actionVerifier?.conclusion === "success"
            ? github.status === "completed"
              ? "Not reached"
              : "Waiting to publish"
            : status(actionVerifier),
      github,
    ),
    row(
      "Container image",
      awaitingContainerApproval
        ? "Waiting for container approval"
        : containerState === "Passed" && !containerFinished
          ? github?.status === "completed"
            ? "Not reached"
            : "Running"
          : containerState,
      github,
    ),
    row(
      "Final release status",
      status(
        github?.status === "completed"
          ? github
          : (githubJobs.find((job) => job.name === "release status") ?? github),
      ),
      github,
    ),
    "",
    awaitingApproval
      ? npmDeployment.prompt
      : awaitingContainerApproval
        ? "Approve the protected **container** deployment in the linked release run."
        : "Progress updates do not change publication approvals or verification requirements.",
    "GitHub Marketplace publication is a separate manual step.",
  ].join("\n");
}

function workflowName(run) {
  const path = run.path?.split("@", 1)[0];
  return workflows.find((name) => path === `.github/workflows/${name}.yml`);
}

async function releaseCommit(github, run) {
  const name = workflowName(run);
  if (!name) return null;
  if (name === "node-ci") {
    return run.event === "push" && run.head_branch === "main"
      ? run.head_sha
      : null;
  }
  if (name === "node-release")
    return ["push", "workflow_dispatch"].includes(run.event) &&
      /^npm-v\d+\.\d+\.\d+$/u.test(run.head_branch)
      ? run.head_sha
      : null;
  if (run.event !== "workflow_dispatch" || run.head_branch !== "main")
    return null;
  const tag = /^Publish (npm-v\d+\.\d+\.\d+)$/u.exec(run.display_title)?.[1];
  if (!tag) return null;
  const ref = await github.request("GET", `git/ref/tags/${tag}`);
  return ref.object.type === "tag"
    ? (await github.request("GET", `git/tags/${ref.object.sha}`)).object.sha
    : ref.object.sha;
}

async function runJobs(github, id) {
  const jobs = [];
  for (let page = 1; ; page += 1) {
    const result = await github.request(
      "GET",
      `actions/runs/${id}/jobs?filter=latest&per_page=100&page=${page}`,
    );
    jobs.push(...result.jobs);
    if (jobs.length >= result.total_count) return jobs;
  }
}

async function awaitingEnvironment(github, run, environment) {
  if (!run || run.status === "completed") return false;
  const deployments = await github.request(
    "GET",
    `actions/runs/${run.id}/pending_deployments`,
  );
  return deployments.some(
    (deployment) => deployment.environment.name === environment,
  );
}

export async function updateReleaseProgress(
  github,
  runId,
  repo = createGitRepository(process.cwd()),
) {
  const incoming = await github.request("GET", `actions/runs/${runId}`);
  const sha = await releaseCommit(github, incoming);
  if (!sha) return { action: "ignored" };
  const name = workflowName(incoming);
  const version = (
    name === "node-release" ? incoming.head_branch : incoming.display_title
  )?.match(/npm-v(\d+\.\d+\.\d+)$/u)?.[1];
  const findPull = async (commit) => {
    const pulls = await github.list(`commits/${commit}/pulls?per_page=100`);
    // The commit endpoint supplies the association; API 2026-03-10 omits merge_commit_sha.
    return pulls.find((candidate) => {
      const candidateVersion =
        /^(?:chore\(release\)|release(?:\([^)]+\))?)!?: (\d+\.\d+\.\d+)$/u.exec(
          candidate.title,
        )?.[1];
      return (
        candidate.merged_at &&
        candidate.base.ref === "main" &&
        candidateVersion &&
        (!version || candidateVersion === version)
      );
    });
  };
  let pull = await findPull(sha);
  if (!pull && name !== "node-ci") {
    // A successful follow-up fix can be tagged after the version bump fails CI.
    const { baseVersion, baseCommit } = readVersionHistory(repo, sha);
    if (baseVersion === version && baseCommit !== sha)
      pull = await findPull(baseCommit);
  }
  if (!pull) return { action: "ignored" };
  const comments = await github.list(
    `issues/${pull.number}/comments?per_page=100`,
  );
  const previous = comments.find(
    (comment) =>
      comment.user?.login === "github-actions[bot]" &&
      comment.body?.startsWith(marker),
  );
  const saved = previous?.body.match(
    /<!-- release-progress-runs: (.+) -->/u,
  )?.[1];
  const ids = saved ? JSON.parse(saved) : {};
  const runs = {};
  for (const name of workflows) {
    if (!ids[name]) continue;
    try {
      runs[name] = await github.request("GET", `actions/runs/${ids[name]}`);
    } catch (error) {
      if (error.status !== 404) throw error;
    }
  }
  if (name === "node-ci") {
    const releasedSha =
      runs["node-release"]?.head_sha ??
      (runs["node-github-release"] &&
        (await releaseCommit(github, runs["node-github-release"])));
    if (releasedSha && releasedSha !== sha) return { action: "ignored" };
  }
  // A recovered release uses the tagged fix, not the original failed bump CI.
  if (name !== "node-ci" && runs["node-ci"]?.head_sha !== sha)
    delete runs["node-ci"];
  const last = runs[name];
  // Serialized release runs keep their active approval ahead of queued duplicates.
  const prioritizeActive = name !== "node-ci" && incoming.id !== last?.id;
  const active = (run) =>
    prioritizeActive && ["in_progress", "waiting"].includes(run?.status);
  if (
    !last ||
    (active(incoming) && !active(last)) ||
    (active(incoming) === active(last) &&
      ((incoming.run_started_at ?? incoming.created_at) >
        (last.run_started_at ?? last.created_at) ||
        ((incoming.run_started_at ?? incoming.created_at) ===
          (last.run_started_at ?? last.created_at) &&
          incoming.id >= last.id)))
  )
    runs[name] = incoming;
  const jobs = Object.fromEntries(
    await Promise.all(
      Object.entries(runs).map(async ([name, run]) => [
        name,
        await runJobs(github, run.id),
      ]),
    ),
  );
  const [awaitingNpm, awaitingContainer] = await Promise.all([
    awaitingEnvironment(github, runs["node-release"], "npm"),
    awaitingEnvironment(github, runs["node-github-release"], "container"),
  ]);
  const body = renderProgress(runs, jobs, awaitingNpm, awaitingContainer);
  if (previous?.body === body)
    return { action: "unchanged", pull: pull.number };
  await github.request(
    previous ? "PATCH" : "POST",
    previous
      ? `issues/comments/${previous.id}`
      : `issues/${pull.number}/comments`,
    { body },
  );
  return { action: previous ? "updated" : "created", pull: pull.number };
}

export async function watchReleaseProgress(github, runId, wait = setTimeout) {
  let previous;
  for (;;) {
    const run = await github.request("GET", `actions/runs/${runId}`);
    const name = workflowName(run);
    if (name === "node-ci" || !(await releaseCommit(github, run))) return;
    const jobs = await runJobs(github, run.id);
    const awaitingApproval = await awaitingEnvironment(
      github,
      run,
      name === "node-release" ? "npm" : "container",
    );
    const current = renderProgress(
      { [name]: run },
      { [name]: jobs },
      name === "node-release" && awaitingApproval,
      name === "node-github-release" && awaitingApproval,
    );
    if (current !== previous) {
      await github.request(
        "POST",
        "actions/workflows/release-progress.yml/dispatches",
        {
          ref: "main",
          inputs: { "run-id": String(run.id) },
        },
      );
    }
    if (run.status === "completed") return;
    previous = current;
    await wait(30_000);
  }
}

if (isMain(import.meta.url)) {
  const github = createGitHubClient(
    process.env.GITHUB_REPOSITORY,
    process.env.GH_TOKEN,
  );
  if (process.env.RELEASE_PROGRESS_WATCH === "true") {
    await watchReleaseProgress(github, process.env.RELEASE_RUN_ID);
  } else {
    const result = await updateReleaseProgress(
      github,
      process.env.RELEASE_RUN_ID,
    );
    console.log(JSON.stringify(result));
    if (result.pull && process.env.GITHUB_OUTPUT) {
      await appendFile(process.env.GITHUB_OUTPUT, `pull=${result.pull}\n`);
    }
  }
}

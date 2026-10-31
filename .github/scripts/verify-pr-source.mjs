import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";

const utf8 = { encoding: "utf8" };
const successful = (job) =>
  job.status === "completed" && job.conclusion === "success";

function samePull(candidate, pr, base) {
  return (
    candidate?.number === pr.number &&
    candidate.head?.sha === pr.head.sha &&
    [pr.base.sha, base].includes(candidate.base?.sha) &&
    ["head", "base"].every(
      (side) =>
        candidate[side]?.ref === pr[side].ref &&
        candidate[side].repo?.id === pr[side].repo.id,
    )
  );
}

export function checkoutBase(pr, sha, cwd) {
  // A depth-one checkout still contains the raw commit and its parent IDs.
  const [object, ...headers] = execFileSync("git", ["cat-file", "--batch"], {
    cwd,
    input: "HEAD\n",
    encoding: "utf8",
  })
    .split("\n\n", 1)[0]
    .split("\n");
  const parents = headers
    .filter((line) => line.startsWith("parent "))
    .map((line) => line.slice(7));
  if (
    !object.startsWith(`${sha} commit `) ||
    parents.length !== 2 ||
    parents[1] !== pr.head.sha
  )
    throw new Error(
      `Stale test merge. Expected ${sha} with head ${pr.head.sha}, checked out ${object} with parents ${parents.join(" ")}. Start a fresh pull request event.`,
    );
  return parents[0];
}

async function confirmTarget({ pr, sha, base, api }) {
  const live = await api(`pulls/${pr.number}`);
  if (!samePull(live, pr, base) || live.merge_commit_sha !== sha)
    throw new Error(
      "The pull request target changed while its checks were running.",
    );
  if (base !== pr.base.sha) {
    // PR metadata can lag its test merge. Compare the named branch itself, including its ancestry.
    const ref = encodeURIComponent(`refs/heads/${pr.base.ref}`);
    const comparison = await api(`compare/${ref}...${pr.base.sha}?per_page=1`);
    if (comparison.base_commit.sha !== base || comparison.status !== "behind")
      throw new Error(
        `Stale test merge. Checked out base ${base}, but ${pr.base.ref} is at ${comparison.base_commit.sha} and event base ${pr.base.sha} is ${comparison.status}. Reopen the pull request or push a commit after its merge ref updates.`,
      );
  }
}

export function realSource(page, run) {
  const required = ["ci", "classify changes"];
  const jobs = page.jobs.filter((job) => required.includes(job.name));
  if (
    page.total_count !== page.jobs.length ||
    jobs.length !== required.length ||
    new Set(jobs.map((j) => j.name)).size !== required.length ||
    !jobs.every(
      (job) =>
        job.run_id === run.id && job.run_attempt === 1 && successful(job),
    )
  )
    return false;
  return jobs
    .find((job) => job.name === "classify changes")
    .steps.some(
      (step) => step.name === "Select required checks" && successful(step),
    );
}

function sourceCandidate(runs, { pr, sha, base }) {
  const target = `PR #${pr.number} → ${pr.base.ref}`;
  const source = `Source CI · ${target}`;
  const edit = `PR edit CI · ${target}`;
  function identified(run) {
    const refs = run.referenced_workflows;
    return (
      run.event === "pull_request" &&
      run.head_sha === pr.head.sha &&
      run.run_attempt === 1 &&
      run.pull_requests.some((p) => samePull(p, pr, base)) &&
      refs?.length &&
      refs.every(
        (ref) => ref.sha === sha && ref.ref === `refs/pull/${pr.number}/merge`,
      ) &&
      [source, edit].includes(run.display_title)
    );
  }
  if (!runs.length || !runs.every(identified)) return "full";
  const [first, ...later] = runs; // Oldest first.
  if (
    first.display_title !== source ||
    later.some((r) => r.display_title !== edit)
  )
    return "full";
  if (runs.some((r) => r.status !== "completed")) return "pending";
  if (runs.every(successful)) return first;
  if (runs.every((r) => r.conclusion === "failure")) {
    console.log(`Failed source CI: ${first.html_url}/attempts/1`);
    return "failed";
  }
  return "full";
}

async function verifyHistory(input, wait) {
  // A retry keeps the ID of its potentially failed previous qualification.
  if (input.runAttempt !== 1) return "full";
  const { pr, runId, api } = input;
  async function candidate() {
    const page = await api(
      `actions/workflows/node-ci.yml/runs?event=pull_request&head_sha=${pr.head.sha}&per_page=100`,
    );
    if (
      page.total_count !== page.workflow_runs.length ||
      !page.workflow_runs.some(
        (run) => run.id === runId && run.run_attempt === 1,
      )
    )
      return "full";
    // A head may belong to several PRs. Keep unassociated runs so ambiguous histories go full.
    const runs = page.workflow_runs.filter(
      (run) =>
        run.id !== runId &&
        (!run.pull_requests.length ||
          run.pull_requests.some((p) => p.number === pr.number)),
    );
    return sourceCandidate(
      runs.sort((a, b) => a.run_number - b.run_number),
      input,
    );
  }
  let source = await candidate();
  while (source === "pending" && wait && (await wait()))
    source = await candidate();
  if (typeof source === "string") return source === "pending" ? "full" : source;
  const page = await api(
    `actions/runs/${source.id}/jobs?filter=latest&per_page=100`,
  );
  if (!realSource(page, source)) return "full";
  const latest = await candidate();
  if (latest === "failed") return "failed";
  return latest.id === source.id ? source.id : "full";
}

export async function verifyEdit(input, wait) {
  await confirmTarget(input);
  let result;
  try {
    result = await verifyHistory(input, wait);
  } catch (error) {
    console.log(
      `Source evidence unavailable. Running full qualification. ${error.message}`,
    );
    result = "full";
  }
  // A history failure can select full CI only while the originating PR target is still current.
  await confirmTarget(input);
  return result;
}

export async function confirmEdit(input, expectedId, classifierAttempt) {
  if (input.runAttempt !== classifierAttempt)
    throw new Error("Re-run all jobs to qualify this pull request edit.");
  if (expectedId && (await verifyHistory(input)) !== expectedId)
    throw new Error(
      "The selected source qualification changed before the CI gate finished.",
    );
  await confirmTarget(input);
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const env = process.env;
  const { pull_request: pr } = JSON.parse(
    readFileSync(env.GITHUB_EVENT_PATH, "utf8"),
  );
  const sha = env.GITHUB_SHA;
  function api(path) {
    const endpoint = `repos/${env.GITHUB_REPOSITORY}/${path}`;
    return JSON.parse(execFileSync("gh", ["api", endpoint], utf8));
  }
  const input = {
    pr,
    sha,
    base: checkoutBase(pr, sha),
    runId: Number(env.GITHUB_RUN_ID),
    runAttempt: Number(env.GITHUB_RUN_ATTEMPT),
    api,
  };
  if (process.argv[2] === "confirm-target")
    await confirmEdit(
      input,
      Number(env.VERIFIED_SOURCE_RUN),
      Number(env.CLASSIFIER_ATTEMPT),
    );
  else {
    // Leave five minutes of the 40-minute classifier budget for ordinary full selection.
    const deadline = Date.now() + 35 * 60_000;
    const result = await verifyEdit(input, async () => {
      if (Date.now() >= deadline) return false;
      await sleep(30_000);
      return true;
    });
    console.log(`Source qualification: ${result}`);
    appendFileSync(env.GITHUB_OUTPUT, `edit-attempt=${input.runAttempt}\n`);
    if (result === "failed") process.exitCode = 1;
    if (typeof result === "number")
      appendFileSync(env.GITHUB_OUTPUT, `source-run=${result}\n`);
  }
}

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

function eligible(pr, repository, sha) {
  return (
    pr.state === "open" &&
    pr.base.repo.full_name === repository &&
    pr.base.ref === "main" &&
    pr.head.sha === sha
  );
}

export async function resolveScanTargets(
  context,
  getPullRequest,
  pullRequestsForCommit,
) {
  const { eventName, event, repository, sha, target } = context;
  // After approval, recheck this matrix entry rather than other PRs on the same commit.
  if (target) {
    if (target.pr === 0) return [{ pr: 0, sha }];
    const pr = await getPullRequest(String(target.pr));
    return eligible(pr, repository, target.sha)
      ? [{ pr: pr.number, sha: target.sha }]
      : [];
  }
  if (eventName === "workflow_run") {
    const run = event.workflow_run;
    if (
      run.event !== "pull_request" ||
      run.actor.login !== "github-actions[bot]" ||
      run.conclusion === "cancelled"
    )
      return [];
    // GITHUB_TOKEN-created PRs do not emit pull_request_target events.
    const requests = await pullRequestsForCommit(run.head_sha);
    const numbers = new Set(run.pull_requests.map((pr) => pr.number));
    return requests
      .filter(
        (pr) =>
          eligible(pr, repository, run.head_sha) &&
          (numbers.size === 0 || numbers.has(pr.number)),
      )
      .map((pr) => ({ pr: pr.number, sha: pr.head.sha }));
  }
  if (eventName !== "workflow_dispatch") return [];
  const { pr_number: number = "", source_sha: sourceSha = "" } =
    event.inputs ?? {};
  if (!number && !sourceSha) return [{ pr: 0, sha }];
  if (!/^[1-9][0-9]*$/.test(number) || !/^[a-f0-9]{40}$/.test(sourceSha)) {
    throw new Error(
      "PR scans require both a positive pr_number and a full source_sha.",
    );
  }

  const pr = await getPullRequest(number);
  if (!eligible(pr, repository, sourceSha)) return [];
  return [{ pr: pr.number, sha: sourceSha }];
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const repository = process.env.GITHUB_REPOSITORY;
  const targets = await resolveScanTargets(
    {
      eventName: process.env.GITHUB_EVENT_NAME,
      event: JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, "utf8")),
      repository,
      sha: process.env.GITHUB_SHA,
      target:
        process.env.PR_NUMBER === undefined
          ? undefined
          : {
              pr: Number(process.env.PR_NUMBER),
              sha: process.env.SOURCE_SHA,
            },
    },
    (number) =>
      JSON.parse(
        execFileSync("gh", ["api", `repos/${repository}/pulls/${number}`], {
          encoding: "utf8",
        }),
      ),
    (sha) =>
      JSON.parse(
        execFileSync(
          "gh",
          [
            "api",
            "--paginate",
            "--slurp",
            `repos/${repository}/commits/${sha}/pulls?per_page=100`,
          ],
          { encoding: "utf8" },
        ),
      ).flat(),
  );
  appendFileSync(
    process.env.GITHUB_OUTPUT,
    `targets=${JSON.stringify(targets)}\n`,
  );
  const message =
    targets.length === 0
      ? "Skipped: the PR is closed, targets another branch, or has a newer head."
      : targets
          .map(
            ({ pr, sha }) => `${pr ? `PR #${pr}` : "Main baseline"} at ${sha}`,
          )
          .join("\n");
  console.log(message);
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, message + "\n");
  }
}

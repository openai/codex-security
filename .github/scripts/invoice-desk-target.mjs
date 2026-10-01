import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export async function resolveScanTargets(context, pullRequestsForCommit) {
  const { eventName, event, repository, sha } = context;
  if (eventName === "workflow_dispatch") return [{ pr: 0, sha }];
  if (eventName !== "workflow_run") return [];

  const run = event.workflow_run;
  if (run.event !== "pull_request" || run.conclusion === "cancelled") return [];

  // Fork runs can have an empty pull_requests list; resolve it through GitHub.
  const pullRequests = await pullRequestsForCommit(run.head_sha);
  const triggeringNumbers = new Set(run.pull_requests.map((pr) => pr.number));
  return pullRequests
    .filter(
      (pr) =>
        pr.state === "open" &&
        pr.base.repo.full_name === repository &&
        pr.base.ref === "main" &&
        pr.head.sha === run.head_sha &&
        (triggeringNumbers.size === 0 || triggeringNumbers.has(pr.number)),
    )
    .map((pr) => ({ pr: pr.number, sha: pr.head.sha }));
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
    },
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
  console.log(
    targets.length === 0
      ? "No current pull request targeting main needs this scan."
      : targets
          .map(
            ({ pr, sha }) => `${pr ? `PR #${pr}` : "Main baseline"} at ${sha}`,
          )
          .join("\n"),
  );
}

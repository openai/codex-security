import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export async function resolveScanTargets(context, getPullRequest) {
  const { eventName, event, repository, sha } = context;
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
  if (
    pr.state !== "open" ||
    pr.base.repo.full_name !== repository ||
    pr.base.ref !== "main" ||
    pr.head.sha !== sourceSha
  )
    return [];
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
    },
    (number) =>
      JSON.parse(
        execFileSync("gh", ["api", `repos/${repository}/pulls/${number}`], {
          encoding: "utf8",
        }),
      ),
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

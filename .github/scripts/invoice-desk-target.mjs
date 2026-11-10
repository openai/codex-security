import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { isMain } from "../../sdk/typescript/scripts/is-main.mjs";

function eligible(pr, repository, sha) {
  return (
    pr.state === "open" &&
    pr.base.repo.full_name === repository &&
    pr.base.ref === "main" &&
    pr.head.sha === sha
  );
}

export async function resolveScanTarget(context, getPullRequest) {
  const { eventName, event, repository, sha } = context;
  // After approval, recheck the same PR and revision selected by the target job.
  let target = context.target;
  if (!target) {
    if (eventName === "schedule") return { pr: 0, sha };
    if (eventName !== "workflow_dispatch") return null;
    const { pr_number: number = "", source_sha: sourceSha = "" } =
      event.inputs ?? {};
    if (!number && !sourceSha) return { pr: 0, sha };
    if (!/^[1-9][0-9]*$/.test(number) || !/^[a-f0-9]{40}$/.test(sourceSha)) {
      throw new Error(
        "PR scans require both a positive pr_number and a full source_sha.",
      );
    }
    target = { pr: number, sha: sourceSha };
  }
  if (target.pr === 0) return { pr: 0, sha };
  const pr = await getPullRequest(String(target.pr));
  return eligible(pr, repository, target.sha)
    ? { pr: pr.number, sha: target.sha }
    : null;
}

if (isMain(import.meta.url)) {
  const repository = process.env.GITHUB_REPOSITORY;
  const target = await resolveScanTarget(
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
  );
  appendFileSync(
    process.env.GITHUB_OUTPUT,
    `sha=${target?.sha ?? ""}\npr=${target?.pr || ""}\n`,
  );
  const message = target
    ? `${target.pr ? `PR #${target.pr}` : "Main baseline"} at ${target.sha}`
    : "Skipped: no eligible PR revision needs a scan.";
  console.log(message);
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, message + "\n");
  }
}

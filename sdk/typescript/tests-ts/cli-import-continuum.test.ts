import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import { collectContinuumIssues } from "../src/continuum-collector.js";
import { normalizeContinuumFindings } from "../src/continuum-findings.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import {
  continuumIssueExport,
  continuumRepository,
} from "./support/continuum-import-fixtures.js";

const command = ["import", "continuum", "example", "--format", "json"];

function awsFixture() {
  const report = continuumIssueExport();
  const { issue, findings } = report.issues[0]!;
  const [shared, first] = findings;
  const secondIssue = {
    ...issue,
    issueId: "issue2",
    issueArn: issue.issueArn.replace(/issue1$/u, "issue2"),
    findingIds: [shared!.findingId],
  };
  const list = {
    items: [issue, secondIssue].map(({ issueId, issueArn }) => ({
      issueId,
      issueArn,
    })),
  };
  const lookup = new Map<string, Record<string, unknown>>(
    [issue, secondIssue].map((item) => [item.issueId, item]),
  );
  const run = async (args: string[]): Promise<Record<string, unknown>> => {
    if (args[1] === "list-code-issues") return list;
    const id = args.at(-1);
    const detail =
      args[1] === "get-code-issue" && id
        ? lookup.get(id)
        : findings.find((finding) => finding.findingId === id);
    if (!detail) throw new Error(`Unexpected AWS call ${args.join(" ")}`);
    return detail;
  };
  return {
    run,
    report: {
      ...report,
      issues: [
        { issue, findings: [first!, shared!] },
        { issue: secondIssue, findings: [shared!] },
      ],
    },
  };
}

test.each([false, true])(
  "import continuum saves one complete report with AWS overrides set to %p",
  async (overrides) => {
    const { run, report } = awsFixture();
    const aws = mock(run);
    const cli = createCliTest(main);
    const options = overrides
      ? ["--aws-profile", "example role", "--aws-region", "us-east-1"]
      : [];
    expect(
      await cli.runCli([...command, ...options], {
        ...dependencies(),
        collectContinuumIssues: (selection) =>
          collectContinuumIssues(selection, aws),
      }),
    ).toBe(0);
    expect(cli.stderr.text()).toBe("");
    const args = [
      "--environment-id",
      "example",
      "--output",
      "json",
      "--no-cli-pager",
      ...(overrides
        ? ["--profile", "example role", "--region", "us-east-1"]
        : []),
    ];
    expect(aws.mock.calls).toEqual([
      [["continuum", "list-code-issues", ...args]],
      [["continuum", "get-code-issue", ...args, "--issue-id", "issue1"]],
      [["continuum", "get-code-finding", ...args, "--finding-id", "one"]],
      [["continuum", "get-code-finding", ...args, "--finding-id", "two"]],
      [["continuum", "get-code-issue", ...args, "--issue-id", "issue2"]],
    ]);
    const captured = JSON.parse(cli.stdout.text());
    expect(captured).toEqual(report);
    expect(
      normalizeContinuumFindings(captured, continuumRepository),
    ).toMatchObject({
      read: 2,
      excluded: [],
    });
  },
);

test.each(["list", "finding"] as const)(
  "import continuum leaves JSON output empty on a %s failure",
  async (failure) => {
    const { run } = awsFixture();
    const cli = createCliTest(main);
    expect(
      await cli.runCli(command, {
        ...dependencies(),
        collectContinuumIssues: (options) =>
          collectContinuumIssues(options, async (args) => {
            if (failure === "list")
              return { ...(await run(args)), NextToken: "next" };
            if (args[1] === "get-code-finding")
              throw new Error("AWS AccessDenied");
            return run(args);
          }),
      }),
    ).toBe(2);
    expect(cli.stdout.text()).toBe("");
    expect(cli.stderr.text()).toContain(
      failure === "list" ? "complete Continuum issue list" : "AWS AccessDenied",
    );
  },
);

test("import continuum rejects an environment ARN before invoking AWS", async () => {
  const cli = createCliTest(main);
  const collect = mock(collectContinuumIssues);
  const arn = "arn:aws:continuum:us-east-1:000000000000:environments/example";
  expect(
    await cli.runCli(command.with(2, arn), {
      ...dependencies(),
      collectContinuumIssues: collect,
    }),
  ).not.toBe(0);
  expect(collect).not.toHaveBeenCalled();
});

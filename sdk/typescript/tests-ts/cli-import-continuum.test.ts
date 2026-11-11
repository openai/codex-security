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

function awsFixture(provider: "github" | "gitlab" = "github") {
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
  const repository =
    provider === "gitlab" ? "example/team/project" : "example/project";
  const sourceRepositoryUrl =
    provider === "gitlab"
      ? "https://gitlab.example.com/example/team/project"
      : continuumRepository;
  const run = async (args: string[]): Promise<Record<string, unknown>> => {
    if (args[1] === "get-environment")
      return {
        configuration: {
          codeConfiguration: {
            sourceConfiguration: {
              s3Sources: [
                { integrationId: "archive", codePrefix: "code/" },
                { integrationId: "archive2", codePrefix: "other/" },
              ],
              repositorySources: [{ integrationId: "git", repository }],
            },
          },
        },
      };
    if (args[1] === "get-integration" && args[3] === "git")
      return provider === "github"
        ? { integrationType: "GITHUB" }
        : {
            integrationType: "GITLAB",
            providerDetails: {
              gitlab: { instanceUrl: "https://gitlab.example.com/" },
            },
          };
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
      sourceRepositoryUrl,
      issues: [
        { issue, findings: [first!, shared!] },
        { issue: secondIssue, findings: [shared!] },
      ],
    },
  };
}

test.each([false, true])(
  "import continuum binds one Git repository alongside S3 sources with AWS overrides set to %p",
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
    const awsArgs = [
      "--output",
      "json",
      "--no-cli-pager",
      ...(overrides
        ? ["--profile", "example role", "--region", "us-east-1"]
        : []),
    ];
    const args = ["--environment-id", "example", ...awsArgs];
    expect(aws.mock.calls).toEqual([
      [["continuum", "get-environment", ...args]],
      [["continuum", "get-integration", "--integration-id", "git", ...awsArgs]],
      [["continuum", "list-code-issues", ...args]],
      [["continuum", "get-code-issue", ...args, "--issue-id", "issue1"]],
      [["continuum", "get-code-finding", ...args, "--finding-id", "one"]],
      [["continuum", "get-code-finding", ...args, "--finding-id", "two"]],
      [["continuum", "get-code-issue", ...args, "--issue-id", "issue2"]],
    ]);
    const captured = JSON.parse(cli.stdout.text());
    expect(captured).toEqual(report);
    expect(normalizeContinuumFindings(captured)).toMatchObject({
      read: 2,
      excluded: [],
    });
  },
);

test("import continuum resolves the repository association for self-managed GitLab", async () => {
  const { run, report } = awsFixture("gitlab");
  const captured = await collectContinuumIssues(
    { environmentId: "example", cwd: ".", environment: {} },
    run,
  );
  expect(captured).toEqual(report);
});

test.each([
  ["an S3-only environment", undefined],
  [
    "an environment with multiple Git repositories",
    [
      { integrationId: "git", repository: "example/project" },
      { integrationId: "git", repository: "example/other" },
    ],
  ],
] as const)(
  "import continuum rejects %s before listing issues",
  async (_name, repositorySources) => {
    const aws = mock(async (_args: string[]) => ({
      configuration: {
        codeConfiguration: {
          sourceConfiguration: {
            s3Sources: [{ integrationId: "archive", codePrefix: "code/" }],
            repositorySources,
          },
        },
      },
    }));
    const cli = createCliTest(main);
    expect(
      await cli.runCli(command, {
        ...dependencies(),
        collectContinuumIssues: (options) =>
          collectContinuumIssues(options, aws),
      }),
    ).toBe(2);
    expect(aws.mock.calls.map(([args]) => args[1])).toEqual([
      "get-environment",
    ]);
    expect(cli.stdout.text()).toBe("");
    expect(cli.stderr.text()).toContain(
      `requires exactly one configured Git repository. This environment has ${repositorySources?.length ?? 0}.`,
    );
  },
);
test.each([
  ["list-code-issues", "complete Continuum issue list"],
  ["get-integration", "AWS AccessDenied"],
  ["get-code-finding", "AWS AccessDenied"],
] as const)(
  "import continuum leaves JSON output empty on a %s failure",
  async (operation, error) => {
    const { run } = awsFixture();
    const cli = createCliTest(main);
    expect(
      await cli.runCli(command, {
        ...dependencies(),
        collectContinuumIssues: (options) =>
          collectContinuumIssues(options, async (args) => {
            if (args[1] !== operation) return run(args);
            if (operation === "list-code-issues")
              return { ...(await run(args)), NextToken: "next" };
            throw new Error(error);
          }),
      }),
    ).toBe(2);
    expect(cli.stdout.text()).toBe("");
    expect(cli.stderr.text()).toContain(error);
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

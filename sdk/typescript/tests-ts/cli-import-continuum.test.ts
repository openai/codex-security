import { expect, mock, test } from "bun:test";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { main } from "../src/cli.js";
import { collectContinuumIssues } from "../src/continuum-collector.js";
import { normalizeContinuumFindings } from "../src/continuum-findings.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import {
  continuumEvidenceArtifact,
  continuumIssueExport,
  continuumRepository,
  patchArtifact,
} from "./support/continuum-import-fixtures.js";

const command = ["import", "continuum", "example", "--format", "json"];

test.skipIf(process.platform === "win32")(
  "launches AWS outside the checkout with vetted settings",
  async () => {
    await using fixture = await scopedTemporaryDirectory("continuum-aws-");
    const cwd = join(fixture.path, "checkout");
    const tools = join(fixture.path, "tools");
    const observed = join(fixture.path, "observed");
    await mkdir(cwd);
    await mkdir(tools);
    await writeFile(
      join(tools, "aws"),
      [
        "#!/bin/sh",
        'printf \'%s\\n\' "$PWD" "$AWS_REGION" "$UNRELATED_SETTING" > "$AWS_TEST_OBSERVED"',
        "printf '{}\\n'",
        "",
      ].join("\n"),
      { mode: 0o755 },
    );

    const environment = {
      PATH: [tools, process.env["PATH"]].filter(Boolean).join(delimiter),
      HOME: fixture.path,
      AWS_REGION: "us-east-1",
      AWS_TEST_OBSERVED: observed,
      UNRELATED_SETTING: "ignore me",
    };
    await expect(
      collectContinuumIssues({ environmentId: "example", cwd, environment }),
    ).rejects.toThrow("requires exactly one configured Git repository");
    expect(await readFile(observed, "utf8")).toBe(`${tools}\nus-east-1\n\n`);
  },
);

function awsFixture(provider: "github" | "gitlab" = "github", s3 = true) {
  const report = continuumIssueExport();
  const { issue: rawIssue, findings } = report.issues[0]!;
  const issue = { ...rawIssue, evidenceAvailability: "AVAILABLE" };
  const artifact = continuumEvidenceArtifact(issue.issueId);
  const patch = patchArtifact("patch1", "+// example\n");
  const patchResponse = {
    artifactId: patch.artifactId,
    artifactType: "PATCH",
    body: { patch },
  };
  const [shared, first] = findings;
  const secondIssue = {
    ...issue,
    issueId: "issue2",
    issueArn: issue.issueArn.replace(/issue1$/u, "issue2"),
    findingIds: [shared!.findingId],
    evidenceAvailability: "NONE",
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
              s3Sources: s3
                ? [
                    { integrationId: "archive", codePrefix: "code/" },
                    { integrationId: "archive2", codePrefix: "other/" },
                  ]
                : [],
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
    if (args[1] === "list-code-issue-artifacts")
      return {
        items: [
          {
            artifactId: artifact.artifactId,
            artifactType: artifact.artifactType,
          },
          ...(!args.includes("--artifact-type")
            ? [
                { artifactId: patch.artifactId, artifactType: "PATCH" },
                { artifactId: "decision1", artifactType: "DECISION" },
              ]
            : []),
        ],
      };
    if (args[1] === "get-code-issue-artifact")
      return args.at(-1) === patch.artifactId ? patchResponse : artifact;
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
        {
          issue: {
            ...issue,
            artifacts: [artifact, ...(!s3 ? [patchResponse] : [])],
          },
          findings: [first!, shared!],
        },
        { issue: { ...secondIssue, artifacts: [] }, findings: [shared!] },
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
      [
        [
          "continuum",
          "list-code-issue-artifacts",
          ...args,
          "--issue-id",
          "issue1",
          "--artifact-type",
          "EVIDENCE",
        ],
      ],
      [
        [
          "continuum",
          "get-code-issue-artifact",
          ...args,
          "--issue-id",
          "issue1",
          "--artifact-id",
          "evidence1",
        ],
      ],
      [["continuum", "get-code-issue", ...args, "--issue-id", "issue2"]],
    ]);
    const captured = JSON.parse(cli.stdout.text());
    expect(captured).toEqual(report);
    const normalized = normalizeContinuumFindings(captured);
    expect(normalized).toMatchObject({ read: 2, excluded: [] });
    expect(normalized.findings[0]?.evidence).toMatchObject({
      details: { scanner_verdict: "EXPLOITABLE" },
      source_data: { evidence_artifacts: report.issues[0]!.issue.artifacts },
    });
    expect(
      normalized.findings[0]?.evidence.source_data?.["issue"],
    ).not.toHaveProperty("artifacts");
    expect(
      normalized.findings[1]?.evidence.details?.scanner_verdict ?? null,
    ).toBeNull();
  },
);

test("import continuum captures AWS patch and evidence artifacts for a Git-only environment", async () => {
  const { run, report } = awsFixture("github", false);
  const aws = mock(run);
  const captured = await collectContinuumIssues(
    { environmentId: "example", cwd: ".", environment: {} },
    aws,
  );
  expect(captured).toEqual(report);
  expect(aws.mock.calls.some(([args]) => args.includes("decision1"))).toBe(
    false,
  );
  expect(normalizeContinuumFindings(captured)).toMatchObject({
    excluded: [],
    findings: [
      {
        source_finding_id: captured.issues[0]!.issue["issueArn"],
        evidence: {
          details: { scanner_verdict: "EXPLOITABLE" },
          source_data: { patches: [patchArtifact("patch1", "+// example\n")] },
        },
      },
      { source_finding_id: captured.issues[1]!.issue["issueArn"] },
    ],
  });
});

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
  ["list-code-issue-artifacts", "complete Continuum issue artifact list"],
  ["get-code-issue-artifact", "AWS AccessDenied"],
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
            if (
              operation === "list-code-issues" ||
              operation === "list-code-issue-artifacts"
            )
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

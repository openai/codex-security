import { expect, mock, test } from "bun:test";
import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { basename, delimiter, join } from "node:path";
import { main } from "../src/cli.js";
import { prepareContinuumAws } from "../src/continuum-aws.js";
import {
  collectContinuumFinding,
  collectContinuumIssues,
} from "../src/continuum-collector.js";
import { normalizeContinuumFindings } from "../src/continuum-findings.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import {
  continuumDetail,
  continuumEvidenceArtifact,
  continuumIssueExport,
  continuumRepository,
  continuumValidationArtifact,
  patchArtifact,
} from "./support/continuum-import-fixtures.js";

const command = ["import", "continuum", "example", "--format", "json"];

test.skipIf(process.platform === "win32")(
  "launches AWS outside the checkout with vetted settings and no Python on PATH",
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
      PATH: tools,
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

async function awsSettingsFixture(root: string) {
  const cwd = join(root, "checkout");
  const tools = join(root, "tools");
  const home = join(root, "home");
  await mkdir(cwd);
  await mkdir(tools);
  await mkdir(home);
  const executable = join(
    tools,
    process.platform === "win32" ? "aws.exe" : "aws",
  );
  await writeFile(executable, "", { mode: 0o755 });
  return {
    cwd,
    tools,
    home,
    executable,
    environment: {
      PATH: [cwd, tools].join(delimiter),
      HOME: home,
      USERPROFILE: home,
    },
  };
}

test("pins trusted AWS profile paths and rejects checkout-relative settings", async () => {
  await using fixture = await scopedTemporaryDirectory("continuum-settings-");
  const { cwd, tools, home, executable, environment } =
    await awsSettingsFixture(fixture.path);
  const config = join(home, "config");
  const launch = await prepareContinuumAws(cwd, {
    ...environment,
    AWS_CONFIG_FILE:
      process.platform === "win32"
        ? "%CONTINUUM_TEST_CONFIG%"
        : "$CONTINUUM_TEST_CONFIG",
    CONTINUUM_TEST_CONFIG: config,
  });
  expect(launch.executable).toBe(executable);
  expect(launch.cwd).toBe(tools);
  expect(launch.environment["PATH"]).toBe(tools);
  expect(launch.environment["AWS_CONFIG_FILE"]).toBe(config);
  expect(launch.environment["CONTINUUM_TEST_CONFIG"]).toBeUndefined();

  await expect(
    prepareContinuumAws(cwd, {
      ...environment,
      AWS_SHARED_CREDENTIALS_FILE: "credentials",
    }),
  ).rejects.toThrow(
    "Use an AWS_SHARED_CREDENTIALS_FILE file outside the selected checkout.",
  );
});

test("protects the selected checkout when AWS starts from another directory", async () => {
  await using fixture = await scopedTemporaryDirectory("continuum-settings-");
  const {
    cwd: sourceRoot,
    home: cwd,
    tools,
    executable,
    environment,
  } = await awsSettingsFixture(fixture.path);
  await writeFile(join(sourceRoot, basename(executable)), "", { mode: 0o755 });

  const launch = await prepareContinuumAws(
    cwd,
    environment,
    undefined,
    sourceRoot,
  );
  expect(launch.executable).toBe(executable);
  expect(launch.cwd).toBe(tools);
  expect(launch.environment["PATH"]).toBe(tools);
  await expect(
    prepareContinuumAws(
      cwd,
      {
        ...environment,
        AWS_CONFIG_FILE: join(sourceRoot, "profile"),
      },
      undefined,
      sourceRoot,
    ),
  ).rejects.toThrow(
    "Use an AWS_CONFIG_FILE file outside the selected checkout.",
  );
});

test.skipIf(process.platform === "win32")(
  "rejects aliases and custom AWS models linked from the checkout",
  async () => {
    await using fixture = await scopedTemporaryDirectory("continuum-settings-");
    const { cwd, home, environment } = await awsSettingsFixture(fixture.path);
    const settings = join(cwd, "settings");
    await writeFile(settings, "{}");
    const models = join(home, "models");
    const version = join(models, "example", "2020-01-01");
    await mkdir(version, { recursive: true });
    await symlink(settings, join(version, "service-2.json"));
    await expect(
      prepareContinuumAws(cwd, {
        ...environment,
        AWS_DATA_PATH: models,
      }),
    ).rejects.toThrow(
      "Use an AWS model path separate from the selected checkout",
    );

    const aliases = join(home, ".aws", "cli");
    await mkdir(aliases, { recursive: true });
    await symlink(settings, join(aliases, "alias"));
    await expect(prepareContinuumAws(cwd, environment)).rejects.toThrow(
      "Use an AWS CLI alias file outside the selected checkout.",
    );
  },
);

function awsFixture(provider: "github" | "gitlab" = "github", s3 = true) {
  const report = continuumIssueExport();
  const { issue: rawIssue, findings } = report.issues[0]!;
  const issue = { ...rawIssue, evidenceAvailability: "AVAILABLE" };
  const artifact = continuumEvidenceArtifact(issue.issueId);
  const validation = continuumValidationArtifact();
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
          {
            artifactId: validation.artifactId,
            artifactType: validation.artifactType,
          },
          { artifactId: patch.artifactId, artifactType: "PATCH" },
          { artifactId: "decision1", artifactType: "DECISION" },
        ],
      };
    if (args[1] === "get-code-issue-artifact") {
      const response = [artifact, validation, patchResponse].find(
        (item) => item.artifactId === args.at(-1),
      );
      if (response) return response;
    }
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
            artifacts: [artifact, validation, ...(!s3 ? [patchResponse] : [])],
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
      [
        [
          "continuum",
          "get-code-issue-artifact",
          ...args,
          "--issue-id",
          "issue1",
          "--artifact-id",
          "validation1",
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

test("import continuum captures one finding and only patches for the named AWS source", async () => {
  await using fixture = await scopedTemporaryDirectory("continuum-finding-");
  const finding = { ...continuumDetail(), duplicateOfIssueId: "issue1" };
  const matching = patchArtifact("match", "+// example\n");
  const other = {
    ...patchArtifact("other", "+// other\n"),
    repositoryName: "archive",
  };
  const { repositoryName: _name, ...unnamed } = patchArtifact(
    "unnamed",
    "+// unnamed\n",
  );
  const patches = [unnamed, other, matching];
  const aws = mock(async (args: string[]) => {
    switch (args[1]) {
      case "get-code-finding":
        return finding;
      case "list-code-issue-artifacts":
        return { items: patches.map(({ artifactId }) => ({ artifactId })) };
      case "get-code-issue-artifact": {
        const { artifactId, ...patch } = patches.find(
          (patch) => patch.artifactId === args.at(-1),
        )!;
        return { artifactId, artifactType: "PATCH", body: { patch } };
      }
      default:
        throw new Error("Unexpected AWS request");
    }
  });
  const cli = createCliTest(main);
  expect(
    await cli.runCli(
      [
        ...command,
        "--finding-id",
        "one",
        "--source-root",
        fixture.path,
        "--repository-name",
        "project",
        "--aws-profile",
        "example role",
        "--aws-region",
        "us-east-1",
      ],
      {
        ...dependencies(),
        collectContinuumFinding: (options) => {
          expect(options.sourceRoot).toBe(fixture.path);
          return collectContinuumFinding(options, aws);
        },
      },
    ),
  ).toBe(0);

  const scope = [
    "--environment-id",
    "example",
    "--output",
    "json",
    "--no-cli-pager",
    "--profile",
    "example role",
    "--region",
    "us-east-1",
  ];
  expect(aws.mock.calls.map(([args]) => args)).toEqual([
    ["continuum", "get-code-finding", ...scope, "--finding-id", "one"],
    [
      "continuum",
      "list-code-issue-artifacts",
      ...scope,
      "--issue-id",
      "issue1",
      "--artifact-type",
      "PATCH",
    ],
    ...["match", "other", "unnamed"].map((id) => [
      "continuum",
      "get-code-issue-artifact",
      ...scope,
      "--issue-id",
      "issue1",
      "--artifact-id",
      id,
    ]),
  ]);
  expect(cli.stderr.text()).toContain(
    "Skipped Continuum patch unnamed: AWS did not identify its repository.",
  );
  const capture = JSON.parse(cli.stdout.text());
  expect(capture).toEqual({ finding, patches: [matching] });
  expect(
    normalizeContinuumFindings(capture, continuumRepository),
  ).toMatchObject({
    read: 1,
    excluded: [],
    findings: [
      {
        source_finding_id: finding.findingArn,
        evidence: { source_data: { patches: [matching] } },
      },
    ],
  });
});

test("import continuum includes an unnamed patch after verifying a Git-only environment", async () => {
  await using fixture = await scopedTemporaryDirectory("continuum-finding-");
  const { run } = awsFixture("github", false);
  const finding = { ...continuumDetail(), createdIssueId: "issue1" };
  const { repositoryName: _name, ...patch } = patchArtifact(
    "unnamed",
    "+// example\n",
  );
  const aws = mock(async (args: string[]) => {
    switch (args[1]) {
      case "get-environment":
        return run(args);
      case "get-code-finding":
        return finding;
      case "list-code-issue-artifacts":
        return { items: [{ artifactId: patch.artifactId }] };
      case "get-code-issue-artifact":
        return {
          artifactId: patch.artifactId,
          artifactType: "PATCH",
          body: { patch },
        };
      default:
        throw new Error("Unexpected AWS request");
    }
  });
  const cli = createCliTest(main);
  expect(
    await cli.runCli(
      [...command, "--finding-id", "one", "--source-root", fixture.path],
      {
        ...dependencies(),
        collectContinuumFinding: (options) =>
          collectContinuumFinding(options, aws),
      },
    ),
  ).toBe(0);
  expect(aws.mock.calls.map(([args]) => args[1])).toEqual([
    "get-environment",
    "get-code-finding",
    "list-code-issue-artifacts",
    "get-code-issue-artifact",
  ]);
  expect(cli.stderr.text()).toBe("");
  expect(JSON.parse(cli.stdout.text())).toEqual({ finding, patches: [patch] });
});

test.each([
  ["one Git repository and S3", ["example/project"], true],
  ["multiple Git repositories", ["example/project", "example/other"], false],
  ["only S3", [], true],
  ["no sources", [], false],
] as const)(
  "import continuum requires a repository name for an environment with %s",
  async (_label, repositories, s3) => {
    await using fixture = await scopedTemporaryDirectory("continuum-finding-");
    const aws = mock(async (_args: string[]) => ({
      configuration: {
        codeConfiguration: {
          sourceConfiguration: {
            repositorySources: repositories.map((repository) => ({
              integrationId: "git",
              repository,
            })),
            ...(s3 && {
              s3Sources: [{ integrationId: "archive", codePrefix: "code/" }],
            }),
          },
        },
      },
    }));
    const cli = createCliTest(main);
    expect(
      await cli.runCli(
        [...command, "--finding-id", "one", "--source-root", fixture.path],
        {
          ...dependencies(),
          collectContinuumFinding: (options) =>
            collectContinuumFinding(options, aws),
        },
      ),
    ).toBe(2);
    expect(aws.mock.calls.map(([args]) => args[1])).toEqual([
      "get-environment",
    ]);
    expect(cli.stdout.text()).toBe("");
    expect(cli.stderr.text()).toContain("Pass --repository-name");
  },
);

test.each([false, true])(
  "import continuum preserves native finding JSON without patches (linked issue: %p)",
  async (linked) => {
    await using fixture = await scopedTemporaryDirectory("continuum-finding-");
    const finding = {
      ...continuumDetail(),
      ...(linked ? { createdIssueId: "issue1" } : {}),
    };
    const cli = createCliTest(main);
    const aws = mock(async (args: string[]) =>
      args[1] === "get-code-finding" ? finding : { items: [] },
    );
    expect(
      await cli.runCli(
        [
          ...command,
          "--finding-id",
          "one",
          "--source-root",
          fixture.path,
          "--repository-name",
          "project",
        ],
        {
          ...dependencies(),
          collectContinuumFinding: (options) =>
            collectContinuumFinding(options, aws),
        },
      ),
    ).toBe(0);
    expect(JSON.parse(cli.stdout.text())).toEqual(finding);
    expect(aws.mock.calls.map(([args]) => args[1])).toEqual(
      linked
        ? ["get-code-finding", "list-code-issue-artifacts"]
        : ["get-code-finding"],
    );
  },
);

test("import continuum rejects inconsistent finding options before collecting", async () => {
  await using fixture = await scopedTemporaryDirectory("continuum-finding-");
  const bulk = mock(collectContinuumIssues);
  const selected = mock(collectContinuumFinding);
  const root = ["--source-root", fixture.path];
  for (const [args, message] of [
    [root, "require --finding-id"],
    [["--finding-id", "one"], "requires --source-root"],
    [
      ["--finding-id", "one", "--source-root", "relative"],
      "must be an absolute path",
    ],
    [
      ["--finding-id", "one", ...root, "--single-repository"],
      "--single-repository",
    ],
  ] as const) {
    const cli = createCliTest(main);
    expect(
      await cli.runCli([...command, ...args], {
        ...dependencies(),
        collectContinuumIssues: bulk,
        collectContinuumFinding: selected,
      }),
    ).not.toBe(0);
    expect(cli.stderr.text()).toContain(message);
  }
  expect(bulk).not.toHaveBeenCalled();
  expect(selected).not.toHaveBeenCalled();
});

test.each(["incomplete list", "artifact read failure"])(
  "import continuum emits no partial finding capture on %s",
  async (failure) => {
    await using fixture = await scopedTemporaryDirectory("continuum-finding-");
    const cli = createCliTest(main);
    const patch = patchArtifact("one", "+// example\n");
    expect(
      await cli.runCli(
        [
          ...command,
          "--finding-id",
          "one",
          "--source-root",
          fixture.path,
          "--repository-name",
          "project",
        ],
        {
          ...dependencies(),
          collectContinuumFinding: (options) =>
            collectContinuumFinding(options, async (args) => {
              if (args[1] === "get-code-finding")
                return { ...continuumDetail(), createdIssueId: "issue1" };
              if (args[1] === "list-code-issue-artifacts")
                return {
                  items: [{ artifactId: "one" }, { artifactId: "two" }],
                  ...(failure === "incomplete list"
                    ? { nextToken: "next" }
                    : {}),
                };
              if (args.at(-1) === "one")
                return {
                  artifactId: "one",
                  artifactType: "PATCH",
                  body: { patch },
                };
              throw new Error("AWS AccessDenied");
            }),
        },
      ),
    ).toBe(2);
    expect(cli.stdout.text()).toBe("");
    expect(cli.stderr.text()).toContain(
      failure === "incomplete list"
        ? "Expected a complete Continuum issue artifact list"
        : "AWS AccessDenied",
    );
  },
);

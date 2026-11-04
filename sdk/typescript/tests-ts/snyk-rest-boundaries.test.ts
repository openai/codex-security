import { expect, mock, test } from "bun:test";
import { readSnykFindings } from "../src/snyk-findings.js";
import { snykJson, snykSarif } from "./support/snyk-import-fixtures.js";
import { prepareNormalizedExternalPublication } from "../src/external-findings-publish.js";
import type { ExternalFindings } from "../src/external-findings.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import {
  normalizeSnykIssues,
  snykRestImportRepository,
} from "../src/snyk-rest-findings.js";
import {
  snykIssue,
  snykLocalFixture,
  snykOptions,
  snykRestFixture,
} from "./support/snyk-rest-fixtures.js";

function cloudCatalog(environment: NodeJS.ProcessEnv, repositoryUrl: string) {
  return {
    environment,
    credentials: async () => ({
      access_token: "synthetic-token",
      account_id: "synthetic-account",
    }),
    fetch: async (url: string, init: RequestInit) => {
      expect(init.method).toBe("GET");
      expect(new URL(url).pathname).toEndWith("/repositories");
      return Response.json({
        object: "page",
        has_more: false,
        next: null,
        data: [
          {
            object: "security.repository",
            id: "repo-example",
            repo_connector_id: "github",
            url: repositoryUrl,
            default_branch: "main",
            reset_marker: "initial",
            import_environment_id: "env-example",
          },
        ],
      });
    },
  };
}

test("a generic Snyk reader can import findings with an SSH repository URL", async () => {
  const target = { repository: snykOptions.sourceRepositoryUrl };
  const report = {
    read: 1,
    findings: [
      {
        source_finding_id: "reader-id",
        evidence: {
          title: "Reader finding",
          severity: "high" as const,
          source_data: {
            format: "snyk-findings-export/v1",
            collection: { target },
          },
        },
      },
    ],
    excluded: [],
    sourceRepositoryUrl: "git@github.com:example/repository.git",
  };
  await using fixture = await snykLocalFixture({
    remote: snykOptions.sourceRepositoryUrl,
  });
  const prepare = (checkout = fixture) => checkout.prepareNormalized(report);
  const first = await prepare();
  expect((await first.import()).counts.created).toBe(1);
  const second = await prepare();
  expect((await second.import()).counts.unchanged).toBe(1);
  await using other = await snykLocalFixture({
    remote: "git@github.com:example/other.git",
  });
  await expect(prepare(other)).rejects.toThrow(
    "does not match a configured remote",
  );
  target.repository = "https://github.com/example/other";
  await expect(prepare()).rejects.toThrow("Snyk reader's repository");
});

test("normalized Snyk Open Source rows require their matching Cloud repository", async () => {
  await using fixture = await snykLocalFixture();
  const normalized = normalizeSnykIssues(
    snykRestFixture("open-source"),
    "cloud",
  );
  expect(normalized.findings).toHaveLength(1);
  await expect(
    prepareNormalizedExternalPublication(
      normalized,
      { provider: "snyk", repository: "repo-example", sourceKey: "example" },
      cloudCatalog(fixture.environment, "https://github.com/example/another"),
    ),
  ).rejects.toThrow(/does not match/);
});

test("an empty normalized Snyk report stops before Cloud credentials", async () => {
  const capture = snykRestFixture("open-source");
  capture.pages[0]!.responseJson = JSON.stringify({ data: [], links: {} });
  const normalized = normalizeSnykIssues(capture);
  expect(normalized.findings).toHaveLength(0);
  const credentials = mock(async () => {
    throw new Error("Unexpected credentials");
  });
  await expect(
    prepareNormalizedExternalPublication(
      normalized,
      { provider: "snyk", repository: "repo-example", sourceKey: "example" },
      {
        environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
        credentials,
      },
    ),
  ).rejects.toThrow("No supported findings");
  expect(credentials).not.toHaveBeenCalled();
});

test("a Snyk asset cannot authorize a projected row from a second repository", async () => {
  const normalized = normalizeSnykIssues(snykRestFixture("open-source"));
  const other = "https://github.com/example/another";
  normalized.findings.push({
    source_finding_id: "blackduck-bom:" + "a".repeat(64),
    evidence: {
      title: "Projected package",
      severity: "high",
      source_data: { sourceRepositoryUrl: other },
    },
  });
  await using fixture = await snykLocalFixture({
    remote: snykOptions.sourceRepositoryUrl,
  });
  await expect(
    prepareNormalizedLocalImport(
      normalized,
      {
        repository: fixture.repository,
        provider: "snyk",
        sourceKey: "example",
      },
      { environment: fixture.environment },
    ),
  ).rejects.toThrow("Snyk original issue");
});

test("Snyk Open Source rows still verify the native project after losing their format and report headers", async () => {
  const { read, findings, excluded } = normalizeSnykIssues(
    snykRestFixture("open-source"),
  );
  delete findings[0]!.evidence.source_data!["format"];
  await using f = await snykLocalFixture({
    remote: "https://github.com/example/other",
  });
  await expect(
    f.prepareNormalized({ read, findings, excluded }),
  ).rejects.toThrow("configured remote");

  // A changed ID and provider cannot relabel the original linked Snyk resources.
  findings[0]!.source_finding_id = "wiz-example";
  await expect(
    prepareNormalizedLocalImport(
      { read, findings, excluded },
      {
        provider: "wiz",
        sourceKey: f.sourceKey,
        repository: f.repository,
      },
      { environment: f.environment },
    ),
  ).rejects.toThrow("Snyk issue key");
});

test("direct import rejects another Snyk issue’s evidence under a stored finding ID", async () => {
  const report = snykRestFixture("open-source");
  await using f = await snykLocalFixture();
  await f.writeJson(report);
  await (await f.prepare()).import();
  const prior = await f.read();
  const oldId = prior[0]!.sourceFindingId;
  expect(prior[0]!.evidence.source_data?.["snykRestIssueKey"]).toBe(
    "opaque-issue-key",
  );
  report.pages[0]!.responseJson = report.pages[0]!.responseJson.replace(
    "opaque-issue-key",
    "another-issue-key",
  );
  const second = normalizeSnykIssues(report);
  expect(second.findings[0]!.source_finding_id).not.toBe(oldId);
  const row = second.findings[0]!;
  row.source_finding_id = oldId;
  const prepare = () => f.prepareNormalized(second);
  await expect(prepare()).rejects.toThrow("Snyk issue key");
  row.source_finding_id =
    normalizeSnykIssues(report).findings[0]!.source_finding_id;
  row.evidence.source_data!["snykRestIssueKey"] = "opaque-issue-key";
  await expect(prepare()).rejects.toThrow("retained Snyk issue key");
  row.source_finding_id = oldId;
  for (const source of [{}, undefined]) {
    row.evidence.source_data = source;
    await expect(prepare()).rejects.toThrow(/Snyk|snyk-rest/);
  }
  expect(await f.read()).toEqual(prior);
});

test("a saved Snyk origin cannot establish that a private host uses GitHub path aliases", async () => {
  const source = "https://scm.example.invalid/Org/repo";
  const alias = "https://scm.example.invalid/org/REPO.git";
  const report = snykRestFixture("open-source", {
    sourceRepositoryUrl: source,
  });
  const project = JSON.parse(report.projectJson);
  project.attributes.origin = "github-enterprise";
  report.projectJson = JSON.stringify(project);
  await using fixture = await snykLocalFixture({ remote: alias });
  const settings = {
    provider: "snyk" as const,
    sourceKey: "example/project",
    repository: fixture.repository,
  };
  const normalized = normalizeSnykIssues(report);
  const prepare = (
    sourceRepositories?: { url: string; platform: "github" }[],
  ) =>
    prepareNormalizedLocalImport(normalized, settings, {
      environment: fixture.environment,
      sourceRepositories,
    });
  await expect(prepare()).rejects.toThrow("configured remote");
  await expect(
    prepare([
      { url: "https://scm.example.invalid/other/project", platform: "github" },
    ]),
  ).rejects.toThrow();
  expect(
    (await prepare([{ url: source, platform: "github" }])).preview.findings,
  ).toHaveLength(1);

  // A native URL that only matches the declared URL under GitHub's rules needs
  // the same independent repository identity as the checkout.
  await using exact = await snykLocalFixture({ remote: source });
  for (const native of [alias, "git@scm.example.invalid:Org/repo"]) {
    project.relationships.target.data.attributes.url = native;
    report.projectJson = JSON.stringify(project);
    await expect(
      prepareNormalizedLocalImport(
        normalizeSnykIssues(report),
        { ...settings, repository: exact.repository },
        { environment: exact.environment },
      ),
    ).rejects.toThrow("original Snyk project");
  }
});

test("unrelated Wiz evidence with Snyk-like field names remains importable locally and reaches Cloud credentials", async () => {
  await using f = await snykLocalFixture();
  const source_data: Record<string, unknown> = {
    ...snykOptions,
    snykRestIssueKey: "upstream-ticket",
    apiVersion: "2026-03-25",
    projectJson: JSON.stringify({
      type: "project",
      id: "repo-name",
      attributes: { origin: "github", type: "npm" },
    }),
    issueJson: "{}",
    targetJson: JSON.stringify({ type: "target", id: 42 }),
    project: { name: "sample" },
    issue: { name: "sample issue" },
  };
  const finding = {
    source_finding_id: "snyk-rest:ticket-42",
    evidence: { title: "Example", severity: "medium" as const, source_data },
  };
  const input = {
    read: 1,
    findings: [finding],
    excluded: [],
    snykRestContext: undefined,
  };
  const options = {
    provider: "wiz" as const,
    sourceKey: "example",
    repository: f.repository,
  };
  const credentials = mock(async () => {
    throw new Error("Reached Wiz Cloud credentials");
  });
  const sources: Record<string, unknown>[] = [
    {
      snykRestIssueKey: "upstream-ticket",
      projectJson: JSON.stringify({
        type: "project",
        id: snykOptions.projectId,
        attributes: { origin: "ticketing", type: "service" },
      }),
    },
  ];
  const original = snykIssue(true);
  for (const [id, org, project] of [
    [42, undefined, undefined],
    ["ticket-42", snykOptions.organizationId, snykOptions.projectId],
    [original.id, undefined, snykOptions.projectId],
    [original.id, snykOptions.organizationId, undefined],
  ]) {
    const issue = {
      ...original,
      id,
      relationships: {
        organization: { data: { type: "organization", id: org } },
        scan_item: { data: { type: "project", id: project } },
      },
    };
    sources.push({
      ...source_data,
      issue,
      issueJson: JSON.stringify(issue),
      ...(id === original.id && { format: "wiz-export/v1" }),
    });
  }
  for (const source of sources) {
    finding.evidence.source_data = source;
    expect(
      (
        await prepareNormalizedLocalImport(input, options, {
          environment: f.environment,
        })
      ).preview.findings,
    ).toHaveLength(1);
    await expect(
      prepareNormalizedExternalPublication(input, options, {
        environment: f.environment,
        credentials,
      }),
    ).rejects.toThrow("Reached Wiz Cloud credentials");
  }
  expect(credentials).toHaveBeenCalledTimes(sources.length);
});

test("a reader may copy an optional hosted context from Snyk CLI JSON or SARIF", async () => {
  await using f = await snykLocalFixture();
  const options = {
    provider: "snyk" as const,
    repository: f.repository,
    sourceKey: "example",
  };
  const credentials = mock(async () => {
    throw new Error("Reached Snyk credentials");
  });
  for (const file of [snykJson(), snykSarif()]) {
    await f.writeJson(file);
    const report = await readSnykFindings(f.file, "local");
    const dependencies = { environment: f.environment, credentials };
    for (const input of [
      report,
      { ...report, snykRestContext: report.snykRestContext },
    ]) {
      expect(
        (await prepareNormalizedLocalImport(input, options, dependencies))
          .preview.findings,
      ).toHaveLength(1);
      await expect(
        prepareNormalizedExternalPublication(input, options, dependencies),
      ).rejects.toThrow("Reached Snyk credentials");
    }
    const malformed = { ...report, snykRestContext: null };
    await expect(
      prepareNormalizedLocalImport(malformed, options, dependencies),
    ).rejects.toThrow(/Snyk report context/);
    await expect(
      prepareNormalizedExternalPublication(malformed, options, dependencies),
    ).rejects.toThrow(/Snyk/);
  }
  expect(credentials).toHaveBeenCalledTimes(4);
});

test("a hosted selection cannot store another normalized project's projected assets", async () => {
  const report = normalizeSnykIssues(snykRestFixture("open-source"));
  const capture = snykRestFixture("open-source", {
    sourceRepositoryUrl: "https://github.com/example/another",
  });
  const otherId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const resource = JSON.parse(capture.projectJson);
  const target = resource.relationships.target.data;
  resource.id = otherId;
  resource.relationships.target.data = { type: "target", id: target.id };
  const response = JSON.parse(capture.pages[0]!.responseJson);
  response.data[0].relationships.scan_item.data.id = otherId;
  const foreign = normalizeSnykIssues({
    ...capture,
    projectId: otherId,
    projectJson: JSON.stringify(resource),
    targetJson: JSON.stringify(target),
    pages: [{ startingAfter: null, responseJson: JSON.stringify(response) }],
  });
  const native = foreign.findings[0]!.evidence.source_data!;
  const row = report.findings[0]!;
  await using fixture = await snykLocalFixture({
    remote: report.sourceRepositoryUrl,
  });
  const prepare = () => fixture.prepareNormalized(report);
  row.source_finding_id = "reader-row";
  for (const key of ["project", "target"]) {
    const json = String(native[key + "Json"]);
    for (const projected of [
      { [key + "Json"]: json },
      { [key]: JSON.parse(json) },
    ]) {
      row.evidence.source_data = projected;
      await expect(prepare()).rejects.toThrow(/Snyk|snyk-rest/);
    }
  }
  const license = JSON.parse(String(native["issueJson"]));
  license.attributes.type = "license";
  for (const projected of [
    { issue: license },
    { issueJson: JSON.stringify(license) },
  ]) {
    row.evidence.source_data = projected;
    await expect(prepare()).rejects.toThrow("selected project");
  }
  delete row.evidence.source_data;
  await expect(prepare()).rejects.toThrow("Original Snyk REST issue evidence");
  expect(await fixture.read()).toBeEmpty();
});

test("retagged original Snyk records remain scoped without a matching source ID or format", async () => {
  const full = normalizeSnykIssues(snykRestFixture("open-source"));
  const row = full.findings[0]!;
  const original = row.evidence.source_data!;
  const { read, findings, excluded } = full;
  const projected = { read, findings, excluded };
  row.source_finding_id = "wiz-reader-row";
  const legacy = {
    ...original,
    project: JSON.parse(String(original["projectJson"])),
    issue: JSON.parse(String(original["issueJson"])),
    target: null,
  };
  delete (legacy as Record<string, unknown>)["projectJson"];
  delete (legacy as Record<string, unknown>)["issueJson"];
  await using f = await snykLocalFixture();
  const opts = {
    provider: "wiz" as const,
    sourceKey: "example",
    repository: f.repository,
  };
  const cloud = cloudCatalog(f.environment, snykOptions.sourceRepositoryUrl);
  for (const source of [
    original,
    legacy,
    { ...legacy, issueJson: "{}", projectJson: "{" },
    { ...original, issue: {}, project: {} },
  ]) {
    row.evidence.source_data = { ...source, format: "reader/v1" };
    delete row.evidence.source_data["snykRestIssueKey"];
    delete row.evidence.source_data["apiVersion"];
    await expect(
      prepareNormalizedExternalPublication(
        projected,
        { ...opts, repository: "repo-example" },
        cloud,
      ),
    ).rejects.toThrow("requires the snyk provider");
    await expect(
      prepareNormalizedLocalImport(projected, opts, {
        environment: f.environment,
      }),
    ).rejects.toThrow(/Snyk|snyk-rest/);
  }
  const mismatched = { ...legacy.project, id: snykOptions.organizationId };
  const target = legacy.project.relationships.target.data;
  for (const resources of [
    { project: mismatched, issue: legacy.issue, target: null },
    { target },
    {
      projectJson: JSON.stringify(mismatched),
      issueJson: original["issueJson"],
      targetJson: "null",
    },
    {
      projectJson: JSON.stringify(mismatched),
      snykRestIssueKey: original["snykRestIssueKey"],
      targetJson: "null",
    },
    {
      snykRestIssueKey: original["snykRestIssueKey"],
      targetJson: JSON.stringify(target),
    },
  ]) {
    row.evidence.source_data = {
      ...snykOptions,
      apiVersion: original["apiVersion"],
      ...resources,
    };
    await expect(
      prepareNormalizedExternalPublication(
        projected,
        { ...opts, repository: "repo-example" },
        cloud,
      ),
    ).rejects.toThrow("requires the snyk provider");
    await expect(
      prepareNormalizedLocalImport(projected, opts, {
        environment: f.environment,
      }),
    ).rejects.toThrow(
      "issue" in resources || "issueJson" in resources
        ? /different project/
        : /Snyk/,
    );
  }
  for (const missing of ["issueJson", "projectJson"]) {
    row.evidence.source_data = { ...original, format: "reader/v1" };
    delete row.evidence.source_data[missing];
    await expect(
      prepareNormalizedExternalPublication(
        projected,
        { ...opts, repository: "repo-example" },
        cloud,
      ),
    ).rejects.toThrow("requires the snyk provider");
    await expect(
      prepareNormalizedLocalImport(projected, opts, {
        environment: f.environment,
      }),
    ).rejects.toThrow(/Snyk|snyk-rest/);
  }
  row.source_finding_id = normalizeSnykIssues(
    snykRestFixture("open-source"),
  ).findings[0]!.source_finding_id;
  const otherTarget = {
    ...target,
    id: snykOptions.organizationId,
    attributes: { url: "https://github.com/example/another-repository" },
  };
  for (const extra of [
    { project: legacy.project, issue: legacy.issue },
    { target: otherTarget },
  ]) {
    row.evidence.source_data = { ...original, ...extra };
    await expect(
      prepareNormalizedLocalImport(
        projected,
        { ...opts, provider: "snyk" },
        { environment: f.environment },
      ),
    ).rejects.toThrow("both v1 and v2");
  }
});

test("an independently verified GitHub source applies to a CLI-monitored Snyk project", async () => {
  const url = "https://scm.example.invalid/Org/repo";
  const report = snykRestFixture("open-source", { sourceRepositoryUrl: url });
  const project = JSON.parse(report.projectJson);
  project.attributes.origin = "cli";
  report.projectJson = JSON.stringify(project);
  await using fixture = await snykLocalFixture({
    remote: "git@scm.example.invalid:org/REPO.git",
  });
  const normalized = normalizeSnykIssues(report);
  const prepare = (
    sourceRepositories?: { url: string; platform: "github" }[],
  ) =>
    prepareNormalizedLocalImport(
      normalized,
      {
        provider: "snyk",
        repository: fixture.repository,
        sourceKey: "example/project",
      },
      { environment: fixture.environment, sourceRepositories },
    );
  await expect(prepare()).rejects.toThrow("configured remote");
  expect(
    (await prepare([{ url, platform: "github" }])).preview.findings,
  ).toHaveLength(1);
  delete normalized.findings[0]!.evidence.source_data;
  await expect(prepare([{ url, platform: "github" }])).rejects.toThrow(/Snyk/);
  normalized.findings[0]!.source_finding_id = "projected-issue";
  await expect(prepare([{ url, platform: "github" }])).rejects.toThrow(/Snyk/);
});

test("a serialized Snyk report keeps its monitored asset when a reader supplies a repository URL", async () => {
  const repository = "https://scm.example.invalid/team/project";
  const other = "https://scm.example.invalid/another/project";
  const report = normalizeSnykIssues(
    snykRestFixture("open-source", { sourceRepositoryUrl: repository }),
  );
  const serialized = JSON.parse(JSON.stringify(report)) as typeof report;

  const projected = Object.assign(
    Object.create({
      get snykRestContext() {
        return report.snykRestContext;
      },
    }),
    { read: 1, excluded: [], findings: report.findings },
  );
  const credentials = mock(async () => {
    throw new Error("Unexpected Cloud credential lookup");
  });
  await expect(
    prepareNormalizedExternalPublication(
      projected,
      { provider: "wiz", sourceKey: "project", repository: "repo-example" },
      {
        environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
        credentials,
      },
    ),
  ).rejects.toThrow(/requires the snyk provider/i);
  const malformed = { ...projected, snykRestContext: {} };
  await expect(
    prepareNormalizedExternalPublication(
      malformed,
      { provider: "snyk", sourceKey: "project", repository: "repo-example" },
      {
        environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
        credentials,
      },
    ),
  ).rejects.toThrow(/Snyk REST report context/);
  expect(credentials).not.toHaveBeenCalled();

  await using matching = await snykLocalFixture({ remote: repository });
  const options = {
    provider: "snyk" as const,
    sourceKey: "project",
    repository: matching.repository,
  };
  await expect(
    prepareNormalizedExternalPublication(
      serialized,
      { ...options, repository: "repo-example" },
      cloudCatalog(matching.environment, other),
    ),
  ).rejects.toThrow("does not match");
  expect(
    (
      await prepareNormalizedLocalImport(serialized, options, {
        environment: matching.environment,
      })
    ).preview.findings,
  ).toHaveLength(1);

  await using foreign = await snykLocalFixture({ remote: other });
  const { sourceRepositoryUrl: _url, ...fields } = serialized;
  const foreignUrl = Object.assign(
    Object.create({
      get sourceRepositoryUrl() {
        return other;
      },
    }),
    fields,
  );
  await expect(
    prepareNormalizedLocalImport(
      foreignUrl,
      { ...options, repository: foreign.repository },
      { environment: foreign.environment },
    ),
  ).rejects.toThrow("original Snyk project");
});

test("projected Snyk findings cannot change destination by losing the report format", async () => {
  const report = normalizeSnykIssues(snykRestFixture("open-source"));
  const row = report.findings[0]!;
  row.source_finding_id = "reader-id";
  delete row.evidence.source_data;
  const credentials = mock(async () => {
    throw new Error("Unexpected credentials");
  });
  await using f = await snykLocalFixture({
    remote: report.sourceRepositoryUrl,
  });
  const options = {
    provider: "wiz" as const,
    repository: f.repository,
    sourceKey: "example",
  };
  for (const format of [undefined, "other-format/v1"]) {
    const context = { ...report.snykRestContext };
    if (format) context["format"] = format;
    else delete context["format"];
    const { snykRestContext: _original, ...fields } = report;
    const projected = Object.assign(
      Object.create({
        get snykRestContext() {
          return context;
        },
      }),
      fields,
    );
    await expect(
      prepareNormalizedExternalPublication(projected, options, {
        environment: f.environment,
        credentials,
      }),
    ).rejects.toThrow(/Snyk|snyk-rest/);
    await expect(
      prepareNormalizedLocalImport(projected, options, {
        environment: f.environment,
      }),
    ).rejects.toThrow(/Snyk|snyk-rest/);
  }
  expect(credentials).not.toHaveBeenCalled();
});

test("rows from a different Snyk monitor cannot use the report's source key even on the same Git URL", async () => {
  const capture = snykRestFixture("open-source");
  const project = JSON.parse(capture.projectJson);
  const target = project.relationships.target.data;
  const integrationId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  project.relationships.target.data = { type: target.type, id: target.id };
  capture.projectJson = JSON.stringify(project);
  capture.targetJson = JSON.stringify({
    ...target,
    relationships: {
      integration: {
        data: {
          type: "integration",
          id: integrationId,
          attributes: { integration_type: "github-cloud-app" },
        },
      },
    },
  });
  const report = normalizeSnykIssues(capture);
  const code = snykRestFixture("code");
  const otherId = "aaaa0000-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const replace = (old: string, replacement = otherId) =>
    JSON.parse(
      JSON.stringify(capture)
        .replaceAll(old, replacement)
        .replace(snykIssue(false).attributes.key, "other-issue-key")
        .replace(snykIssue(false).id, otherId),
    ) as typeof capture;
  await using f = await snykLocalFixture({
    remote: report.sourceRepositoryUrl,
  });
  const prepareCloud = (input: ExternalFindings) =>
    prepareNormalizedExternalPublication(
      input,
      {
        provider: "snyk",
        sourceKey: f.sourceKey,
        repository: report.sourceRepositoryUrl,
      },
      cloudCatalog(f.environment, report.sourceRepositoryUrl),
    );
  const original = report.findings[0]!;
  const sibling = normalizeSnykIssues(replace(snykIssue(false).id))
    .findings[0]!;
  const selected = { ...report, read: 2, findings: [original, sibling] };
  expect(
    (await (await f.prepareNormalized(selected)).import()).counts.created,
  ).toBe(2);
  const stored = await f.read();
  const { projectJson, targetJson } = original.evidence.source_data!;
  for (const row of stored)
    expect(row.evidence.source_data).toMatchObject({ projectJson, targetJson });
  sibling.evidence.source_data!["apiVersion"] = "unsupported";
  await expect(prepareCloud(selected)).rejects.toThrow("API version");
  await expect(f.prepareNormalized(selected)).rejects.toThrow("API version");

  for (const other of [
    replace(capture.organizationId),
    replace(capture.projectId),
    replace(target.id),
    replace(integrationId),
    replace("github-cloud-app", "github-server-app"),
    code,
    { ...capture, apiOrigin: "https://api.au.snyk.io" },
  ]) {
    report.findings = normalizeSnykIssues(other).findings;
    const rowsOnly = {
      read: 2,
      findings: [original, ...report.findings],
      excluded: [],
    };
    for (const input of [report, rowsOnly]) {
      await expect(f.prepareNormalized(input)).rejects.toThrow(
        "Snyk project scope",
      );
      await expect(prepareCloud(input)).rejects.toThrow("Snyk project scope");
    }
  }
  const saved = structuredClone(original);
  saved.source_finding_id = "saved-reader-id";
  saved.evidence.source_data = {
    format: capture.format,
    projectJson: capture.projectJson,
    targetJson: capture.targetJson,
  };
  const checkSaved = (monitor: typeof capture) =>
    snykRestImportRepository(
      { ...normalizeSnykIssues(monitor), findings: [saved] },
      "snyk",
      [],
      [],
      undefined,
      true,
    );
  expect(checkSaved(capture)?.url).toBe(capture.sourceRepositoryUrl);
  for (const id of [capture.projectId, capture.organizationId]) {
    expect(() => checkSaved(replace(id))).toThrow(
      "retained Snyk project scope",
    );
  }
  for (const id of [target.id, integrationId]) {
    expect(() => checkSaved(replace(id))).toThrow(
      "conflicting targets or integrations",
    );
  }
  saved.evidence.source_data = {
    format: capture.format,
    targetJson: capture.targetJson.replace(`"${integrationId}"`, "null"),
  };
  expect(checkSaved(capture)?.url).toBe(capture.sourceRepositoryUrl);
  expect(checkSaved(replace("github-cloud-app", "github"))?.url).toBe(
    capture.sourceRepositoryUrl,
  );
  expect(() =>
    checkSaved(replace("github-cloud-app", "github-server-app")),
  ).toThrow("conflicting targets or integrations");
  expect(await f.read()).toEqual(stored);
});

test("a sparse approved Snyk record still checks its retained repository URLs", () => {
  const url = "https://scm.example.test/Team/Project";
  const { projectJson } = snykRestFixture("open-source", {
    sourceRepositoryUrl: url,
  });
  const project = JSON.parse(projectJson);
  project.attributes.origin = "gitlab";
  const target = project.relationships.target.data;
  for (const source of [
    { format: "snyk-rest-issues/v2", sourceRepositoryUrl: url },
    { format: "snyk-rest-issues/v2", projectJson: JSON.stringify(project) },
    { format: "snyk-rest-issues/v2", targetJson: JSON.stringify(target) },
    { format: "snyk-rest-issues/v1", project },
    { format: "snyk-rest-issues/v1", target },
  ]) {
    const input = {
      read: 1,
      excluded: [],
      findings: [
        {
          source_finding_id: "reader-selected",
          evidence: {
            title: "Issue",
            severity: "low" as const,
            source_data: source,
          },
        },
      ],
    };
    const check = (destination?: string) =>
      snykRestImportRepository(
        input,
        "snyk",
        [],
        destination ? [{ url: destination, platform: "github" }] : [],
        undefined,
        true,
        destination,
      );
    expect(check()).toBeUndefined();
    expect(check(url)?.url).toBe(url);
    if ("project" in source || "projectJson" in source)
      expect(() => check(url.toLowerCase())).toThrow(
        "does not match the original Snyk project",
      );
    expect(() => check("https://scm.example.test/Other/Project")).toThrow(
      "does not match the original Snyk project",
    );
  }
});

test("a sparse approved project retains its known product and target linkage", () => {
  const report = normalizeSnykIssues(snykRestFixture("code"));
  const row = report.findings[0]!;
  row.source_finding_id = "reader-selected";
  const project = JSON.parse(String(report.snykRestContext!["projectJson"]));
  const check = () => {
    row.evidence.source_data = {
      format: "snyk-rest-issues/v2",
      projectJson: JSON.stringify(project),
    };
    return snykRestImportRepository(report, "snyk", [], [], undefined, true);
  };
  expect(check()?.url).toBe(report.sourceRepositoryUrl);
  project.attributes.type = "npm";
  expect(check).toThrow("retained Snyk project scope");
  delete project.attributes.type;
  project.relationships.target.data = null;
  expect(check).toThrow("conflicting targets");
  delete project.relationships.target;
  expect(check()?.url).toBe(report.sourceRepositoryUrl);
});

test("opaque legacy issues retain sibling scope checks on a checkpoint retry", () => {
  const report = normalizeSnykIssues(snykRestFixture("open-source"));
  const native = report.findings[0]!;
  const context = native.evidence.source_data!;
  report.findings.push({
    ...native,
    source_finding_id: "snyk-rest:opaque",
    evidence: {
      ...native.evidence,
      source_data: { format: context["format"] },
    },
  });
  const check = (allowOpaqueLegacyRows: boolean) =>
    snykRestImportRepository(
      report,
      "snyk",
      [],
      [],
      undefined,
      allowOpaqueLegacyRows,
    );
  report.snykRestContext = context;
  expect(() => check(false)).toThrow();
  expect(check(true)?.url).toBe(report.sourceRepositoryUrl);
  // A different Snyk project can monitor exactly the same Git repository.
  report.snykRestContext = JSON.parse(
    JSON.stringify(context).replaceAll(
      snykOptions.projectId,
      "44444444-4444-4444-8444-444444444444",
    ),
  );
  expect(() => check(true)).toThrow("retained Snyk project scope");
});

test.each(["v1", "v2"] as const)(
  "a linked %s issue projection uses its report's project and requires the Snyk provider",
  async (version) => {
    const report = normalizeSnykIssues(snykRestFixture("open-source"));
    const row = report.findings[0]!;
    const full = structuredClone(report);
    const nativeId = row.source_finding_id;
    const json = String(row.evidence.source_data!["issueJson"]);
    const project = (id: string) => {
      const issue = JSON.parse(json);
      issue.relationships.scan_item.data.id = id;
      return {
        ...snykOptions,
        ...(version === "v1"
          ? { issue }
          : { issueJson: JSON.stringify(issue) }),
      };
    };
    row.source_finding_id = "reader-row";
    row.evidence.source_data = project("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    await using fixture = await snykLocalFixture({
      remote: snykOptions.sourceRepositoryUrl,
    });
    const options = {
      provider: "snyk" as const,
      sourceKey: fixture.sourceKey,
      repository: fixture.repository,
    };
    const { read, findings, excluded } = report;
    await expect(
      prepareNormalizedExternalPublication(
        { read, findings, excluded },
        { ...options, repository: "repo-example", provider: "wiz" },
        cloudCatalog(fixture.environment, snykOptions.sourceRepositoryUrl),
      ),
    ).rejects.toThrow(/requires the snyk provider/i);
    const prepare = () => fixture.prepareNormalized(report);
    await expect(prepare()).rejects.toThrow("selected project");
    const retry = () =>
      snykRestImportRepository(report, "snyk", [], [], undefined, true);
    expect(retry).toThrow("selected project");
    row.evidence.source_data = project(snykOptions.projectId);
    expect(retry()?.url).toBe(snykOptions.sourceRepositoryUrl);
    await expect(prepare()).rejects.toThrow("normalized finding ID");
    row.source_finding_id = nativeId;
    const issue = JSON.parse(json);
    const targetlessProject = JSON.parse(
      String(full.snykRestContext!["projectJson"]),
    );
    delete targetlessProject.relationships;
    Object.assign(
      row.evidence.source_data,
      version === "v1"
        ? { project: targetlessProject }
        : { projectJson: JSON.stringify(targetlessProject) },
    );
    await expect(prepare()).rejects.toThrow(
      "missing the report's native target",
    );
    const foreign = snykRestFixture("open-source", {
      sourceRepositoryUrl: "https://github.com/example/other",
    });
    const alternateId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const original = normalizeSnykIssues(
      JSON.parse(
        JSON.stringify(foreign).replaceAll(foreign.projectId, alternateId),
      ),
    ).snykRestContext!;
    row.evidence.source_data =
      version === "v1"
        ? { issue, projectJson: original["projectJson"] }
        : {
            issueJson: json,
            project: JSON.parse(String(original["projectJson"])),
          };
    await expect(prepare()).rejects.toThrow("both v1 and v2");
    expect(await fixture.read()).toBeEmpty();
    const asset = report.snykRestContext!;
    const selected =
      version === "v1"
        ? {
            issue,
            project: JSON.parse(String(asset["projectJson"])),
            target: null,
          }
        : {
            issueJson: json,
            projectJson: asset["projectJson"],
            targetJson: asset["targetJson"],
          };
    row.evidence.source_data = { ...selected, projectId: alternateId };
    await expect(prepare()).rejects.toThrow("project");
    row.evidence.source_data = selected;
    expect((await (await prepare()).import()).counts.created).toBe(1);
    expect((await (await prepare()).import()).counts.unchanged).toBe(1);
    const [stored] = await fixture.read();
    const listed = {
      read: 1,
      findings: [
        {
          source_finding_id: stored!.sourceFindingId,
          evidence: stored!.evidence,
        },
      ],
      excluded: [],
    };
    const replay = await fixture.prepareNormalized(listed);
    expect((await replay.import()).counts.unchanged).toBe(1);
    await expect(
      prepareNormalizedExternalPublication(
        listed,
        { ...options, repository: "repo-example", provider: "wiz" },
        cloudCatalog(fixture.environment, snykOptions.sourceRepositoryUrl),
      ),
    ).rejects.toThrow(/requires the snyk provider/i);
    const complete = await fixture.prepareNormalized(full);
    expect((await complete.import()).counts.created).toBe(0);
    expect(await fixture.read()).toHaveLength(1);
  },
);

test("unmarked native v1 rows survive unrelated issueJson data", async () => {
  const { read, findings, excluded } = normalizeSnykIssues(
    snykRestFixture("open-source"),
  );
  const row = findings[0]!;
  const original = row.evidence.source_data!;
  row.evidence.source_data = {
    ...snykOptions,
    apiVersion: original["apiVersion"],
    project: JSON.parse(String(original["projectJson"])),
    target: null,
    issue: JSON.parse(String(original["issueJson"])),
    issueJson: "{}",
  };
  await using fixture = await snykLocalFixture({
    remote: snykOptions.sourceRepositoryUrl,
  });
  const result = await fixture.prepareNormalized({ read, findings, excluded });
  expect((await result.import()).counts.created).toBe(1);
});

test("a complete SDK row replays with reformatted native JSON and reader annotations", async () => {
  const wire = snykRestFixture("open-source");
  const report = normalizeSnykIssues(wire);
  const row = report.findings[0]!;
  row.evidence.title = "Reader title";
  const retained = row.evidence.source_data!;
  retained["readerNote"] = "preserved";
  await using fixture = await snykLocalFixture({
    remote: snykOptions.sourceRepositoryUrl,
  });
  const prepare = () => fixture.prepareNormalized(report);
  expect((await (await prepare()).import()).counts.created).toBe(1);
  for (const field of ["projectJson", "issueJson"]) {
    const entries = Object.entries(JSON.parse(String(retained[field])));
    retained[field] = JSON.stringify(
      Object.fromEntries(entries.reverse()),
      null,
      2,
    );
  }
  retained["targetJson"] = " null\n";
  const key = retained["snykRestIssueKey"];
  delete retained["snykRestIssueKey"];
  delete retained["format"];
  expect((await (await prepare()).import()).counts.unchanged).toBe(1);
  const [stored] = await fixture.read();
  expect(stored!.version).toBe(1);
  expect(stored!.evidence.title).toBe("Reader title");
  expect(stored!.evidence.source_data).toMatchObject({
    format: wire.format,
    snykRestIssueKey: key,
    readerNote: "preserved",
  });
});

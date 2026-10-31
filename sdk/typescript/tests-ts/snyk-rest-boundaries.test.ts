import { expect, mock, test } from "bun:test";
import { readSnykFindings } from "../src/snyk-findings.js";
import { snykJson, snykSarif } from "./support/snyk-import-fixtures.js";
import { prepareNormalizedExternalPublication } from "../src/external-findings-publish.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { normalizeSnykIssues } from "../src/snyk-rest-findings.js";
import {
  snykIssue,
  snykLocalFixture,
  snykOptions,
  snykRestFixture,
} from "./support/snyk-rest-fixtures.js";

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
  const prepare = (checkout = fixture) =>
    prepareNormalizedLocalImport(
      report,
      {
        provider: "snyk",
        sourceKey: checkout.sourceKey,
        repository: checkout.repository,
      },
      { environment: checkout.environment },
    );
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

test("normalized Snyk REST Open Source rows cannot publish to Cloud", async () => {
  const report = snykRestFixture("open-source");
  const normalized = normalizeSnykIssues(report);
  const fetch = mock(async () => {
    throw new Error("Unexpected Cloud request");
  });
  await expect(
    prepareNormalizedExternalPublication(
      normalized,
      {
        provider: "snyk",
        repository: "https://github.com/example/another",
        sourceKey: "example",
      },
      { environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" }, fetch },
    ),
  ).rejects.toThrow("local import");
  expect(fetch).not.toHaveBeenCalled();
  expect(() => normalizeSnykIssues(report, "cloud")).toThrow("local import");
});

test("an empty normalized Snyk capture keeps its local publication boundary", async () => {
  const capture = snykRestFixture("open-source");
  capture.pages[0]!.responseJson = JSON.stringify({ data: [], links: {} });
  const normalized = normalizeSnykIssues(capture);
  expect(normalized.findings).toHaveLength(0);
  await expect(
    prepareNormalizedExternalPublication(
      normalized,
      {
        provider: "snyk",
        repository: "https://github.com/example/another",
        sourceKey: "example",
      },
      { environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" } },
    ),
  ).rejects.toThrow("Snyk REST findings require a local import");
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
    prepareNormalizedLocalImport(
      { read, findings, excluded },
      {
        provider: "snyk",
        sourceKey: f.sourceKey,
        repository: f.repository,
      },
      { environment: f.environment },
    ),
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
  const prepare = () =>
    prepareNormalizedLocalImport(
      second,
      { provider: "snyk", sourceKey: f.sourceKey, repository: f.repository },
      { environment: f.environment },
    );
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
    projectJson: "{}",
    issueJson: "{}",
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
    source_data["issue"] = issue;
    source_data["issueJson"] = JSON.stringify(issue);
    if (id === original.id) source_data["format"] = "wiz-export/v1";
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
  expect(credentials).toHaveBeenCalledTimes(4);
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
  const prepare = () =>
    prepareNormalizedLocalImport(
      report,
      {
        provider: "snyk",
        repository: fixture.repository,
        sourceKey: fixture.sourceKey,
      },
      { environment: fixture.environment },
    );
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
  const credentials = mock(async () => {
    throw new Error("Unexpected Cloud credentials");
  });
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
      prepareNormalizedExternalPublication(projected, opts, {
        environment: f.environment,
        credentials,
      }),
    ).rejects.toThrow("local import");
    await expect(
      prepareNormalizedLocalImport(projected, opts, {
        environment: f.environment,
      }),
    ).rejects.toThrow(/Snyk|snyk-rest/);
  }
  const mismatched = { ...legacy.project, id: snykOptions.organizationId };
  for (const resources of [
    { project: mismatched, issue: legacy.issue, target: null },
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
  ]) {
    row.evidence.source_data = {
      ...snykOptions,
      apiVersion: original["apiVersion"],
      ...resources,
    };
    await expect(
      prepareNormalizedExternalPublication(projected, opts, {
        environment: f.environment,
        credentials,
      }),
    ).rejects.toThrow("local import");
    await expect(
      prepareNormalizedLocalImport(projected, opts, {
        environment: f.environment,
      }),
    ).rejects.toThrow(
      "snykRestIssueKey" in resources ? /Snyk/ : /different project/,
    );
  }
  for (const missing of ["issueJson", "projectJson"]) {
    row.evidence.source_data = { ...original, format: "reader/v1" };
    delete row.evidence.source_data[missing];
    await expect(
      prepareNormalizedExternalPublication(projected, opts, {
        environment: f.environment,
        credentials,
      }),
    ).rejects.toThrow("local import");
    await expect(
      prepareNormalizedLocalImport(projected, opts, {
        environment: f.environment,
      }),
    ).rejects.toThrow(/Snyk|snyk-rest/);
  }
  row.source_finding_id = normalizeSnykIssues(
    snykRestFixture("open-source"),
  ).findings[0]!.source_finding_id;
  row.evidence.source_data = {
    ...original,
    project: legacy.project,
    issue: legacy.issue,
  };
  await expect(
    prepareNormalizedLocalImport(
      projected,
      { ...opts, provider: "snyk" },
      { environment: f.environment },
    ),
  ).rejects.toThrow("both v1 and v2");
  expect(credentials).not.toHaveBeenCalled();
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

  const credentials = mock(async () => {
    throw new Error("Unexpected Cloud credentials");
  });
  await using matching = await snykLocalFixture({ remote: repository });
  const options = {
    provider: "snyk" as const,
    sourceKey: "project",
    repository: matching.repository,
  };
  await expect(
    prepareNormalizedExternalPublication(
      serialized,
      { ...options, repository: other },
      { environment: matching.environment, credentials },
    ),
  ).rejects.toThrow("local import");
  expect(credentials).not.toHaveBeenCalled();
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
  const report = normalizeSnykIssues(capture);
  const code = snykRestFixture("code");
  const otherId = "aaaa0000-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const replace = (old: string) =>
    JSON.parse(
      JSON.stringify(capture).replaceAll(old, otherId),
    ) as typeof capture;
  const credentials = mock(async () => {
    throw new Error("Unexpected credentials");
  });
  await using f = await snykLocalFixture({
    remote: report.sourceRepositoryUrl,
  });
  const original = report.findings[0]!;
  for (const other of [
    replace(capture.organizationId),
    replace(capture.projectId),
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
      await expect(
        prepareNormalizedLocalImport(
          input,
          {
            provider: "snyk",
            sourceKey: f.sourceKey,
            repository: f.repository,
          },
          { environment: f.environment },
        ),
      ).rejects.toThrow("Snyk project scope");
    }
    await expect(
      prepareNormalizedExternalPublication(
        report,
        {
          provider: "snyk",
          sourceKey: f.sourceKey,
          repository: report.sourceRepositoryUrl,
        },
        { environment: f.environment, credentials },
      ),
    ).rejects.toThrow(/Snyk|snyk-rest/);
  }
  expect(credentials).not.toHaveBeenCalled();
  expect(await f.read()).toHaveLength(0);
});

test.each(["v1", "v2"] as const)(
  "a linked %s issue projection uses its report's project and stays local",
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
    const credentials = mock(async () => {
      throw new Error("Unexpected Cloud credentials");
    });
    const { read, findings, excluded } = report;
    await expect(
      prepareNormalizedExternalPublication(
        { read, findings, excluded },
        { ...options, provider: "wiz" },
        { environment: fixture.environment, credentials },
      ),
    ).rejects.toThrow("local import");
    expect(credentials).not.toHaveBeenCalled();
    const prepare = () =>
      prepareNormalizedLocalImport(report, options, {
        environment: fixture.environment,
      });
    await expect(prepare()).rejects.toThrow("selected project");
    row.evidence.source_data = project(snykOptions.projectId);
    await expect(prepare()).rejects.toThrow("normalized finding ID");
    row.source_finding_id = nativeId;
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
    const replay = await prepareNormalizedLocalImport(listed, options, {
      environment: fixture.environment,
    });
    expect((await replay.import()).counts.unchanged).toBe(1);
    await expect(
      prepareNormalizedExternalPublication(
        listed,
        { ...options, provider: "wiz" },
        { environment: fixture.environment, credentials },
      ),
    ).rejects.toThrow("local import");
    expect(credentials).not.toHaveBeenCalled();
    const complete = await prepareNormalizedLocalImport(full, options, {
      environment: fixture.environment,
    });
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
  const result = await prepareNormalizedLocalImport(
    { read, findings, excluded },
    {
      provider: "snyk",
      sourceKey: fixture.sourceKey,
      repository: fixture.repository,
    },
    { environment: fixture.environment },
  );
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
  const prepare = () =>
    prepareNormalizedLocalImport(
      report,
      {
        provider: "snyk",
        repository: fixture.repository,
        sourceKey: fixture.sourceKey,
      },
      { environment: fixture.environment },
    );
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
  expect((await (await prepare()).import()).counts.unchanged).toBe(1);
  const [stored] = await fixture.read();
  expect(stored!.version).toBe(1);
  expect(stored!.evidence.title).toBe("Reader title");
  expect(stored!.evidence.source_data!["readerNote"]).toBe("preserved");
});

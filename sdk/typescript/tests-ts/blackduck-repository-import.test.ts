import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { normalizeBlackDuckFindings } from "../src/blackduck-findings.js";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import type { ExternalFinding } from "../src/external-findings.js";
import { readVendorFindings } from "../src/wiz-findings.js";
import { normalizeInspectorFindings } from "../src/inspector-findings.js";
import {
  localFindingsFixture,
  localReportFixture,
} from "./external-findings-local-helpers.js";
import { githubDependabotAlert } from "./support/github-dependabot-fixtures.js";
import {
  inspectorPackageFinding,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";
import {
  blackDuckBomReport,
  blackDuckBomRow,
} from "./support/blackduck-import-fixtures.js";

test("Black Duck keeps package occurrences unassessed across replay, mitigation, and missing rows", async () => {
  const sourceRepositoryUrl = "https://git.example.test/project.git";
  await using fixture = await localFindingsFixture({
    remote: sourceRepositoryUrl,
  });
  const path = join(fixture.root, "vulnerable-components.json.gz");
  const options = {
    provider: "blackduck" as const,
    sourceRepositoryUrl,
    repository: fixture.repository,
    sourceKey: "scanner/project-a/release-a",
  };
  const dependencies = { environment: fixture.environment };
  const prepare = async (input: unknown) => {
    await writeFile(path, gzipSync(JSON.stringify(input)));
    return prepareLocalExternalImport(path, options, dependencies);
  };
  const row = {
    ...blackDuckBomRow(),
    packageUrl: "pkg:golang/git.example.test/team/module/v2@v2.1.0",
  };
  const first = await prepare(blackDuckBomReport([row]));
  expect((await first.import()).counts.created).toBe(1);
  expect((await (await prepare([row])).import()).counts.unchanged).toBe(1);
  const mitigated = {
    ...row,
    vulnerabilityWithRemediation: {
      ...row.vulnerabilityWithRemediation,
      remediationStatus: "MITIGATED",
    },
  };
  expect(
    (await (await prepare(blackDuckBomReport([mitigated]))).import()).counts
      .updated,
  ).toBe(1);
  await expect(
    prepare({ ...blackDuckBomReport([row]), totalCount: 20 }),
  ).rejects.toThrow();
  expect(
    (await (await prepare(blackDuckBomReport([]))).import()).counts,
  ).toEqual({
    created: 0,
    updated: 0,
    unchanged: 0,
  });
  const records = await listLocalExternalFindings(options, dependencies);
  expect(records).toHaveLength(1);
  expect(records[0]).toMatchObject({
    provider: "blackduck",
    sourceFindingId: first.preview.findings[0]!.source_finding_id,
    version: 2,
    evidence: {
      packages: [
        {
          name: "git.example.test/team/module/v2",
          ecosystem: "golang",
          installed_version: "v2.1.0",
        },
      ],
    },
    assessment: { state: "not_assessed" },
  });
  const mixed = structuredClone(first.preview);
  mixed.findings.push(
    ...normalizeBlackDuckFindings(
      [blackDuckBomRow(undefined, "release-b")],
      sourceRepositoryUrl,
      "local",
    ).findings,
  );
  await expect(
    prepareNormalizedLocalImport(mixed, options, dependencies),
  ).rejects.toThrow(/same project version/);
  const altered = structuredClone(first.preview);
  altered.findings[0]!.evidence.details = {
    kind: "sast",
    repository: { url: "https://github.com/example/other" },
  };
  await expect(
    prepareNormalizedLocalImport(altered, options, dependencies),
  ).rejects.toThrow(/retained scanner repository/i);
  const remote = sourceRepositoryUrl + "?repo=other";
  fixture.git("remote", "set-url", "origin", remote);
  await expect(
    prepareNormalizedLocalImport(first.preview, options, dependencies),
  ).rejects.toThrow(/does not match a configured remote/);
});

test("Black Duck binds normalized summaries to native findings and comparable remotes", async () => {
  const source = "https://git.example.test/team/application";
  await using fixture = await localFindingsFixture({ remote: source });
  const other = "https://git.example.test/team/other";
  const report = normalizeBlackDuckFindings(
    [blackDuckBomRow()],
    source,
    "local",
  );
  const native = report.findings[0]!;
  const sourceRepositories: { url: string; platform: "github" }[] = [];
  const prepare = (...findings: typeof report.findings) =>
    prepareNormalizedLocalImport(
      { read: findings.length, findings, excluded: [] },
      {
        provider: "blackduck",
        sourceKey: "example",
        repository: fixture.repository,
      },
      { environment: fixture.environment, sourceRepositories },
    );

  fixture.git("remote", "add", "upstream", other + "?repo=different");
  const typed = (id: string, url: string) => ({
    source_finding_id: id,
    evidence: {
      title: "Example",
      severity: "unknown" as const,
      details: { kind: "sast" as const, repository: { url } },
    },
  });
  for (const alias of [
    "ssh://git@git.example.test/team/application.git",
    "https://git.example.test:443/team/application.git",
  ]) {
    const summary = typed("sdk-source", alias);
    await prepare(native, summary);
    await prepare({
      ...native,
      evidence: { ...native.evidence, details: summary.evidence.details },
    });
  }
  for (const declaration of [
    { details: { kind: "sast" as const, repository: { url: other } } },
    { source_data: { sourceRepositoryUrl: other } },
  ]) {
    const summary = {
      source_finding_id: "sdk-summary",
      evidence: {
        title: "Example",
        severity: "unknown" as const,
        ...declaration,
      },
    };
    await expect(prepare(summary, typed("sdk-source", source))).rejects.toThrow(
      /same project version/,
    );
    await expect(prepare(summary, native)).rejects.toThrow(
      /same project version/,
    );
    await expect(prepare(summary)).rejects.toThrow(
      /does not match a configured remote/,
    );
  }

  // An HTTPS row between two SSH rows cannot erase a conflicting login or path mode.
  for (const conflicting of [
    "bob@git.example.test:team/application.git",
    "ssh://alice@git.example.test/team/application.git",
  ]) {
    await expect(
      prepare(
        typed("first", "alice@git.example.test:team/application.git"),
        native,
        typed("second", conflicting),
      ),
    ).rejects.toThrow(/same project version/);
  }

  const alias = typed(
    "case-alias",
    "https://git.example.test/Team/Application",
  );
  await expect(prepare(native, alias)).rejects.toThrow(/same project version/);
  sourceRepositories.push({ url: source, platform: "github" });
  await prepare(native, alias);
  await prepare(typed("sdk-source", source), alias);

  fixture.git("remote", "set-url", "upstream", other);
  const reference = { url: other, platform: "github" as const };
  sourceRepositories.push(reference);
  const pending = prepare(native);
  reference.url = source;
  await expect(pending).rejects.toThrow(/same project version/);

  const projected = {
    source_finding_id: native.source_finding_id,
    evidence: {
      title: "Example",
      severity: "unknown" as const,
      source_data: { sourceRepositoryUrl: source },
    },
  };
  const prepareWiz = (findings: typeof report.findings, urls: string[]) =>
    prepareNormalizedLocalImport(
      { read: findings.length, findings, excluded: [] },
      { provider: "wiz", sourceKey: "example", repository: fixture.repository },
      {
        environment: fixture.environment,
        sourceRepositories: urls.map((url) => ({ url })),
      },
    );
  const second = typed("wiz-row", other);
  await expect(
    prepareWiz(
      [
        {
          ...projected,
          evidence: { ...projected.evidence, details: second.evidence.details },
        },
      ],
      [],
    ),
  ).rejects.toThrow(/retained scanner repository/i);
  await expect(prepareWiz([projected], [other])).rejects.toThrow(
    /reader repository/i,
  );
  await expect(prepareWiz([projected], [source, other])).rejects.toThrow(
    /reader repository/i,
  );
  await prepareWiz([projected, second], [source, other]);
});

function projection(url: string): ExternalFinding {
  return {
    source_finding_id: "blackduck-bom:" + "a".repeat(64),
    evidence: {
      title: "Projected package",
      severity: "high",
      source_data: { sourceRepositoryUrl: url },
    },
  };
}

test.each([
  [
    "https://git.example.test/Team/Project",
    "https://git.example.test/Team/Project?repo=other",
  ],
  [
    "https://git.example.test/Team/Project%20data",
    "git@git.example.test:Team/Project%20data",
  ],
])(
  "projected source %s cannot use checkout remote %s",
  async (source, remote) => {
    await using f = await localFindingsFixture({ remote });
    await expect(
      prepareNormalizedLocalImport(
        { read: 1, findings: [projection(source)], excluded: [] },
        { provider: "wiz", repository: f.repository, sourceKey: "example" },
        { environment: f.environment },
      ),
    ).rejects.toThrow(/does not match a configured remote/);
  },
);

test("a Wiz file can combine projected and native package repositories", async () => {
  await using f = await localReportFixture("wiz.json", {
    provider: "wiz",
    sourceKey: "example",
  });
  const record = {
    id: "wiz-1",
    name: "CVE-2099-0001",
    detailedName: "example",
    vendorSeverity: "HIGH",
    vulnerableAsset: {
      id: "branch-1",
      nativeType: "github#repositoryBranch",
      cloudProviderURL: "https://github.com/example/other/tree/main",
    },
  };
  await f.writeJson([projection(inspectorRepositoryUrl), record]);
  expect((await (await f.prepare()).import()).counts.created).toBe(2);

  const source = "https://git.example.test/Team/Project";
  const remote = source.toLowerCase();
  f.git("remote", "add", "origin", remote);
  record.vulnerableAsset.cloudProviderURL = remote + "/tree/main";
  const projected = {
    ...record,
    id: projection(source).source_finding_id,
    sourceRepositoryUrl: source,
  };
  const normalized = async () =>
    prepareNormalizedLocalImport(
      await readVendorFindings(f.file, "local"),
      { provider: "wiz", sourceKey: f.sourceKey, repository: f.repository },
      { environment: f.environment, sourceRepositories: [{ url: remote }] },
    );
  for (const prepare of [() => f.prepare(), normalized]) {
    await f.writeJson([
      { ...projected, vulnerableAsset: { id: "other-asset" } },
      record,
    ]);
    await expect(prepare()).rejects.toThrow(
      /does not match a configured remote/,
    );
    await f.writeJson([projected, record]);
    expect((await prepare()).preview.findings).toHaveLength(2);
  }
});

test("GitHub owns the casing of a projected Enterprise repository", async () => {
  const source = "https://git.example.test/Team/Project";
  await using f = await localFindingsFixture({ remote: source });
  const report = { read: 1, findings: [projection(source)], excluded: [] };
  const settings = { repository: f.repository, sourceKey: "example" };
  const dependencies = {
    environment: f.environment,
    sourceRepositories: [{ url: source.toLowerCase() }],
  };
  await expect(
    prepareNormalizedLocalImport(
      report,
      { ...settings, provider: "wiz" },
      dependencies,
    ),
  ).rejects.toThrow(/reader repository/i);
  await prepareNormalizedLocalImport(
    report,
    { ...settings, provider: "github" },
    dependencies,
  );
});

test.each(["github", "inspector"] as const)(
  "%s native repository also binds the projected source",
  async (provider) => {
    await using f = await localFindingsFixture();
    const findings = (url: string) => {
      const row = projection(url);
      if (provider === "inspector")
        return [
          ...normalizeInspectorFindings(
            { findings: [inspectorPackageFinding()] },
            inspectorRepositoryUrl,
            "local",
          ).findings,
          row,
        ];
      row.evidence.url = githubDependabotAlert().html_url;
      return [row];
    };
    const prepare = (url: string) => {
      const rows = findings(url);
      return prepareNormalizedLocalImport(
        { read: rows.length, findings: rows, excluded: [] },
        { provider, sourceKey: "example", repository: f.repository },
        { environment: f.environment },
      );
    };
    await prepare(inspectorRepositoryUrl);
    await expect(prepare("https://github.com/example/other")).rejects.toThrow(
      /repository|Dependabot alert/i,
    );
  },
);

test.each(["snyk", "endor"] as const)(
  "%s provenance binds its own projected row and allows separate repository rows",
  async (provider) => {
    await using f = await localFindingsFixture();
    const a = "https://git.example.test/team/a";
    const b = "https://git.example.test/team/b";
    const provenance =
      provider === "snyk"
        ? {
            format: "snyk-findings-export/v1",
            collection: { target: { repository: b } },
          }
        : { runContext: { versionControlProvenance: [{ repositoryUri: b }] } };
    const prepare = (findings: ExternalFinding[], urls: string[] = []) =>
      prepareNormalizedLocalImport(
        { read: findings.length, findings, excluded: [] },
        { provider, repository: f.repository, sourceKey: "example" },
        {
          environment: f.environment,
          sourceRepositories: urls.map((url) => ({ url })),
        },
      );
    const row = projection(a);
    await prepare(
      [
        row,
        {
          source_finding_id: "metadata",
          evidence: { ...row.evidence, source_data: { runContext: "nightly" } },
        },
        {
          source_finding_id: "native",
          evidence: { ...row.evidence, source_data: provenance },
        },
      ],
      [a, b],
    );
    row.evidence.source_data = { ...row.evidence.source_data, ...provenance };
    await expect(prepare([row])).rejects.toThrow(/original provider finding/);
  },
);

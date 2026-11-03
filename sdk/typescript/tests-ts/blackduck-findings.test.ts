import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  blackDuckReportRepositories,
  normalizeBlackDuckFindings,
  readBlackDuckFindings,
} from "../src/blackduck-findings.js";
import {
  blackDuckBomReport,
  blackDuckBomRow,
} from "./support/blackduck-import-fixtures.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const repository = "https://vcs.example.test/team/application";

function retainedUrl(
  source_data: Record<string, unknown> | undefined,
  source_finding_id = "sdk-key",
) {
  const repositories = blackDuckReportRepositories(
    "blackduck",
    [
      {
        source_finding_id,
        evidence: { title: "Example", severity: "unknown", source_data },
      },
    ],
    "cloud",
  );
  return repositories.get(source_finding_id)?.url;
}

test("retains the complete BOM row, project version and caller's repository, not a fix or assessment", () => {
  const row = {
    ...blackDuckBomRow(),
    ignored: true,
    packageUrl: "pkg:maven/example/library@1.0",
    license: { licenseDisplay: "Example license" },
    vulnerabilityWithRemediation: {
      ...blackDuckBomRow().vulnerabilityWithRemediation,
      remediationStatus: "REMEDIATION_COMPLETE",
      description: "Vendor description",
      cweId: "CWE-79",
      relatedVulnerability:
        "https://scanner.example.test/api/vulnerabilities/CVE%2D2099-1000",
      vulnerabilityUpdatedDate: "2026-01-01T00:00:00Z",
      extension: { values: [42] },
    },
  };
  const input = {
    ...blackDuckBomReport([row]),
    appliedFilters: ["ignored:true"],
  };
  const original = structuredClone(row);
  const result = normalizeBlackDuckFindings(input, repository);
  expect(result).toEqual(normalizeBlackDuckFindings([row], repository));
  expect(result).toEqual(
    normalizeBlackDuckFindings(input, repository, "local"),
  );
  expect(result.excluded).toEqual([]);
  const evidence = result.findings[0]!.evidence;
  expect(evidence).toMatchObject({
    title: "BDSA-2099-0001 in Example Library",
    severity: "high",
    description: "Vendor description",
    advisory_ids: [
      "BDSA-2099-0001",
      row.vulnerabilityWithRemediation.relatedVulnerability,
    ],
    packages: [
      {
        name: "example:library",
        ecosystem: "maven",
        installed_version: "1.0",
        fixed_versions: [],
        manifest_path: null,
      },
    ],
    locations: [],
    source_updated_at: null,
  });
  expect(evidence.source_data).toEqual({
    format: "blackduck-bom-6",
    sourceRepositoryUrl: repository,
    projectVersionUrl:
      "https://scanner.example.test/api/projects/project-a/versions/release-a",
    row: original,
  });
  expect(evidence.details).toBeUndefined();
  row.vulnerabilityWithRemediation.extension.values.push(99);
  expect(evidence.source_data?.["row"]).toEqual(original);
});

test("replay keeps native occurrence identity when package coordinates and advisory aliases change", () => {
  const row = blackDuckBomRow();
  const original = normalizeBlackDuckFindings([row], repository).findings[0]!;
  expect(original.evidence.packages).toMatchObject([
    { name: "example:library", ecosystem: "maven", installed_version: "1.0" },
  ]);
  const updated = {
    ...row,
    componentName: "Renamed library",
    componentVersionOriginName: "npmjs",
    componentVersionOriginId: "@example/library/2.0",
    vulnerabilityWithRemediation: {
      ...row.vulnerabilityWithRemediation,
      relatedVulnerability: row.vulnerabilityWithRemediation.vulnerabilityName,
    },
  };
  const replay = normalizeBlackDuckFindings([updated], repository).findings[0]!;
  expect(replay.source_finding_id).toBe(original.source_finding_id);
  expect(replay.evidence.advisory_ids).toEqual(["BDSA-2099-0001"]);
  expect(replay.evidence.packages).toMatchObject([
    { name: "@example/library", ecosystem: "npm", installed_version: "2.0" },
  ]);
  for (const scope of ["%40example", "@example"]) {
    const purl = {
      ...updated,
      packageUrl: `pkg:npm/${scope}/other@3.0?tag=preview#dist`,
    };
    expect(
      normalizeBlackDuckFindings([purl], repository).findings[0]!.evidence
        .packages,
    ).toMatchObject([
      { name: "@example/other", ecosystem: "npm", installed_version: "3.0" },
    ]);
  }
  const opaque = {
    ...updated,
    componentVersionOriginName: "custom",
    componentVersionOriginId: "opaque",
  };
  const finding = normalizeBlackDuckFindings([opaque], repository).findings[0]!;
  expect(finding.source_finding_id).toBe(original.source_finding_id);
  expect(finding.evidence.packages).toEqual([]);
  expect(finding.evidence.source_data?.["row"]).toEqual(opaque);
});

test("uses the full generic package path and keeps the origin fallback for an invalid namespace", () => {
  const row = blackDuckBomRow();
  const packages = (packageUrl: string) =>
    normalizeBlackDuckFindings([{ ...row, packageUrl }], repository)
      .findings[0]!.evidence.packages;
  expect(packages("pkg:generic/tools/example/library@2.0")).toMatchObject([
    {
      name: "tools/example/library",
      ecosystem: "generic",
      installed_version: "2.0",
    },
  ]);
  for (const invalid of [
    "pkg:npm/unscoped/library@2.0",
    "pkg:maven/extra/group/library@2.0",
    "pkg:pypi/extra/library@2.0",
    "pkg:pypi/extra%2Flibrary@2.0",
    "pkg:composer/library@2.0",
  ])
    expect(packages(invalid)).toMatchObject([
      { name: "example:library", ecosystem: "maven", installed_version: "1.0" },
    ]);
});

test("uses the matching native coordinate for a versionless package URL", () => {
  const row = { ...blackDuckBomRow(), componentVersionName: "display label" };
  const packages = (packageUrl: string) =>
    normalizeBlackDuckFindings([{ ...row, packageUrl }], repository)
      .findings[0]!.evidence.packages;
  expect(packages("pkg:maven/example/library")).toMatchObject([
    { name: "example:library", installed_version: "1.0" },
  ]);
  expect(packages("pkg:maven/another/library")).toMatchObject([
    { name: "another:library", installed_version: "display label" },
  ]);
});

test("adding or omitting an unrelated row and changing collection paging metadata do not version retained evidence", () => {
  const row = blackDuckBomRow();
  const other = blackDuckBomRow("BDSA-2099-0002");
  const report = blackDuckBomReport([row, other]);
  report._meta.href += "?offset=0&limit=250";
  for (const target of ["cloud", "local"] as const) {
    const retained = normalizeBlackDuckFindings([row], repository, target)
      .findings[0];
    expect(
      normalizeBlackDuckFindings(report, repository, target).findings[0],
    ).toEqual(retained);
    expect(
      normalizeBlackDuckFindings(blackDuckBomReport([row]), repository, target)
        .findings[0],
    ).toEqual(retained);
  }
});

test("only a complete project-version collection can establish an empty selection", () => {
  const empty = blackDuckBomReport([]);
  expect(normalizeBlackDuckFindings(empty, repository)).toEqual({
    read: 0,
    findings: [],
    excluded: [],
  });
  for (const totalCount of [5, -1, "0", null, undefined])
    expect(() =>
      normalizeBlackDuckFindings({ ...empty, totalCount }, repository),
    ).toThrow(/totalCount/);
  for (const input of [
    [],
    {},
    { items: [], totalCount: 0 },
    { scanStatus: "SUCCESS" },
  ])
    expect(() => normalizeBlackDuckFindings(input, repository)).toThrow();
  for (const suffix of ["?offset=1", "?offset=0&offset=3"])
    expect(() =>
      normalizeBlackDuckFindings(
        { ...empty, _meta: { href: empty._meta.href + suffix } },
        repository,
      ),
    ).toThrow(/page/);
  for (const rel of ["next", "prev"])
    expect(() =>
      normalizeBlackDuckFindings(
        {
          ...empty,
          _meta: {
            ...empty._meta,
            links: [{ rel, href: "https://elsewhere.example.test/page" }],
          },
        },
        repository,
      ),
    ).toThrow(/page/);
  expect(() =>
    normalizeBlackDuckFindings(
      {
        ...empty,
        _meta: {
          href: empty._meta.href.replace(
            "vulnerable-bom-components",
            "components",
          ),
        },
      },
      repository,
    ),
  ).toThrow(/vulnerable-bom-components/);
});

test("selected array replay keeps distinct advisories, origins and sources; evidence edits keep identity", () => {
  const first = blackDuckBomRow();
  const second = blackDuckBomRow("BDSA-2099-0002");
  const alternateSource = {
    ...first,
    vulnerabilityWithRemediation: {
      ...first.vulnerabilityWithRemediation,
      source: "NVD",
    },
  };
  const alternateOrigin = blackDuckBomRow();
  alternateOrigin._meta.links[0]!.href =
    alternateOrigin._meta.links[0]!.href.replace("origin-a", "origin-b");
  const rows = [first, second, alternateSource, alternateOrigin];
  const result = normalizeBlackDuckFindings(
    blackDuckBomReport(rows),
    repository,
  );
  const ids = result.findings.map((finding) => finding.source_finding_id);
  expect(new Set(ids).size).toBe(4);
  first.vulnerabilityWithRemediation.severity = "LOW";
  first.vulnerabilityWithRemediation.remediationStatus = "IGNORED";
  const selection = normalizeBlackDuckFindings(rows.toReversed(), repository);
  expect(
    selection.findings.map((finding) => finding.source_finding_id),
  ).toEqual(ids.toReversed());
  expect(
    selection.findings.map(({ evidence }) => evidence.source_data?.["row"]),
  ).toEqual(rows.toReversed());
  expect(selection.findings.at(-1)!.evidence.severity).toBe("low");
  const duplicated = normalizeBlackDuckFindings(
    [first, second, first],
    repository,
  );
  expect(duplicated.findings).toHaveLength(1);
  expect(() =>
    normalizeBlackDuckFindings(
      blackDuckBomReport([first, second, first]),
      repository,
    ),
  ).toThrow(/pages may overlap/i);
  expect(
    duplicated.excluded.map(({ position, source_finding_id }) => [
      position,
      source_finding_id,
    ]),
  ).toEqual([
    [1, ids[0]!],
    [3, ids[0]!],
  ]);
});

test("rejects overlapping complete pages even when a repeated row has no occurrence ID", () => {
  const row = blackDuckBomRow();
  const incomplete = { ...row, _meta: { links: [] } };
  const reversed = Object.fromEntries(Object.entries(incomplete).reverse());
  const report = blackDuckBomReport([row, incomplete]);
  expect(normalizeBlackDuckFindings(report, repository).excluded).toHaveLength(
    1,
  );
  expect(() =>
    normalizeBlackDuckFindings(
      { ...report, totalCount: 3, items: [...report.items, reversed] },
      repository,
    ),
  ).toThrow(/pages may overlap/);
});

test("unrelated provider columns can share Black Duck field names", () => {
  const finding = {
    source_finding_id: "wiz-finding",
    evidence: {
      title: "Example",
      severity: "unknown" as const,
      source_data: {
        row: {
          componentVersion: "1.0",
          vulnerabilityWithRemediation: { status: "open" },
        },
      },
    },
  };
  expect(blackDuckReportRepositories("wiz", [finding], "cloud").size).toBe(0);
});

test("collection and every selected occurrence must identify the same server, project and version", () => {
  const row = blackDuckBomRow();
  for (const key of ["scanner.example.test", "project-a", "release-a"]) {
    const other = blackDuckBomRow();
    other._meta.links[0]!.href = other._meta.links[0]!.href.replace(
      key,
      "other",
    );
    for (const input of [
      blackDuckBomReport([other]),
      [row, other],
      [other, row],
    ])
      expect(() => normalizeBlackDuckFindings(input, repository)).toThrow(
        /same project version/,
      );
  }
  const envelope = blackDuckBomReport([row]);
  envelope._meta.href = envelope._meta.href.replace("/projects/", "/project/");
  expect(
    normalizeBlackDuckFindings(envelope, repository).findings[0]!
      .source_finding_id,
  ).toBe(
    normalizeBlackDuckFindings([row], repository).findings[0]!
      .source_finding_id,
  );
  const origin = {
    rel: "vulnerabilities",
    href: `${row.componentVersion}/origin/origin-a/vulnerabilities`,
  };
  const unscoped = { ...row, _meta: { links: [origin] } };
  expect(() => normalizeBlackDuckFindings([row, unscoped], repository)).toThrow(
    /Each selected/,
  );
  expect(
    normalizeBlackDuckFindings(blackDuckBomReport([unscoped]), repository)
      .findings[0]!.source_finding_id,
  ).toBe(
    normalizeBlackDuckFindings([row], repository).findings[0]!
      .source_finding_id,
  );
  row._meta.links.push({
    ...origin,
    href: origin.href.replace("origin-a", "origin-b"),
  });
  expect(
    normalizeBlackDuckFindings([row], repository).excluded[0]!.reason,
  ).toMatch(/unambiguous/);
});

test("invalid components and non-vulnerability rows are diagnosed without inventing occurrences", () => {
  const row = blackDuckBomRow();
  const report = blackDuckBomReport();
  const noOrigin = { ...row, _meta: { links: [] } };
  const result = normalizeBlackDuckFindings(
    {
      ...report,
      items: [
        row,
        { license: {} },
        { policyStatus: "IN_VIOLATION" },
        {
          ...row,
          componentVersion: row.componentVersion.replace(
            "component-a",
            "component-b",
          ),
        },
        noOrigin,
        { ...row, _meta: { links: null } },
      ],
      totalCount: 6,
    },
    repository,
  );
  expect(result.findings).toHaveLength(1);
  expect(result.excluded.map(({ position }) => position)).toEqual([
    2, 3, 4, 5, 6,
  ]);
  expect(result.excluded.map(({ reason }) => reason)).toEqual([
    expect.stringContaining("vulnerabilityWithRemediation"),
    expect.stringContaining("vulnerabilityWithRemediation"),
    expect.stringContaining("contradicts"),
    expect.stringContaining("origin"),
    expect.stringContaining("_meta.links"),
  ]);
  const other = blackDuckBomRow(undefined, "release-b");
  expect(() =>
    normalizeBlackDuckFindings(
      {
        ...report,
        items: [{ ...other, _meta: { links: [null, ...other._meta.links] } }],
      },
      repository,
    ),
  ).toThrow(/same project version/);
  const large = { ...row, extra: "x".repeat(270_000) };
  expect(normalizeBlackDuckFindings([large], repository).excluded).toHaveLength(
    1,
  );
  expect(
    normalizeBlackDuckFindings([large], repository, "local").findings[0]!
      .evidence.source_data?.["row"],
  ).toEqual(large);
});

test.each([
  "",
  "not a URL",
  "file:///team/repo",
  "https:vcs.example.test/team/repo",
  "https://vcs.example.test",
  "https://vcs.example.test/",
  "https://vcs.example.test/team/",
  "https://@vcs.example.test/team/repo",
  "https://user:password@vcs.example.test/team/repo",
  `${repository}?token=example`,
  `${repository}#branch`,
  `${repository}?`,
  `${repository}#`,
  "https://vcs.example.test/team//repo",
  "https://vcs.example.test/team/./repo",
  "https://vcs.example.test/team/../repo",
  "https://vcs.example.test/team/.git",
  "https://vcs.example.test/team/...git",
  "https://vcs.example.test/team/%2e%2E/repo",
  "https://vcs.example.test/team/%252e%252e/repo",
  `${repository}\\other`,
  `${repository}%2Fother`,
  `${repository}%5cother`,
  `${repository}%00`,
  `${repository}%3Fbranch`,
  `${repository}%23branch`,
  `${repository}%zz`,
  "https://vcs.example.test/team/%20",
])("rejects ambiguous repository binding %j even without rows", (source) => {
  expect(() =>
    normalizeBlackDuckFindings(blackDuckBomReport([]), source),
  ).toThrow(/source-repository-url/);
  expect(() => retainedUrl({ sourceRepositoryUrl: source })).toThrow(
    /source-repository-url/,
  );
});

test("accepts a nested repository URL and retains it independently of the mutable evidence projection", () => {
  const url =
    "http://vcs.example.test:8080/org/subgroup/Example%20Repository.git/";
  const finding = normalizeBlackDuckFindings([blackDuckBomRow()], url)
    .findings[0]!;
  const data = finding.evidence.source_data;
  expect(retainedUrl(data, finding.source_finding_id)).toBe(url);
  const otherComponent = blackDuckBomRow();
  otherComponent.componentVersion = otherComponent.componentVersion.replace(
    "component-a",
    "component-b",
  );
  expect(() => retainedUrl({ ...data, row: otherComponent })).toThrow(
    /contradicts/,
  );
  const projectVersionUrl = data?.["projectVersionUrl"];
  expect(retainedUrl({ projectVersionUrl })).toBeUndefined();
  expect(retainedUrl({ sourceRepositoryUrl: url, projectVersionUrl })).toBe(
    url,
  );
  expect(retainedUrl(undefined)).toBeUndefined();
  expect(() => retainedUrl({ row: blackDuckBomRow() })).toThrow(
    /source-repository-url/,
  );
  const row = blackDuckBomRow();
  expect(() =>
    retainedUrl({
      sourceRepositoryUrl: repository,
      projectVersionUrl:
        "https://scanner.example.test/api/projects/project-a/versions/release-b",
      row,
    }),
  ).toThrow(/same project version/);
  row.vulnerabilityWithRemediation.source = "UNRECOGNIZED";
  expect(
    normalizeBlackDuckFindings([row], repository).excluded[0]!.reason,
  ).toMatch(/advisory source/);
});

test("normalized input cannot relabel one native occurrence with another finding's ID", () => {
  const [first, second] = normalizeBlackDuckFindings(
    [blackDuckBomRow(), blackDuckBomRow("BDSA-2099-0002")],
    repository,
  ).findings;
  const data = first!.evidence.source_data;
  expect(retainedUrl(data, first!.source_finding_id)).toBe(repository);
  expect(() => retainedUrl(data, second!.source_finding_id)).toThrow(
    /source finding ID/,
  );
  for (const incomplete of [{ ...data, row: null }, { arbitrary: true }]) {
    expect(() => retainedUrl(incomplete, first!.source_finding_id)).toThrow(
      /retained Black Duck/,
    );
  }
  expect(retainedUrl({ arbitrary: true })).toBeUndefined();
});

test("reads JSON and gzip by content and rejects a truncated collection in either target", async () => {
  await using directory = await scopedTemporaryDirectory("blackduck-bom-");
  const path = join(directory.path, "report");
  const items = [blackDuckBomRow(), blackDuckBomRow("BDSA-2099-0002")];
  const expected = normalizeBlackDuckFindings(items, repository);
  for (const bytes of [
    Buffer.from(JSON.stringify(items)),
    gzipSync(JSON.stringify(items)),
  ]) {
    await writeFile(path, bytes);
    for (const target of ["cloud", "local"] as const)
      expect(await readBlackDuckFindings(path, repository, target)).toEqual(
        expected,
      );
  }
  await writeFile(
    path,
    JSON.stringify({ ...blackDuckBomReport(items), totalCount: 5 }),
  );
  for (const target of ["cloud", "local"] as const)
    await expect(
      readBlackDuckFindings(path, repository, target),
    ).rejects.toThrow(/totalCount/);
});

test("checks the component even when a vulnerabilities link omits the origin", () => {
  const row = blackDuckBomRow();
  const link = {
    rel: "vulnerabilities",
    href: row.componentVersion + "/vulnerabilities",
  };
  row._meta.links.push(link);
  expect(normalizeBlackDuckFindings([row], repository).excluded).toEqual([]);
  link.href = link.href.replace("component-a", "component-b");
  expect(
    normalizeBlackDuckFindings([row], repository).excluded[0]!.reason,
  ).toMatch(/contradicts componentVersion/);
});

test("binds row remediation URLs to the project version, component version and origin", () => {
  const row = blackDuckBomRow();
  const matched = row._meta.links[0]!.href;
  const href = matched.replace(
    "/matched-files",
    "/vulnerabilities/native-vulnerability-id/remediation",
  );
  const origin = {
    rel: "vulnerabilities",
    href: row.componentVersion + "/origin/origin-a/vulnerabilities",
  };
  const baseline = normalizeBlackDuckFindings([row], repository).findings[0]!
    .source_finding_id;
  for (const self of [href, href.replace("/origins/origin-a", "")]) {
    const onlySelf = { ...row, _meta: { href: self, links: [origin] } };
    expect(
      normalizeBlackDuckFindings([onlySelf], repository).findings[0]!
        .source_finding_id,
    ).toBe(baseline);
    expect(() =>
      normalizeBlackDuckFindings(
        {
          ...blackDuckBomReport(),
          items: [
            {
              ...row,
              _meta: {
                href: self.replace("release-a", "release-b"),
                links: [origin],
              },
            },
          ],
        },
        repository,
      ),
    ).toThrow(/same project version/);
  }
  for (const [from, to] of [
    ["component-a", "component-b"],
    ["origin-a", "origin-b"],
  ] as const) {
    const conflicting = {
      ...row,
      _meta: { href: href.replace(from, to), links: row._meta.links },
    };
    expect(
      normalizeBlackDuckFindings([conflicting], repository).excluded,
    ).toHaveLength(1);
  }
  const componentLink = {
    rel: "matched-files",
    href: matched.replace("/origins/origin-a", ""),
  };
  const partial = { ...row, _meta: { links: [componentLink] } };
  expect(
    normalizeBlackDuckFindings(
      { ...blackDuckBomReport(), items: [row, partial], totalCount: 2 },
      repository,
    ),
  ).toMatchObject({
    findings: [{ source_finding_id: baseline }],
    excluded: [{ position: 2 }],
  });
  expect(
    normalizeBlackDuckFindings(
      [{ ...partial, _meta: { links: [componentLink, origin] } }],
      repository,
    ).findings[0]!.source_finding_id,
  ).toBe(baseline);
});

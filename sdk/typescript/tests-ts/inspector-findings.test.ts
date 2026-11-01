import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import type { ExternalImportTarget } from "../src/external-import-contract.js";
import {
  inspectorReportRepository,
  normalizeInspectorFindings,
  readInspectorFindings,
} from "../src/inspector-findings.js";
import {
  inspectorIntegrationArn,
  inspectorPackageFinding,
  inspectorProjectId,
  inspectorReport,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";

function normalize(
  findings: unknown[],
  source = inspectorRepositoryUrl,
  target: ExternalImportTarget = "cloud",
  projectMap?: ReadonlyMap<string, string>,
) {
  return normalizeInspectorFindings({ findings }, source, target, projectMap);
}

function codeFinding(
  filePath = "src/example.ts",
  fileName = "example.ts",
  startLine = 8,
) {
  const { packageVulnerabilityDetails: _packages, ...common } =
    inspectorPackageFinding();
  return {
    ...common,
    type: "CODE_VULNERABILITY",
    findingArn: common.findingArn.replace(/a{32}$/u, "b".repeat(32)),
    title: "Synthetic code finding",
    codeVulnerabilityDetails: {
      detectorId: "synthetic-detector",
      detectorName: "Synthetic detector",
      cwes: ["CWE-79"],
      detectorTags: ["example-tag"],
      filePath: { fileName, filePath, startLine, endLine: 12 },
    },
  };
}

function projectFinding(
  repoChanges: Record<string, unknown>,
  resourceChanges: Record<string, unknown> = {},
) {
  const finding = inspectorPackageFinding();
  const resource = finding.resources[0]!;
  Object.assign(resource.details.codeRepository, repoChanges);
  Object.assign(resource, resourceChanges);
  return finding;
}

const projectArn = `${inspectorIntegrationArn}/${inspectorProjectId}`;
const enterprise = "https://scm.example.test/example/project";

test("preserves the native package finding and projects only reported dependency evidence", () => {
  const native = projectFinding({ projectName: "example/project" });
  const map = new Map([[projectArn, inspectorRepositoryUrl]]);
  const read = () =>
    normalize([native], inspectorRepositoryUrl, "cloud", map).findings[0]!;
  const row = read();
  expect(row.source_finding_id).toBe(native.findingArn);
  expect(row.evidence).toMatchObject({
    title: native.title,
    severity: "high",
    description: native.description,
    advisory_ids: ["CVE-2099-1234", "GHSA-2345-6789-cfgh"],
    url: native.packageVulnerabilityDetails.sourceUrl,
    packages: [
      {
        name: "example-package",
        ecosystem: "npm",
        installed_version: "1.0.0",
        fixed_versions: ["1.0.1"],
        manifest_path: "apps/web/package.json",
      },
    ],
    locations: [{ path: "apps/web/package.json", line: null }],
    source_updated_at: Date.parse(native.updatedAt) / 1000,
    source_data: {
      sourceRepositoryUrl: inspectorRepositoryUrl,
      finding: native,
    },
  });
  for (const field of [
    "branch",
    "code_revision",
    "source_scan_id",
    "details",
  ] as const)
    expect(row.evidence[field] ?? null).toBeNull();

  native.status = "CLOSED";
  native.packageVulnerabilityDetails.vulnerablePackages[0]!.version = "^1.0.0";
  const updated = read();
  expect(updated.source_finding_id).toBe(row.source_finding_id);
  expect(updated.evidence.packages![0]!.installed_version).toBeNull();
  expect(updated).not.toHaveProperty("assessment");
  expect(row.evidence.source_data?.["finding"]).toMatchObject({
    status: "ACTIVE",
  });
});

test.each([
  ["NPM", "1.2.3+build.x.1", "2.x", "1.2.3+build.x.1", []],
  ["YARN", "workspace:1.2.3", "1.2.3-rc.x.1", null, ["1.2.3-rc.x.1"]],
  ["CARGO", "1.2", "2", null, []],
  ["CARGO", "1.2.3", "2.0.0", "1.2.3", ["2.0.0"]],
  ["JAR", "1.+", "1.3", null, ["1.3"]],
  ["POM", "First.RELEASE", "Next.RELEASE", "First.RELEASE", ["Next.RELEASE"]],
  ["POM", "LATEST", "RELEASE", null, []],
  ["JAR", "latest.integration", "[1.3,2.0)", null, []],
  [
    "PYTHONPKG",
    "1.0+linux.x.1",
    "1!2.3rc1+lab",
    "1.0+linux.x.1",
    ["1!2.3rc1+lab"],
  ],
  ["OS", "1:2.3-4", "1:2.3-5", "1:2.3-4", ["1:2.3-5"]],
  ["OS", "1.2.3~rc1-1", "1.2.3~rc2-1", "1.2.3~rc1-1", ["1.2.3~rc2-1"]],
] as const)(
  "projects exact %s versions from %s and %s",
  (
    packageManager,
    version,
    fixedInVersion,
    installed_version,
    fixed_versions,
  ) => {
    const finding = inspectorPackageFinding();
    Object.assign(finding.packageVulnerabilityDetails.vulnerablePackages[0]!, {
      packageManager,
      version,
      fixedInVersion,
    });
    expect(normalize([finding]).findings[0]!.evidence.packages).toMatchObject([
      { installed_version, fixed_versions },
    ]);
  },
);

test("retains separate package version components without projecting a partial installed version", () => {
  const finding = inspectorPackageFinding();
  const item = finding.packageVulnerabilityDetails.vulnerablePackages[0]!;
  const fixed = "1:1.2.3-5.el9";
  Object.assign(item, {
    packageManager: "OS",
    epoch: 1,
    version: "1.2.3",
    release: "4.el9",
    fixedInVersion: fixed,
  });
  const { evidence } = normalize([finding]).findings[0]!;
  expect(evidence.packages).toMatchObject([
    { installed_version: null, fixed_versions: [fixed] },
  ]);
  expect(evidence.source_data?.["finding"]).toEqual(finding);
});

test("distinguishes dependency manifests from source files and unsafe paths", () => {
  const finding = inspectorPackageFinding();
  const pkg = { name: "synthetic", version: "1.2.x" };
  const vulnerablePackages = [
    { ...pkg, filePath: "src/example.ts" },
    {
      ...pkg,
      filePath: "api/requirements-dev.txt",
      packageManager: "PIP",
      version: "1.2",
    },
    { ...pkg, filePath: "../package.json" },
  ];
  const { evidence } = normalize([
    {
      ...finding,
      severity: "UNTRIAGED",
      updatedAt: undefined,
      packageVulnerabilityDetails: {
        ...finding.packageVulnerabilityDetails,
        vulnerablePackages,
      },
    },
  ]).findings[0]!;
  expect(evidence.packages).toMatchObject([
    {
      ecosystem: null,
      installed_version: null,
      fixed_versions: [],
      manifest_path: null,
    },
    { ecosystem: "pypi", manifest_path: "api/requirements-dev.txt" },
    { manifest_path: null },
  ]);
  expect(evidence.locations).toEqual([
    { path: "src/example.ts", line: null },
    { path: "api/requirements-dev.txt", line: null },
  ]);
  expect(evidence.severity).toBe("unknown");
  expect(evidence.source_updated_at ?? null).toBeNull();
});

test("projects only repository-relative code locations with a matching filename", () => {
  const evidence = (finding: ReturnType<typeof codeFinding>) =>
    normalize([finding]).findings[0]!.evidence;
  const code = codeFinding();
  expect(evidence(code).locations).toEqual([
    { path: "src/example.ts", line: 8 },
  ]);
  expect(evidence(code).source_data?.["finding"]).toEqual(code);
  for (const path of [
    "/tmp/example.ts",
    "C:\\work\\example.ts",
    "src/../example.ts",
    "file:///tmp/example.ts",
    "https://example.invalid/example.ts",
    "~/example.ts",
    "./C:/work/example.ts",
    "src/",
    "src/other.ts",
  ])
    expect(evidence(codeFinding(path)).locations).toEqual([]);
  expect(
    evidence(codeFinding("src\\example.ts", "example.ts", 0)).locations,
  ).toEqual([{ path: "src/example.ts", line: null }]);
});

test("accepts Unix and timezone-qualified ISO timestamps", () => {
  const native = inspectorPackageFinding();
  const epoch = Date.parse(native.updatedAt) / 1000;
  for (const updatedAt of [
    epoch + 0.125,
    native.updatedAt,
    "2026-01-04T06:06:07.125+01:00",
  ]) {
    const { evidence } = normalize([
      {
        ...native,
        firstObservedAt: epoch - 2,
        lastObservedAt: epoch - 1,
        updatedAt,
      },
    ]).findings[0]!;
    expect(evidence.source_updated_at).toBe(epoch);
    expect(evidence.source_data?.["finding"]).toMatchObject({ updatedAt });
  }
  for (const updatedAt of [
    "January 4",
    "2026-01-04T05:06:07",
    String(epoch),
    null,
  ])
    expect(normalize([{ ...native, updatedAt }]).excluded[0]?.reason).toContain(
      "timestamp",
    );
});

test("accepts a complete native ListFindings envelope, including an empty export", () => {
  expect(normalize([])).toEqual({ read: 0, findings: [], excluded: [] });
  const parse = (input: unknown) =>
    normalizeInspectorFindings(input, inspectorRepositoryUrl);
  for (const invalid of [
    null,
    [],
    {},
    { Findings: [] },
    { findings: null },
    { findings: [], Error: { Code: "AccessDenied" } },
    { detail: inspectorReport() },
    inspectorPackageFinding(),
  ])
    expect(() => parse(invalid)).toThrow();
  for (const key of ["nextToken", "NextToken"])
    for (const token of ["more", null, ""])
      expect(() => parse({ findings: [], [key]: token })).toThrow(
        "continuation",
      );
});

test("retains supported rows and excludes malformed records and both copies of duplicate ARNs", () => {
  const supported = inspectorPackageFinding();
  const duplicate = codeFinding();
  const result = normalize([
    supported,
    null,
    duplicate,
    { ...duplicate, status: "SUPPRESSED" },
  ]);
  expect(result.read).toBe(4);
  expect(result.findings.map((row) => row.source_finding_id)).toEqual([
    supported.findingArn,
  ]);
  expect(
    result.excluded.map((row) => [row.position, row.source_finding_id]),
  ).toEqual([
    [2, null],
    [3, duplicate.findingArn],
    [4, duplicate.findingArn],
  ]);
});

test("excludes workload resources, network findings and workload-only details", () => {
  const pkg = inspectorPackageFinding();
  const code = codeFinding();
  const resource = pkg.resources[0]!;
  const workload = { type: "AWS_EC2_INSTANCE", id: "instance" };
  const detail = pkg.packageVulnerabilityDetails;
  const rows = [
    { ...pkg, resources: [workload] },
    { ...pkg, resources: [resource, workload] },
    { ...pkg, type: "NETWORK_REACHABILITY" },
    { ...pkg, networkReachabilityDetails: {} },
    { ...code, packageVulnerabilityDetails: detail },
    {
      ...pkg,
      resources: [
        {
          ...resource,
          details: { ...resource.details, awsLambdaFunction: {} },
        },
      ],
    },
    {
      ...code,
      codeVulnerabilityDetails: {
        ...code.codeVulnerabilityDetails,
        sourceLambdaLayerArn: "layer",
      },
    },
    ...["sourceLayerHash", "sourceLambdaLayerArn"].map((field) => ({
      ...pkg,
      packageVulnerabilityDetails: {
        ...detail,
        vulnerablePackages: [
          { ...detail.vulnerablePackages[0], [field]: "layer" },
        ],
      },
    })),
  ];
  for (const row of rows) {
    const result = normalize([row]);
    expect(result.findings).toEqual([]);
    expect(result.excluded[0]?.source_finding_id).toBe(row.findingArn);
  }
});

test("requires a complete HTTP(S) repository URL", () => {
  for (const source of [
    "",
    "example/project",
    "https://host.invalid/project",
    "https://user:pass@host.invalid/org/project",
    inspectorRepositoryUrl + "?",
    inspectorRepositoryUrl + "#ref",
    "https://host.invalid/other/../org/project",
    "https://host.invalid/org%2fgroup/project",
  ])
    expect(() => normalize([], source)).toThrow();
});

test.each(["local", "cloud"] as const)(
  "compares native URLs and trusted project maps during %s import and replay",
  (target) => {
    const other = "https://other.example.test/example/project";
    const slug = projectFinding({ projectName: "example/project" });
    const map = new Map([[projectArn, enterprise]]);
    const rows = normalize([slug], enterprise, target, map).findings;
    const replay = (map?: ReadonlyMap<string, string>) =>
      inspectorReportRepository("inspector", rows, target, map);
    expect(replay(map)).toMatchObject({
      findingId: slug.findingArn,
      url: enterprise,
    });
    expect(() => normalize([slug], other, target, map)).toThrow();
    expect(() =>
      normalize([projectFinding({ projectName: other })], other, target, map),
    ).toThrow();
    expect(() => replay(new Map([[projectArn, other]]))).toThrow();

    const retained = rows[0]!.evidence.source_data!;
    retained["sourceRepositoryUrl"] = other;
    retained["projectMap"] = { [projectArn]: other };
    expect(() => replay()).toThrow();
    expect(() => replay(map)).toThrow();

    for (const key of [
      inspectorIntegrationArn,
      inspectorProjectId,
      "example/project",
    ]) {
      const partial = new Map([[key, enterprise]]);
      expect(() => normalize([slug], enterprise, target, partial)).toThrow();
      expect(() =>
        normalize(
          [projectFinding({ projectName: "example/project" }, { id: key })],
          enterprise,
          target,
          partial,
        ),
      ).toThrow();
    }
  },
);

test.each(["local", "cloud"] as const)(
  "binds native URLs to their scheme, host, and namespace for %s",
  (target) => {
    const source = "https://tenant-a.ghe.com/Example/Project";
    const read = (name?: string, id = projectArn, url = source) =>
      normalize([projectFinding({ projectName: name }, { id })], url, target);
    expect(read(source.toLowerCase() + ".git").findings).toHaveLength(1);
    expect(read("project", source).findings).toHaveLength(1);
    expect(read(undefined, source).findings).toHaveLength(1);
    expect(() => read("wrong", source)).toThrow();
    for (const claim of [
      undefined,
      "Example/Project",
      "example/project",
      inspectorProjectId,
      "https://tenant-b.ghe.com/Example/Project",
      source.replace("https:", "http:"),
    ])
      expect(() => read(claim)).toThrow();
    expect(() =>
      read("Example/Project", "ssh://git@tenant-a.ghe.com/Example/Project"),
    ).toThrow();
    expect(() => read(undefined, "Example/Project")).toThrow();
  },
);

test("only a trusted map can bind a namespaced project under a GitLab installation subpath", () => {
  const read = (
    source: string,
    mapped: boolean,
    projectName = "group/project",
  ) =>
    normalize(
      [projectFinding({ providerType: "GITLAB_SELF_MANAGED", projectName })],
      source,
      "local",
      mapped ? new Map([[projectArn, source]]) : undefined,
    );
  const source = "https://scm.example.test/gitlab/group/project";
  expect(read(source, true).findings).toHaveLength(1);
  expect(() => read(source, false)).toThrow();
  expect(() => read(source, true, "Group/project")).toThrow();
  expect(() =>
    read("https://scm.example.test/gitlab/workgroup/project", true),
  ).toThrow();
  expect(() => read(source, true, "../group/project")).toThrow();
});

test("self-managed GitLab is local only and a custom Cloud host needs a GitHub provider", () => {
  const gitlab = projectFinding({
    projectName: enterprise,
    providerType: "GITLAB_SELF_MANAGED",
  });
  const local = normalize([gitlab], enterprise, "local");
  expect(
    inspectorReportRepository("inspector", local.findings, "local")?.url,
  ).toBe(enterprise);
  expect(() =>
    inspectorReportRepository("inspector", local.findings, "cloud"),
  ).toThrow();
  expect(() => normalize([gitlab], enterprise, "cloud")).toThrow();
  expect(() =>
    normalize([projectFinding({ providerType: "GITLAB_SELF_MANAGED" })]),
  ).toThrow();
  const name = "https://gitlab.com/example/project";
  for (const providerType of ["GITHUB", "GITLAB_SELF_MANAGED"])
    expect(() =>
      normalize(
        [projectFinding({ providerType, projectName: name })],
        name,
        "local",
      ),
    ).toThrow();

  const unknown = projectFinding({
    projectName: enterprise,
    providerType: undefined,
  });
  expect(() => normalize([unknown], enterprise, "cloud")).toThrow();
  const { findings } = normalize([unknown], enterprise, "local");
  findings[0]!.evidence.source_data!["providerType"] = "GITHUB";
  expect(
    inspectorReportRepository("inspector", findings, "local")?.platform,
  ).toBeUndefined();
});

test("checks every native source before filtering duplicate or unsupported findings", () => {
  const first = inspectorPackageFinding();
  const other = projectFinding(
    {},
    { id: projectArn.replace("22222222-", "33333333-") },
  );
  expect(() =>
    normalize([first, { ...other, type: "NETWORK_REACHABILITY" }]),
  ).toThrow();
  expect(() =>
    normalize([
      { ...first, resources: [...first.resources, ...other.resources] },
    ]),
  ).toThrow();
  expect(() =>
    normalize([first, projectFinding({ projectName: "other/project" })]),
  ).toThrow();
  expect(() =>
    normalize([{ ...first, awsAccountId: "999999999999" }]),
  ).toThrow();
  for (const resource of [
    { id: projectArn.replace("us-east-1", "us-west-2") },
    { id: "arn:aws:ecr:us-east-1:123456789012:repository/example/project" },
    { providerAccountId: "999999999999" },
    { region: "us-west-2" },
    { partition: "aws-cn" },
  ])
    expect(() => normalize([projectFinding({}, resource)])).toThrow();
  expect(() =>
    normalize([
      projectFinding({
        integrationArn: inspectorIntegrationArn.replace("11111111", "44444444"),
      }),
    ]),
  ).toThrow();

  for (const [one, two] of [
    ["example/project", "Example/Project"],
    [inspectorRepositoryUrl, inspectorRepositoryUrl.toUpperCase()],
    ["integrations/1/projects/2", "integrations/2/projects/2"],
  ]) {
    expect(() =>
      normalize([
        projectFinding({}, { id: one }),
        projectFinding({}, { id: two }),
      ]),
    ).toThrow();
  }
});

function projectRow(id: string, projectName?: string, providerType?: string) {
  const row = projectFinding({ projectName, providerType });
  row.findingArn = row.findingArn.replace(/a{32}$/u, id.repeat(32));
  return row;
}

test.each([
  ["project slug without a host", "example/project", "GITHUB"],
  ["native URL without a provider", enterprise, undefined],
] as const)(
  "sharing proof for a %s requires the same integration",
  (_, name, provider) => {
    const peer = projectRow("a", enterprise, "GITHUB");
    const dependent = projectRow("b", name, provider);
    const rows = [peer, dependent];
    const { findings } = normalize(rows, enterprise);
    const raw = () => normalize(rows, enterprise);
    const replay = () =>
      inspectorReportRepository("inspector", findings, "cloud");
    for (const [index, finding] of rows.entries()) {
      finding.resources[0]!.id = "example/project";
      findings[index]!.evidence.source_data!["finding"] = finding;
    }
    for (const [peerArn, dependentArn] of [
      [inspectorIntegrationArn, inspectorIntegrationArn],
      [inspectorIntegrationArn, undefined],
      [undefined, inspectorIntegrationArn],
      [undefined, undefined],
    ]) {
      Object.assign(peer.resources[0]!.details.codeRepository, {
        integrationArn: peerArn,
      });
      Object.assign(dependent.resources[0]!.details.codeRepository, {
        integrationArn: dependentArn,
      });
      if (peerArn && dependentArn) {
        expect(raw().findings).toHaveLength(2);
        expect(replay()?.url).toBe(enterprise);
      } else {
        expect(raw).toThrow();
        expect(replay).toThrow();
      }
    }
  },
);

test("only surviving rows share project proof, independently of input order", () => {
  const known = projectRow("a", enterprise, "GITHUB");
  const dependent = projectRow("b");
  for (const rows of [
    [known, dependent],
    [dependent, known],
  ]) {
    const { findings } = normalize(rows, enterprise, "cloud");
    expect(findings).toHaveLength(2);
    expect(
      inspectorReportRepository("inspector", findings, "cloud"),
    ).toMatchObject({ url: enterprise, platform: "github" });

    known.title = "a".repeat(513);
    const result = normalize(rows, enterprise, "cloud");
    expect(result.findings).toEqual([]);
    expect(result.excluded.map((row) => row.source_finding_id).sort()).toEqual(
      [known.findingArn, dependent.findingArn].sort(),
    );
    expect(normalize(rows, enterprise, "local").findings).toHaveLength(2);
    known.title = "Restored title";
  }
});

test("after the only provider hint is excluded, valid local rows still share their native URL", () => {
  const source = "https://scm.example.test/Owner/Repo";
  const duplicate = projectRow("a", "Owner/Repo", "GITHUB");
  const exact = projectRow("b", source);
  const slug = projectRow("c", "Owner/Repo");
  const mismatch = projectRow("d", "owner/repo");
  for (const valid of [
    [exact, slug],
    [slug, exact],
  ]) {
    const rows = [duplicate, mismatch, ...valid, duplicate];
    const result = normalize(rows, source, "local");
    expect(result.findings.map((row) => row.source_finding_id)).toEqual(
      valid.map((row) => row.findingArn),
    );
    expect(result.excluded.map((row) => row.position)).toEqual([1, 2, 5]);
    expect(
      inspectorReportRepository("inspector", result.findings, "local")?.url,
    ).toBe(source);
    expect(normalize(rows, source, "cloud").findings).toHaveLength(0);
  }
});

test.each(["cloud", "local"] as const)(
  "rechecks finding identity, resource kind and host during %s replay",
  (target) => {
    const native = inspectorPackageFinding();
    const rows = normalize([native], inspectorRepositoryUrl, target).findings;
    const row = rows[0]!;
    const data = row.evidence.source_data!;
    const replay = () => inspectorReportRepository("inspector", rows, target);
    for (const patch of [
      { format: "some-new-unsupported-format" },
      { finding: codeFinding() },
      { sourceRepositoryUrl: undefined },
      { sourceRepositoryUrl: enterprise },
      { sourceRepositoryUrl: "https://github.com/other/project" },
      { finding: projectFinding({ projectName: "other/project" }) },
      { finding: { ...native, resources: [] } },
      {
        finding: {
          ...native,
          resources: [...native.resources, { type: "AWS_EC2_INSTANCE" }],
        },
      },
    ]) {
      row.evidence.source_data = { ...data, ...patch };
      expect(replay).toThrow();
    }
    row.evidence.source_data = undefined;
    expect(replay).toThrow();
    row.source_finding_id = "opaque";
    expect(replay()).toBeUndefined();
    expect(() =>
      inspectorReportRepository("inspector", rows, target, new Map()),
    ).toThrow();
  },
);

test("distinguishes a Wiz occurrence containing Inspector evidence from the Inspector occurrence itself", () => {
  const native = inspectorPackageFinding();
  const row = normalize([native]).findings[0]!;
  const wiz = (id: string, data: Record<string, unknown>) =>
    inspectorReportRepository(
      "wiz",
      [
        {
          source_finding_id: id,
          evidence: { ...row.evidence, source_data: data },
        },
      ],
      "cloud",
    );

  expect(wiz("wiz-issue", { finding: native })).toBeUndefined();
  expect(wiz(codeFinding().findingArn, { finding: native })).toBeUndefined();
  expect(wiz(native.findingArn, {})).toBeUndefined();
  expect(() => wiz("wiz-issue", row.evidence.source_data!)).toThrow();
  for (const data of [native, { finding: native }])
    expect(() => wiz(native.findingArn, data)).toThrow();
});

test("reads plain and gzip JSON with a snapshot of the supplied map", async () => {
  const directory = await mkdtemp(join(tmpdir(), "synthetic-inspector-"));
  try {
    const path = join(directory, "input.json");
    const report = inspectorReport();
    report.findings[0]!.resources[0]!.details.codeRepository.projectName =
      "example/project";
    const mapping = () => new Map([[projectArn, inspectorRepositoryUrl]]);
    const expected = normalize(
      report.findings,
      inspectorRepositoryUrl,
      "cloud",
      mapping(),
    );
    const json = JSON.stringify(report);
    for (const bytes of [Buffer.from(json), gzipSync(json)]) {
      await writeFile(path, bytes);
      const map = mapping();
      const reading = readInspectorFindings(
        path,
        inspectorRepositoryUrl,
        "cloud",
        map,
      );
      map.clear();
      expect(await reading).toEqual(expected);
    }
    for (const invalid of [
      Buffer.from('{"findings":[]}\n{"findings":[]}'),
      Buffer.from([0xff]),
    ]) {
      await writeFile(path, invalid);
      await expect(
        readInspectorFindings(path, inspectorRepositoryUrl),
      ).rejects.toThrow();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

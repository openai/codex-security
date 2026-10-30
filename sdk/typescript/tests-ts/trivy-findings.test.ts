import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  normalizeTrivyFindings,
  readTrivyFindings,
  trivyRepositoryUrl,
} from "../src/trivy-findings.js";
import { trivyReport } from "./support/trivy-import-fixtures.js";

function normalizeAtRoot(input: unknown) {
  return normalizeTrivyFindings(input, "cloud", ".");
}

test("infers a whole checkout only when Git metadata corroborates the remote", () => {
  const report = trivyReport();
  for (const ArtifactName of [".", "apps/web", "/checkout/apps/web", undefined])
    expect(() => normalizeTrivyFindings({ ...report, ArtifactName })).toThrow(
      "--trivy-scan-root",
    );
  const ambiguousOrigin = { ...report, Metadata: { RepoURL: "r:org/repo" } };
  expect(() => normalizeTrivyFindings(ambiguousOrigin)).toThrow(
    "--trivy-scan-root",
  );
  const remote = { ...report, ArtifactName: report.Metadata.RepoURL };
  const labelOnly = { ...remote, Metadata: {} };
  expect(() => normalizeTrivyFindings(labelOnly)).toThrow("--trivy-scan-root");
  const scoped = normalizeTrivyFindings(labelOnly, "cloud", "apps/web")
    .findings[0]!;
  expect(scoped.evidence.packages![0]!.manifest_path).toBe(
    "apps/web/package-lock.json",
  );
  expect(scoped.evidence.source_data?.["report"]).toMatchObject({
    ArtifactName: remote.ArtifactName,
  });
  const displayName = "arbitrary filesystem display label";
  expect(
    normalizeAtRoot({ ...report, ArtifactName: displayName }).findings[0]!
      .evidence.source_data?.["report"],
  ).toMatchObject({ ArtifactName: displayName });
  const colonDirectory = { ...report, ArtifactName: "apps:web" };
  expect(() => normalizeTrivyFindings(colonDirectory)).toThrow(
    "--trivy-scan-root",
  );
  expect(
    normalizeTrivyFindings(colonDirectory, "local", "packages@v2/apps:web")
      .findings[0]!.evidence.packages![0]!.manifest_path,
  ).toBe("packages@v2/apps:web/package-lock.json");
  expect(
    normalizeTrivyFindings(colonDirectory, "local", "apps:web").findings[0]!
      .evidence.packages![0]!.manifest_path,
  ).toBe("apps:web/package-lock.json");
  const inferred = normalizeTrivyFindings(remote);
  expect(inferred).toEqual(normalizeAtRoot(remote));
  expect(inferred.findings[0]!.evidence.source_data?.["scanRoot"]).toBe(".");
  expect(() => normalizeTrivyFindings(remote, "cloud", "apps/web")).toThrow(
    "--trivy-scan-root",
  );
  expect(() =>
    normalizeTrivyFindings({ ...remote, ArtifactType: "filesystem" }),
  ).toThrow("--trivy-scan-root");
});

test("corroborates Trivy's scheme-less repository target", () => {
  const report = {
    ...trivyReport(),
    ArtifactName: "github.com/example/project",
  };
  const inferred = normalizeTrivyFindings(report);
  expect(inferred.findings[0]!.evidence.packages![0]!.manifest_path).toBe(
    "package-lock.json",
  );
  expect(() => normalizeTrivyFindings(report, "cloud", "apps/web")).toThrow(
    "must be .",
  );
  const targetOnly = { ...report, Metadata: {} };
  const selected = normalizeAtRoot(targetOnly);
  expect(selected.findings[0]!.evidence.source_data!["report"]).toMatchObject({
    ArtifactName: report.ArtifactName,
  });
  expect(
    trivyRepositoryUrl(selected.findings[0]!.evidence.source_data!["report"]),
  ).toBeNull();
  for (const uncorroborated of [
    { ...report, Metadata: {} },
    { ...report, ArtifactName: "github.com/example/other" },
    { ...report, ArtifactName: "./github.com/example/project" },
    { ...report, ArtifactType: "filesystem" },
    { ...report, Metadata: { RepoURL: "http://github.com/example/project" } },
  ])
    expect(() => normalizeTrivyFindings(uncorroborated)).toThrow(
      "--trivy-scan-root",
    );
});

test("a mixed-case HTTPS label and lowercase Git metadata require explicit-root inspection", () => {
  const report = {
    ...trivyReport(),
    ArtifactName: "HTTPS://github.com/example/project",
  };
  expect(() => normalizeTrivyFindings(report)).toThrow("--trivy-scan-root");
  const batch = normalizeTrivyFindings(report, "local", "apps/web");
  const retained = batch.findings[0]!.evidence.source_data!["report"];
  expect(retained).toMatchObject({
    ArtifactName: report.ArtifactName,
    Metadata: { RepoURL: report.Metadata.RepoURL },
  });
  expect(() => trivyRepositoryUrl(retained, report.Metadata.RepoURL)).toThrow(
    "different repositories",
  );
  const targetOnly = { ...report, Metadata: {} };
  expect(() => normalizeTrivyFindings(targetOnly)).toThrow("--trivy-scan-root");
  const selected = normalizeAtRoot(targetOnly);
  expect(selected.findings[0]!.evidence.source_data!["report"]).toMatchObject({
    ArtifactName: report.ArtifactName,
  });
});

test.each([
  ["é/repo", "%C3%A9/repo", true],
  ["team name/répo", "team%20name/r%C3%A9po", true],
  ["Team%20Name/répo", "Team%20Name/r%C3%A9po", true],
  ["a%2520b/x é", "a%2520b/x%20%C3%A9", true],
  ["a%FF/répo", "a%FF/r%C3%A9po", true],
  ["%72epo/café", "repo/caf%C3%A9", false],
  ["a%2f b/repo", "a/%20b/repo", false],
  ["other/../repo name", "repo%20name", false],
  ["repo name", "Repo%20name", false],
] as const)(
  "retains the scanner target %s when the cloned path is %s",
  (target, cloned, matches) => {
    for (const [prefix, clonedBase] of [
      ["https://git.example.test:08443/", "https://git.example.test:08443/"],
      ["git.example.test/", "https://git.example.test/"],
    ] as const) {
      const report = {
        ...trivyReport(),
        ArtifactName: prefix + target,
        Metadata: { RepoURL: clonedBase + cloned },
      };
      const input = normalizeAtRoot(report);
      if (matches) {
        expect(normalizeTrivyFindings(report)).toEqual(input);
        expect(() => normalizeTrivyFindings(report, "local", "nested")).toThrow(
          "must be .",
        );
      } else
        expect(() => normalizeTrivyFindings(report)).toThrow(
          "--trivy-scan-root",
        );
      const saved = input.findings[0]!.evidence.source_data!["report"];
      expect(saved).toMatchObject({
        ArtifactName: report.ArtifactName,
        Metadata: report.Metadata,
      });
      if (matches || prefix !== clonedBase)
        expect(trivyRepositoryUrl(saved)).toBe(report.Metadata.RepoURL);
      else
        expect(() => trivyRepositoryUrl(saved)).toThrow(
          "different repositories",
        );
    }
  },
);

test("identical SSH declarations can use an SSH-config host alias", () => {
  const url = "ssh://git@git.1/org/project";
  const report = {
    ...trivyReport(),
    ArtifactName: url,
    Metadata: { RepoURL: url },
  };
  expect(normalizeTrivyFindings(report)).toEqual(normalizeAtRoot(report));
  const native = { ...report, Metadata: { RepoURL: "git@git.1:org/project" } };
  expect(() => normalizeTrivyFindings(native)).toThrow("--trivy-scan-root");
  expect(() => trivyRepositoryUrl(native)).toThrow("different repositories");
});

test("a GitHub SSH path corroborates its encoded HTTP spelling", () => {
  const report = {
    ...trivyReport(),
    ArtifactName: "https://github.com/example/%E2%84%AAit",
    Metadata: { RepoURL: "ssh://git@github.com/example/Kit.git" },
  };
  expect(normalizeTrivyFindings(report)).toEqual(normalizeAtRoot(report));
  report.ArtifactName = "https://github.com/example/Kit";
  expect(() => normalizeTrivyFindings(report)).toThrow("--trivy-scan-root");
});

test("requires a scan root for aliases on an unverified Git host", () => {
  const report = {
    ...trivyReport(),
    ArtifactName: "https://git.example.test/org/project",
    Metadata: { RepoURL: "git@git.example.test:org/project.git" },
  };
  const scoped = normalizeTrivyFindings(report, "local", "apps/web");
  expect(scoped.findings[0]!.evidence.packages![0]!.manifest_path).toBe(
    "apps/web/package-lock.json",
  );
  for (const [ArtifactName, RepoURL] of [
    [report.ArtifactName, report.Metadata.RepoURL],
    [report.ArtifactName, "https://git.example.test/org/Project"],
    [report.ArtifactName, "https://git.example.test/org/other"],
    [report.ArtifactName, "https://other.example.test/org/project"],
    [report.ArtifactName, "https://git.example.test:8443/org/project"],
    [
      "http://git.example.test/org/project",
      "http://git.example.test/ORG/other",
    ],
  ]) {
    const different = { ...report, ArtifactName, Metadata: { RepoURL } };
    expect(() => normalizeTrivyFindings(different)).toThrow(
      "--trivy-scan-root",
    );
    expect(() => trivyRepositoryUrl(different)).toThrow(
      "different repositories",
    );
  }
});

test("a repository display label cannot supply an SSH account omitted from Git metadata", () => {
  const report = {
    ...trivyReport(),
    ArtifactName: "ssh://tenant-a@git.example.test:2222/org/project",
    Metadata: { RepoURL: "ssh://git.example.test:2222/org/project" },
  };
  expect(() => normalizeTrivyFindings(report)).toThrow("--trivy-scan-root");
  const retained =
    normalizeAtRoot(report).findings[0]!.evidence.source_data!["report"];
  expect(trivyRepositoryUrl(retained)).toBe(report.Metadata.RepoURL);
  expect(retained).toMatchObject({
    ArtifactName: report.ArtifactName,
    Metadata: report.Metadata,
  });
});

test("rejects unsafe scan directories before importing even a clean local report", () => {
  const report = { ...trivyReport(), Results: [] };
  for (const root of [
    "",
    "../web",
    "apps\\..\\web",
    "/apps/web",
    "C:\\apps",
    "C:apps",
    "\\\\host\\share",
    "https://example.invalid/repo",
    "git@example.invalid:repo",
    "a\0b",
  ])
    expect(() => normalizeTrivyFindings(report, "local", root)).toThrow(
      "--trivy-scan-root",
    );
});

test("whole-checkout and scoped scans resolve the same manifest and package occurrence", () => {
  const report = trivyReport();
  const result = report.Results[0]!;
  const run = (prefix: string, root: string) => {
    const path = prefix + "vendor/package.json";
    return normalizeTrivyFindings(
      {
        ...report,
        Results: [
          {
            ...result,
            Target: prefix + result.Target,
            Packages: [{ ...result.Packages[0]!, FilePath: path }],
            Vulnerabilities: [{ ...result.Vulnerabilities[0]!, PkgPath: path }],
          },
        ],
      },
      "local",
      root,
    ).findings[0]!;
  };
  const directory = process.platform === "win32" ? "apps/web" : "apps\\web";
  const full = run(directory + "/", ".");
  const scoped = run("", "./apps\\web/");
  expect(scoped.source_finding_id).toBe(full.source_finding_id);
  expect(scoped.source_finding_id).not.toBe(
    run("", directory === "apps/web" ? "apps/api" : "apps/web")
      .source_finding_id,
  );
  expect(scoped.evidence.locations).toEqual(full.evidence.locations);
  expect(scoped.evidence).toMatchObject({
    packages: [{ manifest_path: `${directory}/package-lock.json` }],
    locations: [
      { path: `${directory}/package-lock.json`, line: null },
      { path: `${directory}/vendor/package.json`, line: 12 },
    ],
    source_data: {
      scanRoot: directory,
      result: { Target: "package-lock.json" },
      vulnerability: { PkgPath: "vendor/package.json" },
      package: { FilePath: "vendor/package.json" },
    },
  });
});

test.each([
  ["node-pkg", "Node.js"],
  ["npm", "../manifest"],
  ["npm", ""],
  ["npm", undefined],
] as const)(
  "scopes %s target %s without inventing a manifest",
  (Type, Target) => {
    const report = trivyReport();
    const result = report.Results[0]!;
    const run = (root: string, PkgPath?: string) =>
      normalizeTrivyFindings(
        {
          ...report,
          Results: [
            {
              ...result,
              Target,
              Type,
              Packages: [{ ...result.Packages[0]!, FilePath: PkgPath }],
              Vulnerabilities: [{ ...result.Vulnerabilities[0]!, PkgPath }],
            },
          ],
        },
        "cloud",
        root,
      ).findings[0]!;
    const scoped = run("apps/web", "vendor/package.json");
    expect(scoped.source_finding_id).toBe(
      run(".", "apps/web/vendor/package.json").source_finding_id,
    );
    expect(scoped.evidence.packages![0]!.manifest_path).toBeNull();
    expect(scoped.evidence.locations).toEqual([
      { path: "apps/web/vendor/package.json", line: 12 },
    ]);
    for (const path of [undefined, "/outside/package.json"]) {
      const web = run("apps/web", path);
      expect(web.evidence.locations).toEqual([]);
      expect(web.source_finding_id).not.toBe(
        run("apps/api", path).source_finding_id,
      );
    }
  },
);

test("retains the detected vulnerability and only its package declarations and scan context", () => {
  const report = trivyReport();
  report.ArtifactName = report.Metadata.RepoURL;
  const result = report.Results[0]!;
  const pkg = result.Packages[0]!;
  pkg.Locations.push({ StartLine: 42, EndLine: 45 });
  result.Packages.unshift({
    ...pkg,
    Name: "unrelated-inventory",
    ID: "unrelated-inventory@1.0.0",
    Identifier: { PURL: "pkg:npm/unrelated-inventory", UID: "another-uid" },
    Locations: [{ StartLine: 2, EndLine: 6 }],
  });
  Object.assign(pkg, { DependsOn: ["unrelated-inventory"] });
  Object.assign(report.Metadata, {
    CommitMsg: "unrelated-metadata",
    Author: "unrelated-metadata",
  });
  const original = structuredClone(report);
  const output = normalizeAtRoot(report);
  expect(report).toEqual(original);
  expect(output).toMatchObject({ read: 1, excluded: [] });
  const { evidence } = output.findings[0]!;
  expect(evidence).toMatchObject({
    title: result.Vulnerabilities[0]!.Title,
    severity: "high",
    url: result.Vulnerabilities[0]!.PrimaryURL,
    advisory_ids: ["CVE-2099-0001", "GHSA-2345-6789-cfgh"],
    packages: [
      {
        name: pkg.Name,
        ecosystem: "npm",
        manifest_path: result.Target,
        installed_version: "1.0.0",
        fixed_versions: ["1.0.1", "2.0.3"],
      },
    ],
    locations: [
      { path: result.Target, line: 12 },
      { path: result.Target, line: 42 },
    ],
    branch: "main",
    code_revision: null,
    source_scan_id: report.ReportID,
    source_data: {
      report: { Metadata: { Commit: report.Metadata.Commit } },
      result: { Type: "npm", Target: result.Target },
      package: { ID: pkg.ID, Locations: pkg.Locations },
    },
  });
  expect(evidence.details).toBeUndefined();
  result.Vulnerabilities[0]!.Status = "affected";
  expect(evidence.source_data?.["vulnerability"]).toEqual(
    original.Results[0]!.Vulnerabilities[0],
  );
  expect(JSON.stringify(evidence.source_data)).not.toContain("unrelated-");
});

test("filesystem scans without inventory or Git metadata do not invent lines, versions or revisions", () => {
  const report = {
    SchemaVersion: 2,
    ArtifactType: "filesystem",
    ArtifactName: "scan-root",
    Results: [
      {
        Class: "lang-pkgs",
        Type: "npm",
        Target: "app\\package-lock.json",
        Vulnerabilities: [
          { VulnerabilityID: "CVE-2099-0001", PkgName: "example" },
        ],
      },
    ],
  };
  const { evidence } = normalizeAtRoot(report).findings[0]!;
  expect(evidence).toMatchObject({
    severity: "unknown",
    source_data: { report: { ArtifactName: report.ArtifactName } },
    branch: null,
    code_revision: null,
    source_scan_id: null,
    packages: [
      {
        installed_version: null,
        fixed_versions: [],
        manifest_path: "app\\package-lock.json",
      },
    ],
    locations: [{ path: "app\\package-lock.json", line: null }],
  });
  expect(trivyRepositoryUrl(evidence.source_data?.["report"])).toBeNull();
});

function normalizeResult(result: unknown) {
  return normalizeAtRoot({ ...trivyReport(), Results: [result] });
}

test("a later PURL enriches the ecosystem without changing a Poetry occurrence's identity", () => {
  const result = trivyReport().Results[0]!;
  const run = (PkgIdentifier?: { PURL: string }) =>
    normalizeResult({
      ...result,
      Type: "poetry",
      Target: "poetry.lock",
      Vulnerabilities: [
        {
          VulnerabilityID: "CVE-2099-0001",
          PkgName: "example",
          PkgIdentifier,
        },
      ],
    }).findings[0]!;
  const before = run();
  const after = run({ PURL: "pkg:pypi/example@1.0.0" });
  expect(before.evidence.packages![0]!.ecosystem).toBe("poetry");
  expect(after.evidence.packages![0]!.ecosystem).toBe("pypi");
  expect(after.source_finding_id).toBe(before.source_finding_id);
  expect(after.evidence.source_data?.["result"]).toMatchObject({
    Type: "poetry",
  });
});

test("new scan, commit, fingerprint, versions, severity and declaration range update the same occurrence", () => {
  const report = trivyReport();
  const first = normalizeAtRoot(report).findings[0]!;
  const result = report.Results[0]!;
  const vulnerability = result.Vulnerabilities[0]!;
  report.Metadata.Commit = "c".repeat(40);
  report.ReportID = "next-scan";
  Object.assign(vulnerability, {
    Severity: "LOW",
    InstalledVersion: "1.0.2",
    FixedVersion: "1.0.3",
    PkgID: "example@1.0.2",
    PkgIdentifier: { UID: "changed", PURL: "pkg:npm/%40example/package@1.0.2" },
    Fingerprint: "changed",
  });
  Object.assign(result.Packages[0]!, {
    ID: vulnerability.PkgID,
    Version: vulnerability.InstalledVersion,
    Identifier: vulnerability.PkgIdentifier,
    Locations: [{ StartLine: 81, EndLine: 90 }],
  });
  const next = normalizeAtRoot(report).findings[0]!;
  expect(next.source_finding_id).toBe(first.source_finding_id);
  expect(next.evidence).toMatchObject({
    severity: "low",
    locations: [{ line: 81 }],
  });
});

test("manifests, analyzers, names, advisories and concrete package paths distinguish occurrences regardless of order", () => {
  const report = trivyReport();
  const result = report.Results[0]!;
  const vuln = result.Vulnerabilities[0]!;
  const results = [
    { ...result, Target: "apps/web/package-lock.json" },
    { ...result, Target: "apps\\web/package-lock.json" },
    { ...result, Type: "yarn" },
    {
      ...result,
      Vulnerabilities: [
        vuln,
        { ...vuln, PkgName: "other" },
        { ...vuln, VulnerabilityID: "CVE-2099-0002" },
        { ...vuln, PkgPath: "a/package.json" },
        { ...vuln, PkgPath: "a\\package.json" },
      ],
    },
  ];
  const run = () => normalizeAtRoot({ ...report, Results: results });
  const first = run();
  expect(first.excluded).toEqual([]);
  const ids = first.findings.map((finding) => finding.source_finding_id).sort();
  expect(new Set(ids).size).toBe(8);
  expect(first.findings[1]!.evidence).toMatchObject({
    packages: [{ manifest_path: "apps\\web/package-lock.json" }],
    locations: [{ path: "apps\\web/package-lock.json", line: 12 }],
    source_data: { result: { Target: "apps\\web/package-lock.json" } },
  });
  results.reverse();
  for (const group of results) group.Vulnerabilities.reverse();
  expect(
    run()
      .findings.map((finding) => finding.source_finding_id)
      .sort(),
  ).toEqual(ids);
});

test("different installed versions alone cannot disambiguate two detections in a manifest", () => {
  const result = trivyReport().Results[0]!;
  const vuln = result.Vulnerabilities[0]!;
  const output = normalizeResult({
    ...result,
    Vulnerabilities: [
      vuln,
      {
        ...vuln,
        PkgID: "other-version",
        InstalledVersion: "2.0.0",
        PkgPath: result.Target,
      },
      { ...vuln, VulnerabilityID: "another-advisory" },
    ],
  });
  expect(output.read).toBe(3);
  expect(output.findings).toHaveLength(1);
  expect(output.excluded.map(({ position }) => position)).toEqual([1, 2]);
  expect(output.excluded[0]!.source_finding_id).toBe(
    output.excluded[1]!.source_finding_id,
  );
  expect(output.excluded[0]!.reason).toMatch(/ambiguous duplicate/i);
});

test.each([
  ["node-pkg", "Node.js"],
  ["python-pkg", "Python"],
  ["conda-pkg", "Conda"],
  ["gemspec", "Ruby"],
  ["jar", "Java"],
  ["kubernetes", "Kubernetes"],
])(
  "%s aggregate target %s is not a manifest or file location",
  (type, label) => {
    const result = trivyReport().Results[0]!;
    const vuln = result.Vulnerabilities[0]!;
    const path = "app/installed/package.json";
    const output = normalizeResult({
      ...result,
      Type: type,
      Target: label,
      Vulnerabilities: [vuln, { ...vuln, PkgPath: path }],
    });
    expect(output.excluded).toEqual([]);
    expect(output.findings[0]!.evidence.locations).toEqual([]);
    expect(output.findings[1]!.evidence.locations).toEqual([
      { path, line: null },
    ]);
    expect(output.findings[1]!.evidence.packages![0]!.manifest_path).toBeNull();
  },
);

test("keeps ambiguous Java package paths in the original evidence", () => {
  const result = trivyReport().Results[0]!;
  const paths = [
    "service.war/lib/dep.jar",
    "lib/dep.jar",
    "service.war/lib/dep.par",
    "service.war/lib/dep.JAR",
  ];
  const { findings, excluded } = normalizeResult({
    ...result,
    Type: "jar",
    Target: "Java",
    Vulnerabilities: paths.map((PkgPath) => ({
      ...result.Vulnerabilities[0]!,
      PkgPath,
    })),
  });
  expect(excluded).toEqual([]);
  expect(findings.map(({ evidence }) => evidence.locations)).toEqual([
    [],
    ...paths.slice(1).map((path) => [{ path, line: null }]),
  ]);
  expect(findings[0]!.evidence.source_data?.["vulnerability"]).toMatchObject({
    PkgPath: paths[0],
  });
});

test("declaration ranges come from an unambiguous package at the reported path", () => {
  const result = trivyReport().Results[0]!;
  const vuln = result.Vulnerabilities[0]!;
  const pkg = result.Packages[0]!;
  const selected = { ...pkg, FilePath: "a/package.json" };
  const other = {
    ...pkg,
    FilePath: "a\\package.json",
    Locations: [{ StartLine: 24, EndLine: 28 }],
  };
  const group = {
    ...result,
    Packages: [other, selected],
    Vulnerabilities: [{ ...vuln, PkgPath: selected.FilePath }],
  };
  const run = () => normalizeResult(group).findings[0]!.evidence;
  expect(run().locations).toEqual([
    { path: result.Target, line: null },
    { path: selected.FilePath, line: 12 },
  ]);
  group.Packages.push({ ...other, FilePath: selected.FilePath });
  expect(run().locations![1]!.line).toBeNull();
  expect(run().source_data?.["package"]).toBeUndefined();
});

test("only ID-less detections use a unique name/version match from inventory", () => {
  const result = trivyReport().Results[0]!;
  const pkg = result.Packages[0]!;
  const vuln = result.Vulnerabilities[0]!;
  const sparse = {
    VulnerabilityID: vuln.VulnerabilityID,
    PkgName: pkg.Name,
    InstalledVersion: pkg.Version,
  };
  const line = (value: unknown, packages = [pkg]) =>
    normalizeResult({ ...result, Packages: packages, Vulnerabilities: [value] })
      .findings[0]!.evidence.locations![0]!.line;
  expect(line(sparse)).toBe(12);
  expect(
    line(sparse, [
      pkg,
      { ...pkg, ID: "other", Identifier: { ...pkg.Identifier, UID: "other" } },
    ]),
  ).toBeNull();
  expect(line({ ...sparse, PkgID: "unknown-id" })).toBeNull();
  expect(
    line({ ...sparse, PkgIdentifier: { PURL: pkg.Identifier.PURL } }),
  ).toBe(12);
  expect(
    line({ ...sparse, PkgIdentifier: { PURL: "pkg:npm/other@1.0.0" } }),
  ).toBeNull();
  expect(
    line({ ...vuln, PkgIdentifier: { UID: "conflicting-uid" } }),
  ).toBeNull();
  expect(line({ ...vuln, PkgID: "conflicting-id" })).toBeNull();
});

test("conflicting package names or installed versions suppress enrichment even with matching IDs", () => {
  const result = trivyReport().Results[0]!;
  const pkg = result.Packages[0]!;
  for (const mismatch of [{ Name: "unrelated" }, { Version: "9.0.0" }]) {
    const output = normalizeResult({
      ...result,
      Packages: [{ ...pkg, ...mismatch }],
    });
    expect(output.excluded).toEqual([]);
    const { evidence } = output.findings[0]!;
    expect(evidence.locations).toEqual([{ path: result.Target, line: null }]);
    expect(evidence.source_data?.["package"]).toBeUndefined();
    expect(evidence.packages![0]!.installed_version).toBe(pkg.Version);
  }
});

test.each([
  "/work/manifest",
  "C:\\work\\manifest",
  "\\\\host\\share\\manifest",
  "../manifest",
  "https://example.invalid/file",
])("keeps %s out of repository paths", (path) => {
  const result = trivyReport().Results[0]!;
  const output = normalizeResult({
    ...result,
    Target: path,
    Vulnerabilities: [{ ...result.Vulnerabilities[0]!, PkgPath: path }],
  });
  const { evidence } = output.findings[0]!;
  expect(evidence.locations).toEqual([]);
  expect(evidence.packages![0]!.manifest_path).toBeNull();
  expect(evidence.source_data?.["result"]).toMatchObject({ Target: path });
});

test("clean native reports differ from unsupported, mixed and malformed findings", () => {
  const report = trivyReport();
  const { Results: groups, ...header } = report;
  const result = groups[0]!;
  for (const Results of [
    undefined,
    [],
    [{ ...result, Vulnerabilities: undefined }],
  ])
    expect(normalizeAtRoot({ ...report, Results })).toEqual({
      read: 0,
      report: header,
      excluded: [],
      findings: [],
    });
  const secret = {
    Class: "secret",
    Secrets: [{ Match: "excluded-secret-evidence" }],
  };
  const mixed = normalizeAtRoot({
    ...report,
    Results: [
      secret,
      result,
      { Class: "os-pkgs", Vulnerabilities: result.Vulnerabilities },
      { Class: "config" },
      { Class: "license" },
      {
        ...result,
        Vulnerabilities: [{}],
        ExperimentalModifiedFindings: [{ Finding: "excluded-modification" }],
      },
    ],
  });
  expect(mixed.read).toBe(7);
  expect(mixed.findings).toHaveLength(1);
  expect(mixed.excluded.map(({ position }) => position)).toEqual([
    1, 3, 4, 5, 6, 7,
  ]);
  expect(JSON.stringify(mixed)).not.toContain("excluded-secret-evidence");
  expect(JSON.stringify(mixed)).not.toContain("excluded-modification");
  expect(
    normalizeAtRoot({ ...report, Results: [secret] }).excluded,
  ).toHaveLength(1);
  expect(() =>
    normalizeAtRoot({ ...report, ArtifactType: "container_image" }),
  ).toThrow(/repository and filesystem/);
  expect(() => normalizeAtRoot({ ...report, SchemaVersion: 1 })).toThrow(
    /SchemaVersion 2/,
  );
  expect(() => normalizeAtRoot({ version: "2.1.0", runs: [] })).toThrow(
    /SchemaVersion 2/,
  );
});

test.each([
  [
    ".",
    "git@example.invalid:group/project.git",
    "git@example.invalid:group/project.git",
  ],
  [
    "C:\\work\\project",
    "ssh://git@example.invalid/project",
    "ssh://git@example.invalid/project",
  ],
  [
    "https://example.invalid/project",
    undefined,
    "https://example.invalid/project",
  ],
  [
    "https://github.com/example/project",
    "https://github.com/example/project.git",
    "https://github.com/example/project.git",
  ],
  ["relative/project", "file:///work/project", null],
  ["C:\\work\\checkout", "D:mirrors\\project.git", null],
  ["\\\\server\\share\\checkout", "D:mirrors/project.git", null],
  ["//server/share/checkout", "D:mirror.git", null],
  [".", "r:org/repo", null],
  [".", "git@host:org@ver/repo", "git@host:org@ver/repo"],
  [".", "user@r:org/repo", "user@r:org/repo"],
  [".", "ssh://r/org/repo", "ssh://r/org/repo"],
] as const)(
  "retains Git repository provenance for artifact %s and remote %s",
  (ArtifactName, RepoURL, expected) => {
    const report = { ...trivyReport(), ArtifactName, Metadata: { RepoURL } };
    expect(
      trivyRepositoryUrl(
        normalizeTrivyFindings(report, "cloud", ".").findings[0]!.evidence
          .source_data?.["report"],
      ),
    ).toBe(expected);
  },
);

test("binding rejects conflicting repository claims; clean reports still reject unsafe remote URLs", () => {
  const report = { ...trivyReport(), Results: [] };
  expect(() =>
    trivyRepositoryUrl({
      ...report,
      ArtifactName: "https://example.invalid/other",
    }),
  ).toThrow(/different repositories/);
  for (const source of [
    "https://synthetic-user@example.invalid/repo",
    "https://example\\scanner:fixture@example.invalid/repo",
    "http:///example\\scanner:fixture@example.invalid/repo",
    "ssh://git:fixture@example.invalid/repo",
    "git://fixture@example.invalid/repo",
    "https://example.invalid/repo?token=fixture",
    "ssh://git@github.com/example/project?",
  ]) {
    expect(() =>
      normalizeTrivyFindings(
        { ...report, Metadata: { RepoURL: source } },
        "cloud",
        ".",
      ),
    ).toThrow(/without credentials/);
    expect(() =>
      normalizeTrivyFindings({ ...report, ArtifactName: source }, "cloud", "."),
    ).toThrow(/without credentials/);
    expect(() => trivyRepositoryUrl({ ArtifactName: source })).toThrow(
      /without credentials/,
    );
    expect(() => trivyRepositoryUrl({ Metadata: { RepoURL: source } })).toThrow(
      /without credentials/,
    );
  }
});

test("a repository target can carry an HTTPS account without an explicit scheme", () => {
  const report = trivyReport();
  for (const ArtifactName of [
    "fixture@example.invalid/repo",
    "example:fixture@example.invalid/repo",
    "example:fixture@example.invalid:443/repo",
    ".fixture@example.invalid/repo",
    "\\fixture@example.invalid/repo",
  ]) {
    const header = { ArtifactName, Metadata: {} };
    expect(() =>
      normalizeAtRoot({ ...report, ...header, Results: [] }),
    ).toThrow(/without credentials/);
    expect(() => trivyRepositoryUrl(header)).toThrow(/without credentials/);
    expect(() =>
      trivyRepositoryUrl({ Metadata: { RepoURL: ArtifactName } }),
    ).toThrow(/without credentials/);
  }
  for (const ArtifactName of [
    "/checkout/team@local/repo",
    "apps/team@local/repo",
    "\\\\server\\builds@nightly\\checkout",
    "git@example.invalid:group/repo",
  ]) {
    expect(
      normalizeAtRoot({ ...report, ArtifactName, Results: [] }).report,
    ).toHaveProperty("ArtifactName", ArtifactName);
  }
});

test("reads native JSON and gzip by content, applying the destination's evidence limits", async () => {
  const directory = await mkdtemp(join(tmpdir(), "trivy-import-"));
  try {
    const path = join(directory, "report.json");
    const report = trivyReport();
    await writeFile(path, JSON.stringify(report));
    await expect(readTrivyFindings(path)).rejects.toThrow("--trivy-scan-root");
    expect(await readTrivyFindings(path, "cloud", "apps/web")).toEqual(
      normalizeTrivyFindings(report, "cloud", "apps/web"),
    );
    const custom = "x".repeat(256 * 1024);
    Object.assign(report.Results[0]!.Vulnerabilities[0]!, { Custom: custom });
    await writeFile(path, gzipSync(JSON.stringify(report)));
    const cloud = await readTrivyFindings(path, "cloud", ".");
    expect(cloud.findings).toEqual([]);
    expect(cloud.excluded[0]!.reason).toContain("256 KiB");
    const local = await readTrivyFindings(path, "local", ".");
    expect(local.excluded).toEqual([]);
    expect(
      local.findings[0]!.evidence.source_data?.["vulnerability"],
    ).toMatchObject({ Custom: custom });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

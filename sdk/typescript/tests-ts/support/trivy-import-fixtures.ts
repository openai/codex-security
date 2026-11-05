export function trivyRepositoryHeader(RepoURL: string) {
  return {
    SchemaVersion: 2,
    ArtifactType: "repository",
    Metadata: { RepoURL },
  };
}

export function trivyReport() {
  const name = "@example/package";
  const version = "1.0.0";
  const id = `${name}@${version}`;
  const identifier = {
    PURL: "pkg:npm/%40example/package@1.0.0",
    UID: "123456789abcdef0",
  };
  return {
    SchemaVersion: 2,
    Trivy: { Version: "0.76.1" },
    ReportID: "00000000-0000-7000-8000-000000000001",
    CreatedAt: "2026-01-01T00:00:00Z",
    ArtifactName: ".",
    ArtifactType: "repository",
    Metadata: {
      RepoURL: "https://github.com/example/project",
      Branch: "main",
      Commit: "a".repeat(40),
    },
    Results: [
      {
        Target: "package-lock.json",
        Class: "lang-pkgs",
        Type: "npm",
        Packages: [
          {
            ID: id,
            Name: name,
            Version: version,
            Identifier: { ...identifier },
            Relationship: "indirect",
            Locations: [{ StartLine: 12, EndLine: 17 }],
          },
        ],
        Vulnerabilities: [
          {
            VulnerabilityID: "CVE-2099-0001",
            VendorIDs: ["GHSA-2345-6789-cfgh"],
            PkgName: name,
            PkgID: id,
            PkgIdentifier: { ...identifier },
            InstalledVersion: version,
            FixedVersion: "1.0.1, 2.0.3",
            Status: "fixed",
            Fingerprint: `sha256:${"b".repeat(64)}`,
            Title: "Synthetic dependency vulnerability",
            Description: "A vulnerable version was detected.",
            Severity: "HIGH",
            SeveritySource: "ghsa",
            PrimaryURL: "https://example.invalid/advisories/CVE-2099-0001",
            References: [
              "https://example.invalid/advisories/GHSA-2345-6789-cfgh",
            ],
            CweIDs: ["CWE-79"],
          },
        ],
      },
    ],
  };
}

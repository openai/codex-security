export function githubDependabotAlert(
  number = 1,
  repository = "example/project",
  host = "github.com",
) {
  const hostname = new URL(`https://${host}`).hostname;
  const api =
    hostname === "github.com" || hostname.endsWith(".ghe.com")
      ? `https://api.${host}`
      : `https://${host}/api/v3`;
  const pkg = { ecosystem: "npm", name: "synthetic-widget" };
  const vulnerability = {
    package: { ...pkg },
    severity: "high",
    vulnerable_version_range: "< 2.0.1",
    first_patched_version: { identifier: "2.0.1" } as {
      identifier: string;
    } | null,
  };
  const created = "2026-01-01T00:00:00Z";
  return {
    number,
    state: "open",
    dependency: {
      package: { ...pkg },
      manifest_path: "app/package-lock.json",
      version_requirement: "^1.2.0" as string | null,
      scope: "runtime",
      relationship: "transitive",
    },
    security_advisory: {
      ghsa_id: "GHSA-2345-6789-cfgh",
      cve_id: "CVE-2099-12345",
      summary: "Synthetic dependency advisory",
      description: "Synthetic fixture for import tests.",
      severity: "critical",
      identifiers: [
        { type: "GHSA", value: "GHSA-2345-6789-cfgh" },
        { type: "CVE", value: "CVE-2099-12345" },
      ],
      vulnerabilities: [structuredClone(vulnerability)],
      cvss: { score: 0, vector_string: null },
      cwes: [{ cwe_id: "CWE-79", name: "Synthetic weakness" }],
      references: [],
      published_at: created,
      updated_at: created,
      withdrawn_at: null as string | null,
    },
    security_vulnerability: vulnerability,
    html_url: `https://${host}/${repository}/security/dependabot/${number}`,
    url: `${api}/repos/${repository}/dependabot/alerts/${number}`,
    created_at: created,
    updated_at: created,
    dismissed_at: null as string | null,
    dismissed_by: null,
    dismissed_reason: null as string | null,
    dismissed_comment: null as string | null,
    fixed_at: null as string | null,
    auto_dismissed_at: null as string | null,
  };
}

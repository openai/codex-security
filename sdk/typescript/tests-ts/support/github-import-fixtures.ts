import type { ImportedGitHubCodeScanningAlert } from "../../src/github.js";

export function importedAlert(
  ref = "refs/heads/main",
  host = "github.com",
): ImportedGitHubCodeScanningAlert {
  const url = `https://${host}/example/project/security/code-scanning/12`;
  return {
    source: "github-code-scanning",
    repository: "example/project",
    number: 12,
    url,
    alert: {
      number: 12,
      html_url: url,
      state: "open",
      dismissed_reason: null,
      dismissed_comment: null,
      updated_at: "2026-01-02T00:00:00Z",
      rule: {
        id: "synthetic/sql-query",
        name: "Untrusted query input",
        security_severity_level: "high",
        severity: "error",
        description: "Query input reaches the database.",
        help: "Use query parameters.",
        tags: ["external/cwe/cwe-089"],
      },
      tool: { name: "Synthetic Scanner", version: "1.0" },
      most_recent_instance: {
        ref,
        commit_sha: "a".repeat(40),
        state: "open",
        message: { text: "Untrusted input at the query." },
        location: { path: "src/query.ts", start_line: 12, end_line: 14 },
      },
    } as ImportedGitHubCodeScanningAlert["alert"],
  };
}

export function importedAdvisory(
  selection: "repository" | "global" = "repository",
) {
  const ghsaId = "GHSA-2345-6789-cfgh";
  const url =
    selection === "repository"
      ? `https://github.com/example/project/security/advisories/${ghsaId}`
      : `https://github.com/advisories/${ghsaId}`;
  return {
    source: "github-security-advisory" as const,
    selection,
    repository: "example/project",
    githubHost: "github.com",
    ghsaId,
    url,
    advisory: {
      ghsa_id: ghsaId,
      cve_id: "CVE-2026-0001",
      html_url: url,
      summary: "Synthetic dependency advisory",
      description: "A published report for an example package.",
      severity: "high",
      state: "published",
      withdrawn_at: null,
      updated_at: "2026-01-02T00:00:00Z",
      identifiers: [
        { type: "GHSA", value: ghsaId },
        { type: "CVE", value: "CVE-2026-0001" },
      ],
      vulnerabilities: [
        {
          package: { name: "example-package", ecosystem: "npm" },
          vulnerable_version_range: ">= 1.0.0, < 1.2.3",
          ...(selection === "repository"
            ? { patched_versions: "1.2.3" }
            : { first_patched_version: "1.2.3" }),
        },
      ],
      cwes: [{ cwe_id: "CWE-79", name: "Synthetic weakness" }],
    },
  } as unknown as import("../../src/github-advisories.js").ImportedGitHubAdvisory;
}

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { expect, test } from "bun:test";
import {
  dependabotRepository,
  normalizeGitHubDependabotAlerts,
} from "../src/github-dependabot-findings.js";
import {
  normalizeGitHubAdvisories,
  readGitHubFindings,
} from "../src/github-findings.js";
import { githubDependabotAlert } from "./support/github-dependabot-fixtures.js";
import {
  importedAdvisory,
  importedAlert,
} from "./support/github-import-fixtures.js";
import {
  removeTemporaryDirectory,
  temporaryDirectory,
} from "./support/temporary-directories.js";

function retainedRepository(
  source_data: unknown,
  source_finding_id = "opaque",
  url?: string | null,
) {
  return dependabotRepository({
    source_finding_id,
    evidence: {
      title: "Example",
      severity: "unknown",
      url,
      source_data: source_data as Record<string, unknown> | undefined,
    },
  });
}

test("matches the affected dependency, retains the original alert, and never invents an installed version or revision", () => {
  const alert = githubDependabotAlert();
  alert.security_advisory.vulnerabilities.push({
    ...alert.security_vulnerability,
    package: { ecosystem: "npm", name: "unrelated-package" },
  });
  const original = structuredClone(alert);
  const result = normalizeGitHubDependabotAlerts(alert);
  expect(result.excluded).toEqual([]);
  expect(result.findings).toHaveLength(1);
  const finding = result.findings[0]!;
  expect(finding).toMatchObject({
    source_finding_id: "github.com/example/project/dependabot/1",
    evidence: {
      title: alert.security_advisory.summary,
      severity: "high",
      url: alert.html_url,
      source_updated_at: 1767225600,
      packages: [
        {
          name: "synthetic-widget",
          ecosystem: "npm",
          manifest_path: "app/package-lock.json",
          installed_version: null,
          vulnerable_version_range: "< 2.0.1",
          fixed_versions: ["2.0.1"],
        },
      ],
      advisory_ids: ["GHSA-2345-6789-cfgh", "CVE-2099-12345"],
      locations: [{ path: "app/package-lock.json", line: null }],
      branch: null,
      code_revision: null,
    },
  });
  expect(finding.evidence.packages).toHaveLength(1);
  expect(finding.evidence.source_data).toEqual(original);
  expect(finding.evidence).not.toHaveProperty("details");
  expect(finding.evidence).not.toHaveProperty("assessment");
  expect(alert).toEqual(original);
  alert.dependency.package.name = "changed-after-normalization";
  alert.security_advisory.identifiers.length = 0;
  expect(finding.evidence.source_data).toEqual(original);
});

test("extra metadata cannot hide a native alert or contradict its family", () => {
  const raw = { ...githubDependabotAlert(), source: "extra" };
  for (const target of ["local", "cloud"] as const) {
    const occurrence = normalizeGitHubDependabotAlerts(raw, target)
      .findings[0]!;
    expect(occurrence.evidence.source_data).toEqual(raw);
    expect(dependabotRepository(occurrence)).toBe(
      "https://github.com/example/project",
    );
    expect(retainedRepository(raw, "alert-2")).toBe(
      "https://github.com/example/project",
    );
    for (const source of ["github-code-scanning", "github-security-advisory"]) {
      const contradictory = { ...raw, source };
      expect(() =>
        normalizeGitHubDependabotAlerts(contradictory, target),
      ).toThrow(/family/i);
      expect(() => retainedRepository(contradictory)).toThrow(/family/i);
    }
  }
});

test("does not attribute unrelated advisory packages, ranges, or GHSA aliases", () => {
  const alert = githubDependabotAlert();
  const native = alert.security_advisory;
  const match = alert.security_vulnerability;
  for (const changed of [
    { vulnerabilities: [] },
    {
      vulnerabilities: [
        { ...match, package: { ...match.package, name: "different" } },
      ],
    },
    {
      vulnerabilities: [
        { ...match, package: { ...match.package, ecosystem: "pip" } },
      ],
    },
    { vulnerabilities: [{ ...match, vulnerable_version_range: ">= 10.0" }] },
    { identifiers: [{ type: "GHSA", value: "GHSA-2222-3333-4444" }] },
  ]) {
    for (const target of ["cloud", "local"] as const)
      expect(() =>
        normalizeGitHubDependabotAlerts(
          {
            ...alert,
            security_advisory: { ...native, ...changed },
          },
          target,
        ),
      ).toThrow(/advisory/i);
  }
});

test("uses the matched vulnerability package when the dependency omits it", () => {
  const alert = githubDependabotAlert();
  const withoutPackage = {
    ...alert,
    dependency: { manifest_path: alert.dependency.manifest_path },
  };
  for (const target of ["cloud", "local"] as const) {
    const result = normalizeGitHubDependabotAlerts(
      [withoutPackage, githubDependabotAlert(2)],
      target,
    );
    expect(result.excluded).toEqual([]);
    expect(result.findings).toHaveLength(2);
    expect(result.findings[0]!.evidence.packages![0]).toMatchObject({
      ...alert.security_vulnerability.package,
      manifest_path: alert.dependency.manifest_path,
    });
    expect(result.findings[0]!.evidence.source_data).toEqual(withoutPackage);
  }
});

test.each([
  "file:///etc/passwd",
  "https://example.test/lock",
  "file:outside",
  "git+ssh://example.test/lock",
  ".",
  "project/.",
  "project/",
])(
  "never projects a URI or directory as a checkout manifest: %s",
  (manifest_path) => {
    const raw = githubDependabotAlert();
    raw.dependency.manifest_path = manifest_path;
    for (const target of ["local", "cloud"] as const)
      expect(() => normalizeGitHubDependabotAlerts(raw, target)).toThrow(
        /repository-relative/i,
      );
  },
);

test("preserves a Git manifest path containing a literal backslash", () => {
  const alert = githubDependabotAlert();
  const path = "legacy\\client/package-lock.json";
  alert.dependency.manifest_path = path;
  for (const target of ["local", "cloud"] as const) {
    const { findings } = normalizeGitHubDependabotAlerts(alert, target);
    expect(findings[0]!.evidence.packages![0]!.manifest_path).toBe(path);
    expect(findings[0]!.evidence.locations![0]!.path).toBe(path);
  }
});

test.each(["open", "fixed", "dismissed", "auto_dismissed"])(
  "keeps %s as source state even for a withdrawn advisory",
  (state) => {
    const alert = githubDependabotAlert();
    alert.state = state;
    alert.security_advisory.withdrawn_at = alert.updated_at;
    alert.security_vulnerability.first_patched_version = null;
    alert.dependency.version_requirement = "= 1.2.0";
    const finding = normalizeGitHubDependabotAlerts(alert).findings[0]!;
    expect(finding.source_finding_id).toBe(
      "github.com/example/project/dependabot/1",
    );
    expect(finding.evidence.source_data).toMatchObject({ state });
    expect(finding.evidence).not.toHaveProperty("details");
    expect(finding.evidence.packages![0]).toMatchObject({
      installed_version: null,
      fixed_versions: [],
    });
  },
);

test("retains raw repository, status and CWEs without treating the alert as a GHSA disclosure", () => {
  const alert = githubDependabotAlert(
    3,
    "Example/Project",
    "git.example.test:8443",
  );
  const cwes = [
    { cwe_id: "CWE-79", name: "Synthetic" },
    { cwe_id: "NVD-CWE-noinfo" },
  ];
  const selected = {
    ...alert,
    repository: { full_name: "Example/Project" },
    state: "dismissed",
    security_advisory: { ...alert.security_advisory, cwes },
  };
  for (const target of ["local", "cloud"] as const) {
    const finding = normalizeGitHubDependabotAlerts(selected, target)
      .findings[0]!;
    expect(finding.evidence).not.toHaveProperty("details");
    expect(finding.evidence.source_data).toEqual(selected);
    expect(dependabotRepository(finding)).toBe(
      "https://git.example.test:8443/example/project",
    );
    expect(finding.evidence.packages![0]!.installed_version).toBeNull();
    for (const scope of ["repository", "global"] as const) {
      const disclosure = normalizeGitHubAdvisories(
        [importedAdvisory(scope)],
        target,
      ).findings[0]!;
      expect(disclosure.evidence.advisory_ids).toContain(
        selected.security_advisory.ghsa_id,
      );
      expect(disclosure.evidence.details).toMatchObject({
        kind: "advisory",
        advisory: { source: scope },
      });
      expect(disclosure.source_finding_id).not.toBe(finding.source_finding_id);
    }
  }
});

test("scopes identity by host, repo and alert number, never by GHSA or manifest", () => {
  const first = githubDependabotAlert(1, "Example/Project");
  const second = githubDependabotAlert(2);
  const stored = normalizeGitHubDependabotAlerts([first, second]).findings;
  expect(stored.map((row) => row.source_finding_id)).toEqual([
    "github.com/example/project/dependabot/1",
    "github.com/example/project/dependabot/2",
  ]);
  first.state = "fixed";
  first.dependency.manifest_path = "moved/package-lock.json";
  expect(
    normalizeGitHubDependabotAlerts(first).findings[0]!.source_finding_id,
  ).toBe(stored[0]!.source_finding_id);
  expect(() =>
    normalizeGitHubDependabotAlerts([
      [first],
      [{ ...first, state: "dismissed" }],
    ]),
  ).toThrow(/duplicate/i);
  expect(() =>
    normalizeGitHubDependabotAlerts([
      first,
      githubDependabotAlert(1, "example/another"),
    ]),
  ).toThrow(/one GitHub host and repository/);
  expect(() =>
    normalizeGitHubDependabotAlerts([
      first,
      githubDependabotAlert(1, "example/project", "git.example.test"),
    ]),
  ).toThrow(/one GitHub host and repository/);
});

test.each([
  "github.com",
  "tenant.ghe.com",
  "git.example.test",
  "git.example.test:443",
  "git.example.test:8443",
])("checks API, web, repository slug and explicit port for %s", (host) => {
  const alert = githubDependabotAlert(17, "Example/Project", host);
  const declared = {
    full_name: "example/project",
    html_url: `https://${host}/Example/Project`,
    url: alert.url.replace(/\/dependabot\/alerts\/17$/, ""),
  };
  const row = { ...alert, repository: declared };
  expect(retainedRepository(row)).toBe(`https://${host}/example/project`);
  expect(
    normalizeGitHubDependabotAlerts(row).findings[0]!.source_finding_id,
  ).toBe(`${host}/example/project/dependabot/17`);
  for (const bad of [
    { ...row, number: 18 },
    { ...row, url: alert.url + "?next=test" },
    {
      ...row,
      html_url: alert.html_url.replace(host, "unrelated.example.test"),
    },
    { ...row, url: alert.url.replace("Example/Project", "Example/Other") },
    { ...row, url: alert.url.replace("/alerts/17", "/alerts/18") },
    { ...row, repository: { ...declared, full_name: "example/other" } },
    {
      ...row,
      repository: {
        ...declared,
        html_url: "https://git.example.test/example/other",
      },
    },
    { ...row, repository: { ...declared, url: declared.url + "/other" } },
  ])
    expect(() => retainedRepository(bad)).toThrow();
});

test("checks the normalized occurrence ID against the original Dependabot alert", () => {
  const alert = githubDependabotAlert(
    17,
    "Example/Project",
    "git.example.test:443",
  );
  const finding = normalizeGitHubDependabotAlerts(alert).findings[0]!;
  const raw = finding.evidence.source_data;
  expect(dependabotRepository(finding)).toBe(
    "https://git.example.test:443/example/project",
  );
  for (const wrong of [
    "github.com/example/project/dependabot/17",
    "git.example.test/example/project/dependabot/17",
    "git.example.test:443/example/other/dependabot/17",
    "git.example.test:443/example/project/code-scanning/17",
    "git.example.test:443/example/project/dependabot/18",
    "",
  ])
    expect(() => retainedRepository(raw, wrong)).toThrow(
      /source finding ID.*original Dependabot alert/i,
    );
  for (const unrelated of [importedAlert(), importedAdvisory()]) {
    expect(() =>
      retainedRepository(
        unrelated,
        finding.source_finding_id,
        finding.evidence.url,
      ),
    ).toThrow(/source family/i);

    expect(() =>
      retainedRepository(unrelated, finding.source_finding_id),
    ).toThrow();
    expect(
      retainedRepository(unrelated, "unrelated-occurrence"),
    ).toBeUndefined();
  }
});

test("normalized callers may keep opaque IDs, REST links and partial metadata", () => {
  for (const host of [
    "github.com",
    "tenant.ghe.com",
    "git.example.test:8443",
  ]) {
    const alert = githubDependabotAlert(12, "example/project", host);
    for (const url of [alert.url, alert.html_url]) {
      for (const data of [
        alert,
        { security_vulnerability: alert.security_vulnerability },
        undefined,
      ])
        expect(retainedRepository(data, "alert-12", url)).toBe(
          `https://${host}/example/project`,
        );
      expect(() =>
        retainedRepository(
          { security_vulnerability: {}, number: 13 },
          "alert-12",
          url,
        ),
      ).toThrow(/alert number/i);
    }
  }
});

test("rejects credential-bearing links, foreign API origins, and repo traversal", () => {
  const alert = githubDependabotAlert();
  for (const html_url of [
    alert.html_url + "#state",
    alert.html_url.replace("https://", "https://login@"),
    alert.html_url.replace("/example/project/", "/example/../"),
    alert.html_url.replace("project", "project%2Fother"),
  ])
    expect(() =>
      normalizeGitHubDependabotAlerts({ ...alert, html_url }),
    ).toThrow();
  const enterprise = githubDependabotAlert(
    1,
    "example/project",
    "git.example.test:443",
  );
  for (const url of [
    enterprise.url.replace(":443", ""),
    enterprise.url.replace("/api/v3", ""),
    enterprise.url.replace("git.example.test", "api.github.com"),
  ])
    expect(() =>
      normalizeGitHubDependabotAlerts({ ...enterprise, url }),
    ).toThrow();
  for (const unrelated of [
    importedAdvisory(),
    importedAlert(),
    { action: "published", security_advisory: {} },
    {},
    null,
  ])
    expect(retainedRepository(unrelated)).toBeUndefined();
});

test("handles unambiguous slurped arrays and rejects incomplete page or record shapes", () => {
  const alerts = Array.from({ length: 501 }, (_, index) =>
    githubDependabotAlert(index + 1),
  );
  const paged = Array.from({ length: 6 }, (_, index) =>
    alerts.slice(index * 100, (index + 1) * 100),
  );
  expect(normalizeGitHubDependabotAlerts(paged)).toEqual(
    normalizeGitHubDependabotAlerts(alerts),
  );
  for (const empty of [[], [[]]])
    expect(normalizeGitHubDependabotAlerts(empty)).toEqual({
      read: 0,
      findings: [],
      excluded: [],
    });
  const first = alerts[0]!;
  expect(normalizeGitHubDependabotAlerts([[first], []])).toEqual(
    normalizeGitHubDependabotAlerts([first]),
  );
  for (const invalid of [
    null,
    [first, [first]],
    [[first], [null]],
    [[[first]]],
    [first, importedAdvisory()],
    { alerts: [first] },
    { ...first, security_vulnerability: undefined },
    { ...first, dependency: null },
    { ...first, dependency: { package: null } },
    {
      ...first,
      dependency: { ...first.dependency, manifest_path: "../other/lock" },
    },
    {
      ...first,
      dependency: {
        ...first.dependency,
        package: { ecosystem: "npm", name: "another" },
      },
    },
    {
      ...first,
      security_advisory: { ...first.security_advisory, ghsa_id: "not-an-id" },
    },
    {
      ...first,
      security_vulnerability: {
        ...first.security_vulnerability,
        first_patched_version: {},
      },
    },
    { ...first, updated_at: "invalid" },
    { ...first, state: "closed" },
    { ...first, number: Number.MAX_SAFE_INTEGER + 1 },
  ])
    expect(() => normalizeGitHubDependabotAlerts(invalid)).toThrow();
});

test("keeps destination limits distinct without truncating original data", () => {
  const alert = {
    ...githubDependabotAlert(),
    vendor_extra: "x".repeat(270000),
  };
  expect(normalizeGitHubDependabotAlerts(alert, "cloud")).toMatchObject({
    read: 1,
    findings: [],
    excluded: [
      {
        position: 1,
        source_finding_id: "github.com/example/project/dependabot/1",
      },
    ],
  });
  expect(
    normalizeGitHubDependabotAlerts(alert, "local").findings[0]!.evidence
      .source_data,
  ).toEqual(alert);
  const longIdentity = githubDependabotAlert(1, "example/" + "x".repeat(510));
  expect(
    normalizeGitHubDependabotAlerts(longIdentity).excluded[0]?.reason,
  ).toContain("512");
  expect(
    normalizeGitHubDependabotAlerts(longIdentity, "local").findings,
  ).toHaveLength(1);
});

test("file reader dispatches native lists, selected JSONL and gzip while preserving existing GitHub families", async () => {
  const root = await temporaryDirectory("github-dependabot-");
  try {
    const file = join(root, "alerts");
    const alerts = [githubDependabotAlert(1), githubDependabotAlert(2)];
    for (const data of [
      JSON.stringify(alerts),
      alerts.map((item) => JSON.stringify(item)).join("\n"),
      alerts.map((item) => JSON.stringify([item])).join("\n"),
      gzipSync(JSON.stringify(alerts.map((item) => [item]))),
    ]) {
      await writeFile(file, data);
      expect(await readGitHubFindings(file)).toEqual(
        normalizeGitHubDependabotAlerts(alerts),
      );
    }
    await writeFile(
      file,
      JSON.stringify([importedAlert(), importedAdvisory()]),
    );
    const existing = await readGitHubFindings(file);
    expect(existing.excluded).toEqual([]);
    expect(existing.findings.map((row) => row.source_finding_id)).toEqual([
      expect.stringContaining("/code-scanning/"),
      expect.stringContaining("/security-advisory/"),
    ]);
    for (const repository of ["dependabot/alerts", "security/dependabot"]) {
      const saved = importedAlert();
      const url = saved.url.replace(saved.repository, repository);
      await writeFile(
        file,
        JSON.stringify({
          ...saved,
          repository,
          url,
          alert: { ...saved.alert, html_url: url },
        }),
      );
      const codeScanning = await readGitHubFindings(file);
      expect(codeScanning.excluded).toEqual([]);
      expect(codeScanning.findings[0]!.source_finding_id).toContain(
        `/${repository}/code-scanning/12/`,
      );
    }
    await writeFile(file, JSON.stringify([importedAlert(), []]));
    const legacyWithMalformedSibling = await readGitHubFindings(file);
    expect(legacyWithMalformedSibling.findings).toHaveLength(1);
    expect(legacyWithMalformedSibling.excluded).toHaveLength(1);
    for (const invalid of [
      JSON.stringify([alerts[0], importedAlert()]),
      '{"number":1',
      JSON.stringify([alerts[0], [alerts[1]]]),
    ]) {
      await writeFile(file, invalid);
      await expect(readGitHubFindings(file)).rejects.toThrow();
    }
  } finally {
    await removeTemporaryDirectory(root);
  }
});

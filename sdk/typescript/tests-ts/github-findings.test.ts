import { expect, test } from "bun:test";
import { Octokit } from "@octokit/core";
import { runInNewContext } from "node:vm";
import { importGitHubCodeScanningAlerts } from "../src/github.js";
import { importGitHubAdvisories } from "../src/github-advisories.js";
import { validateExternalEvidence } from "../src/external-import-contract.js";
import {
  normalizeGitHubCodeScanningAlerts,
  normalizeGitHubAdvisories,
} from "../src/github-findings.js";
import type { ImportedGitHubCodeScanningAlert } from "../src/github.js";

import {
  importedAlert,
  importedAdvisory,
} from "./support/github-import-fixtures.js";

test.each(["local", "cloud"] as const)(
  "validates intrinsic numbers and retains vendor evidence on %s",
  (target) => {
    const normalize = (extension: unknown) => {
      const selected = importedAlert();
      Object.assign(selected.alert, { extension: [extension] });
      return normalizeGitHubCodeScanningAlerts([selected], target);
    };
    // Cross-realm wrappers still serialize as numbers. Ordinary objects with
    // user-defined coercion or a Number tag retain their normal JSON shape.
    const unsafe = runInNewContext("new Number(2 ** 53)");
    expect(normalize(2 ** 53).excluded[0]?.reason).toContain("safe integer");
    const spoof = { [Symbol.toStringTag]: "Number", valueOf: () => NaN };
    expect(normalize(unsafe).excluded[0]?.reason).toContain("safe integer");
    expect(normalize(spoof).findings).toHaveLength(1);
    expect(normalize(new Number(Infinity)).excluded[0]?.reason).toContain(
      "finite JSON numbers",
    );
    const captured = (extension: unknown) => {
      const data = normalize(extension).findings[0]!.evidence.source_data;
      return (data?.["alert"] as { extension: unknown[] }).extension[0];
    };
    const plain = { score: new Number(7) };
    expect(captured(plain)).toBe(plain);
    const score = Object.assign(new Number(7), {
      unit: "ms",
      toJSON: () => 2 ** 53,
    });
    class Score extends Number {
      get unit() {
        return "ms";
      }
    }
    class Metrics {
      #unit = "ms";
      score = score;
      get unit() {
        return this.#unit;
      }
    }
    const input = {
      score,
      elapsed: new Score(7),
      metrics: new Metrics(),
      get unit() {
        return this.elapsed.unit;
      },
      get privateUnit() {
        return this.metrics.unit;
      },
      nested: {
        get scores() {
          return [score];
        },
      },
      bytes: Buffer.from([1, 2]),
    };
    // Capture from the original receivers, then return ordinary stored data.
    const retained = captured(input);
    expect(JSON.parse(JSON.stringify(retained))).toEqual({
      score: 7,
      elapsed: 7,
      metrics: { score: 7 },
      unit: "ms",
      privateUnit: "ms",
      nested: { scores: [7] },
      bytes: { "0": 1, "1": 2 },
    });
    expect(JSON.stringify(input.score)).toBe(String(2 ** 53));
    // An own serializer is not structured-cloneable but can provide JSON.
    expect(
      captured({
        score,
        bytes: input.bytes,
        detail: { toJSON: () => "retained" },
      }),
    ).toEqual({
      score: 7,
      bytes: { type: "Buffer", data: [1, 2] },
      detail: "retained",
    });
    const throwing = Object.assign(new Number(7), {
      toJSON() {
        throw new Error("vendor numeric hook");
      },
    });
    expect(JSON.stringify(captured(throwing))).toBe("7");
    class SerializedMetrics {
      #unit = "ms";
      score = runInNewContext("new Number(7)");
      toJSON() {
        return { score: this.score, unit: this.#unit };
      }
    }
    const metrics = new SerializedMetrics();
    expect(captured(metrics)).toBe(metrics);
    expect(JSON.parse(JSON.stringify(metrics))).toEqual({
      score: 7,
      unit: "ms",
    });
    const changing = {
      score,
      get update() {
        this.score = Object.assign(new Number(2 ** 53), {
          unit: "ms",
          toJSON: () => 7,
        });
        return true;
      },
    };
    expect(normalize(changing).excluded[0]?.reason).toContain("safe integer");
    expect(
      normalize(Object.assign(new Number(2 ** 53), { toJSON: () => 12 }))
        .excluded[0]?.reason,
    ).toContain("safe integer");
    expect(
      normalize(Object.assign(new Number(Infinity), { valueOf: () => 12 }))
        .excluded[0]?.reason,
    ).toContain("finite JSON numbers");
    expect(
      normalize(Object.assign(new Number(7), { hidden: Infinity })).excluded[0]
        ?.reason,
    ).toContain("finite JSON numbers");
  },
);

test("code-scanning mapping preserves full evidence and selected instance status without assessing it", () => {
  const imported = importedAlert("refs/heads/review");
  const result = normalizeGitHubCodeScanningAlerts([imported]);
  expect(result.excluded).toEqual([]);
  expect(result.findings[0]).toMatchObject({
    evidence: {
      title: "Untrusted query input",
      severity: "high",
      branch: "refs/heads/review",
      code_revision: "a".repeat(40),
      source_updated_at: 1767312000,
      source_data: imported,
      locations: [{ path: "src/query.ts", line: 12 }],
      details: {
        kind: "sast",
        repository: { url: "https://github.com/example/project" },
        source_status: "open",
        scanner_origin: "Synthetic Scanner",
        weakness_ids: ["CWE-89"],
        code: { end_line: 14 },
      },
    },
  });
  expect(result.findings[0]!.evidence).not.toHaveProperty("assessment");
});

test("code-scanning identities isolate hosts, repositories and selected refs but not updated evidence", () => {
  const first = importedAlert();
  const changed = structuredClone(first);
  changed.alert.most_recent_instance.commit_sha = "b".repeat(40);
  changed.alert.most_recent_instance.state = "fixed";
  const identity = (input: ImportedGitHubCodeScanningAlert) =>
    normalizeGitHubCodeScanningAlerts([input]).findings[0]!.source_finding_id;
  expect(identity(changed)).toBe(identity(first));
  expect(identity(importedAlert("refs/heads/review"))).not.toBe(
    identity(first),
  );
  expect(
    identity(importedAlert("refs/heads/main", "git.example.test")),
  ).not.toBe(identity(first));
  const other = JSON.parse(
    JSON.stringify(first).replaceAll("example/project", "example/other"),
  ) as ImportedGitHubCodeScanningAlert;
  expect(identity(other)).not.toBe(identity(first));
  expect(() => normalizeGitHubCodeScanningAlerts([first, changed])).toThrow(
    "Duplicate source finding id",
  );
});

test("SARIF levels do not fabricate security severity and malformed siblings remain explicit exclusions", () => {
  const noRating = importedAlert();
  delete noRating.alert.rule.security_severity_level;
  const badRepository = importedAlert("refs/heads/other");
  badRepository.repository = "example/wrong";
  const result = normalizeGitHubCodeScanningAlerts([badRepository, noRating]);
  expect(result.read).toBe(2);
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]!.evidence.severity).toBe("unknown");
  expect(result.excluded).toEqual([
    {
      position: 1,
      source_finding_id: badRepository.url,
      reason:
        "GitHub alert URL does not match the selected repository and alert.",
    },
  ]);
});

test.each(["repository", "global"] as const)(
  "%s advisories preserve package ranges without claiming an installed dependency",
  (selection) => {
    const imported = importedAdvisory(selection);
    const result = normalizeGitHubAdvisories([imported]);
    expect(result.excluded).toEqual([]);
    expect(result.findings[0]!.evidence).toMatchObject({
      advisory_ids: [imported.ghsaId, "CVE-2026-0001"],
      packages: [
        {
          name: "example-package",
          ecosystem: "npm",
          vulnerable_version_range: ">= 1.0.0, < 1.2.3",
          installed_version: null,
          manifest_path: null,
          fixed_versions: ["1.2.3"],
        },
      ],
      locations: [],
      source_data: imported,
      details: {
        kind: "advisory",
        advisory: { source: selection },
        source_status: "published",
      },
    });
    if (selection === "repository")
      expect(result.findings[0]!.evidence.details!.repository!.url).toBe(
        "https://github.com/example/project",
      );
    else
      expect(result.findings[0]!.evidence.details).not.toHaveProperty(
        "repository",
      );
  },
);

test("advisory withdrawal and unknown severity remain source evidence with stable identity", () => {
  const imported = importedAdvisory("global");
  const before = normalizeGitHubAdvisories([imported]).findings[0]!;
  const changed = {
    ...imported,
    advisory: {
      ...imported.advisory,
      withdrawn_at: "2026-01-03T00:00:00Z",
      severity: null,
    },
  };
  const after = normalizeGitHubAdvisories([changed as typeof imported])
    .findings[0]!;
  expect(after.source_finding_id).toBe(before.source_finding_id);
  expect(after.evidence.severity).toBe("unknown");
  expect(after.evidence.details!.source_status).toBe("withdrawn");
  expect(after.evidence).not.toHaveProperty("assessment");
});

test("repository/global advisory identities stay separate and source URL conflicts are explicit exclusions", () => {
  const repository = importedAdvisory();
  const global = importedAdvisory("global");
  expect(normalizeGitHubAdvisories([repository, global]).findings).toHaveLength(
    2,
  );
  repository.repository = "example/other";
  const result = normalizeGitHubAdvisories([repository, global]);
  expect(result.findings).toHaveLength(1);
  expect(result.excluded[0]!.reason).toContain(
    "does not match the selected source",
  );
});

test.each(["repository", "global"] as const)(
  "%s advisories retain disclosures with nullable package metadata",
  (selection) => {
    const imported = importedAdvisory(selection);
    const known = imported.advisory.vulnerabilities![0]!;
    for (const vulnerabilities of [
      null,
      [
        { ...known, package: null },
        { ...known, package: { ecosystem: "npm", name: null } },
        known,
      ],
    ]) {
      const input = {
        ...imported,
        advisory: { ...imported.advisory, vulnerabilities },
      } as unknown as typeof imported;
      const result = normalizeGitHubAdvisories([input]);
      expect(result.excluded).toEqual([]);
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0]!.evidence.source_data as unknown).toEqual(
        input,
      );
      expect(result.findings[0]!.evidence.packages).toHaveLength(
        vulnerabilities === null ? 0 : 1,
      );
    }
  },
);

test("normalized global advisory evidence rejects invented source repository provenance", () => {
  const evidence = normalizeGitHubAdvisories([importedAdvisory("global")])
    .findings[0]!.evidence;
  evidence.details!.repository = { url: "https://github.com/example/project" };
  expect(() => validateExternalEvidence(evidence)).toThrow(
    "Global advisory evidence cannot claim a source repository",
  );
});

test.each([
  { kind: "sast" },
  { kind: "secret" },
  { kind: "iac" },
  { kind: "advisory" },
  { kind: "advisory", advisory: { source: "repository" } },
  {
    kind: "sast",
    repository: { url: "https://github.com/example/project" },
    advisory: { source: "repository" },
  },
])(
  "external evidence enforces repository and advisory source context: %j",
  (details) => {
    expect(() =>
      validateExternalEvidence({
        title: "Synthetic evidence",
        severity: "unknown",
        details,
      }),
    ).toThrow();
  },
);

test("global advisories accept canonical public links from an Enterprise API without changing source host identity", () => {
  const imported = importedAdvisory("global");
  imported.githubHost = "git.example.test";
  const result = normalizeGitHubAdvisories([imported]);
  expect(result.excluded).toEqual([]);
  expect(result.findings[0]!.source_finding_id).toStartWith(
    "git.example.test/global/security-advisory/",
  );
  expect(result.findings[0]!.evidence.url).toBe(imported.url);
  expect(result.findings[0]!.evidence.source_data as unknown).toEqual(imported);
  expect(result.findings[0]!.evidence.details).not.toHaveProperty("repository");
  const wrongRepositoryHost = importedAdvisory("repository");
  wrongRepositoryHost.githubHost = "git.example.test";
  expect(
    normalizeGitHubAdvisories([wrongRepositoryHost]).excluded,
  ).toHaveLength(1);
});

test("repository-wide dismissal takes precedence over detection state while selected refs keep their own open/fixed state", () => {
  const imported = importedAlert("refs/heads/review");
  imported.alert.state = "dismissed";
  imported.alert.dismissed_reason = "false positive";
  expect(
    normalizeGitHubCodeScanningAlerts([imported]).findings[0]!.evidence.details!
      .source_status,
  ).toBe("dismissed");
  imported.alert.state = "fixed";
  imported.alert.dismissed_reason = null;
  expect(
    normalizeGitHubCodeScanningAlerts([imported]).findings[0]!.evidence.details!
      .source_status,
  ).toBe("open");
});

test.each(["security/code-scanning", "code-scanning"])(
  "code-scanning accepts the %s HTML route without changing identity or repository binding",
  (route) => {
    const original = importedAlert();
    const imported = structuredClone(original);
    imported.url = `https://github.com/example/project/${route}/12`;
    imported.alert.html_url = imported.url;
    const result = normalizeGitHubCodeScanningAlerts([imported]);
    expect(result.excluded).toEqual([]);
    expect(result.findings[0]!.source_finding_id).toBe(
      normalizeGitHubCodeScanningAlerts([original]).findings[0]!
        .source_finding_id,
    );
    expect(result.findings[0]!.evidence.source_data as unknown).toEqual(
      imported,
    );
    imported.repository = "example/other";
    expect(normalizeGitHubCodeScanningAlerts([imported]).excluded).toHaveLength(
      1,
    );
    imported.repository = original.repository;
    imported.url = `https://github.com/example/project/${route}/13`;
    imported.alert.html_url = imported.url;
    expect(normalizeGitHubCodeScanningAlerts([imported]).excluded).toHaveLength(
      1,
    );
  },
);

test("real GitHub readers and mappings preserve explicit ports in repository evidence and identities", async () => {
  const codeIds = new Set<string>();
  const advisoryIds = new Set<string>();
  for (const port of ["", ":443", ":8443"]) {
    const host = `git.example.test${port}`;
    const alert = importedAlert("refs/heads/main", host);
    const advisory = importedAdvisory();
    advisory.githubHost = host;
    advisory.url = advisory.advisory.html_url = advisory.url.replace(
      "github.com",
      host,
    );
    const github = new Octokit({
      request: {
        fetch: async (resource: Parameters<typeof fetch>[0]) => {
          const url = new URL(
            resource instanceof Request ? resource.url : resource,
          );
          return Response.json(
            url.pathname.includes("code-scanning")
              ? alert.alert
              : advisory.advisory,
          );
        },
      },
    });
    const dependency = {
      environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
      createGitHub: async (selectedHost: string) => {
        expect(selectedHost).toBe(host);
        return github;
      },
    };
    const importedAlerts = await importGitHubCodeScanningAlerts(
      { repository: alert.repository, alertNumbers: [12], githubHost: host },
      dependency,
    );
    const code = normalizeGitHubCodeScanningAlerts(importedAlerts);
    const importedAdvisories = await importGitHubAdvisories(
      {
        repository: advisory.repository,
        advisoryIds: [advisory.ghsaId],
        githubHost: host,
      },
      dependency,
    );
    const disclosed = normalizeGitHubAdvisories(importedAdvisories);
    expect(code.excluded).toEqual([]);
    expect(disclosed.excluded).toEqual([]);
    for (const result of [code, disclosed])
      expect(result.findings[0]!.evidence.details!.repository!.url).toBe(
        `https://${host}/example/project`,
      );
    expect(code.findings[0]!.evidence.source_data as unknown).toEqual(
      importedAlerts[0],
    );
    expect(disclosed.findings[0]!.evidence.source_data as unknown).toEqual(
      importedAdvisories[0],
    );
    codeIds.add(code.findings[0]!.source_finding_id);
    advisoryIds.add(disclosed.findings[0]!.source_finding_id);
  }
  expect(codeIds.size).toBe(3);
  expect(advisoryIds.size).toBe(3);
});

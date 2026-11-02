import { expect, test } from "bun:test";
import { Octokit } from "@octokit/core";
import { runInNewContext } from "node:vm";
import { importGitHubCodeScanningAlerts } from "../src/github.js";
import { importGitHubAdvisories } from "../src/github-advisories.js";
import { validateExternalEvidence } from "../src/external-import-contract.js";
import { previousReaderSelection } from "../src/reader-selection.js";
import {
  normalizeGitHubCodeScanningAlerts,
  normalizeGitHubAdvisories,
} from "../src/github-findings.js";
import type { ImportedGitHubCodeScanningAlert } from "../src/github.js";

import {
  importedAlert,
  importedAdvisory,
} from "./support/github-import-fixtures.js";

test("captures a record-root serializer with its selection index once", () => {
  const row = importedAlert(),
    keys: string[] = [];
  const instance = row.alert["most_recent_instance"] as Record<string, unknown>;
  Object.setPrototypeOf(row, {
    toJSON(key: string) {
      keys.push(key);
      return {
        ...row,
        alert: {
          ...row.alert,
          most_recent_instance: { ...instance, ref: "refs/heads/" + key },
        },
      };
    },
  });
  const output = normalizeGitHubCodeScanningAlerts([row]);
  expect(output.findings[0]?.evidence.branch).toBe("refs/heads/0");
  expect(keys).toEqual(["0"]);
  const old = previousReaderSelection(output, structuredClone(output));
  expect(old?.sourceFindingIds).toHaveLength(1);
  expect(old?.snapshot).toBeUndefined();
});

test("an alert with hidden mapped rule fields retains its possible earlier occurrence", () => {
  const row = importedAlert();
  const rule = row.alert["rule"] as Record<string, unknown>;
  Object.defineProperty(rule, "name", {
    enumerable: false,
    value: "Hidden title",
  });
  Object.defineProperty(rule, "security_severity_level", {
    enumerable: false,
    value: "critical",
  });
  const current = normalizeGitHubCodeScanningAlerts([row]);
  const id = current.findings[0]!.source_finding_id;
  expect(current.findings[0]?.evidence.title).not.toBe("Hidden title");
  expect(current.findings[0]?.evidence.severity).toBe("unknown");
  const prior = previousReaderSelection(current, structuredClone(current));
  expect(prior?.snapshot).toBeUndefined();
  expect(prior?.uncertainFindingIds).toEqual([id]);
});

test("advisory membership with a hidden numeric getter is uncertain without reading it", () => {
  const first = importedAdvisory("repository"),
    second = importedAdvisory("global");
  let reads = 0;
  const score = Object.defineProperty(new Number(7), "bad", {
    enumerable: true,
    get: () => {
      reads++;
      return Infinity;
    },
  });
  Object.assign(second.advisory, { score });
  const current = normalizeGitHubAdvisories([first, second]);
  expect(reads).toBe(0);
  expect(current.findings).toHaveLength(2);
  const prior = previousReaderSelection(current, structuredClone(current));
  expect(prior?.snapshot).toBeUndefined();
  expect(prior?.uncertainFindingIds).toEqual([
    current.findings[1]!.source_finding_id,
  ]);
  expect(prior?.knownFindings?.map((f) => f.source_finding_id)).toEqual([
    current.findings[0]!.source_finding_id,
  ]);
});

test("a getter can mutate a later GitHub row before its historical evidence is observed", () => {
  const first = importedAlert("refs/heads/first");
  const middle = importedAlert("refs/heads/middle");
  const last = importedAlert("refs/heads/last");
  const counter = { count: 0 };
  Object.assign(middle.alert, {
    extension: {
      get sample() {
        return ++counter.count;
      },
    },
  });
  Object.assign(last.alert, { extension: counter });
  const fresh = normalizeGitHubCodeScanningAlerts([first, middle, last]);
  const prior = previousReaderSelection(fresh, structuredClone(fresh));
  expect(counter.count).toBe(1);
  expect(prior?.sourceFindingIds).toEqual(
    fresh.findings.map((row) => row.source_finding_id),
  );
  expect(prior?.uncertainFindingIds).toEqual([
    fresh.findings[1]!.source_finding_id,
  ]);
  expect(prior?.knownFindings?.map((row) => row.source_finding_id)).toEqual([
    fresh.findings[0]!.source_finding_id,
  ]);
});

test("locally normalized GitHub output retains the original Buffer for Cloud checkpoint verification", () => {
  const row = importedAlert();
  Object.assign(row.alert, { payload: Buffer.from([5, 17, 129]) });
  const current = normalizeGitHubCodeScanningAlerts([row], "local");
  expect(current.findings[0]?.evidence.source_data?.["alert"]).toMatchObject({
    payload: { type: "Buffer", data: [5, 17, 129] },
  });
  const prior = previousReaderSelection(current, structuredClone(current));
  expect(
    prior?.snapshot?.findings[0]?.evidence.source_data?.["alert"],
  ).toMatchObject({ payload: Uint8Array.from([5, 17, 129]) });
});

test.each([7, 2 ** 53])(
  "a compact export with a deeply shared raw number %i uses the emitted value",
  (value) => {
    const row = importedAlert();
    let reads = 0;
    let graph: unknown = {
      score: value,
      get unused() {
        reads++;
        return 1;
      },
    };
    for (let i = 0; i < 28; i++) graph = { left: graph, right: graph };
    Object.assign(row.alert, { extension: { graph, toJSON: () => "summary" } });
    const output = normalizeGitHubCodeScanningAlerts([row]);
    expect(reads).toBe(0);
    expect(output.findings[0]?.evidence.source_data?.["alert"]).toMatchObject({
      extension: "summary",
    });
  },
);

test.each(["local", "cloud"] as const)(
  "observes a stateful mapped GitHub ref only once on %s",
  (target) => {
    function fixture() {
      const row = importedAlert();
      let count = 0;
      Object.defineProperty(row.alert["most_recent_instance"], "ref", {
        enumerable: true,
        get: () => "refs/heads/r" + ++count,
      });
      return { row, count: () => count };
    }
    const direct = fixture(),
      saved = fixture();
    const result = normalizeGitHubCodeScanningAlerts([direct.row], target);
    const exported = normalizeGitHubCodeScanningAlerts(
      JSON.parse(JSON.stringify([saved.row])),
      target,
    );
    expect(result).toEqual(exported);
    expect(result.findings[0]?.evidence.branch).toBe("refs/heads/r1");
    expect(direct.count()).toBe(1);
  },
);

test.each(["local", "cloud"] as const)(
  "maps the exported GitHub occurrence and checks its identity on %s",
  (target) => {
    const rows = ["main", "review"].map((ref) => {
      const row = importedAlert("refs/heads/" + ref);
      const instance = row.alert["most_recent_instance"] as Record<
        string,
        unknown
      >;
      Object.setPrototypeOf(instance, {
        toJSON(this: typeof instance) {
          return { ...this, ref: "refs/heads/exported" };
        },
      });
      return row;
    });
    const plain = JSON.parse(JSON.stringify(rows));
    const read = normalizeGitHubCodeScanningAlerts([rows[0]!], target);
    expect(read).toEqual(normalizeGitHubCodeScanningAlerts([plain[0]], target));
    expect(read.findings[0]!.evidence.branch).toBe("refs/heads/exported");
    expect(() => normalizeGitHubCodeScanningAlerts(rows, target)).toThrow(
      "Duplicate source finding id",
    );
    if (target === "cloud") {
      const old = previousReaderSelection(
        read,
        structuredClone(read),
      )?.snapshot;
      expect(old?.findings[0]!.evidence.branch).toBe("refs/heads/main");
      expect(old?.findings[0]!.source_finding_id).not.toBe(
        read.findings[0]!.source_finding_id,
      );
    }
  },
);

test.each(["local", "cloud"] as const)(
  "retains exactly the exported GitHub values on %s",
  (target) => {
    const score = Object.assign(new Number(7), {
      toJSON: (key: string) => (key === "score" ? 9 : 1e-7),
    });
    class Samples extends Array<number> {
      toJSON() {
        return { count: this.length };
      }
    }
    const extension = {
      score,
      get alias() {
        return score;
      },
      samples: new Samples(1, 2),
      warning: Object.assign(new Error("scanner warning"), { code: "W1" }),
      bytes: Buffer.from([1, 2]),
    };
    const row = importedAlert();
    Object.assign(row.alert, { extension });
    const read = normalizeGitHubCodeScanningAlerts([row], target);
    expect(read.excluded).toEqual([]);
    const alert = read.findings[0]!.evidence.source_data!["alert"] as Record<
      string,
      unknown
    >;
    expect(alert["extension"]).toEqual({
      score: 9,
      alias: 1e-7,
      samples: { count: 2 },
      warning: { code: "W1" },
      bytes: { type: "Buffer", data: [1, 2] },
    });
    extension.warning.code = "later";
    expect(alert["extension"]).toMatchObject({ warning: { code: "W1" } });
  },
);

test.each(["local", "cloud"] as const)(
  "checks emitted GitHub numbers and retains previous numeric exclusions on %s",
  (target) => {
    function reason(value: unknown) {
      const row = importedAlert();
      Object.assign(row.alert, { metric: value });
      return normalizeGitHubCodeScanningAlerts([row], target).excluded[0]
        ?.reason;
    }
    for (const value of [
      2 ** 53,
      runInNewContext("new Number(2 ** 53)"),
      Object.assign(new Number(7), { toJSON: () => 2 ** 53 }),
    ])
      expect(reason(value)).toContain("safe integer");
    expect(reason({ toJSON: () => NaN })).toContain("finite JSON");
    for (const [metric, exported, previousReason] of [
      [Object.assign(new Number(7), { hidden: Infinity }), 7, "finite JSON"],
      [{ x: 2 ** 53, toJSON: () => "summary" }, "summary", "safe integer"],
    ] as const) {
      const allowed = importedAlert("refs/heads/first");
      const row = importedAlert();
      Object.assign(row.alert, { metric });
      const result = normalizeGitHubCodeScanningAlerts([allowed, row], target);
      expect(result.excluded).toEqual([]);
      expect(result.findings[1]?.evidence.source_data?.["alert"]).toMatchObject(
        { metric: exported },
      );
      if (target === "cloud") {
        const previous = previousReaderSelection(
          result,
          structuredClone(result),
        )?.snapshot;
        expect(previous?.findings.map((f) => f.source_finding_id)).toEqual([
          result.findings[0]!.source_finding_id,
        ]);
        expect(previous?.excluded[0]?.reason).toContain(previousReason);
      }
    }
  },
);

test.each(["cloud", "local"] as const)(
  "accepts a boxed integer explicitly exported as safe JSON on %s",
  (target) => {
    for (const emitted of ["9007199254740992", 7]) {
      const row = importedAlert();
      Object.assign(row.alert, {
        metric: Object.assign(new Number(2 ** 53), { toJSON: () => emitted }),
      });
      const normalized = normalizeGitHubCodeScanningAlerts([row], target);
      expect(normalized).toEqual(
        normalizeGitHubCodeScanningAlerts(
          JSON.parse(JSON.stringify([row])),
          target,
        ),
      );
      expect(
        normalized.findings[0]?.evidence.source_data?.["alert"],
      ).toMatchObject({ metric: emitted });
    }
  },
);

test("a data-field number's original native value survives only for verifying an earlier approval", () => {
  const row = importedAlert();
  const score = Object.assign(new Number(7), { toJSON: () => 9 });
  Object.assign(row.alert, { score });
  const result = normalizeGitHubCodeScanningAlerts([row]);
  const previous = previousReaderSelection(result, structuredClone(result));
  const saved = previous?.snapshot?.findings[0]?.evidence.source_data?.[
    "alert"
  ] as { score: Number };
  expect(
    previousReaderSelection({ ...result }, structuredClone(result))?.snapshot,
  ).toBe(previous?.snapshot);
  expect(
    previousReaderSelection({ ...result }, { ...result, read: result.read + 1 })
      ?.snapshot,
  ).toBeUndefined();
  expect(Number.prototype.valueOf.call(saved.score)).toBe(7);
  expect(result.findings[0]?.evidence.source_data?.["alert"]).toMatchObject({
    score: 9,
  });
});

test("uses the actual first wire and preserves only an occurrence hint for getter-dependent approvals", () => {
  const score = Object.assign(new Number(7), { toJSON: () => 9 });
  let reads = 0;
  const shared = {
    score,
    get sample() {
      return ++reads;
    },
  };
  const rows = ["main", "review", "excluded"].map((name) => {
    const row = importedAlert("refs/heads/" + name);
    Object.assign(row.alert, { shared });
    return row;
  });
  Object.assign(rows[2]!.alert, {
    extra: { toJSON: () => "retained" },
    pad: "x".repeat(256 * 1024),
  });
  const output = normalizeGitHubCodeScanningAlerts(rows);
  const fresh = output.findings.map(
    ({ evidence }) =>
      (
        evidence.source_data!["alert"] as {
          shared: { score: number; sample: number };
        }
      ).shared,
  );
  expect(fresh).toEqual([
    { score: 9, sample: 1 },
    { score: 9, sample: 2 },
  ]);
  expect(reads).toBe(3);
  const prior = previousReaderSelection(output, structuredClone(output));
  expect(prior?.snapshot).toBeUndefined();
  expect(prior?.unprovenIdPrefixes).toEqual([
    "github.com/example/project/code-scanning/12/",
  ]);
});

test("an exported row over the Cloud byte limit can have an exact historical selection", () => {
  const row = importedAlert(),
    raw = { score: new Number(1e-7), bytes: Buffer.from([1]), pad: "" };
  Object.assign(row.alert, { raw });
  const read = () => normalizeGitHubCodeScanningAlerts([row]);
  const size = Buffer.byteLength(JSON.stringify(read().findings[0]!.evidence));
  raw.pad = "x".repeat(256 * 1024 - size - 1);
  expect(read().findings).toHaveLength(1);
  raw.pad += "x";
  const current = read();
  expect(current.findings).toHaveLength(0);
  expect(current.excluded[0]?.reason).toContain("256 KiB");
  const old = previousReaderSelection(
    current,
    structuredClone(current),
  )?.snapshot;
  expect(old?.findings).toHaveLength(1);
  expect(old?.excluded).toEqual([]);
});

test("applies the Cloud byte limit to numbers returned by a vendor serializer", () => {
  const row = importedAlert();
  const score = Object.assign(new Number(1), { toJSON: () => 123456 });
  const extension = { pad: "", formatted: { toJSON: () => ({ score }) } };
  Object.assign(row.alert, { extension });
  const read = () => normalizeGitHubCodeScanningAlerts([row]);
  const evidence = read().findings[0]!.evidence;
  extension.pad = "x".repeat(
    256 * 1024 - Buffer.byteLength(JSON.stringify(evidence)),
  );
  expect(read().findings).toHaveLength(1);
  extension.pad += "x";
  expect(read().excluded[0]?.reason).toContain("256 KiB");
});

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
  const rows = [badRepository, noRating];
  rows.length = 3;
  const result = normalizeGitHubCodeScanningAlerts(rows);
  expect(result.read).toBe(3);
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]!.evidence.severity).toBe("unknown");
  expect(result.excluded).toEqual([
    {
      position: 1,
      source_finding_id: badRepository.url,
      reason:
        "GitHub alert URL does not match the selected repository and alert.",
    },
    {
      position: 3,
      source_finding_id: null,
      reason: "GitHub finding must be an object.",
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

test("Cloud rejects over-depth exported GitHub rows before reading shared leaves", () => {
  const row = importedAlert();
  let reads = 0;
  let graph: unknown = {
    get value() {
      reads++;
      return 1;
    },
  };
  for (let i = 0; i < 7; i++) graph = { left: graph, right: graph };
  for (let i = 0; i < 22; i++) graph = { next: graph };
  Object.assign(row.alert, { extension: graph });

  const output = normalizeGitHubCodeScanningAlerts([row]);
  expect(output.excluded[0]?.reason).toBe(
    "Evidence exceeds the Cloud JSON depth limit of 20.",
  );
  expect(reads).toBe(0);
  expect(
    normalizeGitHubCodeScanningAlerts([row], "local").findings,
  ).toHaveLength(1);
  expect(reads).toBe(128);
});

test("an over-depth exported GitHub Buffer can retain its valid native selection", () => {
  const row = importedAlert();
  let graph: unknown = Buffer.from([7]);
  for (let i = 0; i < 16; i++) graph = { next: graph };
  Object.assign(row.alert, { extension: graph });

  const previous = normalizeGitHubCodeScanningAlerts([structuredClone(row)]);
  const current = normalizeGitHubCodeScanningAlerts([row]);
  expect(current.excluded[0]?.reason).toBe(
    "Evidence exceeds the Cloud JSON depth limit of 20.",
  );
  expect(previous.findings).toHaveLength(1);
  expect(
    JSON.stringify(previousReaderSelection(current, current)?.snapshot),
  ).toBe(JSON.stringify(previous));
});

test("an over-depth GitHub export cannot prove a custom serializer's old byte limit", () => {
  for (const oldPayload of [{ tiny: true }, { pad: "x".repeat(256 * 1024) }]) {
    const row = importedAlert();
    let graph: unknown = 1;
    for (let i = 0; i < 24; i++) graph = { next: graph };
    const keys: string[] = [];
    Object.defineProperty(row, "toJSON", {
      value(key: string) {
        keys.push(key);
        return key === "source_data" ? oldPayload : { graph };
      },
    });
    const current = normalizeGitHubCodeScanningAlerts([row]);
    expect(keys).toEqual(["0"]);
    expect(current.excluded[0]?.reason).toContain("depth limit");
    expect(previousReaderSelection(current, current)?.snapshot).toBeUndefined();
    expect(
      previousReaderSelection(current, current)?.sourceFindingIds,
    ).toHaveLength(1);
  }
});

test("discarded native Buffer fields cannot establish an old GitHub selection", () => {
  const row = importedAlert(),
    buffer = Buffer.from([7]);
  let extra: unknown = 7,
    graph: unknown = buffer;
  for (let i = 0; i < 24; i++) extra = { next: extra };
  Object.assign(buffer, { extra });
  for (let i = 0; i < 16; i++) graph = { next: graph };
  Object.assign(row.alert, { extension: graph });
  const current = normalizeGitHubCodeScanningAlerts([row]);
  expect(current.excluded[0]?.reason).toContain("depth limit");
  expect(previousReaderSelection(current, current)?.snapshot).toBeUndefined();
});

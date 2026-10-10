import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { discoverScaInputs, normalizeOsvOutput } from "../src/sca-osv.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  compareScaResults,
  createScaUpdateHandoff,
  renderScaReport,
} from "../src/sca-report.js";
import type {
  ScaAssessment,
  ScaResult,
  TriageFinding,
} from "../src/sca-types.js";

const { create: temporaryDirectory, cleanup } = createTemporaryDirectories();
afterEach(cleanup);

function fixture(): ScaResult {
  return {
    schemaVersion: "sca/v0",
    status: "completed",
    startedAt: "2026-09-01T00:00:00Z",
    completedAt: "2026-09-01T00:01:00Z",
    repository: {
      path: "/workspace/base",
      revision: "synthetic-revision",
      dirty: false,
    },
    scanner: {
      name: "osv-scanner",
      version: "2.6.0",
      argv: ["scan", "source"],
      startedAt: "2026-09-01T00:00:00Z",
      completedAt: "2026-09-01T00:00:30Z",
      exitCode: 1,
      rawOutputPath: "/reports/base/osv.json",
      stderrPath: "/reports/base/osv.stderr",
      advisoryMode: "offline",
      advisorySnapshotId: "synthetic-database-digest",
    },
    coverage: {
      status: "complete",
      inputs: [
        {
          path: "package-lock.json",
          sha256: "base-digest",
          format: "npm",
          status: "scanned",
          reason: null,
        },
      ],
      configFiles: [],
      limitations: [],
      unresolvedPackages: 0,
    },
    components: [
      {
        id: "component-1",
        name: "synthetic-package",
        version: "1.0.0",
        ecosystem: "npm",
        sourcePath: "package-lock.json",
        dependencyGroups: ["dev"],
      },
    ],
    matches: [
      {
        id: "match-1",
        componentId: "component-1",
        advisoryIds: ["SYNTHETIC-1"],
        aliases: ["SYNTHETIC-ALIAS-1"],
        sourceAdvisories: [
          { id: "SYNTHETIC-1", modified: "2026-08-01T00:00:00Z" },
        ],
        severity: "HIGH",
        fixedVersions: ["1.0.2"],
        advisoryModifiedAt: ["2026-08-01T00:00:00Z"],
      },
    ],
    assessments: [],
    diagnostics: [],
    model: { model: null, skillDigest: null, threadId: null, costUsd: null },
    outputDir: "/reports/base",
  };
}

function triage(verdict: TriageFinding["verdict"]): TriageFinding {
  return {
    triage_item_id: "assessment-1",
    input_id: "match-1",
    source_type: "advisory",
    title: "Synthetic dependency advisory",
    verdict,
    confidence: "medium",
    normalized_input: {
      vulnerable_component: "synthetic-package",
      claimed_source: "lockfile",
      claimed_sink: "unknown",
      claimed_control: "unknown",
      affected_version_or_path: "1.0.0",
      preconditions: [],
      impact: "synthetic impact",
      references: ["SYNTHETIC-1"],
    },
    affected_locations: [],
    reachable_path: [],
    boundary_assessment: {
      product_surface: "unknown",
      source_trust: "unknown",
      boundary_crossed: null,
      policy_basis: "static application context",
    },
    exploitability_stack_rank: {
      rank_queue: null,
      rank: null,
      rationale: "static assessment",
      drivers: [],
    },
    evidence: ["package-lock.json contains the resolved version."],
    counterevidence: [
      "The affected API is not imported in the inspected entrypoint.",
    ],
    proof_gaps: ["Deployment entrypoints are unavailable."],
    recommended_next_step: "Review deployment configuration.",
    fix_finding_handoff: "Update to 999.0.0.",
  };
}

function addMatch(
  result: ScaResult,
  id: string,
  version: string,
  alias = "SYNTHETIC-ALIAS-1",
) {
  result.components.push({
    ...result.components[0]!,
    id: `component-${id}`,
    version,
  });
  result.matches.push({
    ...result.matches[0]!,
    id,
    componentId: `component-${id}`,
    aliases: [alias],
  });
}

describe("SCA report", () => {
  test.each(["confirmed", "needs_review", "not_actionable"] as const)(
    "retains advisory facts with %s assessment",
    (verdict) => {
      const result = fixture();
      result.assessments = [
        {
          matchId: "match-1",
          status: "completed",
          verdict,
          triage: triage(verdict),
          error: null,
        },
      ];
      const report = renderScaReport(result);
      for (const value of [
        "match-1",
        "synthetic-package",
        "1.0.0",
        "SYNTHETIC-1",
        "SYNTHETIC-ALIAS-1",
        "HIGH",
        "1.0.2",
        verdict,
        "Deployment entrypoints are unavailable.",
      ])
        expect(report).toContain(value);
      expect(report).toContain("unknown from scanner evidence");
      expect(report).toContain("not verified");
      expect(report).not.toContain("999.0.0");
    },
  );

  test.each(["not_started", "failed", "cancelled"] as const)(
    "keeps matches when assessment is %s",
    (status) => {
      const result = fixture();
      result.assessments = [
        {
          matchId: "match-1",
          status,
          verdict: null,
          triage: null,
          error: status === "failed" ? "Model unavailable" : null,
        },
      ];
      const report = renderScaReport(result);
      expect(report).toContain("SYNTHETIC-1");
      expect(report).toContain(status);
      if (status === "failed") expect(report).toContain("Model unavailable");
    },
  );

  test("shows full observed inventory, coverage exclusions, and diagnostics", () => {
    const result = fixture();
    result.components.push({
      ...result.components[0]!,
      id: "component-clean",
      name: "synthetic-unmatched-package",
    });
    result.coverage.configFiles = [
      { path: "osv-scanner.toml", sha256: "configuration-digest" },
    ];
    result.coverage.inputs.push({
      path: "nested/package-lock.json",
      sha256: "unsupported-digest",
      format: "npm",
      status: "unsupported",
      reason: "Unsupported lockfile format",
    });
    result.coverage.status = "partial";
    result.coverage.unresolvedPackages = 2;
    result.coverage.limitations = [
      "Configured package exclusions may remove inventory entries.",
    ];
    result.diagnostics = ["Matching completed for one effective input."];
    const report = renderScaReport(result);
    for (const value of [
      "synthetic-unmatched-package",
      "osv-scanner.toml",
      "suppressed package counts are unavailable",
      "Unsupported lockfile format",
      "Unresolved packages: **2**",
      ...result.diagnostics,
    ])
      expect(report).toContain(value);
  });

  test("does not describe a zero-match incomplete run as clean", () => {
    const result = fixture();
    result.matches = [];
    result.coverage.status = "failed";
    result.coverage.inputs = [];
    const report = renderScaReport(result);
    expect(report).toContain("matching coverage is incomplete");
    expect(report).toContain("No lockfile inputs were evaluated");
    expect(report).not.toContain(
      "No advisory matches were reported within the effective evaluated scope",
    );
  });

  test("renders package names containing Markdown delimiters without losing their identity", () => {
    const result = fixture();
    result.components[0]!.name = "synthetic`package";
    expect(renderScaReport(result)).toContain("`` synthetic`package ``");
  });
});

describe("SCA comparison", () => {
  test("correlates relative source paths across checkout roots and added aliases", () => {
    const base = fixture();
    const head = fixture();
    head.repository.path = "/other-checkout/head";
    head.matches[0]!.id = "head-match";
    head.matches[0]!.advisoryIds = ["NEW-SYNTHETIC-ID"];
    head.matches[0]!.aliases.push("SYNTHETIC-1");
    head.coverage.inputs[0]!.sha256 = "changed-lockfile-digest";
    const comparison = compareScaResults(base, head);
    expect(comparison.comparable).toBe(true);
    expect(comparison.persisting).toEqual([
      { baseMatchIds: ["match-1"], headMatchIds: ["head-match"] },
    ]);
    expect(comparison.introduced).toEqual([]);
  });

  test.each([
    [
      "/workspace/base",
      "/workspace/base/nested/package-lock.json",
      "/workspace/head",
      "/workspace/head/nested/package-lock.json",
    ],
    [
      "C:\\work tree\\base",
      "C:\\work tree\\base\\nested\\package-lock.json",
      "D:\\head checkout",
      "D:\\head checkout\\nested\\package-lock.json",
    ],
    [
      "C:\\base",
      "nested\\package-lock.json",
      "/head",
      "nested/package-lock.json",
    ],
  ])(
    "correlates source identities between %s and another checkout",
    (baseRoot, baseSource, headRoot, headSource) => {
      const base = fixture();
      const head = fixture();
      base.repository.path = baseRoot!;
      head.repository.path = headRoot!;
      base.components[0]!.sourcePath = baseSource!;
      head.components[0]!.sourcePath = headSource!;
      base.coverage.inputs[0]!.path = baseSource!;
      head.coverage.inputs[0]!.path = headSource!;
      const comparison = compareScaResults(base, head);
      expect(comparison.persisting).toHaveLength(1);
      expect(comparison.comparable).toBe(true);
    },
  );

  test("does not conflate literal POSIX backslashes with directory separators", () => {
    const base = fixture();
    const head = fixture();
    base.components[0]!.sourcePath = "nested\\folder/package-lock.json";
    base.coverage.inputs[0]!.path = base.components[0]!.sourcePath;
    head.components[0]!.sourcePath = "nested/folder/package-lock.json";
    head.coverage.inputs[0]!.path = head.components[0]!.sourcePath;
    head.matches[0]!.id = "head-match";
    const comparison = compareScaResults(base, head);
    expect(comparison.persisting).toEqual([]);
    expect(comparison.newlyObserved).toEqual(["head-match"]);
    expect(comparison.introduced).toEqual([]);
    expect(comparison.noLongerObserved).toEqual([
      { matchId: "match-1", resolved: false },
    ]);
    expect(comparison.comparable).toBe(false);
  });

  test.skipIf(process.platform === "win32")(
    "preserves distinct drive-like POSIX inventory paths in saved comparisons",
    async () => {
      const repository = await temporaryDirectory("codex-security-sca-");
      const paths = [
        "C:\\folder/package-lock.json",
        "C:/folder/package-lock.json",
      ];
      for (const path of paths) {
        await mkdir(dirname(join(repository, path)), { recursive: true });
        await writeFile(
          join(repository, path),
          JSON.stringify({ lockfileVersion: 3, packages: {} }),
        );
      }
      const { inputs } = await discoverScaInputs(repository);
      expect(inputs.map(({ path }) => path).sort()).toEqual([...paths].sort());
      const results = paths.map((path) => {
        const result = fixture();
        result.repository.path = repository;
        result.coverage.inputs = inputs.filter((input) => input.path === path);
        const normalized = normalizeOsvOutput(
          {
            results: [
              {
                source: { path: join(repository, path) },
                packages: [
                  {
                    package: {
                      ecosystem: "npm",
                      name: "synthetic-package",
                      version: "1.0.0",
                    },
                    vulnerabilities: [{ id: "SYNTHETIC-1" }],
                  },
                ],
              },
            ],
          },
          { repositoryPath: repository, inputs: result.coverage.inputs },
        );
        expect(normalized.diagnostics).toEqual([]);
        expect(normalized.components[0]!.sourcePath).toBe(path);
        result.components = normalized.components;
        result.matches = normalized.matches;
        return JSON.parse(JSON.stringify(result)) as ScaResult;
      });
      const comparison = compareScaResults(results[0]!, results[1]!);
      expect(comparison.persisting).toEqual([]);
      expect(comparison.newlyObserved).toEqual([results[1]!.matches[0]!.id]);
      expect(comparison.noLongerObserved).toEqual([
        { matchId: results[0]!.matches[0]!.id, resolved: false },
      ]);
      expect(comparison.comparable).toBe(false);
    },
  );

  test("keeps separate versions and correlates an unambiguous version change", () => {
    const base = fixture();
    const head = fixture();
    addMatch(base, "old-version", "2.0.0");
    addMatch(head, "new-version", "2.0.1");
    const comparison = compareScaResults(base, head);
    expect(comparison.persisting).toEqual([
      { baseMatchIds: ["match-1"], headMatchIds: ["match-1"] },
    ]);
    expect(comparison.changedVersion).toEqual([
      { baseMatchIds: ["old-version"], headMatchIds: ["new-version"] },
    ]);
    expect(comparison.noLongerObserved).toEqual([]);
  });

  test("reports many-to-many version correlations as ambiguous", () => {
    const base = fixture();
    const head = fixture();
    addMatch(base, "old-second", "2.0.0");
    head.components[0]!.version = "1.0.1";
    addMatch(head, "new-second", "2.0.1");
    const comparison = compareScaResults(base, head);
    expect(comparison.ambiguous).toEqual([
      {
        baseMatchIds: ["match-1", "old-second"],
        headMatchIds: ["match-1", "new-second"],
      },
    ]);
    expect(comparison.changedVersion).toEqual([]);
    expect(comparison.noLongerObserved).toEqual([]);
  });

  test("does not merge unrelated advisories or different source lockfiles", () => {
    const base = fixture();
    const head = fixture();
    head.matches[0]!.advisoryIds = ["SYNTHETIC-UNRELATED"];
    head.matches[0]!.aliases = [];
    expect(compareScaResults(base, head).introduced).toEqual(["match-1"]);
    head.matches[0] = { ...base.matches[0]! };
    head.components[0]!.sourcePath = "nested/package-lock.json";
    expect(compareScaResults(base, head).persisting).toEqual([]);
  });

  test("resolves absent matches only with complete matching and the same frozen database", () => {
    const base = fixture();
    const head = fixture();
    head.matches = [];
    head.scanner.exitCode = 0;
    expect(compareScaResults(base, head).noLongerObserved).toEqual([
      { matchId: "match-1", resolved: true },
    ]);
    const reverse = compareScaResults(head, base);
    expect(reverse.newlyObserved).toEqual(["match-1"]);
    expect(reverse.introduced).toEqual(["match-1"]);
  });

  test("does not call a conditionally excluded match resolved under unchanged configuration", () => {
    const base = fixture();
    const head = fixture();
    // The same PackageOverrides dev-group rule can start excluding the package
    // when its lockfile group changes; suppressed identities are not recorded.
    base.components[0]!.dependencyGroups = [];
    for (const result of [base, head])
      result.coverage.configFiles = [
        { path: "osv-scanner.toml", sha256: "unchanged-dev-group-rule" },
      ];
    head.coverage.inputs[0]!.sha256 = "package-moved-to-dev-group";
    head.components = [];
    head.matches = [];
    head.scanner.exitCode = 0;
    const comparison = compareScaResults(base, head);
    expect(comparison.comparable).toBe(false);
    expect(
      comparison.reasons.some((reason) => reason.includes("exclusions")),
    ).toBe(true);
    expect(comparison.noLongerObserved).toEqual([
      { matchId: "match-1", resolved: false },
    ]);
  });

  test.each([
    [
      "incomplete coverage",
      (result: ScaResult) => {
        result.coverage.status = "partial";
      },
    ],
    [
      "unresolved components",
      (result: ScaResult) => {
        result.coverage.unresolvedPackages = 1;
      },
    ],
    [
      "missing scope",
      (result: ScaResult) => {
        result.coverage.inputs = [];
      },
    ],
    [
      "different scope",
      (result: ScaResult) => {
        result.coverage.inputs[0]!.path = "nested/package-lock.json";
      },
    ],
    [
      "changed exclusion configuration",
      (result: ScaResult) => {
        result.coverage.configFiles.push({
          path: "osv-scanner.toml",
          sha256: "changed-config",
        });
      },
    ],
    [
      "scanner failure",
      (result: ScaResult) => {
        result.scanner.exitCode = 127;
      },
    ],
    [
      "scanner version drift",
      (result: ScaResult) => {
        result.scanner.version = "2.7.0";
      },
    ],
    [
      "unknown snapshot",
      (result: ScaResult) => {
        result.scanner.advisorySnapshotId = null;
      },
    ],
    [
      "advisory snapshot drift",
      (result: ScaResult) => {
        result.scanner.advisorySnapshotId = "other-snapshot";
      },
    ],
    [
      "live advisory data",
      (result: ScaResult) => {
        result.scanner.advisoryMode = "online";
      },
    ],
  ] as const)(
    "does not infer introduction or resolution after %s",
    (_label, change) => {
      const base = fixture();
      const head = fixture();
      head.matches = [];
      head.scanner.exitCode = 0;
      change(head);
      const comparison = compareScaResults(base, head);
      expect(comparison.comparable).toBe(false);
      expect(comparison.reasons.length).toBeGreaterThan(0);
      expect(comparison.noLongerObserved).toEqual([
        { matchId: "match-1", resolved: false },
      ]);
      const reverse = compareScaResults(head, base);
      expect(reverse.newlyObserved).toEqual(["match-1"]);
      expect(reverse.introduced).toEqual([]);
    },
  );

  test("does not reuse earlier assessments or let them alter raw-match comparison", () => {
    const base = fixture();
    const head = fixture();
    const assessment: ScaAssessment = {
      matchId: "match-1",
      status: "completed",
      verdict: "not_actionable",
      triage: triage("not_actionable"),
      error: null,
    };
    base.assessments.push(assessment);
    head.status = "partial";
    head.assessments.push({
      ...assessment,
      status: "failed",
      verdict: null,
      triage: null,
      error: "No model available",
    });
    expect(compareScaResults(base, head).persisting).toHaveLength(1);
    expect(compareScaResults(base, head).comparable).toBe(true);
    expect(head.assessments[0]!.status).toBe("failed");
  });
});

describe("SCA update handoff", () => {
  test("uses only selected scanner fixed-version facts and caller-specified normal checks", () => {
    const result = fixture();
    result.assessments = [
      {
        matchId: "match-1",
        status: "completed",
        verdict: "confirmed",
        triage: triage("confirmed"),
        error: null,
      },
    ];
    addMatch(result, "unselected-match", "2.0.0");
    const handoff = createScaUpdateHandoff(
      result,
      ["match-1", "match-1"],
      ["npm run typecheck", "npm test"],
    );
    expect(handoff.matchIds).toEqual(["match-1"]);
    expect(handoff.candidates).toHaveLength(1);
    expect(handoff.candidates[0]!.fixedVersions).toEqual(["1.0.2"]);
    expect(handoff.findingText).not.toContain("unselected-match");
    expect(handoff.findingText).not.toContain("999.0.0");
    expect(handoff.validationInstructions).toContain("npm run typecheck");
    expect(handoff.validationInstructions).toContain("npm test");
    expect(handoff.validationInstructions).toContain(
      "actual resolved versions",
    );
    expect(handoff.validationInstructions).toContain(
      "Do not create or run vulnerability reproductions",
    );
    expect(
      handoff.unresolvedDecisions.some((decision) =>
        decision.includes("dependency chain"),
      ),
    ).toBe(true);
  });

  test("does not invent fixes or compatibility checks", () => {
    const result = fixture();
    result.matches[0]!.fixedVersions = [];
    const handoff = createScaUpdateHandoff(result, ["match-1"]);
    expect(handoff.candidates[0]!.fixedVersions).toEqual([]);
    expect(
      handoff.unresolvedDecisions.some((decision) =>
        decision.includes("No source advisory fixed version"),
      ),
    ).toBe(true);
    expect(handoff.validationInstructions).toContain(
      "No project checks were supplied",
    );
  });

  test("rejects missing selections and unknown match IDs", () => {
    expect(() => createScaUpdateHandoff(fixture(), [])).toThrow(
      "Select at least one",
    );
    expect(() => createScaUpdateHandoff(fixture(), ["missing"])).toThrow(
      "Unknown SCA match",
    );
  });
});

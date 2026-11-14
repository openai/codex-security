import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import {
  discoverScaInputs,
  normalizeOsvOutput,
  runOsvScan,
} from "../src/sca-osv.js";
import {
  dependencyScanResult,
  readDependencyScan,
  saveDependencyScan,
} from "../src/sca.js";
import { dependencyInventorySummary } from "../src/sca-summary.js";
import { dependencyTriageContract } from "../src/sca-triage.js";
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
      affected_version_or_path: "1.0.0 in package-lock.json",
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

  test.each([
    "Synthetic failed turn\n\n# Synthetic error heading\n\n<!--",
    "Synthetic failed `turn`\r\n\r\n```\r\n# Synthetic error heading\r\n<!--",
    "<span hidden>Synthetic failed turn</span>",
    "Synthetic failed turn; retry the assessment.",
  ])(
    "keeps failed-assessment diagnostics literal in saved reports: %j",
    async (message) => {
      const result = fixture();
      result.outputDir = await temporaryDirectory("sca-assessment-error-");
      result.status = "partial";
      addMatch(result, "later-match", "2.0.0", "SYNTHETIC-LATER-ADVISORY");
      result.assessments = [
        {
          matchId: "match-1",
          status: "failed",
          verdict: null,
          triage: null,
          error: message,
        },
      ];
      await saveDependencyScan(result);
      const saved = JSON.parse(
        await readFile(join(result.outputDir, "sca-result.json"), "utf8"),
      ) as ScaResult;
      expect(saved).toEqual(result);
      expect(saved.assessments[0]?.error).toBe(message);
      const html = Bun.markdown.html(
        await readFile(join(result.outputDir, "report.md"), "utf8"),
      );
      expect(html).not.toContain("<h1>Synthetic error heading</h1>");
      expect(html).not.toContain("<!--");
      expect(html).not.toContain("<span hidden>");
      expect(html).toContain("Synthetic failed");
      expect(html.match(/<p>Next action:/g)).toHaveLength(2);
      expect(html).toContain("SYNTHETIC-LATER-ADVISORY");
      expect(html).toContain("<h2>Retained evidence</h2>");
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
    expect(report.indexOf(result.diagnostics[0]!)).toBeLessThan(
      report.indexOf("synthetic-unmatched-package"),
    );
  });

  test.each([
    { groups: ["dev", "build"] },
    { groups: ["<!--"] },
    { groups: ["Synthetic group\n\n# Synthetic group heading\n\n<!--"] },
    {
      groups: [
        "Synthetic `group`\r\n\r\n```\r\n# Synthetic group heading\r\n<!--",
      ],
    },
    { groups: ["<span hidden>Synthetic group</span>"] },
    { groups: [] },
  ])(
    "keeps scanner dependency groups literal in saved reports: %j",
    async ({ groups }) => {
      const result = fixture();
      result.outputDir = await temporaryDirectory("sca-report-groups-");
      const raw = {
        results: [
          {
            source: { path: "package-lock.json", type: "lockfile" },
            packages: ["synthetic-package", "synthetic-later-package"].map(
              (name, index) => ({
                package: { name, version: "1.0.0", ecosystem: "npm" },
                dependency_groups: index === 0 ? groups : ["production"],
                vulnerabilities: [
                  {
                    id:
                      index === 0 ? "SYNTHETIC-1" : "SYNTHETIC-LATER-ADVISORY",
                  },
                ],
              }),
            ),
          },
        ],
      };
      const rawBefore = JSON.stringify(raw);
      const normalized = normalizeOsvOutput(raw, {
        repositoryPath: result.repository.path,
        inputs: result.coverage.inputs,
      });
      expect(normalized.diagnostics).toEqual([]);
      result.components = normalized.components;
      result.matches = normalized.matches;
      const before = JSON.stringify(result);
      renderScaReport(result);
      expect(JSON.stringify(result)).toBe(before);
      await saveDependencyScan(result);
      const saved = JSON.parse(
        await readFile(join(result.outputDir, "sca-result.json"), "utf8"),
      ) as ScaResult;
      expect(saved).toEqual(result);
      expect(saved.components[0]!.dependencyGroups).toEqual([...groups]);
      expect(JSON.stringify(raw)).toBe(rawBefore);
      const report = await readFile(
        join(result.outputDir, "report.md"),
        "utf8",
      );
      const html = Bun.markdown.html(report);
      expect(html).not.toContain("<h1>Synthetic group heading</h1>");
      expect(html).not.toContain("<!--");
      expect(html).not.toContain("<span hidden>");
      expect(html.match(/<p>Next action:/g)).toHaveLength(2);
      expect(html).toContain("<code>SYNTHETIC-LATER-ADVISORY</code>");
      expect(html).toContain("<h2>Retained evidence</h2>");
      for (const group of groups)
        expect(report).toContain(
          /[\r\n]/u.test(group) ? JSON.stringify(group) : group,
        );
    },
  );

  test.skipIf(process.platform === "win32").each(
    [
      "selected\n# Synthetic clean result\n<!--/requirements.txt",
      "selected\n\n```\n# Synthetic clean result\n<!--/requirements.txt",
      "selected\r\n# Synthetic clean result\r\n<!--/requirements.txt",
    ].flatMap((sourcePath) => [
      { sourcePath, pinned: true },
      { sourcePath, pinned: false },
    ]),
  )(
    "retains literal multiline dependency paths in saved reports: %j",
    async ({ sourcePath, pinned }) => {
      const root = await temporaryDirectory("sca-report-multiline-");
      const repository = join(root, "repository");
      const output = join(root, "output");
      await mkdir(dirname(join(repository, sourcePath)), { recursive: true });
      await writeFile(
        join(repository, sourcePath),
        `synthetic-package${pinned ? "==" : ">="}1.2.3\n`,
      );
      const scan = await runOsvScan(
        { repositoryPath: repository, outputDir: output },
        {
          executable: process.execPath,
          runProcess: async (_executable, argv) =>
            argv[0] === "--version"
              ? {
                  stdout: "osv-scanner version: 2.6.0",
                  stderr: "",
                  exitCode: 0,
                }
              : {
                  stdout: JSON.stringify({
                    results: [
                      {
                        source: { path: argv.at(-1), type: "lockfile" },
                        packages: [
                          {
                            package: {
                              name: "synthetic-package",
                              version: "1.2.3",
                              ecosystem: "PyPI",
                            },
                            vulnerabilities: [{ id: "SYNTHETIC-ADVISORY" }],
                          },
                        ],
                      },
                    ],
                  }),
                  stderr: "",
                  exitCode: 1,
                },
        },
      );
      const result = dependencyScanResult(
        scan,
        { path: repository, revision: null, dirty: null },
        output,
      );
      await saveDependencyScan(result);
      const saved = JSON.parse(
        await readFile(join(output, "sca-result.json"), "utf8"),
      ) as ScaResult;
      expect(saved.coverage.inputs[0]?.path).toBe(sourcePath);
      expect(saved.coverage.inputs).toEqual(scan.coverage.inputs);
      expect(saved.coverage.limitations).toEqual(scan.coverage.limitations);
      expect(saved.diagnostics).toEqual(scan.diagnostics);
      expect(saved.matches).toHaveLength(pinned ? 1 : 0);
      const report = await readFile(join(output, "report.md"), "utf8");
      const html = Bun.markdown.html(report);
      expect(html).not.toContain("<h1>Synthetic clean result</h1>");
      expect(html).not.toContain("<!--");
      expect(html).toContain("<h2>Observed components</h2>");
      expect(html).toContain("<h2>Retained evidence</h2>");
      if (pinned) expect(html).toContain("SYNTHETIC-ADVISORY");
      expect(report).toContain(JSON.stringify(sourcePath));
      for (const limitation of scan.coverage.limitations.filter((value) =>
        value.includes(sourcePath),
      ))
        expect(report).toContain(JSON.stringify(limitation));
    },
  );

  test.each(["partial", "failed"] as const)(
    "distinguishes a zero-match %s run from model assessment",
    (status) => {
      const result = fixture();
      result.matches = [];
      result.status = status;
      result.coverage.status = status;
      if (status === "failed") result.coverage.inputs = [];
      const report = renderScaReport(result);
      expect(report).toContain("matching coverage is incomplete");
      expect(report).toContain("Model assessment: **not run**");
      if (status === "failed")
        expect(report).toContain("No lockfile inputs were evaluated");
      expect(report).not.toContain(
        "No advisory matches were reported within the effective evaluated scope",
      );
    },
  );

  test("summarizes assessment outcomes without losing unassessed matches", () => {
    const result = fixture();
    for (const id of ["failed", "cancelled", "pending"])
      addMatch(result, id, "1.0.0");
    result.assessments = [
      {
        matchId: "match-1",
        status: "completed",
        verdict: "needs_review",
        triage: triage("needs_review"),
        error: null,
      },
      ...(["failed", "cancelled"] as const).map((status) => ({
        matchId: status,
        status,
        verdict: null,
        triage: null,
        error: "Assessment unavailable",
      })),
    ];
    const report = renderScaReport(result);
    for (const outcome of ["completed", "failed", "cancelled", "not started"])
      expect(report).toContain(`1 ${outcome}`);
  });

  test.each([
    {
      label: "local dependency origins",
      path: "package-lock.json",
      content: JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "node_modules/synthetic-package": {
            name: "[synthetic](https://example.test/package)",
            version: "1.0.0",
            resolved:
              'file:synthetic\r\n```\r\n\r\n# Fabricated summary\r\n\r\n<img src="https://example.test/image.png">',
          },
        },
      }),
      value:
        '[synthetic](https://example.test/package)@file:synthetic\r\n```\r\n\r\n# Fabricated summary\r\n\r\n<img src="https://example.test/image.png">',
    },
    {
      label: "unsupported lockfile versions",
      path: "package-lock.json",
      content: JSON.stringify({
        lockfileVersion:
          'synthetic\n```\n\n# Fabricated summary\n\n[synthetic](https://example.test/package) <img src="https://example.test/image.png">',
      }),
      value:
        'synthetic\n```\n\n# Fabricated summary\n\n[synthetic](https://example.test/package) <img src="https://example.test/image.png">',
    },
    {
      label: "paths repeated in coverage and diagnostics",
      path: "[synthetic](target)/requirements.txt",
      content: "synthetic-package==1.0.0\n",
      value:
        "[synthetic](target)/requirements.txt supplies declared Python pins",
    },
  ])(
    "renders discovered $label literally",
    async ({ path, content, value }) => {
      const repository = await temporaryDirectory("sca-report-discovery-");
      const inputPath = join(repository, path);
      await mkdir(dirname(inputPath), { recursive: true });
      await writeFile(inputPath, content);
      const { diagnostics, localReferences, ...coverage } =
        await discoverScaInputs(repository);
      const result = fixture();
      Object.assign(result.coverage, coverage);
      result.coverage.unresolvedPackages = localReferences.length;
      result.diagnostics = diagnostics;
      const evidence = structuredClone(result);
      const report = renderScaReport(result);
      expect(report).toContain(
        /[\r\n]/u.test(value) ? JSON.stringify(value).slice(1, -1) : value,
      );
      const rendered = Bun.markdown.html(report);
      expect(rendered).not.toMatch(/<(?:a|img)\b/u);
      expect(rendered).not.toMatch(/<h[1-6]\b[^>]*>Fabricated summary/u);
      expect(rendered).toContain("[synthetic](");
      expect(rendered).toContain("<h2>Observed components</h2>");
      expect(rendered).toContain("<h2>Retained evidence</h2>");
      expect(result).toEqual(evidence);
      expect(await readFile(inputPath, "utf8")).toBe(content);
    },
  );

  test.each([null, 0, 0.12])(
    "reports model cost %p without assuming zero",
    (cost) => {
      const result = fixture();
      result.model.costUsd = cost;
      expect(renderScaReport(result)).toContain(
        cost === null ? "unavailable" : `$${cost.toFixed(2)}`,
      );
    },
  );

  test("renders package names containing Markdown delimiters without losing their identity", () => {
    const result = fixture();
    result.components[0]!.name = "synthetic`package";
    expect(renderScaReport(result)).toContain("`` synthetic`package ``");
  });

  test.each(["\n", "\r\n", "\r"])(
    "renders affected-package values as literal text with %p line breaks",
    (newline) => {
      const result = fixture();
      const value = `synthetic\`one\`\`two${newline}\`\`\`${newline}${newline}# Fabricated summary${newline}${newline}[synthetic](https://example.test/package) <img src="https://example.test/image.png">`;
      Object.assign(result.components[0]!, {
        name: value,
        version: value,
        sourcePath: value,
      });
      Object.assign(result.matches[0]!, {
        advisoryIds: [value],
        severity: value,
        fixedVersions: [value],
      });
      result.packageContexts = [
        {
          componentId: "component-1",
          manifestPath: "package.json",
          projectName: value,
          private: true,
          installedPath: null,
          dependencyGroups: [],
          dependencyChain: [{ name: value, version: value, path: "synthetic" }],
          limitations: [],
        },
      ];
      const evidence = structuredClone(result);
      expect(dependencyInventorySummary(result)).toEqual([
        "Matching: 1 dependency files checked; 1 advisory matches across 1 package occurrences.",
        `${value}@${value} — ${value} (project: ${value}, private)`,
        `  Local chain: ${value}@${value}`,
        `  ${value} · severity ${value} · candidate fixes: ${value}`,
      ]);
      const summary = renderScaReport(result)
        .split("## Affected packages\n\n")[1]!
        .split("\n\n## ")[0]!;
      expect(summary).toContain(JSON.stringify(value));
      const rendered = Bun.markdown.html(summary);
      expect(rendered).not.toMatch(/<(?:a|img|h[1-6])\b/u);
      expect(rendered).toContain("<code>");
      expect(rendered).toContain("synthetic`one``two");
      expect(rendered).toContain("[synthetic](https://example.test/package)");
      expect(rendered).toContain("&lt;img");
      expect(result).toEqual(evidence);
    },
  );

  test("keeps multiline coverage diagnostics literal across platforms", () => {
    const result = fixture();
    const message = "Synthetic path\r\n```\r\n# Forged heading\r\n<!--";
    result.coverage.inputs[0]!.reason = message;
    result.coverage.limitations = [message];
    result.diagnostics = [message];
    const original = JSON.stringify(result);
    const report = renderScaReport(result);
    const html = Bun.markdown.html(report);
    expect(html).not.toContain("<h1>Forged heading</h1>");
    expect(html).not.toContain("<!--");
    expect(html).toContain("<h2>Observed components</h2>");
    expect(html).toContain("<h2>Retained evidence</h2>");
    expect(html).toContain("SYNTHETIC-1");
    expect(report).toContain(JSON.stringify(message));
    expect(JSON.stringify(result)).toBe(original);
  });

  test.each(
    [
      "evidence",
      "counterevidence",
      "proof_gaps",
      "recommended_next_step",
    ].flatMap((field) =>
      [
        "Synthetic detail\n\n# Synthetic assessment heading\n\n<!--",
        "Synthetic `detail`\r\n\r\n```\r\n# Synthetic assessment heading\r\n<!--",
        "<span hidden>Synthetic detail</span>",
      ].map((message) => ({ field, message })),
    ),
  )(
    "keeps schema-valid assessment text literal in saved reports: %j",
    async ({ field, message }) => {
      const result = fixture();
      result.outputDir = await temporaryDirectory("sca-assessment-report-");
      result.status = "partial";
      result.coverage.status = "partial";
      result.coverage.limitations = ["Synthetic matching limitation."];
      result.diagnostics = ["Synthetic scanner diagnostic."];
      addMatch(result, "later-match", "2.0.0", "SYNTHETIC-LATER-ADVISORY");
      const finding = {
        ...triage("needs_review"),
        [field]: field === "recommended_next_step" ? message : [message],
      };
      const contract = await dependencyTriageContract(
        fileURLToPath(
          new URL("../../../plugins/codex-security/", import.meta.url),
        ),
      );
      result.assessments = contract.parse(
        JSON.stringify({
          schema_version: "triage-finding/v0",
          repository: {
            path: result.repository.path,
            revision: result.repository.revision,
          },
          findings: [
            finding,
            {
              ...triage("needs_review"),
              input_id: "later-match",
              triage_item_id: "later-assessment",
              normalized_input: {
                ...triage("needs_review").normalized_input,
                affected_version_or_path: "2.0.0 in package-lock.json",
                references: ["SYNTHETIC-LATER-ADVISORY"],
              },
            },
          ],
        }),
        result,
      );
      expect(result.assessments.map(({ status }) => status)).toEqual([
        "completed",
        "completed",
      ]);
      expect(result.assessments[0]?.triage).toEqual(finding);
      await saveDependencyScan(result);
      const saved = JSON.parse(
        await readFile(join(result.outputDir, "sca-result.json"), "utf8"),
      ) as ScaResult;
      expect(saved).toEqual(result);
      expect(saved.assessments[0]?.triage).toEqual(finding);
      const report = await readFile(
        join(result.outputDir, "report.md"),
        "utf8",
      );
      const html = Bun.markdown.html(report);
      expect(html).toContain("<h2>Coverage</h2>");
      expect(html).toContain("Synthetic matching limitation.");
      expect(html).toContain("<h2>Diagnostics</h2>");
      expect(html).toContain("Synthetic scanner diagnostic.");
      expect(html).not.toContain("<h1>Synthetic assessment heading</h1>");
      expect(html).not.toContain("<!--");
      expect(html).not.toContain("<span hidden>");
      expect(html).toContain("<h2>Retained evidence</h2>");
      expect(html).toContain("SYNTHETIC-LATER-ADVISORY");
      expect(report).toContain(
        /[\r\n]/u.test(message) ? JSON.stringify(message) : message,
      );
    },
  );

  test("keeps empty assessment lists and a plain next action readable", () => {
    const result = fixture();
    const finding = triage("needs_review");
    finding.evidence = [];
    finding.counterevidence = [];
    finding.proof_gaps = [];
    result.assessments = [
      {
        matchId: "match-1",
        status: "completed",
        verdict: finding.verdict,
        triage: finding,
        error: null,
      },
    ];
    const html = Bun.markdown.html(renderScaReport(result));
    expect(html).toContain("No decisive evidence supplied.");
    expect(html.match(/None supplied\./g)).toHaveLength(2);
    expect(html).toContain(finding.recommended_next_step);
    expect(html).toContain("<h2>Retained evidence</h2>");
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
      "C:\\work tree\\base\\Nested\\Package-Lock.json",
      "D:\\head checkout",
      "D:\\head checkout\\nested\\package-lock.json",
    ],
    [
      "C:\\base",
      "Nested\\package-lock.json",
      "/head",
      "Nested/package-lock.json",
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

  test("keeps advisory occurrences in case-distinct lockfiles separate in saved Windows inventories", async () => {
    const paths = ["Lib/package-lock.json", "lib/package-lock.json"] as const;
    async function savedOccurrence(sourcePath: string, matchId: string) {
      const result = fixture();
      result.repository.path = "C:\\workspace";
      result.coverage.inputs = paths.map((path) => ({
        ...result.coverage.inputs[0]!,
        path,
      }));
      result.components[0]!.sourcePath = sourcePath;
      result.matches[0]!.id = matchId;
      result.outputDir = await temporaryDirectory("sca-windows-inventory-");
      await saveDependencyScan(result);
      return JSON.parse(
        await readFile(join(result.outputDir, "sca-result.json"), "utf8"),
      ) as ScaResult;
    }

    const base = await savedOccurrence(paths[0], "base-match");
    const head = await savedOccurrence(paths[1], "head-match");
    expect(compareScaResults(base, head)).toMatchObject({
      comparable: true,
      persisting: [],
      introduced: ["head-match"],
      noLongerObserved: [{ matchId: "base-match", resolved: true }],
    });
  });

  test.each([
    ["nested\\folder/package-lock.json", "nested/folder/package-lock.json"],
    ["Nested/Package-Lock.json", "nested/package-lock.json"],
  ])(
    "preserves distinct POSIX source identities %s and %s",
    (basePath, headPath) => {
      const base = fixture();
      const head = fixture();
      base.components[0]!.sourcePath = basePath;
      base.coverage.inputs[0]!.path = base.components[0]!.sourcePath;
      head.components[0]!.sourcePath = headPath;
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
    },
  );

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

  test.each([false, true])(
    "keeps separate versions and correlates an unambiguous version change (reverse order: %p)",
    (reverseOrder) => {
      const base = fixture();
      const head = fixture();
      addMatch(base, "old-version", "2.0.0");
      addMatch(head, "new-version", "2.0.1");
      if (reverseOrder) {
        base.matches.reverse();
        head.matches.reverse();
      }
      const comparison = compareScaResults(base, head);
      expect(comparison.persisting).toEqual([
        { baseMatchIds: ["match-1"], headMatchIds: ["match-1"] },
      ]);
      expect(comparison.changedVersion).toEqual([
        { baseMatchIds: ["old-version"], headMatchIds: ["new-version"] },
      ]);
      expect(comparison.noLongerObserved).toEqual([]);
    },
  );

  test("retains exact versions when aliases connect transitively within each scan", () => {
    const base = fixture();
    const head = fixture();
    for (const result of [base, head]) {
      result.matches[0]!.advisoryIds = ["SYNTHETIC-A"];
      result.matches[0]!.aliases = ["SYNTHETIC-X"];
      addMatch(result, "second", "2.0.0");
      result.matches[1]!.advisoryIds = ["SYNTHETIC-B"];
      result.matches[1]!.aliases = ["SYNTHETIC-X", "SYNTHETIC-Y"];
      addMatch(result, "third", "3.0.0");
      result.matches[2]!.advisoryIds = ["SYNTHETIC-C"];
      result.matches[2]!.aliases = ["SYNTHETIC-Y"];
    }
    head.components[1]!.version = "2.0.1";
    head.components[2]!.version = "3.0.1";
    const comparison = compareScaResults(base, head);
    expect(comparison.persisting).toEqual([
      { baseMatchIds: ["match-1"], headMatchIds: ["match-1"] },
    ]);
    expect(comparison.ambiguous).toEqual([
      {
        baseMatchIds: ["second", "third"],
        headMatchIds: ["second", "third"],
      },
    ]);
    expect(comparison.noLongerObserved).toEqual([]);
    expect(comparison.introduced).toEqual([]);
  });

  test.each([
    {
      name: "a merged advisory group",
      base: [
        { version: "1.0.0", ids: ["SYNTHETIC-A"] },
        { version: "2.0.0", ids: ["SYNTHETIC-B"] },
      ],
      head: [{ version: "1.0.0", ids: ["SYNTHETIC-A", "SYNTHETIC-B"] }],
    },
    {
      name: "a bridge connected to another same-version occurrence",
      base: [
        { version: "1.0.0", ids: ["SYNTHETIC-A"] },
        { version: "2.0.0", ids: ["SYNTHETIC-B"] },
        { version: "3.0.0", ids: ["SYNTHETIC-A"] },
      ],
      head: [
        { version: "1.0.0", ids: ["SYNTHETIC-A"] },
        { version: "2.0.0", ids: ["SYNTHETIC-A", "SYNTHETIC-B"] },
      ],
    },
  ])("keeps $name ambiguous across versions and input order", (scenario) => {
    function report(
      packages: readonly { version: string; ids: readonly string[] }[],
    ) {
      const result = fixture();
      const normalized = normalizeOsvOutput(
        {
          results: [
            {
              source: { path: "package-lock.json", type: "lockfile" },
              packages: packages.map(({ version, ids }) => ({
                package: {
                  name: "synthetic-package",
                  ecosystem: "npm",
                  version,
                },
                vulnerabilities: ids.map((id) => ({
                  id,
                  aliases: ids.filter((alias) => alias !== id),
                })),
              })),
            },
          ],
        },
        {
          repositoryPath: result.repository.path,
          inputs: result.coverage.inputs,
        },
      );
      expect(normalized.diagnostics).toEqual([]);
      result.components = normalized.components;
      result.matches = normalized.matches;
      return result;
    }
    for (const base of [scenario.base, scenario.base.toReversed()]) {
      for (const head of [scenario.head, scenario.head.toReversed()]) {
        const before = report(base);
        const after = report(head);
        for (const [left, right] of [
          [before, after],
          [after, before],
        ] as const) {
          const comparison = compareScaResults(left, right);
          expect(comparison.comparable).toBe(true);
          expect(comparison.persisting).toEqual([]);
          expect(comparison.changedVersion).toEqual([]);
          expect(comparison.noLongerObserved).toEqual([]);
          expect(comparison.newlyObserved).toEqual([]);
          expect(comparison.introduced).toEqual([]);
          expect(comparison.ambiguous).toHaveLength(1);
          expect(comparison.ambiguous[0]!.baseMatchIds.toSorted()).toEqual(
            left.matches.map(({ id }) => id).sort(),
          );
          expect(comparison.ambiguous[0]!.headMatchIds.toSorted()).toEqual(
            right.matches.map(({ id }) => id).sort(),
          );
        }
      }
    }
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

  test("retains observed introduction chains and their limitations in saved reports and handoffs", async () => {
    const result = fixture();
    result.outputDir = await temporaryDirectory("sca-context-limitations-");
    const manyBackticks = "`x".repeat(1_000_000);
    addMatch(result, "missing-chain", "2.0.0");
    result.packageContexts = [
      {
        componentId: "component-1",
        manifestPath: "packages/app/package.json",
        projectName: "synthetic-app",
        private: true,
        installedPath: "node_modules/synthetic-package",
        dependencyChain: [
          { name: "synthetic-app", version: "1.0.0", path: "packages/app" },
          {
            name: "synthetic-introducer",
            version: "3.0.0",
            path: "node_modules/synthetic-introducer",
          },
          {
            name: "synthetic-package",
            version: "1.0.0",
            path: "node_modules/synthetic-package",
          },
        ],
        dependencyGroups: ["dev"],
        limitations: [
          "<!-- synthetic installed-source limitation",
          manyBackticks,
        ],
      },
    ];
    await saveDependencyScan(result);
    const saved = await readDependencyScan(result.outputDir);
    expect(saved.packageContexts?.[0]?.limitations).toEqual(
      result.packageContexts[0]!.limitations,
    );
    const handoff = createScaUpdateHandoff(saved, ["match-1", "missing-chain"]);
    expect(handoff.findingText).toContain("synthetic-introducer");
    expect(handoff.findingText).toContain("packages/app/package.json");
    expect(handoff.findingText).toContain("not a complete graph");
    for (const [text, heading] of [
      [await readFile(join(result.outputDir, "report.md"), "utf8"), "Coverage"],
      [handoff.findingText, "Decisions to resolve"],
    ] as const) {
      expect(text.includes("`` " + manyBackticks + " ``")).toBe(true);
      const html = Bun.markdown.html(text);
      expect(html).toContain(
        "<code>&lt;!-- synthetic installed-source limitation</code>",
      );
      expect(html).toContain(`<h2>${heading}</h2>`);
    }
    const missing = handoff.unresolvedDecisions.filter((decision) =>
      decision.includes("dependency chain"),
    );
    expect(missing).toHaveLength(1);
    expect(missing[0]).toContain("missing-chain");
    expect(missing[0]).not.toContain("match-1");
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

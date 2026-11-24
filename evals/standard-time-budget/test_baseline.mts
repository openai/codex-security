import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  BASELINE_SCHEMA_VERSION,
  compareBaselines,
  createReleaseBaseline,
  hashSnapshotMap,
  loadBaseline,
  validateReleaseBaseline,
  type SavedExperiment,
} from "./baseline.mts";
import { hashText, type RunRecord, type Variant } from "./experiment.mts";
import { createFixture, type Fixture, type SourceCase } from "./fixtures.mts";
import { gradeResult, type Result, type SourceLocation } from "./grade.mts";

const baselineScript = fileURLToPath(
  new URL("./baseline.mts", import.meta.url),
);

function findingFor(
  fixture: Fixture,
  expected: SourceCase,
  role = "root_control",
): Result["findings"][number] {
  return {
    title: expected.id,
    taxonomy: { cwe: [expected.cwes[0]!] },
    locations: [
      { path: expected.path, startLine: expected.line, role },
    ] as SourceLocation[],
    codeEvidence: [
      {
        path: expected.path,
        startLine: expected.line,
        code: fixture.files[expected.path]!.split("\n")[expected.line - 1]!,
      },
    ],
  };
}

function makeSavedExperiment(
  fixture: Fixture,
  overrides: Partial<SavedExperiment> = {},
): SavedExperiment {
  const source = Object.fromEntries(
    Object.entries(fixture.files).map(([path, content]) => [
      path,
      hashText(content),
    ]),
  );
  return {
    model: "gpt-5.6-sol",
    pairs: 1,
    budgetMinutes: 5,
    reasoningEffort: "xhigh",
    evaluator: {
      "fixtures.mts": hashText("fixtures-rev"),
      "grade.mts": hashText("grade-rev"),
    },
    source,
    plugin: { "SKILL.md": hashText("skill-rev") },
    sdk: { "api.js": hashText("sdk-rev") },
    packageVersions: {
      "@openai/codex": "0.167.1",
      "@openai/codex-sdk": "0.167.1",
      "@openai/codex-security": "0.10.0",
    },
    codexExecutable: {
      command: "/local/host/bin/codex",
      files: [
        { path: "/local/host/libexec/codex-native", sha256: hashText("bin") },
      ],
    },
    ...overrides,
  };
}

function completedRun(
  fixture: Fixture,
  pair: number,
  variant: Variant,
  matchedIds: string[],
  options: {
    extraFindings?: Result["findings"];
    usage?: RunRecord["usage"];
    elapsedMs?: number;
  } = {},
): RunRecord {
  const positiveSet = new Set(matchedIds);
  const findings: Result["findings"] = [
    ...fixture.positives
      .filter((entry) => positiveSet.has(entry.id))
      .map((entry) => findingFor(fixture, entry)),
    ...(options.extraFindings ?? []),
  ];
  return {
    pair,
    variant,
    startedAt: "2026-10-01T00:00:00.000Z",
    advisoryBudgetMinutes: variant === "time-aware" ? 5 : null,
    promptSha256: hashText(`prompt-${pair}-${variant}`),
    status: "completed",
    elapsedMs: options.elapsedMs ?? 1200,
    usage:
      options.usage === undefined
        ? { input_tokens: 1000, cached_input_tokens: 400, output_tokens: 200 }
        : options.usage,
    report: {
      ...gradeResult({ findings }, fixture),
      scanId: `scan-${pair}-${variant}`,
      scanDir: `/local/host/reports/run-1/pair-${pair}-${variant}/scan`,
      reportPath: `/local/host/reports/run-1/pair-${pair}-${variant}/scan/report.md`,
    },
  };
}

function createFiveCaseFixture(): Fixture {
  const full = createFixture();
  const excludedFiles = new Set(["src/statements.py", "src/grants.py"]);
  const excludedCaseIds = new Set([
    "statement-tenant-selection",
    "report-unverified-grant",
    "statement-session-tenant",
    "statement-contained-path",
    "report-verified-grant",
  ]);
  const files = Object.fromEntries(
    Object.entries(full.files)
      .filter(([path]) => !excludedFiles.has(path))
      .map(([path, text]) => {
        if (path === "README.md") return [path, `${text}\n# 5-case revision\n`];
        if (path === "src/app.py") {
          return [
            path,
            text
              .replace("from .statements import statements\n", "")
              .replace("from .grants import grants\n", ""),
          ];
        }
        return [path, text];
      }),
  );
  return {
    files,
    positives: full.positives.filter((entry) => !excludedCaseIds.has(entry.id)),
    controls: full.controls.filter((entry) => !excludedCaseIds.has(entry.id)),
  };
}

test("snapshot digests order paths independently of the host locale", () => {
  const digest = hashText("fixture");
  assert.equal(
    hashSnapshotMap({ "ä.py": digest, "z.py": digest }),
    hashText(
      JSON.stringify([
        ["z.py", digest],
        ["ä.py", digest],
      ]),
    ),
  );
});

test("export strips host paths and raw source while round-tripping comparison results", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "baseline-export-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const runDir = join(root, "run-1");
  await mkdir(runDir, { recursive: true });
  const fixture = createFixture();
  const experiment = makeSavedExperiment(fixture);
  const runs: RunRecord[] = [
    completedRun(
      fixture,
      1,
      "time-aware",
      fixture.positives.map((entry) => entry.id),
    ),
    completedRun(
      fixture,
      1,
      "baseline",
      fixture.positives.map((entry) => entry.id),
    ),
  ];
  await Promise.all([
    writeFile(join(runDir, "experiment.json"), JSON.stringify(experiment)),
    writeFile(join(runDir, "fixture.json"), JSON.stringify(fixture)),
    writeFile(join(runDir, "runs.json"), JSON.stringify(runs)),
  ]);

  const exported = await loadBaseline(runDir);
  const serialized = JSON.stringify(exported);
  assert.equal(exported.schemaVersion, BASELINE_SCHEMA_VERSION);
  assert.equal(serialized.includes("/local/host/"), false);
  assert.equal(serialized.includes("scanDir"), false);
  assert.equal(serialized.includes("reportPath"), false);
  assert.equal(serialized.includes("requests.head"), false);
  assert.equal(serialized.includes("URLSafeTimedSerializer"), false);
  assert.deepEqual(exported.experiment.digests.codexExecutableSha256, [
    hashText("bin"),
  ]);
  assert.equal(
    exported.experiment.digests.fixturesModuleSha256,
    experiment.evaluator["fixtures.mts"],
  );
  assert.deepEqual(
    exported.runs.map((run) => [run.pair, run.variant]),
    [
      [1, "baseline"],
      [1, "time-aware"],
    ],
  );

  const exportPath = join(root, "baseline.json");
  await writeFile(exportPath, serialized);
  const reloaded = await loadBaseline(exportPath);
  assert.deepEqual(reloaded, exported);
  assert.deepEqual(
    compareBaselines(reloaded, exported),
    compareBaselines(exported, exported),
  );
});

test("export omits structured host path fields while keeping synthetic failure host-path diagnostics verbatim", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "baseline-failure-diagnostic-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const runDir = join(root, "run-1");
  await mkdir(runDir, { recursive: true });
  const fixture = createFixture();
  const experiment = makeSavedExperiment(fixture);
  const failureDiagnostic =
    "spawn /local/host/worktrees/scan-state/worker failed: ENOENT (synthetic token=keep-verbatim)";
  const runs: RunRecord[] = [
    completedRun(
      fixture,
      1,
      "baseline",
      fixture.positives.map((entry) => entry.id),
    ),
    {
      pair: 1,
      variant: "time-aware",
      startedAt: "2026-10-01T00:02:00.000Z",
      advisoryBudgetMinutes: 5,
      promptSha256: null,
      status: "failed",
      error: failureDiagnostic,
      elapsedMs: 350,
      usage: null,
    },
  ];
  await Promise.all([
    writeFile(join(runDir, "experiment.json"), JSON.stringify(experiment)),
    writeFile(join(runDir, "fixture.json"), JSON.stringify(fixture)),
    writeFile(join(runDir, "runs.json"), JSON.stringify(runs)),
  ]);

  const exportPath = join(root, "baseline.json");
  const exportRun = spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      baselineScript,
      "export",
      runDir,
      exportPath,
    ],
    { encoding: "utf8" },
  );
  assert.equal(exportRun.status, 0, exportRun.stderr);

  const exportedText = await readFile(exportPath, "utf8");
  assert.equal(exportedText.includes("/local/host/bin/codex"), false);
  assert.equal(
    exportedText.includes("/local/host/libexec/codex-native"),
    false,
  );
  assert.equal(exportedText.includes("/local/host/reports/run-1/"), false);
  assert.equal(exportedText.includes("scanDir"), false);
  assert.equal(exportedText.includes("reportPath"), false);
  assert.equal(exportedText.includes(failureDiagnostic), true);

  const reloaded = await loadBaseline(exportPath);
  const failedAttempt = reloaded.runs.find(
    (run) => run.pair === 1 && run.variant === "time-aware",
  );
  assert.equal(failedAttempt?.status, "failed");
  assert.equal(failedAttempt.error, failureDiagnostic);

  const comparisonPath = join(root, "comparison.json");
  const compareRun = spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      baselineScript,
      "compare",
      exportPath,
      exportPath,
      comparisonPath,
    ],
    { encoding: "utf8" },
  );
  assert.equal(compareRun.status, 0, compareRun.stderr);
  const comparison = JSON.parse(await readFile(comparisonPath, "utf8"));
  assert.deepEqual(comparison.arms["time-aware"].baseline.failures, [
    { pair: 1, error: failureDiagnostic },
  ]);
  assert.deepEqual(comparison.arms["time-aware"].candidate.failures, [
    { pair: 1, error: failureDiagnostic },
  ]);
  assert.equal(comparison.arms["time-aware"].flags.hasRunFailures, true);
});

test("corpus expansion scores comparable cases without false regressions and catches masked drops", () => {
  const fiveCase = createFiveCaseFixture();
  const sevenCase = createFixture();
  const fiveIds = fiveCase.positives.map((entry) => entry.id);

  const baseline = createReleaseBaseline({
    experiment: makeSavedExperiment(fiveCase),
    fixture: fiveCase,
    runs: [
      completedRun(fiveCase, 1, "baseline", fiveIds),
      completedRun(fiveCase, 1, "time-aware", fiveIds),
    ],
  });

  // Candidate matches all 5 shared cases and misses the 2 newly added cases.
  const expandedSameShared = createReleaseBaseline({
    experiment: makeSavedExperiment(sevenCase, {
      evaluator: {
        "fixtures.mts": hashText("fixtures-rev-2"),
        "grade.mts": hashText("grade-rev"),
      },
    }),
    fixture: sevenCase,
    runs: [
      completedRun(sevenCase, 1, "baseline", fiveIds),
      completedRun(sevenCase, 1, "time-aware", fiveIds),
    ],
  });

  const noRegression = compareBaselines(baseline, expandedSameShared);
  assert.equal(noRegression.provenance.fixtureIdentical, false);
  assert.equal(
    noRegression.provenance.digests.fixturesModuleSha256.changed,
    true,
  );
  assert.deepEqual(noRegression.corpus.positives.comparable, fiveIds);
  assert.deepEqual(noRegression.corpus.positives.added, [
    "statement-tenant-selection",
    "report-unverified-grant",
  ]);
  assert.deepEqual(noRegression.corpus.controls.added, [
    "statement-session-tenant",
    "statement-contained-path",
    "report-verified-grant",
  ]);
  assert.deepEqual(noRegression.corpus.sourceFiles.changed, [
    "README.md",
    "src/app.py",
  ]);
  assert.equal(noRegression.arms.baseline.delta.comparableRecall, 0);
  assert.ok(
    Math.abs(noRegression.arms.baseline.delta.rawRecall! - -2 / 7) < 1e-12,
  );
  assert.deepEqual(noRegression.arms.baseline.flags.regressedCases, []);
  assert.equal(noRegression.arms.baseline.flags.corpusChanged, true);

  // Candidate misses SSRF on shared corpus while finding both newly added cases (6/7 > 5/5 raw count).
  const maskedRegressionIds = [
    ...fiveIds.filter((id) => id !== "partner-status-ssrf"),
    "statement-tenant-selection",
    "report-unverified-grant",
  ];
  const expandedMaskedDrop = createReleaseBaseline({
    experiment: makeSavedExperiment(sevenCase),
    fixture: sevenCase,
    runs: [
      completedRun(sevenCase, 1, "baseline", maskedRegressionIds),
      completedRun(sevenCase, 1, "time-aware", fiveIds),
    ],
  });

  const masked = compareBaselines(baseline, expandedMaskedDrop);
  assert.equal(masked.arms.baseline.candidate.rawFoundCount, 6);
  assert.equal(masked.arms.baseline.baseline.rawFoundCount, 5);
  assert.ok(
    Math.abs(masked.arms.baseline.delta.comparableRecall! - -0.2) < 1e-12,
  );
  assert.deepEqual(masked.arms.baseline.flags.regressedCases, [
    "partner-status-ssrf",
  ]);
});

test("changed case definitions and removed cases are excluded from comparable recall, while CWE order and single-line endLine stay comparable", () => {
  const baseFixture = createFixture();
  const baseIds = baseFixture.positives.map((entry) => entry.id);
  const baseline = createReleaseBaseline({
    experiment: makeSavedExperiment(baseFixture),
    fixture: baseFixture,
    runs: [
      completedRun(baseFixture, 1, "baseline", baseIds),
      completedRun(baseFixture, 1, "time-aware", baseIds),
    ],
  });

  const updated = createFixture();
  updated.files["src/invoices.py"] =
    `${updated.files["src/invoices.py"]}\n# comment\n`;
  updated.positives = updated.positives
    .filter((entry) => entry.id !== "preview-reflected-html")
    .map((entry) => {
      if (entry.id === "export-path-traversal") {
        // Reordered mixed-case CWEs + redundant single-line endLine keep definition equivalent.
        return {
          ...entry,
          endLine: entry.line,
          cwes: ["CWE-73", "cwe-36", "cwe-23", "CWE-22"],
        };
      }
      if (entry.id === "catalog-sql-injection") {
        return { ...entry, line: entry.line + 1 };
      }
      return entry;
    });

  const candIds = updated.positives.map((entry) => entry.id);
  const candidate = createReleaseBaseline({
    experiment: makeSavedExperiment(updated),
    fixture: updated,
    runs: [
      completedRun(
        updated,
        1,
        "baseline",
        candIds.filter((id) => id !== "catalog-sql-injection"),
      ),
      completedRun(updated, 1, "time-aware", candIds),
    ],
  });

  const comparison = compareBaselines(baseline, candidate);
  assert.deepEqual(comparison.corpus.positives.removed, [
    "preview-reflected-html",
  ]);
  assert.deepEqual(comparison.corpus.positives.changed, [
    "invoice-tenant-isolation",
    "catalog-sql-injection",
  ]);
  assert.equal(
    comparison.corpus.positives.comparable.includes("export-path-traversal"),
    true,
  );
  assert.deepEqual(
    candidate.corpus.positives.find((c) => c.id === "export-path-traversal")
      ?.cwes,
    ["CWE-73", "CWE-36", "CWE-23", "CWE-22"],
  );
  assert.equal(
    comparison.arms.baseline.cases.comparable.find(
      (c) => c.id === "export-path-traversal",
    )?.status,
    "unchanged",
  );
  // Missing changed case catalog-sql-injection must not trigger a comparable recall regression.
  assert.equal(comparison.arms.baseline.delta.comparableRecall, 0);
  assert.deepEqual(comparison.arms.baseline.flags.regressedCases, []);
  assert.deepEqual(
    comparison.arms.baseline.cases.changed.map((entry) => ({
      id: entry.id,
      baseRecall: entry.baseline.recall,
      candRecall: entry.candidate.recall,
    })),
    [
      { id: "invoice-tenant-isolation", baseRecall: 1, candRecall: 1 },
      { id: "catalog-sql-injection", baseRecall: 1, candRecall: 0 },
    ],
  );
  assert.deepEqual(comparison.arms.baseline.cases.removed, [
    {
      id: "preview-reflected-html",
      baseline: { foundRuns: 1, completedRuns: 1, recall: 1 },
    },
  ]);
});

test("failures, missing interrupted runs, unknown token usage, duplicates, and adjudication remain explicit", () => {
  const fiveCase = createFiveCaseFixture();
  const sevenCase = createFixture();
  const fiveIds = fiveCase.positives.map((entry) => entry.id);

  const baseline = createReleaseBaseline({
    experiment: makeSavedExperiment(fiveCase, { pairs: 2 }),
    fixture: fiveCase,
    runs: [
      completedRun(fiveCase, 1, "baseline", fiveIds, {
        usage: {
          input_tokens: 100,
          cached_input_tokens: 40,
          output_tokens: 20,
        },
        elapsedMs: 1000,
      }),
      completedRun(fiveCase, 2, "baseline", fiveIds, {
        usage: {
          input_tokens: 200,
          cached_input_tokens: 60,
          output_tokens: 40,
        },
        elapsedMs: 1400,
      }),
      completedRun(fiveCase, 1, "time-aware", fiveIds),
      completedRun(fiveCase, 2, "time-aware", fiveIds),
    ],
  });

  // Candidate has pairs=3: pair 1 completes with overlap + duplicate + unmatched + evidence error,
  // pair 2 fails verbatim, pair 3 was interrupted (missing=1).
  const dupFinding = findingFor(sevenCase, sevenCase.positives[0]!);
  const compControl = findingFor(
    sevenCase,
    sevenCase.controls.find((c) => c.id === "invoice-scoped-query")!,
  );
  const newControl = findingFor(
    sevenCase,
    sevenCase.controls.find((c) => c.id === "statement-session-tenant")!,
  );
  const unmatched = {
    ...findingFor(sevenCase, sevenCase.positives[1]!),
    taxonomy: { cwe: ["CWE-400"] },
  };
  const badEvidence = {
    ...findingFor(sevenCase, sevenCase.positives[2]!),
    codeEvidence: [{ path: "src/downloads.py", startLine: 1, code: "wrong" }],
  };

  const candidate = createReleaseBaseline({
    experiment: makeSavedExperiment(sevenCase, { pairs: 3 }),
    fixture: sevenCase,
    runs: [
      completedRun(sevenCase, 1, "baseline", fiveIds, {
        extraFindings: [
          dupFinding,
          compControl,
          newControl,
          unmatched,
          badEvidence,
        ],
        // cached_input_tokens omitted; total_tokens should still equal 120 + 30 = 150.
        usage: { input_tokens: 120, output_tokens: 30 },
        elapsedMs: 1500,
      }),
      {
        pair: 2,
        variant: "baseline",
        startedAt: "2026-10-01T00:05:00.000Z",
        advisoryBudgetMinutes: null,
        promptSha256: null,
        status: "failed",
        error: "worker exited 1: synthetic diagnostic token=keep-verbatim",
        elapsedMs: 500,
        usage: null,
      },
      completedRun(sevenCase, 1, "time-aware", fiveIds, {
        // Missing cached_input_tokens must not hide known input + output totals.
        usage: {
          input_tokens: 300,
          output_tokens: 50,
        },
      }),
      completedRun(sevenCase, 2, "time-aware", fiveIds, {
        usage: {
          input_tokens: 300,
          cached_input_tokens: 100,
          output_tokens: 50,
        },
      }),
      completedRun(sevenCase, 3, "time-aware", fiveIds, {
        usage: {
          input_tokens: 300,
          cached_input_tokens: 100,
          output_tokens: 50,
        },
      }),
    ],
  });

  const comparison = compareBaselines(baseline, candidate);
  const baseArm = comparison.arms.baseline;
  assert.equal(baseArm.baseline.usage.totals.total_tokens, 360);
  assert.equal(baseArm.baseline.usage.meanPerRun.total_tokens, 180);
  assert.equal(baseArm.candidate.configured, 3);
  assert.equal(baseArm.candidate.attempted, 2);
  assert.equal(baseArm.candidate.completed, 1);
  assert.equal(baseArm.candidate.failed, 1);
  assert.equal(baseArm.candidate.missing, 1);
  assert.equal(baseArm.candidate.successRate, 0.5);
  assert.equal(baseArm.candidate.completionRate, 1 / 3);
  assert.deepEqual(baseArm.candidate.failures, [
    {
      pair: 2,
      error: "worker exited 1: synthetic diagnostic token=keep-verbatim",
    },
  ]);
  assert.equal(baseArm.candidate.safeControlFindings, 2);
  assert.equal(baseArm.candidate.comparableSafeControlFindings, 1);
  assert.equal(baseArm.candidate.duplicateFindings, 1);
  assert.equal(baseArm.candidate.unmatchedFindings, 2);
  assert.equal(baseArm.candidate.evidenceErrors, 2);
  assert.equal(baseArm.candidate.adjudicationRequiredRuns, 1);
  assert.equal(baseArm.candidate.usage.missingUsageRuns, 2);
  assert.equal(baseArm.candidate.usage.totals.total_tokens, null);
  assert.equal(baseArm.delta.meanUsage.total_tokens, null);
  assert.equal(baseArm.flags.hasRunFailures, true);
  assert.equal(baseArm.flags.hasMissingRuns, true);
  assert.equal(baseArm.flags.hasUnknownUsage, true);
  assert.equal(baseArm.flags.needsAdjudication, true);
  assert.equal(baseArm.flags.duplicatesIncreased, true);
  assert.equal(baseArm.flags.evidenceErrorsIncreased, true);
  assert.equal(baseArm.flags.comparableControlAccusationsIncreased, true);

  // time-aware arm compares full input/output totals across unequal pair counts (2 vs 3)
  // even when cached_input_tokens is missing on one run.
  const timedArm = comparison.arms["time-aware"];
  assert.equal(timedArm.baseline.usage.meanPerRun.total_tokens, 1200);
  assert.equal(timedArm.candidate.usage.meanPerRun.total_tokens, 350);
  assert.equal(timedArm.delta.meanUsage.total_tokens, -850);
  assert.equal(timedArm.candidate.usage.totals.cached_input_tokens, null);
  assert.equal(timedArm.delta.meanUsage.cached_input_tokens, null);
  assert.equal(timedArm.candidate.usage.missingUsageRuns, 1);
  assert.equal(timedArm.flags.hasRunFailures, false);
  assert.equal(timedArm.flags.hasMissingRuns, false);
  assert.equal(timedArm.flags.hasUnknownUsage, true);
});

test("multi-pair variability reports min/max/mean and uses exact rational comparison", () => {
  const fixture = createFixture();
  const allIds = fixture.positives.map((entry) => entry.id);
  const partialIds = allIds.slice(0, 5);

  const baseline = createReleaseBaseline({
    experiment: makeSavedExperiment(fixture, { pairs: 3 }),
    fixture,
    runs: [
      completedRun(fixture, 1, "baseline", allIds),
      completedRun(fixture, 2, "baseline", allIds),
      completedRun(fixture, 3, "baseline", partialIds),
      completedRun(fixture, 1, "time-aware", allIds),
      completedRun(fixture, 2, "time-aware", allIds),
      completedRun(fixture, 3, "time-aware", allIds),
    ],
  });
  const candidate = createReleaseBaseline({
    experiment: makeSavedExperiment(fixture, { pairs: 6 }),
    fixture,
    runs: [
      completedRun(fixture, 1, "baseline", allIds),
      completedRun(fixture, 2, "baseline", allIds),
      completedRun(fixture, 3, "baseline", allIds),
      completedRun(fixture, 4, "baseline", allIds),
      completedRun(fixture, 5, "baseline", partialIds),
      completedRun(fixture, 6, "baseline", partialIds),
      ...Array.from({ length: 6 }, (_, i) =>
        completedRun(fixture, i + 1, "time-aware", allIds),
      ),
    ],
  });

  const comparison = compareBaselines(baseline, candidate);
  const baseArm = comparison.arms.baseline;
  // Last case was found 2/3 in baseline and 4/6 in candidate => exact 0 delta despite 1/3 floating point.
  const lastCase = baseArm.cases.comparable.at(-1)!;
  assert.equal(lastCase.baseline.foundRuns, 2);
  assert.equal(lastCase.candidate.foundRuns, 4);
  assert.equal(lastCase.recallDelta, 0);
  assert.equal(lastCase.status, "unchanged");
  assert.equal(baseArm.delta.comparableRecall, 0);
  assert.equal(baseArm.candidate.comparableRecall.min, 5 / 7);
  assert.equal(baseArm.candidate.comparableRecall.max, 1);
  assert.equal(baseArm.candidate.comparableRecall.mean, (4 * 7 + 2 * 5) / 42);
});

test("rejects cross-artifact mismatches, duplicate runs, and unsupported schemas", () => {
  const fixture = createFixture();
  const allIds = fixture.positives.map((entry) => entry.id);
  const experiment = makeSavedExperiment(fixture);

  const mismatchedFixture = createFixture();
  mismatchedFixture.files["src/invoices.py"] += "\n";
  assert.throws(
    () =>
      createReleaseBaseline({
        experiment,
        fixture: mismatchedFixture,
        runs: [completedRun(fixture, 1, "baseline", allIds)],
      }),
    /do not match fixture\.files/,
  );

  const fiveCase = createFiveCaseFixture();
  assert.throws(
    () =>
      createReleaseBaseline({
        experiment,
        fixture,
        runs: [
          completedRun(
            fiveCase,
            1,
            "baseline",
            fiveCase.positives.map((entry) => entry.id),
          ),
        ],
      }),
    /do not match corpus positives/,
  );

  assert.throws(
    () =>
      createReleaseBaseline({
        experiment,
        fixture,
        runs: [
          completedRun(fixture, 1, "baseline", allIds),
          completedRun(fixture, 1, "baseline", allIds),
        ],
      }),
    /Duplicate run for pair 1\/baseline/,
  );

  const valid = createReleaseBaseline({
    experiment,
    fixture,
    runs: [completedRun(fixture, 1, "baseline", allIds)],
  });
  assert.throws(
    () => validateReleaseBaseline({ ...valid, schemaVersion: 2 }),
    /Unsupported ReleaseBaseline schemaVersion/,
  );

  assert.throws(
    () => hashSnapshotMap({ "a.py": "not-a-sha256" }),
    /SHA-256 hex digest/,
  );
});

test("CLI export and compare commands support run directories, baseline JSON files, and usage errors", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "baseline-cli-"));
  t.after(() => rm(root, { recursive: true, force: true }));

  const fiveCase = createFiveCaseFixture();
  const sevenCase = createFixture();
  const baseDir = join(root, "run-base");
  const candDir = join(root, "run-cand");
  await Promise.all([
    mkdir(baseDir, { recursive: true }),
    mkdir(candDir, { recursive: true }),
  ]);
  const fiveIds = fiveCase.positives.map((entry) => entry.id);

  await Promise.all([
    writeFile(
      join(baseDir, "experiment.json"),
      JSON.stringify(makeSavedExperiment(fiveCase)),
    ),
    writeFile(join(baseDir, "fixture.json"), JSON.stringify(fiveCase)),
    writeFile(
      join(baseDir, "runs.json"),
      JSON.stringify([completedRun(fiveCase, 1, "baseline", fiveIds)]),
    ),
    writeFile(
      join(candDir, "experiment.json"),
      JSON.stringify(makeSavedExperiment(sevenCase)),
    ),
    writeFile(join(candDir, "fixture.json"), JSON.stringify(sevenCase)),
    writeFile(
      join(candDir, "runs.json"),
      JSON.stringify([
        completedRun(sevenCase, 1, "baseline", fiveIds.slice(0, 4)),
      ]),
    ),
  ]);

  const exportedFile = join(root, "baseline.json");
  const exportRun = spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      baselineScript,
      "export",
      baseDir,
      exportedFile,
    ],
    { encoding: "utf8" },
  );
  assert.equal(exportRun.status, 0, exportRun.stderr);

  const exportStdout = spawnSync(
    process.execPath,
    ["--experimental-strip-types", baselineScript, "export", baseDir],
    { encoding: "utf8" },
  );
  assert.equal(exportStdout.status, 0, exportStdout.stderr);
  assert.equal(exportStdout.stdout, await readFile(exportedFile, "utf8"));

  const comparisonFile = join(root, "comparison.json");
  const compareRun = spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      baselineScript,
      "compare",
      exportedFile,
      candDir,
      comparisonFile,
    ],
    { encoding: "utf8" },
  );
  assert.equal(compareRun.status, 0, compareRun.stderr);
  const parsed = JSON.parse(await readFile(comparisonFile, "utf8"));
  assert.ok(
    Math.abs(parsed.arms.baseline.delta.comparableRecall - -0.2) < 1e-12,
  );
  assert.deepEqual(parsed.arms.baseline.flags.regressedCases, [
    "partner-status-ssrf",
  ]);

  const badRun = spawnSync(
    process.execPath,
    ["--experimental-strip-types", baselineScript, "unknown"],
    { encoding: "utf8" },
  );
  assert.equal(badRun.status, 1);
  assert.match(badRun.stderr, /Usage:/);
});

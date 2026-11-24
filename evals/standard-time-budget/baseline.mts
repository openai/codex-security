import { readFile, stat, writeFile } from "node:fs/promises";
import { join, posix, resolve, win32 } from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import {
  hashText,
  validateExperiment,
  type ExperimentConfig,
  type RunRecord,
  type Variant,
} from "./experiment.mts";
import type { Fixture, SourceCase } from "./fixtures.mts";
import {
  mean,
  sumKnown,
  summarizeUsage,
  usageFields,
  variants,
} from "./summary.mts";

export const BASELINE_SCHEMA_VERSION = 1;
type Snapshot = Record<string, string>;
export interface SavedExperiment extends ExperimentConfig {
  reasoningEffort?: string | null;
  evaluator: Snapshot;
  source: Snapshot;
  plugin?: Snapshot;
  sdk?: Snapshot;
  packageVersions?: Record<string, string>;
  codexExecutable?: {
    command?: string;
    files: { path?: string; sha256: string }[];
  };
}

function check(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function digest(value: string) {
  check(
    typeof value === "string" && /^[\da-f]{64}$/u.test(value),
    "Expected SHA-256 hex digest.",
  );
  return value;
}

export function hashSnapshotMap(files: Snapshot) {
  // Stable across host locales and insertion order.
  const entries = Object.keys(files)
    .sort()
    .map((path) => [path, digest(files[path]!)]);
  return hashText(JSON.stringify(entries));
}

function stringMap(values: Snapshot): Snapshot {
  check(
    !!values && typeof values === "object" && !Array.isArray(values),
    "Expected a snapshot map.",
  );
  for (const [key, value] of Object.entries(values))
    check(
      !!key.trim() && !win32.isAbsolute(key) && typeof value === "string",
      "Invalid snapshot entry.",
    );
  return values;
}

function sourceDigests(evaluator: Snapshot, source: Snapshot) {
  return {
    evaluatorSha256: hashSnapshotMap(evaluator),
    fixturesModuleSha256: evaluator["fixtures.mts"] ?? null,
    sourceSha256: hashSnapshotMap(source),
  };
}

type BaselineCase = SourceCase & { fileSha256: string };
function corpusCases(entries: BaselineCase[], source: Snapshot) {
  const ids = new Set<string>();
  return entries.map(({ id, path, line, endLine = line, cwes, fileSha256 }) => {
    check(!!id.trim() && !ids.has(id), `Invalid or duplicate case ID: ${id}`);
    ids.add(id);
    check(
      Object.hasOwn(source, path) && source[path] === fileSha256,
      `Case ${id} source mismatch.`,
    );
    check(
      Number.isSafeInteger(line) &&
        line > 0 &&
        Number.isSafeInteger(endLine) &&
        endLine >= line,
      `Invalid case span: ${id}`,
    );
    const accepted = [...new Set(cwes.map((cwe) => cwe.trim().toUpperCase()))];
    check(!!accepted.length && !accepted.includes(""), `Missing CWE: ${id}`);
    return {
      id,
      path,
      line,
      ...(endLine > line ? { endLine } : {}),
      cwes: accepted,
      fileSha256,
    };
  });
}

// Both input forms pass through checkedRuns, which selects the portable fields.
function projectRun(run: RunRecord) {
  if (run.status === "failed") return run;
  const { safeControlDetails, unmatchedFindings, evidenceErrors, ...scores } =
    run.report;
  return {
    ...run,
    report: {
      ...scores,
      safeControlAccusations: safeControlDetails.map(
        (entry) => entry.controlIds,
      ),
      unmatchedFindingsCount: unmatchedFindings.length,
      evidenceErrorsCount: evidenceErrors.length,
    },
  };
}

type ProjectedRun = ReturnType<typeof projectRun>;
type Score = Extract<ProjectedRun, { status: "completed" }>["report"];

function count(value: number) {
  check(
    Number.isSafeInteger(value) && value >= 0,
    "Expected a nonnegative integer count.",
  );
  return value;
}

function checkedReport(
  report: Score,
  positives: BaselineCase[],
  controls: Set<string>,
) {
  const {
    expectedCount,
    foundCount,
    passed,
    needsAdjudication,
    safeControlAccusations,
    safeControlFindings,
  } = report;
  const cases = report.cases.map(({ id, found }) => ({ id, found }));
  check(
    expectedCount === positives.length &&
      cases.length === expectedCount &&
      cases.every(
        (entry, i) =>
          entry.id === positives[i]!.id && typeof entry.found === "boolean",
      ),
    "Run cases do not match corpus positives.",
  );
  const matchedIds = cases
    .filter((entry) => entry.found)
    .map((entry) => entry.id);
  check(
    isDeepStrictEqual(matchedIds, report.matchedIds) &&
      foundCount === matchedIds.length,
    "Run matches disagree with cases.",
  );
  check(
    safeControlFindings === safeControlAccusations.length &&
      safeControlAccusations.every(
        (ids) =>
          Array.isArray(ids) &&
          ids.length > 0 &&
          ids.every((id) => controls.has(id)),
      ),
    "Invalid safe-control accusations.",
  );
  const unmatchedFindingsCount = count(report.unmatchedFindingsCount);
  check(
    typeof passed === "boolean" &&
      typeof needsAdjudication === "boolean" &&
      (needsAdjudication || !(safeControlFindings || unmatchedFindingsCount)),
    "Invalid grading status.",
  );
  check(
    report.recall === foundCount / expectedCount,
    "Run recall disagrees with cases.",
  );
  const evidenceErrorsCount = count(report.evidenceErrorsCount);
  check(
    !passed ||
      (foundCount === expectedCount &&
        !needsAdjudication &&
        !evidenceErrorsCount),
    "Passing run has missing cases or grading issues.",
  );
  return {
    passed,
    needsAdjudication,
    cases,
    matchedIds,
    foundCount,
    expectedCount,
    recall: report.recall,
    duplicateFindings: count(report.duplicateFindings),
    safeControlFindings,
    safeControlAccusations,
    unmatchedFindingsCount,
    evidenceErrorsCount,
  };
}

function runUsage(usage: unknown) {
  if (usage == null) return null;
  check(
    typeof usage === "object" && !Array.isArray(usage),
    "Invalid token usage.",
  );
  return Object.fromEntries(
    usageFields.map((field) => {
      const value = (usage as Record<string, number | null>)[field];
      return [field, value == null ? null : count(value)];
    }),
  );
}

function checkedRuns(
  runs: ProjectedRun[],
  pairs: number,
  positives: BaselineCase[],
  controls: BaselineCase[],
) {
  const controlIds = new Set(controls.map((entry) => entry.id));
  const seen = new Set<string>();
  const checked = runs.map((run) => {
    const {
      pair,
      variant,
      startedAt,
      elapsedMs,
      advisoryBudgetMinutes = null,
      promptSha256,
    } = run;
    const key = `${pair}/${variant}`;
    check(
      variants.includes(variant) &&
        Number.isSafeInteger(pair) &&
        pair > 0 &&
        pair <= pairs,
      `Invalid pair/variant: ${key}`,
    );
    check(!seen.has(key), `Duplicate run for pair ${key}`);
    seen.add(key);
    check(
      !!startedAt.trim() &&
        Number.isFinite(elapsedMs) &&
        elapsedMs >= 0 &&
        (advisoryBudgetMinutes === null ||
          (Number.isFinite(advisoryBudgetMinutes) &&
            advisoryBudgetMinutes > 0)),
      `Invalid timing: ${key}`,
    );
    const metadata = {
      pair,
      variant,
      startedAt,
      elapsedMs,
      advisoryBudgetMinutes,
      promptSha256: promptSha256 === null ? null : digest(promptSha256),
      usage: runUsage(run.usage),
    };
    if (run.status === "failed") {
      check(typeof run.error === "string", "Missing failure diagnostic.");
      return { ...metadata, status: run.status, error: run.error };
    }
    check(run.status === "completed", "Invalid run status.");
    return {
      ...metadata,
      status: run.status,
      report: checkedReport(run.report, positives, controlIds),
    };
  });
  return checked.sort(
    (a, b) =>
      a.pair - b.pair ||
      variants.indexOf(a.variant) - variants.indexOf(b.variant),
  );
}

function projectExperiment(experiment: SavedExperiment) {
  const { source, evaluator, plugin, sdk, codexExecutable } = experiment;
  return {
    ...validateExperiment(experiment),
    evaluator,
    source,
    reasoningEffort: experiment.reasoningEffort ?? null,
    packageVersions: experiment.packageVersions ?? {},
    digests: {
      ...sourceDigests(evaluator, source),
      pluginSha256: plugin ? hashSnapshotMap(plugin) : null,
      sdkSha256: sdk ? hashSnapshotMap(sdk) : null,
      codexExecutableSha256:
        codexExecutable?.files.map((file) => file.sha256) ?? [],
    },
  };
}

export function createReleaseBaseline({
  experiment,
  fixture,
  runs,
}: {
  experiment: SavedExperiment;
  fixture: Fixture;
  runs: RunRecord[];
}) {
  const files = Object.fromEntries(
    Object.entries(fixture.files).map(([path, text]) => [path, hashText(text)]),
  );
  check(
    isDeepStrictEqual(files, experiment.source),
    "Experiment hashes do not match fixture.files.",
  );
  const cases = (entries: SourceCase[]) =>
    entries.map((entry) => ({ ...entry, fileSha256: files[entry.path] }));
  return validateReleaseBaseline({
    schemaVersion: BASELINE_SCHEMA_VERSION,
    experiment: projectExperiment(experiment),
    corpus: {
      positives: cases(fixture.positives),
      controls: cases(fixture.controls),
    },
    runs: runs.map(projectRun),
  });
}

export type ReleaseBaseline = ReturnType<typeof validateReleaseBaseline>;

export function validateReleaseBaseline(input: unknown) {
  const value = input as {
    schemaVersion: number;
    experiment: ReturnType<typeof projectExperiment>;
    corpus: { positives: BaselineCase[]; controls: BaselineCase[] };
    runs: ProjectedRun[];
  };
  check(
    value?.schemaVersion === BASELINE_SCHEMA_VERSION,
    "Unsupported ReleaseBaseline schemaVersion.",
  );
  const config = validateExperiment(value.experiment);
  const { digests, reasoningEffort, packageVersions } = value.experiment;
  check(
    reasoningEffort === null || typeof reasoningEffort === "string",
    "Invalid reasoning effort.",
  );
  const source = stringMap(value.experiment.source);
  for (const path of Object.keys(source))
    check(
      path !== "." &&
        path !== ".." &&
        !path.startsWith("../") &&
        posix.normalize(path) === path,
      "Invalid fixture file path.",
    );
  const evaluator = stringMap(value.experiment.evaluator);
  const hashes = sourceDigests(evaluator, source);
  check(
    Object.entries(hashes).every(
      ([key, hash]) => digests[key as keyof typeof hashes] === hash,
    ),
    "Baseline snapshot digest mismatch.",
  );
  const positives = corpusCases(value.corpus.positives, source);
  const controls = corpusCases(value.corpus.controls, source);
  check(positives.length > 0, "Missing positive cases.");
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    experiment: {
      ...config,
      source,
      evaluator,
      reasoningEffort,
      packageVersions: stringMap(packageVersions),
      digests: {
        ...hashes,
        pluginSha256:
          digests.pluginSha256 === null ? null : digest(digests.pluginSha256),
        sdkSha256:
          digests.sdkSha256 === null ? null : digest(digests.sdkSha256),
        codexExecutableSha256: digests.codexExecutableSha256.map(digest),
      },
    },
    corpus: { positives, controls },
    runs: checkedRuns(value.runs, config.pairs, positives, controls),
  };
}

export async function loadBaseline(path: string) {
  const json = async (file: string) => JSON.parse(await readFile(file, "utf8"));
  if (!(await stat(path)).isDirectory())
    return validateReleaseBaseline(await json(path));
  return createReleaseBaseline({
    experiment: await json(join(path, "experiment.json")),
    fixture: await json(join(path, "fixture.json")),
    runs: await json(join(path, "runs.json")),
  });
}

function diffEntries<T>(before: Map<string, T>, after: Map<string, T>) {
  const comparable: string[] = [];
  const changed: string[] = [];
  const removed: string[] = [];
  for (const [id, value] of before) {
    if (!after.has(id)) removed.push(id);
    else if (isDeepStrictEqual(value, after.get(id))) comparable.push(id);
    else changed.push(id);
  }
  const added = [...after.keys()].filter((id) => !before.has(id));
  return { comparable, added, removed, changed };
}

function diffCorpus(base: ReleaseBaseline, cand: ReleaseBaseline) {
  const byId = (cases: BaselineCase[]) =>
    new Map(cases.map((c) => [c.id, { ...c, cwes: new Set(c.cwes) }]));
  const files = (s: Snapshot) =>
    new Map(
      Object.keys(s)
        .sort()
        .map((name) => [name, s[name]]),
    );
  const { comparable, ...changes } = diffEntries(
    files(base.experiment.source),
    files(cand.experiment.source),
  );
  return {
    positives: diffEntries(
      byId(base.corpus.positives),
      byId(cand.corpus.positives),
    ),
    controls: diffEntries(
      byId(base.corpus.controls),
      byId(cand.corpus.controls),
    ),
    sourceFiles: { unchanged: comparable, ...changes },
  };
}

type Corpus = ReturnType<typeof diffCorpus>;
type ScoreReport = ReturnType<typeof checkedReport>;

function rate(numerator: number | null, denominator: number) {
  return numerator === null || denominator === 0
    ? null
    : numerator / denominator;
}

function delta(base: number | null, cand: number | null) {
  return base === null || cand === null ? null : cand - base;
}

function recall(counts: number[], size: number) {
  const found = size ? sumKnown(counts) : null;
  const expected = counts.length * size || null;
  return {
    found,
    expected,
    // Divide once so equivalent fractions yield identical rates across runs.
    score: {
      mean: rate(found, expected ?? 0),
      min: expected ? Math.min(...counts) / size : null,
      max: expected ? Math.max(...counts) / size : null,
    },
  };
}

const tokenFields = [...usageFields, "total_tokens"] as const;
function tokenMetrics(
  fn: (field: (typeof tokenFields)[number]) => number | null,
) {
  return Object.fromEntries(tokenFields.map((k) => [k, fn(k)])) as Record<
    (typeof tokenFields)[number],
    number | null
  >;
}

function summarizeArm(
  baseline: ReleaseBaseline,
  variant: Variant,
  corpus: Corpus,
) {
  const configured = baseline.experiment.pairs;
  const attempts = baseline.runs.filter((run) => run.variant === variant);
  const finished = attempts.filter((run) => run.status === "completed");
  const failures = attempts
    .filter((run) => run.status === "failed")
    .map(({ pair, error }) => ({ pair, error }));
  const reports = finished.map((run) => run.report);
  const completed = reports.length;
  const comparable = new Set(corpus.positives.comparable);
  const controls = new Set(corpus.controls.comparable);
  const found = new Map<string, number>();
  const shared = recall(
    reports.map(({ matchedIds }) => {
      let sharedCount = 0;
      for (const id of matchedIds) {
        found.set(id, (found.get(id) ?? 0) + 1);
        if (comparable.has(id)) sharedCount++;
      }
      return sharedCount;
    }),
    comparable.size,
  );
  const raw = recall(
    reports.map((r) => r.foundCount),
    baseline.corpus.positives.length,
  );
  const sum = (fn: (r: ScoreReport) => number) => sumKnown(reports.map(fn));
  const duplicateFindings = sum((r) => r.duplicateFindings);
  const safeControlFindings = sum((r) => r.safeControlFindings);
  const comparableSafeControlFindings = controls.size
    ? sum(
        (r) =>
          r.safeControlAccusations.filter((ids) =>
            ids.some((id) => controls.has(id)),
          ).length,
      )
    : null;
  const unmatchedFindings = sum((r) => r.unmatchedFindingsCount);
  const evidenceErrors = sum((r) => r.evidenceErrorsCount);
  const adjudicationRequiredRuns = reports.filter(
    (r) => r.needsAdjudication,
  ).length;
  const { missingUsageRuns, ...totals } = summarizeUsage(attempts);
  return {
    caseRate(id: string) {
      const foundRuns = found.get(id) ?? 0;
      return {
        foundRuns,
        completedRuns: completed,
        recall: rate(foundRuns, completed),
      };
    },
    accusations(id: string) {
      const counts = reports.map(
        (r) =>
          r.safeControlAccusations.filter((ids) => ids.includes(id)).length,
      );
      return {
        runs: counts.filter((n) => n > 0).length,
        findings: sumKnown(counts) ?? 0,
      };
    },
    summary: {
      configured,
      attempted: attempts.length,
      completed,
      failed: failures.length,
      missing: configured - attempts.length,
      successRate: rate(completed, attempts.length),
      completionRate: completed / configured,
      failures,
      comparableRecall: shared.score,
      comparableFoundCount: shared.found,
      comparableExpectedCount: shared.expected,
      rawRecall: raw.score,
      rawFoundCount: raw.found,
      rawExpectedCount: raw.expected,
      duplicateFindings,
      meanDuplicateFindings: rate(duplicateFindings, completed),
      safeControlFindings,
      meanSafeControlFindings: rate(safeControlFindings, completed),
      comparableSafeControlFindings,
      meanComparableSafeControlFindings: rate(
        comparableSafeControlFindings,
        completed,
      ),
      unmatchedFindings,
      meanUnmatchedFindings: rate(unmatchedFindings, completed),
      evidenceErrors,
      meanEvidenceErrors: rate(evidenceErrors, completed),
      adjudicationRequiredRuns,
      adjudicationRate: rate(adjudicationRequiredRuns, completed),
      meanElapsedMs: mean(attempts.map((r) => r.elapsedMs)),
      meanCompletedElapsedMs: mean(finished.map((r) => r.elapsedMs)),
      usage: {
        totals,
        missingUsageRuns,
        meanPerRun: tokenMetrics((field) =>
          rate(totals[field], attempts.length),
        ),
      },
    },
  };
}

function compareArm(
  base: ReleaseBaseline,
  cand: ReleaseBaseline,
  variant: Variant,
  corpus: Corpus,
  revision: { corpusChanged: boolean; graderChanged: boolean | null },
) {
  const before = summarizeArm(base, variant, corpus);
  const after = summarizeArm(cand, variant, corpus);
  const b = before.summary;
  const c = after.summary;
  const pair = (id: string) => ({
    id,
    baseline: before.caseRate(id),
    candidate: after.caseRate(id),
  });
  const comparable = corpus.positives.comparable.map((id) => {
    const rates = pair(id);
    const recallDelta = delta(rates.baseline.recall, rates.candidate.recall);
    const status =
      recallDelta === null
        ? "unmeasured"
        : recallDelta > 0
          ? "improved"
          : recallDelta < 0
            ? "regressed"
            : "unchanged";
    return { ...rates, recallDelta, status };
  });
  const changes = {
    comparableRecall: delta(b.comparableRecall.mean, c.comparableRecall.mean),
    rawRecall: delta(b.rawRecall.mean, c.rawRecall.mean),
    successRate: delta(b.successRate, c.successRate),
    completionRate: delta(b.completionRate, c.completionRate),
    meanElapsedMs: delta(b.meanElapsedMs, c.meanElapsedMs),
    meanCompletedElapsedMs: delta(
      b.meanCompletedElapsedMs,
      c.meanCompletedElapsedMs,
    ),
    meanDuplicateFindings: delta(
      b.meanDuplicateFindings,
      c.meanDuplicateFindings,
    ),
    meanSafeControlFindings: delta(
      b.meanSafeControlFindings,
      c.meanSafeControlFindings,
    ),
    meanComparableSafeControlFindings: delta(
      b.meanComparableSafeControlFindings,
      c.meanComparableSafeControlFindings,
    ),
    meanUnmatchedFindings: delta(
      b.meanUnmatchedFindings,
      c.meanUnmatchedFindings,
    ),
    meanEvidenceErrors: delta(b.meanEvidenceErrors, c.meanEvidenceErrors),
    meanUsage: tokenMetrics((k) =>
      delta(b.usage.meanPerRun[k], c.usage.meanPerRun[k]),
    ),
  };
  return {
    baseline: b,
    candidate: c,
    delta: changes,
    cases: {
      comparable,
      added: corpus.positives.added.map((id) => ({
        id,
        candidate: after.caseRate(id),
      })),
      removed: corpus.positives.removed.map((id) => ({
        id,
        baseline: before.caseRate(id),
      })),
      changed: corpus.positives.changed.map(pair),
    },
    controls: corpus.controls.comparable.map((id) => {
      const b = before.accusations(id);
      const c = after.accusations(id);
      return {
        id,
        baselineAccusedRuns: b.runs,
        candidateAccusedRuns: c.runs,
        baselineFindings: b.findings,
        candidateFindings: c.findings,
      };
    }),
    flags: {
      ...revision,
      regressedCases: comparable
        .filter((r) => r.status === "regressed")
        .map((r) => r.id),
      improvedCases: comparable
        .filter((r) => r.status === "improved")
        .map((r) => r.id),
      hasRunFailures: b.failed > 0 || c.failed > 0,
      hasMissingRuns: b.missing > 0 || c.missing > 0,
      hasUnknownUsage:
        b.usage.missingUsageRuns > 0 || c.usage.missingUsageRuns > 0,
      needsAdjudication:
        b.adjudicationRequiredRuns > 0 || c.adjudicationRequiredRuns > 0,
      evidenceErrorsIncreased: (changes.meanEvidenceErrors ?? 0) > 0,
      duplicatesIncreased: (changes.meanDuplicateFindings ?? 0) > 0,
      comparableControlAccusationsIncreased:
        (changes.meanComparableSafeControlFindings ?? 0) > 0,
    },
  };
}

function diffFields<T extends Record<string, unknown>>(before: T, after: T) {
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  return Object.fromEntries(
    [...keys].sort().map((key) => {
      const baseline = Object.hasOwn(before, key) ? before[key] : null;
      const candidate = Object.hasOwn(after, key) ? after[key] : null;
      return [
        key,
        {
          baseline,
          candidate,
          changed: !isDeepStrictEqual(baseline, candidate),
        },
      ];
    }),
  ) as {
    [K in keyof T]: {
      baseline: T[K] | null;
      candidate: T[K] | null;
      changed: boolean;
    };
  };
}

export function compareBaselines(
  baselineInput: ReleaseBaseline,
  candidateInput: ReleaseBaseline,
) {
  const baseline = validateReleaseBaseline(baselineInput);
  const candidate = validateReleaseBaseline(candidateInput);
  const corpus = diffCorpus(baseline, candidate);
  const fixtureIdentical = Object.values(corpus).every(
    ({ added, removed, changed }) =>
      !added.length && !removed.length && !changed.length,
  );
  const config = ({
    model,
    pairs,
    budgetMinutes,
    reasoningEffort,
  }: ReleaseBaseline["experiment"]) => ({
    model,
    pairs,
    budgetMinutes,
    reasoningEffort,
  });
  const b = baseline.experiment;
  const c = candidate.experiment;
  const digests = diffFields(
    { ...b.digests, graderSha256: b.evaluator["grade.mts"] ?? null },
    { ...c.digests, graderSha256: c.evaluator["grade.mts"] ?? null },
  );
  const grader = digests.graderSha256;
  const revision = {
    corpusChanged: !fixtureIdentical,
    graderChanged: grader.baseline && grader.candidate ? grader.changed : null,
  };
  const arm = (variant: Variant) =>
    compareArm(baseline, candidate, variant, corpus, revision);
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    provenance: {
      fixtureIdentical,
      ...diffFields(config(b), config(c)),
      packageVersions: diffFields(b.packageVersions, c.packageVersions),
      digests,
    },
    corpus,
    arms: { baseline: arm("baseline"), "time-aware": arm("time-aware") },
  };
}

async function main([command, ...args]: string[]) {
  const inputs = command === "export" ? 1 : command === "compare" ? 2 : 0;
  if (!inputs || args.length < inputs || args.length > inputs + 1) {
    process.stderr.write(
      "Usage:\n  baseline.mts export <run-dir> [output.json]\n  baseline.mts compare <baseline-path> <candidate-path> [output.json]\n",
    );
    process.exitCode = 1;
    return;
  }
  const baseline = await loadBaseline(args[0]!);
  const result =
    inputs === 1
      ? baseline
      : compareBaselines(baseline, await loadBaseline(args[1]!));
  const text = JSON.stringify(result, null, 2) + "\n";
  const output = args[inputs];
  if (output === undefined) process.stdout.write(text);
  else await writeFile(output, text, { flag: "wx" });
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  await main(process.argv.slice(2));
}

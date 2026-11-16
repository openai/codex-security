import { readFile, stat, writeFile } from "node:fs/promises";
import { join, posix, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  hashText,
  validateExperiment,
  type ExperimentConfig,
  type RunRecord,
  type RunReport,
  type Variant,
} from "./experiment.mts";
import type { Fixture, SourceCase } from "./fixtures.mts";

export const BASELINE_SCHEMA_VERSION = 1 as const;

const variants = ["baseline", "time-aware"] as const;
const usageFields = [
  "input_tokens",
  "cached_input_tokens",
  "output_tokens",
] as const;
type UsageField = (typeof usageFields)[number];
const sha256Pattern = /^[a-f0-9]{64}$/u;

export interface BaselineCase {
  id: string;
  path: string;
  line: number;
  endLine?: number;
  cwes: string[];
  fileSha256: string;
}

export interface SavedExperiment extends ExperimentConfig {
  reasoningEffort?: string | null;
  execution?: string;
  order?: string;
  evaluator: Record<string, string>;
  source: Record<string, string>;
  plugin?: Record<string, string>;
  sdk?: Record<string, string>;
  packageVersions?: Record<string, string>;
  codexExecutable?: {
    command?: string;
    files: Array<{ path?: string; sha256: string }>;
  };
}

export interface BaselineUsage {
  input_tokens: number | null;
  cached_input_tokens: number | null;
  output_tokens: number | null;
}

export interface BaselineCompletedReport {
  passed: boolean;
  recall: number;
  foundCount: number;
  expectedCount: number;
  matchedIds: string[];
  cases: Array<{ id: string; found: boolean }>;
  duplicateFindings: number;
  safeControlFindings: number;
  safeControlAccusations: string[][];
  unmatchedFindingsCount: number;
  evidenceErrorsCount: number;
  needsAdjudication: boolean;
}

export type BaselineAttempt = {
  pair: number;
  variant: Variant;
  startedAt: string;
  advisoryBudgetMinutes: number | null;
  promptSha256: string | null;
  elapsedMs: number;
  usage: BaselineUsage | null;
} & (
  | { status: "completed"; report: BaselineCompletedReport; error?: never }
  | { status: "failed"; error: string; report?: never }
);

export interface ReleaseBaseline {
  schemaVersion: typeof BASELINE_SCHEMA_VERSION;
  experiment: {
    model: string;
    pairs: number;
    budgetMinutes: number;
    reasoningEffort: string | null;
    packageVersions: Record<string, string>;
    digests: {
      fixturesModuleSha256: string | null;
      evaluatorSha256: string;
      sourceSha256: string;
      pluginSha256: string | null;
      sdkSha256: string | null;
      codexExecutableSha256: string[];
    };
    evaluator: Record<string, string>;
    source: Record<string, string>;
  };
  corpus: { positives: BaselineCase[]; controls: BaselineCase[] };
  runs: BaselineAttempt[];
}

export interface CaseRate {
  foundRuns: number;
  completedRuns: number;
  recall: number | null;
}

export interface ArmSummary {
  configured: number;
  attempted: number;
  completed: number;
  failed: number;
  missing: number;
  successRate: number | null;
  completionRate: number | null;
  failures: Array<{ pair: number; error: string }>;
  comparableRecall: {
    mean: number | null;
    min: number | null;
    max: number | null;
  };
  comparableFoundCount: number | null;
  comparableExpectedCount: number | null;
  rawRecall: { mean: number | null; min: number | null; max: number | null };
  rawFoundCount: number | null;
  rawExpectedCount: number | null;
  duplicateFindings: number | null;
  meanDuplicateFindings: number | null;
  safeControlFindings: number | null;
  meanSafeControlFindings: number | null;
  comparableSafeControlFindings: number | null;
  meanComparableSafeControlFindings: number | null;
  unmatchedFindings: number | null;
  meanUnmatchedFindings: number | null;
  evidenceErrors: number | null;
  meanEvidenceErrors: number | null;
  adjudicationRequiredRuns: number;
  adjudicationRate: number | null;
  meanElapsedMs: number | null;
  meanCompletedElapsedMs: number | null;
  usage: {
    totals: Record<UsageField | "total_tokens", number | null>;
    meanPerRun: Record<UsageField | "total_tokens", number | null>;
    missingUsageRuns: number;
  };
}

export interface ArmComparison {
  baseline: ArmSummary;
  candidate: ArmSummary;
  delta: {
    comparableRecall: number | null;
    rawRecall: number | null;
    successRate: number | null;
    completionRate: number | null;
    meanElapsedMs: number | null;
    meanCompletedElapsedMs: number | null;
    meanDuplicateFindings: number | null;
    meanComparableSafeControlFindings: number | null;
    meanSafeControlFindings: number | null;
    meanUnmatchedFindings: number | null;
    meanEvidenceErrors: number | null;
    meanUsage: Record<UsageField | "total_tokens", number | null>;
  };
  cases: {
    comparable: Array<{
      id: string;
      baseline: CaseRate;
      candidate: CaseRate;
      recallDelta: number | null;
      status: "unchanged" | "improved" | "regressed" | "unmeasured";
    }>;
    added: Array<{ id: string; candidate: CaseRate }>;
    removed: Array<{ id: string; baseline: CaseRate }>;
    changed: Array<{ id: string; baseline: CaseRate; candidate: CaseRate }>;
  };
  controls: Array<{
    id: string;
    baselineAccusedRuns: number;
    candidateAccusedRuns: number;
    baselineFindings: number;
    candidateFindings: number;
  }>;
  flags: {
    regressedCases: string[];
    improvedCases: string[];
    hasRunFailures: boolean;
    hasMissingRuns: boolean;
    hasUnknownUsage: boolean;
    needsAdjudication: boolean;
    corpusChanged: boolean;
    evidenceErrorsIncreased: boolean;
    duplicatesIncreased: boolean;
    comparableControlAccusationsIncreased: boolean;
  };
}

function assertSha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !sha256Pattern.test(value)) {
    throw new Error(
      `${label} must be a lowercase 64-character SHA-256 hex digest.`,
    );
  }
  return value;
}

function normalizeRelativePath(path: string, label: string): string {
  const normalized = posix.normalize(path);
  if (
    !path.trim() ||
    posix.isAbsolute(normalized) ||
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../")
  ) {
    throw new Error(
      `${label} must be a relative path inside the fixture: ${path}`,
    );
  }
  return normalized;
}

function sortRecord<T>(record: Record<string, T>): Record<string, T> {
  return Object.fromEntries(
    Object.entries(record).sort(([a], [b]) => a.localeCompare(b)),
  );
}

export function hashSnapshotMap(files: Record<string, string>): string {
  if (typeof files !== "object" || files === null || Array.isArray(files)) {
    throw new Error("Snapshot map must be an object.");
  }
  const sorted = Object.entries(files)
    .map(([key, digest]) => {
      if (!key.trim()) throw new Error("Snapshot map keys must be non-empty.");
      return [key, assertSha256(digest, `Snapshot digest for ${key}`)] as const;
    })
    .sort(([a], [b]) => a.localeCompare(b));
  return hashText(JSON.stringify(sorted));
}

function normalizeSnapshotMap(
  files: Record<string, string> | undefined,
  label: string,
  normalizeKeys = false,
): Record<string, string> {
  if (typeof files !== "object" || files === null || Array.isArray(files)) {
    throw new Error(`${label} must be an object.`);
  }
  const normalized: Record<string, string> = {};
  for (const [key, digest] of Object.entries(files)) {
    const cleanKey = normalizeKeys
      ? normalizeRelativePath(key, `${label} path`)
      : key;
    if (!cleanKey.trim() || cleanKey in normalized) {
      throw new Error(`${label} has invalid or duplicate key: ${key}`);
    }
    normalized[cleanKey] = assertSha256(
      digest,
      `${label} digest for ${cleanKey}`,
    );
  }
  return sortRecord(normalized);
}

function normalizeUsage(value: unknown): BaselineUsage | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Run usage must be an object or null.");
  }
  const record = value as Record<string, unknown>;
  const result = {} as BaselineUsage;
  for (const field of usageFields) {
    const raw = record[field];
    if (raw === undefined || raw === null) result[field] = null;
    else if (typeof raw === "number" && Number.isFinite(raw) && raw >= 0) {
      result[field] = raw;
    } else {
      throw new Error(
        `Run usage.${field} must be a non-negative finite number or null.`,
      );
    }
  }
  return result;
}

function normalizeCorpus(
  entries: Array<SourceCase & { fileSha256?: string }>,
  kind: "positive" | "control",
  sourceHashes: Record<string, string>,
  requireFileSha256: boolean,
): BaselineCase[] {
  if (!Array.isArray(entries)) {
    throw new Error(`Corpus ${kind} cases must be an array.`);
  }
  if (kind === "positive" && entries.length === 0) {
    throw new Error("Corpus requires at least one positive case.");
  }
  const seen = new Set<string>();
  return entries.map((entry) => {
    if (!entry?.id?.trim() || seen.has(entry.id)) {
      throw new Error(`Invalid or duplicate ${kind} case ID: ${entry?.id}`);
    }
    seen.add(entry.id);
    const path = normalizeRelativePath(entry.path, `Case ${entry.id} path`);
    const fileSha256 = sourceHashes[path];
    if (!fileSha256) {
      throw new Error(
        `Case ${entry.id} references unknown source file ${path}.`,
      );
    }
    if (requireFileSha256 || entry.fileSha256 !== undefined) {
      if (
        assertSha256(entry.fileSha256, `Case ${entry.id} fileSha256`) !==
        fileSha256
      ) {
        throw new Error(
          `Case ${entry.id} fileSha256 does not match source hash.`,
        );
      }
    }
    if (!Number.isSafeInteger(entry.line) || entry.line < 1) {
      throw new Error(
        `Case ${entry.id} requires a positive integer start line.`,
      );
    }
    if (
      entry.endLine !== undefined &&
      (!Number.isSafeInteger(entry.endLine) || entry.endLine < entry.line)
    ) {
      throw new Error(`Case ${entry.id} endLine must be >= line.`);
    }
    const cwes = [
      ...new Set(
        (entry.cwes ?? [])
          .map((cwe) => String(cwe).trim().toUpperCase())
          .filter(Boolean),
      ),
    ];
    if (cwes.length === 0)
      throw new Error(`Case ${entry.id} requires at least one CWE.`);
    return {
      id: entry.id,
      path,
      line: entry.line,
      ...(entry.endLine !== undefined && entry.endLine > entry.line
        ? { endLine: entry.endLine }
        : {}),
      cwes,
      fileSha256,
    };
  });
}

function normalizeRuns(
  rawRuns: Array<RunRecord | BaselineAttempt>,
  pairs: number,
  positives: BaselineCase[],
  controls: BaselineCase[],
  fromSavedRun: boolean,
): BaselineAttempt[] {
  if (!Array.isArray(rawRuns)) throw new Error("Runs must be an array.");
  const controlIds = new Set(controls.map((entry) => entry.id));
  const seen = new Set<string>();
  const normalized = rawRuns.map((record, index): BaselineAttempt => {
    const label = `runs[${index}]`;
    if (record.variant !== "baseline" && record.variant !== "time-aware") {
      throw new Error(`${label}.variant must be "baseline" or "time-aware".`);
    }
    if (
      !Number.isSafeInteger(record.pair) ||
      record.pair < 1 ||
      record.pair > pairs
    ) {
      throw new Error(
        `${label}.pair must be an integer between 1 and ${pairs}.`,
      );
    }
    const key = `${record.pair}/${record.variant}`;
    if (seen.has(key)) throw new Error(`Duplicate run for pair ${key}`);
    seen.add(key);
    if (
      typeof record.elapsedMs !== "number" ||
      !Number.isFinite(record.elapsedMs) ||
      record.elapsedMs < 0
    ) {
      throw new Error(
        `${label}.elapsedMs must be a non-negative finite number.`,
      );
    }
    if (
      typeof record.startedAt !== "string" ||
      !record.startedAt.trim() ||
      (record.advisoryBudgetMinutes !== undefined &&
        record.advisoryBudgetMinutes !== null &&
        (typeof record.advisoryBudgetMinutes !== "number" ||
          !Number.isFinite(record.advisoryBudgetMinutes) ||
          record.advisoryBudgetMinutes <= 0))
    ) {
      throw new Error(
        `${label} has invalid startedAt or advisoryBudgetMinutes.`,
      );
    }
    const base = {
      pair: record.pair,
      variant: record.variant,
      startedAt: record.startedAt,
      advisoryBudgetMinutes: record.advisoryBudgetMinutes ?? null,
      promptSha256:
        record.promptSha256 === null
          ? null
          : assertSha256(record.promptSha256, `${label}.promptSha256`),
      elapsedMs: record.elapsedMs,
      usage: normalizeUsage(record.usage),
    };
    if (record.status === "failed") {
      if (typeof record.error !== "string") {
        throw new Error(`${label}.error must be a string.`);
      }
      return { ...base, status: "failed", error: record.error };
    }
    if (record.status !== "completed" || !record.report) {
      throw new Error(
        `${label} must have status "completed" with report, or "failed".`,
      );
    }
    const report = record.report as RunReport | BaselineCompletedReport;
    const cases: Array<{ id: string; found: boolean }> = report.cases;
    if (
      report.expectedCount !== positives.length ||
      cases.length !== positives.length ||
      !cases.every(
        (entry, i) =>
          entry.id === positives[i]!.id && typeof entry.found === "boolean",
      )
    ) {
      throw new Error(`${label}.report.cases do not match corpus positives.`);
    }
    const expectedMatched = cases
      .filter((entry) => entry.found)
      .map((entry) => entry.id);
    const matchedIds: string[] = report.matchedIds;
    const matchedSet = new Set(matchedIds);
    if (
      matchedSet.size !== expectedMatched.length ||
      matchedIds.length !== expectedMatched.length ||
      !expectedMatched.every((id) => matchedSet.has(id)) ||
      report.foundCount !== expectedMatched.length
    ) {
      throw new Error(
        `${label}.report.matchedIds/foundCount disagree with cases.`,
      );
    }
    const safeControlAccusations = fromSavedRun
      ? (report as RunReport).safeControlDetails.map(
          (detail) => detail.controlIds,
        )
      : (report as BaselineCompletedReport).safeControlAccusations;
    for (const ids of safeControlAccusations) {
      if (
        !Array.isArray(ids) ||
        ids.length === 0 ||
        ids.some((id) => !controlIds.has(id))
      ) {
        throw new Error(`${label}.report references unknown safe-control ID.`);
      }
    }
    if (
      !Number.isSafeInteger(report.duplicateFindings) ||
      report.duplicateFindings < 0 ||
      !Number.isSafeInteger(report.safeControlFindings) ||
      report.safeControlFindings < 0
    ) {
      throw new Error(
        `${label}.report finding counts must be non-negative integers.`,
      );
    }
    if (report.safeControlFindings !== safeControlAccusations.length) {
      throw new Error(
        `${label}.report.safeControlFindings disagrees with accusation list.`,
      );
    }
    const unmatchedFindingsCount = fromSavedRun
      ? (report as RunReport).unmatchedFindings.length
      : (report as BaselineCompletedReport).unmatchedFindingsCount;
    const evidenceErrorsCount = fromSavedRun
      ? (report as RunReport).evidenceErrors.length
      : (report as BaselineCompletedReport).evidenceErrorsCount;
    if (
      !Number.isSafeInteger(unmatchedFindingsCount) ||
      unmatchedFindingsCount < 0 ||
      !Number.isSafeInteger(evidenceErrorsCount) ||
      evidenceErrorsCount < 0
    ) {
      throw new Error(`${label}.report counts must be non-negative integers.`);
    }
    const needsAdjudication =
      Boolean(report.needsAdjudication) ||
      unmatchedFindingsCount > 0 ||
      safeControlAccusations.length > 0;
    if (!fromSavedRun && needsAdjudication && !report.needsAdjudication) {
      throw new Error(
        `${label}.report.needsAdjudication must be true when adjudication is pending.`,
      );
    }
    return {
      ...base,
      status: "completed",
      report: {
        passed: Boolean(report.passed),
        recall: expectedMatched.length / positives.length,
        foundCount: report.foundCount,
        expectedCount: report.expectedCount,
        matchedIds: [...matchedIds],
        cases: cases.map((entry) => ({ id: entry.id, found: entry.found })),
        duplicateFindings: report.duplicateFindings,
        safeControlFindings: report.safeControlFindings,
        safeControlAccusations: safeControlAccusations.map((ids) => [...ids]),
        unmatchedFindingsCount,
        evidenceErrorsCount,
        needsAdjudication,
      },
    };
  });
  return normalized.sort(
    (a, b) =>
      a.pair - b.pair ||
      variants.indexOf(a.variant) - variants.indexOf(b.variant),
  );
}

export function createReleaseBaseline({
  experiment,
  fixture,
  runs,
}: {
  experiment: SavedExperiment;
  fixture: Fixture;
  runs: RunRecord[];
}): ReleaseBaseline {
  const config = validateExperiment(experiment);
  const evaluator = normalizeSnapshotMap(
    experiment.evaluator,
    "experiment.evaluator",
  );
  const source = normalizeSnapshotMap(
    experiment.source,
    "experiment.source",
    true,
  );
  if (!fixture?.files || typeof fixture.files !== "object") {
    throw new Error("fixture.files must be an object.");
  }
  const fixtureFiles: Record<string, string> = {};
  for (const [path, contents] of Object.entries(fixture.files)) {
    const clean = normalizeRelativePath(path, "fixture.files path");
    if (clean in fixtureFiles)
      throw new Error(`Duplicate fixture path: ${clean}`);
    fixtureFiles[clean] = contents;
  }
  const sourceKeys = Object.keys(source);
  const fixtureKeys = Object.keys(fixtureFiles).sort((a, b) =>
    a.localeCompare(b),
  );
  if (
    sourceKeys.length !== fixtureKeys.length ||
    !sourceKeys.every(
      (key, i) =>
        key === fixtureKeys[i] && hashText(fixtureFiles[key]!) === source[key],
    )
  ) {
    throw new Error("experiment.source hashes do not match fixture.files.");
  }
  const positives = normalizeCorpus(
    fixture.positives,
    "positive",
    source,
    false,
  );
  const controls = normalizeCorpus(fixture.controls, "control", source, false);
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    experiment: {
      ...config,
      reasoningEffort: experiment.reasoningEffort ?? null,
      packageVersions: sortRecord(experiment.packageVersions ?? {}),
      digests: {
        fixturesModuleSha256: evaluator["fixtures.mts"] ?? null,
        evaluatorSha256: hashSnapshotMap(evaluator),
        sourceSha256: hashSnapshotMap(source),
        pluginSha256: experiment.plugin
          ? hashSnapshotMap(
              normalizeSnapshotMap(experiment.plugin, "experiment.plugin"),
            )
          : null,
        sdkSha256: experiment.sdk
          ? hashSnapshotMap(
              normalizeSnapshotMap(experiment.sdk, "experiment.sdk"),
            )
          : null,
        codexExecutableSha256: (experiment.codexExecutable?.files ?? []).map(
          (file, i) =>
            assertSha256(file.sha256, `codexExecutable.files[${i}].sha256`),
        ),
      },
      evaluator,
      source,
    },
    corpus: { positives, controls },
    runs: normalizeRuns(runs, config.pairs, positives, controls, true),
  };
}

export function validateReleaseBaseline(value: unknown): ReleaseBaseline {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("ReleaseBaseline must be a JSON object.");
  }
  const candidate = value as ReleaseBaseline;
  if (candidate.schemaVersion !== BASELINE_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported ReleaseBaseline schemaVersion: ${String(candidate.schemaVersion)}.`,
    );
  }
  const config = validateExperiment(candidate.experiment);
  const evaluator = normalizeSnapshotMap(
    candidate.experiment.evaluator,
    "evaluator",
  );
  const source = normalizeSnapshotMap(
    candidate.experiment.source,
    "source",
    true,
  );
  const { digests } = candidate.experiment ?? {};
  if (
    !digests ||
    typeof digests !== "object" ||
    !Array.isArray(digests.codexExecutableSha256) ||
    !candidate.corpus ||
    typeof candidate.corpus !== "object"
  ) {
    throw new Error(
      "ReleaseBaseline is missing required experiment.digests or corpus fields.",
    );
  }
  if (
    digests.fixturesModuleSha256 !== (evaluator["fixtures.mts"] ?? null) ||
    assertSha256(digests.evaluatorSha256, "digests.evaluatorSha256") !==
      hashSnapshotMap(evaluator) ||
    assertSha256(digests.sourceSha256, "digests.sourceSha256") !==
      hashSnapshotMap(source)
  ) {
    throw new Error(
      "ReleaseBaseline digests do not match evaluator/source snapshots.",
    );
  }
  const positives = normalizeCorpus(
    candidate.corpus.positives,
    "positive",
    source,
    true,
  );
  const controls = normalizeCorpus(
    candidate.corpus.controls,
    "control",
    source,
    true,
  );
  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    experiment: {
      ...config,
      reasoningEffort: candidate.experiment.reasoningEffort ?? null,
      packageVersions: sortRecord(candidate.experiment.packageVersions ?? {}),
      digests: {
        fixturesModuleSha256: digests.fixturesModuleSha256,
        evaluatorSha256: digests.evaluatorSha256,
        sourceSha256: digests.sourceSha256,
        pluginSha256:
          digests.pluginSha256 === null
            ? null
            : assertSha256(digests.pluginSha256, "digests.pluginSha256"),
        sdkSha256:
          digests.sdkSha256 === null
            ? null
            : assertSha256(digests.sdkSha256, "digests.sdkSha256"),
        codexExecutableSha256: digests.codexExecutableSha256.map((digest, i) =>
          assertSha256(digest, `digests.codexExecutableSha256[${i}]`),
        ),
      },
      evaluator,
      source,
    },
    corpus: { positives, controls },
    runs: normalizeRuns(
      candidate.runs,
      config.pairs,
      positives,
      controls,
      false,
    ),
  };
}

export async function loadBaseline(
  targetPath: string,
): Promise<ReleaseBaseline> {
  const info = await stat(targetPath);
  if (info.isDirectory()) {
    const [experiment, fixture, runs] = await Promise.all(
      ["experiment.json", "fixture.json", "runs.json"].map(async (file) =>
        JSON.parse(await readFile(join(targetPath, file), "utf8")),
      ),
    );
    return createReleaseBaseline({
      experiment: experiment as SavedExperiment,
      fixture: fixture as Fixture,
      runs: runs as RunRecord[],
    });
  }
  if (info.isFile()) {
    return validateReleaseBaseline(
      JSON.parse(await readFile(targetPath, "utf8")),
    );
  }
  throw new Error(`Unsupported baseline path: ${targetPath}`);
}

function sameCaseDefinition(a: BaselineCase, b: BaselineCase): boolean {
  if (
    a.path !== b.path ||
    a.line !== b.line ||
    (a.endLine ?? a.line) !== (b.endLine ?? b.line) ||
    a.fileSha256 !== b.fileSha256
  ) {
    return false;
  }
  const cwesA = new Set(a.cwes);
  const cwesB = new Set(b.cwes);
  return cwesA.size === cwesB.size && [...cwesA].every((cwe) => cwesB.has(cwe));
}

function diffCases(baseCases: BaselineCase[], candCases: BaselineCase[]) {
  const baseById = new Map(baseCases.map((entry) => [entry.id, entry]));
  const candById = new Map(candCases.map((entry) => [entry.id, entry]));
  const comparable: string[] = [];
  const changed: string[] = [];
  const removed: string[] = [];
  for (const entry of baseCases) {
    const cand = candById.get(entry.id);
    if (!cand) removed.push(entry.id);
    else if (sameCaseDefinition(entry, cand)) comparable.push(entry.id);
    else changed.push(entry.id);
  }
  const added = candCases
    .filter((entry) => !baseById.has(entry.id))
    .map((entry) => entry.id);
  return { comparable, added, removed, changed };
}

function diffSourceFiles(
  baseSource: Record<string, string>,
  candSource: Record<string, string>,
) {
  const unchanged: string[] = [];
  const added: string[] = [];
  const removed: string[] = [];
  const changed: string[] = [];
  const keys = [
    ...new Set([...Object.keys(baseSource), ...Object.keys(candSource)]),
  ].sort((a, b) => a.localeCompare(b));
  for (const key of keys) {
    if (!(key in baseSource)) added.push(key);
    else if (!(key in candSource)) removed.push(key);
    else if (baseSource[key] === candSource[key]) unchanged.push(key);
    else changed.push(key);
  }
  return { unchanged, added, removed, changed };
}

function sumKnown(values: Array<number | null>): number | null {
  return values.length > 0 && values.every((v): v is number => v !== null)
    ? values.reduce((total, v) => total + v, 0)
    : null;
}

function compareRatios(
  baseNum: number | null,
  baseDen: number,
  candNum: number | null,
  candDen: number,
): -1 | 0 | 1 | null {
  if (baseNum === null || candNum === null || baseDen <= 0 || candDen <= 0) {
    return null;
  }
  const left = candNum * baseDen;
  const right = baseNum * candDen;
  return left === right ? 0 : left > right ? 1 : -1;
}

function ratioDelta(
  baseNum: number | null,
  baseDen: number,
  candNum: number | null,
  candDen: number,
): number | null {
  const cmp = compareRatios(baseNum, baseDen, candNum, candDen);
  if (cmp === null) return null;
  return cmp === 0 ? 0 : candNum! / candDen - baseNum! / baseDen;
}

function nullableDelta(
  base: number | null,
  cand: number | null,
): number | null {
  if (base === null || cand === null) return null;
  return cand === base ? 0 : cand - base;
}

function mean(values: number[]): number | null {
  return values.length > 0
    ? values.reduce((total, value) => total + value, 0) / values.length
    : null;
}

function summarizeArm(
  baseline: ReleaseBaseline,
  variant: Variant,
  comparablePositiveIds: string[],
  comparableControlIds: string[],
): {
  summary: ArmSummary;
  completedRuns: Array<Extract<BaselineAttempt, { status: "completed" }>>;
} {
  const configured = baseline.experiment.pairs;
  const attempts = baseline.runs.filter((run) => run.variant === variant);
  const completedRuns = attempts.filter(
    (run): run is Extract<BaselineAttempt, { status: "completed" }> =>
      run.status === "completed",
  );
  const failedRuns = attempts.filter(
    (run): run is Extract<BaselineAttempt, { status: "failed" }> =>
      run.status === "failed",
  );
  const completed = completedRuns.length;
  const comparableSet = new Set(comparablePositiveIds);
  const comparableControlSet = new Set(comparableControlIds);

  const rawRecalls = completedRuns.map((run) => run.report.recall);
  const rawFoundCount =
    completed > 0
      ? completedRuns.reduce((s, r) => s + r.report.foundCount, 0)
      : null;
  const rawExpectedCount =
    completed > 0
      ? completedRuns.reduce((s, r) => s + r.report.expectedCount, 0)
      : null;

  let comparableFoundCount: number | null = null;
  let comparableExpectedCount: number | null = null;
  let comparableRecall: ArmSummary["comparableRecall"] = {
    mean: null,
    min: null,
    max: null,
  };
  if (completed > 0 && comparablePositiveIds.length > 0) {
    const perRunFound = completedRuns.map(
      (run) =>
        run.report.cases.filter((c) => c.found && comparableSet.has(c.id))
          .length,
    );
    const perRunRecalls = perRunFound.map(
      (n) => n / comparablePositiveIds.length,
    );
    comparableFoundCount = perRunFound.reduce((s, n) => s + n, 0);
    comparableExpectedCount = completed * comparablePositiveIds.length;
    comparableRecall = {
      mean: comparableFoundCount / comparableExpectedCount,
      min: Math.min(...perRunRecalls),
      max: Math.max(...perRunRecalls),
    };
  }

  const countCompleted = (fn: (r: BaselineCompletedReport) => number) =>
    completed > 0
      ? completedRuns.reduce((s, run) => s + fn(run.report), 0)
      : null;
  const meanCompleted = (total: number | null) =>
    total !== null && completed > 0 ? total / completed : null;

  const duplicateFindings = countCompleted((r) => r.duplicateFindings);
  const safeControlFindings = countCompleted((r) => r.safeControlFindings);
  const comparableSafeControlFindings =
    completed > 0 && comparableControlIds.length > 0
      ? completedRuns.reduce(
          (sum, run) =>
            sum +
            run.report.safeControlAccusations.filter((ids) =>
              ids.some((id) => comparableControlSet.has(id)),
            ).length,
          0,
        )
      : null;
  const unmatchedFindings = countCompleted((r) => r.unmatchedFindingsCount);
  const evidenceErrors = countCompleted((r) => r.evidenceErrorsCount);
  const adjudicationRequiredRuns = completedRuns.filter(
    (run) => run.report.needsAdjudication,
  ).length;

  const totalTokensFor = (run: BaselineAttempt) => {
    const input = run.usage?.input_tokens ?? null;
    const output = run.usage?.output_tokens ?? null;
    return input === null || output === null ? null : input + output;
  };
  const totals = {
    input_tokens: sumKnown(attempts.map((r) => r.usage?.input_tokens ?? null)),
    cached_input_tokens: sumKnown(
      attempts.map((r) => r.usage?.cached_input_tokens ?? null),
    ),
    output_tokens: sumKnown(
      attempts.map((r) => r.usage?.output_tokens ?? null),
    ),
    total_tokens: sumKnown(attempts.map(totalTokensFor)),
  };
  const meanPerRun = Object.fromEntries(
    Object.entries(totals).map(([k, v]) => [
      k,
      v !== null && attempts.length > 0 ? v / attempts.length : null,
    ]),
  ) as Record<UsageField | "total_tokens", number | null>;

  return {
    completedRuns,
    summary: {
      configured,
      attempted: attempts.length,
      completed,
      failed: failedRuns.length,
      missing: Math.max(0, configured - attempts.length),
      successRate: attempts.length > 0 ? completed / attempts.length : null,
      completionRate: configured > 0 ? completed / configured : null,
      failures: failedRuns.map((run) => ({ pair: run.pair, error: run.error })),
      comparableRecall,
      comparableFoundCount,
      comparableExpectedCount,
      rawRecall: {
        mean: mean(rawRecalls),
        min: rawRecalls.length > 0 ? Math.min(...rawRecalls) : null,
        max: rawRecalls.length > 0 ? Math.max(...rawRecalls) : null,
      },
      rawFoundCount,
      rawExpectedCount,
      duplicateFindings,
      meanDuplicateFindings: meanCompleted(duplicateFindings),
      safeControlFindings,
      meanSafeControlFindings: meanCompleted(safeControlFindings),
      comparableSafeControlFindings,
      meanComparableSafeControlFindings: meanCompleted(
        comparableSafeControlFindings,
      ),
      unmatchedFindings,
      meanUnmatchedFindings: meanCompleted(unmatchedFindings),
      evidenceErrors,
      meanEvidenceErrors: meanCompleted(evidenceErrors),
      adjudicationRequiredRuns,
      adjudicationRate:
        completed > 0 ? adjudicationRequiredRuns / completed : null,
      meanElapsedMs: mean(attempts.map((r) => r.elapsedMs)),
      meanCompletedElapsedMs: mean(completedRuns.map((r) => r.elapsedMs)),
      usage: {
        totals,
        meanPerRun,
        missingUsageRuns: attempts.filter((r) =>
          usageFields.some((field) => (r.usage?.[field] ?? null) === null),
        ).length,
      },
    },
  };
}

function caseRate(
  completedRuns: Array<Extract<BaselineAttempt, { status: "completed" }>>,
  caseId: string,
): CaseRate {
  const completedRunsCount = completedRuns.length;
  const foundRuns = completedRuns.filter((run) =>
    run.report.cases.some((entry) => entry.id === caseId && entry.found),
  ).length;
  return {
    foundRuns,
    completedRuns: completedRunsCount,
    recall: completedRunsCount > 0 ? foundRuns / completedRunsCount : null,
  };
}

function compareArm(
  baseline: ReleaseBaseline,
  candidate: ReleaseBaseline,
  variant: Variant,
  corpus: {
    positives: ReturnType<typeof diffCases>;
    controls: ReturnType<typeof diffCases>;
    sourceFiles: ReturnType<typeof diffSourceFiles>;
  },
  fixtureIdentical: boolean,
): ArmComparison {
  const baseArm = summarizeArm(
    baseline,
    variant,
    corpus.positives.comparable,
    corpus.controls.comparable,
  );
  const candArm = summarizeArm(
    candidate,
    variant,
    corpus.positives.comparable,
    corpus.controls.comparable,
  );
  const base = baseArm.summary;
  const cand = candArm.summary;
  const perCompletedDelta = (b: number | null, c: number | null) =>
    ratioDelta(b, base.completed, c, cand.completed);
  const increasedPerCompleted = (b: number | null, c: number | null) =>
    compareRatios(b, base.completed, c, cand.completed) === 1;

  const comparableCases = corpus.positives.comparable.map((id) => {
    const baseRate = caseRate(baseArm.completedRuns, id);
    const candRate = caseRate(candArm.completedRuns, id);
    const recallDelta = ratioDelta(
      baseRate.foundRuns,
      baseRate.completedRuns,
      candRate.foundRuns,
      candRate.completedRuns,
    );
    const cmp = compareRatios(
      baseRate.foundRuns,
      baseRate.completedRuns,
      candRate.foundRuns,
      candRate.completedRuns,
    );
    const status =
      cmp === null
        ? "unmeasured"
        : cmp > 0
          ? "improved"
          : cmp < 0
            ? "regressed"
            : "unchanged";
    return {
      id,
      baseline: baseRate,
      candidate: candRate,
      recallDelta,
      status,
    } as const;
  });

  const controls = corpus.controls.comparable.map((id) => {
    const count = (runs: typeof baseArm.completedRuns) => ({
      accusedRuns: runs.filter((r) =>
        r.report.safeControlAccusations.some((ids) => ids.includes(id)),
      ).length,
      findings: runs.reduce(
        (s, r) =>
          s +
          r.report.safeControlAccusations.filter((ids) => ids.includes(id))
            .length,
        0,
      ),
    });
    const b = count(baseArm.completedRuns);
    const c = count(candArm.completedRuns);
    return {
      id,
      baselineAccusedRuns: b.accusedRuns,
      candidateAccusedRuns: c.accusedRuns,
      baselineFindings: b.findings,
      candidateFindings: c.findings,
    };
  });

  return {
    baseline: base,
    candidate: cand,
    delta: {
      comparableRecall: ratioDelta(
        base.comparableFoundCount,
        base.comparableExpectedCount ?? 0,
        cand.comparableFoundCount,
        cand.comparableExpectedCount ?? 0,
      ),
      rawRecall: ratioDelta(
        base.rawFoundCount,
        base.rawExpectedCount ?? 0,
        cand.rawFoundCount,
        cand.rawExpectedCount ?? 0,
      ),
      successRate: ratioDelta(
        base.completed,
        base.attempted,
        cand.completed,
        cand.attempted,
      ),
      completionRate: ratioDelta(
        base.completed,
        base.configured,
        cand.completed,
        cand.configured,
      ),
      meanElapsedMs: nullableDelta(base.meanElapsedMs, cand.meanElapsedMs),
      meanCompletedElapsedMs: nullableDelta(
        base.meanCompletedElapsedMs,
        cand.meanCompletedElapsedMs,
      ),
      meanDuplicateFindings: perCompletedDelta(
        base.duplicateFindings,
        cand.duplicateFindings,
      ),
      meanComparableSafeControlFindings:
        corpus.controls.comparable.length > 0
          ? perCompletedDelta(
              base.comparableSafeControlFindings,
              cand.comparableSafeControlFindings,
            )
          : null,
      meanSafeControlFindings: perCompletedDelta(
        base.safeControlFindings,
        cand.safeControlFindings,
      ),
      meanUnmatchedFindings: perCompletedDelta(
        base.unmatchedFindings,
        cand.unmatchedFindings,
      ),
      meanEvidenceErrors: perCompletedDelta(
        base.evidenceErrors,
        cand.evidenceErrors,
      ),
      meanUsage: Object.fromEntries(
        (
          [
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "total_tokens",
          ] as const
        ).map((field) => [
          field,
          nullableDelta(
            base.usage.meanPerRun[field],
            cand.usage.meanPerRun[field],
          ),
        ]),
      ) as Record<UsageField | "total_tokens", number | null>,
    },
    cases: {
      comparable: comparableCases,
      added: corpus.positives.added.map((id) => ({
        id,
        candidate: caseRate(candArm.completedRuns, id),
      })),
      removed: corpus.positives.removed.map((id) => ({
        id,
        baseline: caseRate(baseArm.completedRuns, id),
      })),
      changed: corpus.positives.changed.map((id) => ({
        id,
        baseline: caseRate(baseArm.completedRuns, id),
        candidate: caseRate(candArm.completedRuns, id),
      })),
    },
    controls,
    flags: {
      regressedCases: comparableCases
        .filter((entry) => entry.status === "regressed")
        .map((entry) => entry.id),
      improvedCases: comparableCases
        .filter((entry) => entry.status === "improved")
        .map((entry) => entry.id),
      hasRunFailures: base.failed > 0 || cand.failed > 0,
      hasMissingRuns: base.missing > 0 || cand.missing > 0,
      hasUnknownUsage:
        base.usage.missingUsageRuns > 0 || cand.usage.missingUsageRuns > 0,
      needsAdjudication:
        base.adjudicationRequiredRuns > 0 || cand.adjudicationRequiredRuns > 0,
      corpusChanged: !fixtureIdentical,
      evidenceErrorsIncreased: increasedPerCompleted(
        base.evidenceErrors,
        cand.evidenceErrors,
      ),
      duplicatesIncreased: increasedPerCompleted(
        base.duplicateFindings,
        cand.duplicateFindings,
      ),
      comparableControlAccusationsIncreased:
        corpus.controls.comparable.length > 0 &&
        increasedPerCompleted(
          base.comparableSafeControlFindings,
          cand.comparableSafeControlFindings,
        ),
    },
  };
}

function fieldDiff<T>(
  baseline: T,
  candidate: T,
  equals: (a: T, b: T) => boolean = (a, b) => a === b,
) {
  return { baseline, candidate, changed: !equals(baseline, candidate) };
}

export function compareBaselines(
  baselineInput: ReleaseBaseline,
  candidateInput: ReleaseBaseline,
) {
  const baseline = validateReleaseBaseline(baselineInput);
  const candidate = validateReleaseBaseline(candidateInput);
  const positives = diffCases(
    baseline.corpus.positives,
    candidate.corpus.positives,
  );
  const controls = diffCases(
    baseline.corpus.controls,
    candidate.corpus.controls,
  );
  const sourceFiles = diffSourceFiles(
    baseline.experiment.source,
    candidate.experiment.source,
  );
  const corpus = { positives, controls, sourceFiles };
  const fixtureIdentical =
    baseline.experiment.digests.sourceSha256 ===
      candidate.experiment.digests.sourceSha256 &&
    [
      positives.added,
      positives.removed,
      positives.changed,
      controls.added,
      controls.removed,
      controls.changed,
      sourceFiles.added,
      sourceFiles.removed,
      sourceFiles.changed,
    ].every((list) => list.length === 0);

  const packageKeys = [
    ...new Set([
      ...Object.keys(baseline.experiment.packageVersions),
      ...Object.keys(candidate.experiment.packageVersions),
    ]),
  ].sort((a, b) => a.localeCompare(b));

  return {
    schemaVersion: BASELINE_SCHEMA_VERSION,
    provenance: {
      fixtureIdentical,
      model: fieldDiff(baseline.experiment.model, candidate.experiment.model),
      reasoningEffort: fieldDiff(
        baseline.experiment.reasoningEffort,
        candidate.experiment.reasoningEffort,
      ),
      pairs: fieldDiff(baseline.experiment.pairs, candidate.experiment.pairs),
      budgetMinutes: fieldDiff(
        baseline.experiment.budgetMinutes,
        candidate.experiment.budgetMinutes,
      ),
      packageVersions: Object.fromEntries(
        packageKeys.map((name) => [
          name,
          fieldDiff(
            baseline.experiment.packageVersions[name] ?? null,
            candidate.experiment.packageVersions[name] ?? null,
          ),
        ]),
      ),
      digests: {
        fixturesModuleSha256: fieldDiff(
          baseline.experiment.digests.fixturesModuleSha256,
          candidate.experiment.digests.fixturesModuleSha256,
        ),
        evaluatorSha256: fieldDiff(
          baseline.experiment.digests.evaluatorSha256,
          candidate.experiment.digests.evaluatorSha256,
        ),
        sourceSha256: fieldDiff(
          baseline.experiment.digests.sourceSha256,
          candidate.experiment.digests.sourceSha256,
        ),
        pluginSha256: fieldDiff(
          baseline.experiment.digests.pluginSha256,
          candidate.experiment.digests.pluginSha256,
        ),
        sdkSha256: fieldDiff(
          baseline.experiment.digests.sdkSha256,
          candidate.experiment.digests.sdkSha256,
        ),
        codexExecutableSha256: fieldDiff(
          baseline.experiment.digests.codexExecutableSha256,
          candidate.experiment.digests.codexExecutableSha256,
          (a, b) => a.length === b.length && a.every((v, i) => v === b[i]),
        ),
      },
    },
    corpus,
    arms: {
      baseline: compareArm(
        baseline,
        candidate,
        "baseline",
        corpus,
        fixtureIdentical,
      ),
      "time-aware": compareArm(
        baseline,
        candidate,
        "time-aware",
        corpus,
        fixtureIdentical,
      ),
    },
  };
}

export type BaselineComparison = ReturnType<typeof compareBaselines>;

async function main(argv: string[]) {
  const [command, ...args] = argv;
  if (command === "export" && (args.length === 1 || args.length === 2)) {
    const [sourcePath, outputPath] = args;
    const formatted =
      JSON.stringify(await loadBaseline(sourcePath!), null, 2) + "\n";
    if (outputPath !== undefined)
      await writeFile(outputPath, formatted, "utf8");
    else process.stdout.write(formatted);
    return;
  }
  if (command === "compare" && (args.length === 2 || args.length === 3)) {
    const [baselinePath, candidatePath, outputPath] = args;
    const [baseline, candidate] = await Promise.all([
      loadBaseline(baselinePath!),
      loadBaseline(candidatePath!),
    ]);
    const formatted =
      JSON.stringify(compareBaselines(baseline, candidate), null, 2) + "\n";
    if (outputPath !== undefined)
      await writeFile(outputPath, formatted, "utf8");
    else process.stdout.write(formatted);
    return;
  }
  process.stderr.write(
    "Usage:\n  baseline.mts export <run-dir> [output.json]\n  baseline.mts compare <baseline-path> <candidate-path> [output.json]\n",
  );
  process.exitCode = 1;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  await main(process.argv.slice(2));
}

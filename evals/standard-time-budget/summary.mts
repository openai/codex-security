import type {
  CompletedRunRecord,
  RunRecord,
  RunReport,
  Variant,
} from "./experiment.mts";

const variants = ["baseline", "time-aware"] as const;
const usageFields = [
  "input_tokens",
  "cached_input_tokens",
  "output_tokens",
] as const;
type UsageField = (typeof usageFields)[number];

function mean(values: number[]) {
  return values.length
    ? values.reduce((total, value) => total + value, 0) / values.length
    : null;
}

function usageValue(record: RunRecord, field: UsageField) {
  const usage = record.usage as Partial<Record<UsageField, number>> | undefined;
  const value = usage?.[field];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function totalTokens(record: RunRecord) {
  const input = usageValue(record, "input_tokens");
  const output = usageValue(record, "output_tokens");
  return input === null || output === null ? null : input + output;
}

function sumKnown(values: (number | null)[]) {
  return values.length &&
    values.every((value): value is number => value !== null)
    ? values.reduce((total, value) => total + value, 0)
    : null;
}

function summarizeArm(records: RunRecord[]) {
  const completed = records.filter(
    (record): record is CompletedRunRecord => record.status === "completed",
  );
  const qualityCount = (getValue: (report: RunReport) => number) =>
    completed.length
      ? completed.reduce((total, record) => total + getValue(record.report), 0)
      : null;
  return {
    attempted: records.length,
    completed: completed.length,
    failed: records.length - completed.length,
    successRate: records.length ? completed.length / records.length : null,
    meanElapsedMs: mean(records.map((record) => record.elapsedMs)),
    meanRecall: mean(completed.map((record) => record.report.recall)),
    foundCount: qualityCount((report) => report.foundCount),
    expectedCount: qualityCount((report) => report.expectedCount),
    safeControlFindings: qualityCount((report) => report.safeControlFindings),
    unmatchedFindings: qualityCount(
      (report) => report.unmatchedFindings.length,
    ),
    evidenceErrors: qualityCount((report) => report.evidenceErrors.length),
    usage: {
      ...(Object.fromEntries(
        usageFields.map((field) => [
          field,
          sumKnown(records.map((record) => usageValue(record, field))),
        ]),
      ) as Record<UsageField, number | null>),
      total_tokens: sumKnown(records.map(totalTokens)),
      missingUsageRuns: records.filter((record) =>
        usageFields.some((field) => usageValue(record, field) === null),
      ).length,
    },
  };
}

export function summarizeRuns(records: RunRecord[]) {
  const pairs = new Map<number, Partial<Record<Variant, RunRecord>>>();
  for (const record of records) {
    const variant = record.variant;
    const pair = pairs.get(record.pair) ?? {};
    if (pair[variant]) {
      throw new Error(
        `Duplicate run for pair ${record.pair}/${record.variant}`,
      );
    }
    pair[variant] = record;
    pairs.set(record.pair, pair);
  }
  const completedPairs = [...pairs.values()].filter(
    (pair): pair is Record<Variant, CompletedRunRecord> =>
      variants.every((variant) => pair[variant]?.status === "completed"),
  );
  const meanDelta = (
    getValue: (record: CompletedRunRecord) => number | null,
  ) => {
    const deltas = completedPairs.map((pair) => {
      const baseline = getValue(pair.baseline);
      const timeAware = getValue(pair["time-aware"]);
      return baseline === null || timeAware === null
        ? null
        : timeAware - baseline;
    });
    return deltas.every((delta): delta is number => delta !== null)
      ? mean(deltas)
      : null;
  };
  return {
    arms: Object.fromEntries(
      variants.map((variant) => [
        variant,
        summarizeArm(records.filter((record) => record.variant === variant)),
      ]),
    ),
    paired: {
      totalPairs: pairs.size,
      completedPairs: completedPairs.length,
      excludedPairs: pairs.size - completedPairs.length,
      meanDelta: {
        recall: meanDelta((record) => record.report.recall),
        elapsedMs: meanDelta((record) => record.elapsedMs),
        foundCount: meanDelta((record) => record.report.foundCount),
        safeControlFindings: meanDelta(
          (record) => record.report.safeControlFindings,
        ),
        unmatchedFindings: meanDelta(
          (record) => record.report.unmatchedFindings.length,
        ),
        evidenceErrors: meanDelta(
          (record) => record.report.evidenceErrors.length,
        ),
        ...(Object.fromEntries(
          usageFields.map((field) => [
            field,
            meanDelta((record) => usageValue(record, field)),
          ]),
        ) as Record<UsageField, number | null>),
        total_tokens: meanDelta(totalTokens),
      },
    },
  };
}

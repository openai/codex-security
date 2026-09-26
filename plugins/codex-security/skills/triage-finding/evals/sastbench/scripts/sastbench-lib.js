#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const SASTBENCH_ROOT = path.resolve(__dirname, "..");
const EVAL_ROOT = path.resolve(SASTBENCH_ROOT, "..");
const SASTBENCH_REPOSITORY_URL = "https://github.com/RivalSecurity/sastbench.git";
const SASTBENCH_COMMIT = "b8d95b7720491b21d039b7504999577ba7ebb12b";
const SASTBENCH_DATASET_RELATIVE_PATH = path.join("data", "sastbench-v0.1-original.json");
const SASTBENCH_DATASET_SHA256 =
  "57c765633bdefc2130d3725dd9648bc49b85456e4dd733c55f49d44d883c9487";
const EXPECTED_CASE_COUNT = 2737;
const EXPECTED_LABEL_COUNTS = Object.freeze({
  true_positive: 299,
  false_positive: 2438,
});
const REPRESENTATIVE_SAMPLE_SPEC = Object.freeze({
  profile: "representative-100-v1",
  seed: "sastbench-representative-v1",
  labelCounts: Object.freeze({
    true_positive: 40,
    false_positive: 60,
  }),
});
const DEFAULT_INSTALL_ROOT = path.join(EVAL_ROOT, "artifacts", "sastbench");
const DEFAULT_DATASET_PATH = path.join(DEFAULT_INSTALL_ROOT, SASTBENCH_DATASET_RELATIVE_PATH);
const DEFAULT_TARGET_ROOT = path.join(EVAL_ROOT, "artifacts", "sastbench-targets");
const ALLOWED_LABELS = new Set(Object.keys(EXPECTED_LABEL_COUNTS));
const REQUIRED_ANALYZER_FIELDS = [
  "vulnerability_type",
  "vulnerability_name",
  "description",
  "locations",
  "commit_context",
];

function sha256Text(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(filename) {
  return sha256Text(fs.readFileSync(filename));
}

function loadDataset(filename = DEFAULT_DATASET_PATH, expectations) {
  const records = JSON.parse(fs.readFileSync(filename, "utf8"));
  validateDataset(records, expectations);
  return records;
}

function requireNonEmptyString(value, field, index) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`SastBench case ${index} requires non-empty ${field}`);
  }
}

function requireString(value, field, index) {
  if (typeof value !== "string") {
    throw new Error(`SastBench case ${index} requires string ${field}`);
  }
}

function validateLocation(location, caseIndex, locationIndex) {
  if (!location || typeof location !== "object" || Array.isArray(location)) {
    throw new Error(`SastBench case ${caseIndex} location ${locationIndex} must be an object`);
  }
  requireNonEmptyString(location.file, `locations[${locationIndex}].file`, caseIndex);
  // SastBench preserves scanner-native locations. One finding uses line 0 to
  // mean file-level scope, and some zero-width findings encode end = start - 1.
  if (!Number.isInteger(location.line_start) || location.line_start < 0) {
    throw new Error(`SastBench case ${caseIndex} location ${locationIndex} requires line_start`);
  }
  if (!Number.isInteger(location.line_end) || location.line_end < 0) {
    throw new Error(`SastBench case ${caseIndex} location ${locationIndex} requires line_end`);
  }
}

function validateRecord(record, index) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(`SastBench case ${index} must be an object`);
  }
  requireNonEmptyString(record.repo_name, "repo_name", index);
  requireNonEmptyString(record.repo_url, "repo_url", index);
  requireNonEmptyString(record.commit_hash, "commit_hash", index);
  if (!/^[a-f0-9]{40}$/i.test(record.commit_hash)) {
    throw new Error(`SastBench case ${index} commit_hash must be a 40-character Git SHA`);
  }
  if (!ALLOWED_LABELS.has(record.ground_truth)) {
    throw new Error(`SastBench case ${index} has unsupported ground_truth: ${record.ground_truth}`);
  }
  if (!record.to_analyzer || typeof record.to_analyzer !== "object") {
    throw new Error(`SastBench case ${index} requires to_analyzer`);
  }
  for (const field of REQUIRED_ANALYZER_FIELDS) {
    if (!(field in record.to_analyzer)) {
      throw new Error(`SastBench case ${index} requires to_analyzer.${field}`);
    }
  }
  requireNonEmptyString(
    record.to_analyzer.vulnerability_type,
    "to_analyzer.vulnerability_type",
    index,
  );
  for (const field of ["vulnerability_name", "description"]) {
    requireString(record.to_analyzer[field], `to_analyzer.${field}`, index);
  }
  if (!Array.isArray(record.to_analyzer.locations) || record.to_analyzer.locations.length === 0) {
    throw new Error(`SastBench case ${index} requires at least one to_analyzer location`);
  }
  record.to_analyzer.locations.forEach((location, locationIndex) =>
    validateLocation(location, index, locationIndex),
  );
  const context = record.to_analyzer.commit_context;
  if (!context || typeof context !== "object") {
    throw new Error(`SastBench case ${index} requires to_analyzer.commit_context`);
  }
  if (context.commit !== record.commit_hash) {
    throw new Error(`SastBench case ${index} commit_context.commit does not match commit_hash`);
  }
}

function validateDataset(
  records,
  expectations = {
    caseCount: EXPECTED_CASE_COUNT,
    labelCounts: EXPECTED_LABEL_COUNTS,
  },
) {
  if (!Array.isArray(records)) {
    throw new Error("SastBench dataset must be a JSON array");
  }
  records.forEach(validateRecord);
  const counts = { true_positive: 0, false_positive: 0 };
  for (const record of records) {
    counts[record.ground_truth] += 1;
  }
  if (records.length !== expectations.caseCount) {
    throw new Error(
      `SastBench dataset case count mismatch: expected ${expectations.caseCount}, got ${records.length}`,
    );
  }
  for (const label of ALLOWED_LABELS) {
    if (counts[label] !== expectations.labelCounts[label]) {
      throw new Error(
        `SastBench ${label} count mismatch: expected ${expectations.labelCounts[label]}, got ${counts[label]}`,
      );
    }
  }
  return { caseCount: records.length, labelCounts: counts };
}

function opaqueCaseId(index) {
  if (!Number.isInteger(index) || index < 0) {
    throw new Error("SastBench case index must be a non-negative integer");
  }
  return `sastbench-${String(index).padStart(6, "0")}`;
}

function repositoryStateId(record) {
  return `state-${sha256Text(`${record.repo_url}\0${record.commit_hash}`).slice(0, 16)}`;
}

function buildStateJobs(records, targetRoot = DEFAULT_TARGET_ROOT) {
  const jobsByKey = new Map();
  records.forEach((record, index) => {
    const key = `${record.repo_url}\0${record.commit_hash}`;
    const existing = jobsByKey.get(key);
    const caseEntry = { index, caseId: opaqueCaseId(index), groundTruth: record.ground_truth };
    if (existing) {
      existing.cases.push(caseEntry);
      return;
    }
    const stateId = repositoryStateId(record);
    jobsByKey.set(key, {
      stateId,
      repoName: record.repo_name,
      repoUrl: record.repo_url,
      commitHash: record.commit_hash,
      targetDir: path.join(path.resolve(targetRoot), stateId),
      cases: [caseEntry],
    });
  });
  return [...jobsByKey.values()];
}

function formatLocation(location) {
  const functionName = location.function ? ` (${location.function})` : "";
  return `${location.file}:${location.line_start}-${location.line_end}${functionName}`;
}

function buildFindingInput(record, caseId) {
  const analyzer = record.to_analyzer;
  const locations = analyzer.locations.map((location) => `   - ${formatLocation(location)}`);
  const title = [analyzer.vulnerability_type, analyzer.vulnerability_name]
    .filter((part) => part.trim().length > 0)
    .join(" ");
  const findingLines = [
    "Source type: scanner_ticket",
    `1. input_id: ${caseId}`,
    `   title: ${title}`,
    `   weakness: ${analyzer.vulnerability_type}`,
  ];
  if (analyzer.description.trim().length > 0) {
    findingLines.push(`   claim: ${analyzer.description}`);
  }
  findingLines.push(
    `   repository: ${analyzer.commit_context.repo}`,
    `   repository revision: ${analyzer.commit_context.commit}`,
    "   scanner locations:",
    ...locations,
  );
  return findingLines.join("\n");
}

function buildPromptVars(record, index, targetRoot = DEFAULT_TARGET_ROOT) {
  const caseId = opaqueCaseId(index);
  return {
    case_id: caseId,
    target_repo: path.join(path.resolve(targetRoot), repositoryStateId(record)),
    finding_input: buildFindingInput(record, caseId),
  };
}

function buildPromptfooTest(record, index, targetRoot, metadata = {}) {
  const vars = buildPromptVars(record, index, targetRoot);
  return {
    description: `SastBench case ${vars.case_id}`,
    metadata: {
      case_id: vars.case_id,
      ground_truth: record.ground_truth,
      ...metadata,
    },
    vars,
  };
}

function generatePromptfooTests(records, targetRoot = DEFAULT_TARGET_ROOT) {
  return records.map((record, index) => buildPromptfooTest(record, index, targetRoot));
}

function evidenceSizeBucket(record) {
  const locationCount = record.to_analyzer.locations.length;
  if (locationCount === 1) {
    return "1";
  }
  if (locationCount <= 3) {
    return "2-3";
  }
  if (locationCount <= 10) {
    return "4-10";
  }
  return "11+";
}

function allocateSampleCounts(strata, sampleCount) {
  if (sampleCount < strata.length) {
    throw new Error(
      `Representative sample count ${sampleCount} cannot cover ${strata.length} evidence strata`,
    );
  }
  const populationCount = strata.reduce((total, stratum) => total + stratum.entries.length, 0);
  const allocations = new Map(strata.map((stratum) => [stratum.name, 1]));
  let remaining = sampleCount - strata.length;

  while (remaining > 0) {
    const candidates = strata
      .filter((stratum) => allocations.get(stratum.name) < stratum.entries.length)
      .map((stratum) => ({
        stratum,
        deficit:
          (stratum.entries.length * sampleCount) / populationCount -
          allocations.get(stratum.name),
      }))
      .sort(
        (left, right) =>
          right.deficit - left.deficit || left.stratum.name.localeCompare(right.stratum.name),
      );
    if (candidates.length === 0) {
      throw new Error(`Representative sample count ${sampleCount} exceeds the population`);
    }
    const selectedName = candidates[0].stratum.name;
    allocations.set(selectedName, allocations.get(selectedName) + 1);
    remaining -= 1;
  }
  return allocations;
}

function representativeSortKey(entry) {
  const record = entry.record;
  return [
    record.repo_name,
    record.metadata.cwe_id,
    (record.metadata.languages || []).slice().sort().join(","),
    record.to_analyzer.locations[0].file,
    String(entry.index).padStart(6, "0"),
  ].join("\0");
}

function deterministicSystematicSample(entries, sampleCount, seed, stratumName) {
  if (sampleCount === entries.length) {
    return [...entries];
  }
  const sortedEntries = [...entries].sort((left, right) =>
    representativeSortKey(left).localeCompare(representativeSortKey(right)),
  );
  const interval = sortedEntries.length / sampleCount;
  const seedValue = crypto
    .createHash("sha256")
    .update(`${seed}\0${stratumName}`)
    .digest()
    .readUInt32BE(0);
  const start = (seedValue / 2 ** 32) * interval;
  return Array.from(
    { length: sampleCount },
    (_, sampleIndex) => sortedEntries[Math.floor(start + sampleIndex * interval)],
  );
}

/**
 * Select a deterministic, ground-truth-stratified sample. Evidence-size strata
 * preserve the benchmark's mix of small and large scanner tickets, while
 * systematic selection over repository/CWE/language ordering spreads each
 * stratum across the benchmark's main metadata dimensions.
 */
function selectRepresentativeSample(records, sampleSpec = REPRESENTATIVE_SAMPLE_SPEC) {
  requireNonEmptyString(sampleSpec.profile, "sample profile", "sample");
  requireNonEmptyString(sampleSpec.seed, "sample seed", "sample");
  const selectedEntries = [];

  for (const label of ALLOWED_LABELS) {
    const requestedCount = sampleSpec.labelCounts[label];
    if (!Number.isInteger(requestedCount) || requestedCount <= 0) {
      throw new Error(`Representative sample requires a positive integer count for ${label}`);
    }
    const labelEntries = records
      .map((record, index) => ({ record, index }))
      .filter((entry) => entry.record.ground_truth === label);
    if (requestedCount > labelEntries.length) {
      throw new Error(
        `Representative sample requests ${requestedCount} ${label} cases from ${labelEntries.length}`,
      );
    }
    const entriesByBucket = new Map();
    for (const entry of labelEntries) {
      const bucket = evidenceSizeBucket(entry.record);
      const existing = entriesByBucket.get(bucket) || [];
      existing.push(entry);
      entriesByBucket.set(bucket, existing);
    }
    const strata = [...entriesByBucket.entries()]
      .map(([bucket, entries]) => ({ name: `${label}:${bucket}`, entries }))
      .sort((left, right) => left.name.localeCompare(right.name));
    const allocations = allocateSampleCounts(strata, requestedCount);

    for (const stratum of strata) {
      const stratumSampleCount = allocations.get(stratum.name);
      const sampleWeight = stratum.entries.length / stratumSampleCount;
      for (const entry of deterministicSystematicSample(
        stratum.entries,
        stratumSampleCount,
        sampleSpec.seed,
        stratum.name,
      )) {
        selectedEntries.push({
          ...entry,
          sampleStratum: stratum.name,
          sampleWeight,
        });
      }
    }
  }

  return selectedEntries.sort((left, right) => left.index - right.index);
}

function generateRepresentativeSampleTests(
  records,
  targetRoot = DEFAULT_TARGET_ROOT,
  sampleSpec = REPRESENTATIVE_SAMPLE_SPEC,
) {
  return selectRepresentativeSample(records, sampleSpec).map((entry) =>
    buildPromptfooTest(entry.record, entry.index, targetRoot, {
      sample_profile: sampleSpec.profile,
      sample_stratum: entry.sampleStratum,
      sample_weight: entry.sampleWeight,
    }),
  );
}

module.exports = {
  SASTBENCH_ROOT,
  EVAL_ROOT,
  SASTBENCH_REPOSITORY_URL,
  SASTBENCH_COMMIT,
  SASTBENCH_DATASET_RELATIVE_PATH,
  SASTBENCH_DATASET_SHA256,
  EXPECTED_CASE_COUNT,
  EXPECTED_LABEL_COUNTS,
  REPRESENTATIVE_SAMPLE_SPEC,
  DEFAULT_INSTALL_ROOT,
  DEFAULT_DATASET_PATH,
  DEFAULT_TARGET_ROOT,
  sha256Text,
  sha256File,
  loadDataset,
  validateDataset,
  opaqueCaseId,
  repositoryStateId,
  buildStateJobs,
  buildPromptVars,
  generatePromptfooTests,
  selectRepresentativeSample,
  generateRepresentativeSampleTests,
};

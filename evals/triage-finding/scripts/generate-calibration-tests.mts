#!/usr/bin/env node
import type { CalibrationCase, CalibrationVariant } from "../types.ts";

import fs from "node:fs";
import { hash } from "node:crypto";
import path from "node:path";

export const DEFAULT_DATASET = path.join(
  import.meta.dirname,
  "..",
  "datasets",
  "triage-calibration-seed.json",
);
const DEFAULT_OUTPUT = path.join(
  import.meta.dirname,
  "..",
  "tests",
  "calibration-oss.yaml",
);
const DEFAULT_REPO_ROOT = "evals/triage-finding/artifacts/calibration-repos";

function parseArgs(argv: string[]) {
  const args = {
    dataset: DEFAULT_DATASET,
    output: DEFAULT_OUTPUT,
    repoRoot: DEFAULT_REPO_ROOT,
    caseId: null as string | null,
    variantId: null as string | null,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dataset") {
      args.dataset = argv[++index];
    } else if (arg === "--output") {
      args.output = argv[++index];
    } else if (arg === "--repo-root") {
      args.repoRoot = argv[++index];
    } else if (arg === "--case") {
      args.caseId = argv[++index];
    } else if (arg === "--variant") {
      args.variantId = argv[++index];
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return args;
}

function quote(value: unknown) {
  return JSON.stringify(String(value));
}

function indentedBlock(value: unknown) {
  return `      ${String(value)
    .replace(/\r\n?/g, "\n")
    .replace(/\n/g, "\n      ")}`;
}

export function variantCaseId(
  testCase: Pick<CalibrationCase, "case_id">,
  variant: CalibrationVariant,
) {
  return `calibration-${hash("sha256", `${testCase.case_id}\0${variant.checkout_ref}`).slice(0, 16)}`;
}

function evidenceTerms(testCase: CalibrationCase) {
  const terms = (testCase.finding.anchor_locations || []).map(
    (location) => location.path,
  );
  return [...new Set(terms)];
}

export function findingInput(
  testCase: CalibrationCase,
  variant: CalibrationVariant,
) {
  const finding = testCase.finding;
  const lines = [
    `Source type: ${testCase.source_type}`,
    `1. input_id: ${variantCaseId(testCase, variant)}`,
    `   title: ${finding.title}`,
  ];

  if (finding.advisory_ids?.length) {
    lines.push(`   advisory ids: ${finding.advisory_ids.join(", ")}`);
  }
  if (finding.weakness) {
    lines.push(`   weakness: ${finding.weakness}`);
  }
  if (finding.severity) {
    lines.push(`   severity: ${finding.severity}`);
  }
  if (finding.language) {
    lines.push(`   affected language: ${finding.language}`);
  }
  if (finding.anchor_locations?.length) {
    const anchors = finding.anchor_locations
      .map((location) => `${location.path}:${location.line}`)
      .join(", ");
    lines.push(`   anchor locations: ${anchors}`);
  }

  return lines.join("\n");
}

function testYaml(
  testCase: CalibrationCase,
  variant: CalibrationVariant,
  repoRoot: string,
) {
  const generatedCaseId = variantCaseId(testCase, variant);
  const terms = evidenceTerms(testCase);
  const lines = [
    `- description: ${quote(`calibration ${variant.variant_id}: ${testCase.case_id}`)}`,
    "  metadata:",
    `    case_id: ${generatedCaseId}`,
    "    suite: calibration-oss",
    `    calibration_case_id: ${testCase.case_id}`,
    `    calibration_variant: ${variant.variant_id}`,
    `    repo: ${quote(testCase.repo.name)}`,
    `    expected_binary_label: ${variant.expected_binary_label}`,
    "  vars:",
    `    case_id: ${generatedCaseId}`,
    `    calibration_repo: ${generatedCaseId}`,
    `    calibration_repo_root: ${quote(repoRoot === DEFAULT_REPO_ROOT ? "" : path.resolve(repoRoot))}`,
    `    source_type_under_test: ${testCase.source_type}`,
    `    expected_ids: ${variantCaseId(testCase, variant)}`,
    `    expected_source_types: ${testCase.source_type}`,
    `    expected_verdicts: ${variant.expected_verdict}`,
    `    expected_binary_label: ${variant.expected_binary_label}`,
    `    expected_evidence_terms: ${quote(terms.join(", "))}`,
    "    finding_input: |-",
    indentedBlock(findingInput(testCase, variant)),
    "    eval_instructions: |-",
    indentedBlock(
      `This is an automated OSS calibration eval. Do not ask follow-up questions.
Inspect only the supplied repository checkout, the named anchor locations and the smallest related static evidence needed for the verdict.
Do not spawn subagents, run tests, run builds, start applications, run exploit PoCs, modify files, or search for unrelated vulnerabilities.
Return the normal triage-finding result: concise Markdown plus exactly one fenced JSON block.
The JSON block must conform to schema_version "triage-finding/v0" and include source_type, verdict, evidence, counterevidence, proof_gaps, boundary_assessment, and exploitability_stack_rank.`,
    ),
  ];

  return lines.join("\n");
}

export function selectedVariants(
  dataset: { cases: CalibrationCase[] },
  args: { caseId?: string | null; variantId?: string | null },
) {
  const variants = [];
  for (const testCase of dataset.cases) {
    if (args.caseId && testCase.case_id !== args.caseId) {
      continue;
    }

    for (const variant of testCase.variants) {
      if (args.variantId && variant.variant_id !== args.variantId) {
        continue;
      }

      variants.push({ testCase, variant });
    }
  }
  if (variants.length === 0) {
    throw new Error("No calibration variants matched the requested filters.");
  }
  return variants;
}

if (import.meta.filename === fs.realpathSync(process.argv[1])) {
  const args = parseArgs(process.argv.slice(2));
  const dataset = JSON.parse(fs.readFileSync(args.dataset, "utf8"));
  const variants = selectedVariants(dataset, args);
  const tests = variants.map(({ testCase, variant }) =>
    testYaml(testCase, variant, args.repoRoot),
  );
  const output = `${tests.join("\n\n")}\n`;
  fs.mkdirSync(path.dirname(args.output), { recursive: true });
  fs.writeFileSync(args.output, output);
  console.log(`wrote ${variants.length} calibration tests to ${args.output}`);
}

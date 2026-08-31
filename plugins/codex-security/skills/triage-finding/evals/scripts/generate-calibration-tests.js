#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_DATASET = path.join(__dirname, "..", "datasets", "triage-calibration-seed.json");
const DEFAULT_OUTPUT = path.join(__dirname, "..", "tests", "calibration-oss.yaml");
const DEFAULT_REPO_ROOT =
  "plugins/codex-security/skills/triage-finding/evals/artifacts/calibration-repos";

function parseArgs(argv) {
  const args = {
    dataset: DEFAULT_DATASET,
    output: DEFAULT_OUTPUT,
    repoRoot: DEFAULT_REPO_ROOT,
    caseId: null,
    variantId: null,
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

function quote(value) {
  return JSON.stringify(String(value));
}

function scalar(value) {
  return String(value).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

function indentedBlock(value, spaces) {
  const indent = " ".repeat(spaces);
  return scalar(value)
    .split("\n")
    .map((line) => `${indent}${line}`)
    .join("\n");
}

function variantCaseId(testCase, variant) {
  return `${testCase.case_id}-${variant.variant_id}`;
}

function inputId(testCase, variant) {
  const base = testCase.finding.input_id || testCase.finding.input_id_base || testCase.case_id;
  return `${base}-${variant.variant_id}`;
}

function targetRepoPath(repoRoot, testCase, variant) {
  return path.posix.join(repoRoot, testCase.case_id, variant.variant_id);
}

function evidenceTerms(testCase, variant) {
  const terms = [];
  for (const location of testCase.finding.anchor_locations || []) {
    terms.push(location.path);
  }
  if (variant.variant_id === "fixed" && testCase.finding.fix_patch_ref) {
    const fixCommit = variant.checkout_ref;
    terms.push(fixCommit);
  }
  return [...new Set(terms)];
}

function findingInput(testCase, variant) {
  const finding = testCase.finding;
  const lines = [
    `Source type: ${testCase.source_type}`,
    `1. input_id: ${inputId(testCase, variant)}`,
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
  if (finding.fix_patch_ref) {
    lines.push(`   fix evidence: ${finding.fix_patch_ref}`);
  }
  lines.push(
    `   repository state: checked out at ${variant.checkout_ref}. Triage whether the original finding affects this exact state.`,
  );

  return lines.join("\n");
}

function testYaml(testCase, variant, args) {
  const generatedCaseId = variantCaseId(testCase, variant);
  const terms = evidenceTerms(testCase, variant);
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
    `    target_repo: ${targetRepoPath(args.repoRoot, testCase, variant)}`,
    `    source_type_under_test: ${testCase.source_type}`,
    `    expected_ids: ${inputId(testCase, variant)}`,
    `    expected_source_types: ${testCase.source_type}`,
    `    expected_verdicts: ${variant.expected_verdict}`,
    `    expected_binary_label: ${variant.expected_binary_label}`,
    `    expected_evidence_terms: ${quote(terms.join(", "))}`,
    "    finding_input: |-",
    indentedBlock(findingInput(testCase, variant), 6),
    "    eval_instructions: |-",
    indentedBlock(
      [
        "This is an automated OSS calibration eval. Do not ask follow-up questions.",
        "Inspect only the supplied repository checkout, the named anchor locations, the fix evidence, and the smallest related static evidence needed for the verdict.",
        "Do not spawn subagents, run tests, run builds, start applications, run exploit PoCs, modify files, or search for unrelated vulnerabilities.",
        "Return the normal triage-finding result: concise Markdown plus exactly one fenced JSON block.",
        'The JSON block must conform to schema_version "triage-finding/v0" and include source_type, verdict, evidence, counterevidence, proof_gaps, boundary_assessment, and exploitability_stack_rank.',
      ].join("\n"),
      6,
    ),
  ];

  return lines.join("\n");
}

function selectedVariants(dataset, args) {
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
  return variants;
}

function generateFromVariants(variants, args) {
  if (variants.length === 0) {
    throw new Error("No calibration variants matched the requested filters.");
  }

  const tests = variants.map(({ testCase, variant }) => testYaml(testCase, variant, args));
  return `${tests.join("\n\n")}\n`;
}

function generate(dataset, args) {
  return generateFromVariants(selectedVariants(dataset, args), args);
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const dataset = JSON.parse(fs.readFileSync(args.dataset, "utf8"));
  const variants = selectedVariants(dataset, args);
  const output = generateFromVariants(variants, args);
  fs.mkdirSync(path.dirname(args.output), { recursive: true });
  fs.writeFileSync(args.output, output);
  console.log(`wrote ${variants.length} calibration tests to ${args.output}`);
}

if (require.main === module) {
  main();
}

module.exports = {
  generate,
  inputId,
  selectedVariants,
  targetRepoPath,
  variantCaseId,
};

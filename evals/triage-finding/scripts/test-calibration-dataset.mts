#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const datasetPath = path.join(
  import.meta.dirname,
  "..",
  "datasets",
  "triage-calibration-seed.json",
);
const dataset = JSON.parse(fs.readFileSync(datasetPath, "utf8"));

assert.equal(dataset.schema_version, "triage-finding-calibration-dataset/v0");
assert.equal(dataset.name, "triage-finding-calibration-seed");
assert.ok(Array.isArray(dataset.static_constraints));
assert.ok(Array.isArray(dataset.scoring_targets));
assert.ok(
  dataset.shared_evidence_sets &&
    typeof dataset.shared_evidence_sets === "object",
);
assert.ok(Array.isArray(dataset.cases));

const caseIds = new Set();
const evidenceSetIds = new Set(Object.keys(dataset.shared_evidence_sets));
let confirmedCount = 0;
let notActionableCount = 0;

for (const testCase of dataset.cases) {
  assert.ok(testCase.case_id, "case_id is required");
  assert.ok(
    !caseIds.has(testCase.case_id),
    `duplicate case_id: ${testCase.case_id}`,
  );
  caseIds.add(testCase.case_id);

  assert.ok(
    testCase.case_family,
    `${testCase.case_id}: case_family is required`,
  );
  assert.equal(
    testCase.case_family,
    "oss-vuln-fix-pair",
    `${testCase.case_id}: calibration seed must stay OSS-only`,
  );
  assert.ok(
    testCase.source_type,
    `${testCase.case_id}: source_type is required`,
  );
  assert.ok(testCase.repo?.name, `${testCase.case_id}: repo.name is required`);
  assert.ok(
    testCase.finding?.title,
    `${testCase.case_id}: finding.title is required`,
  );
  assert.ok(
    testCase.gold?.basis,
    `${testCase.case_id}: gold.basis is required`,
  );
  assert.ok(
    Array.isArray(testCase.variants),
    `${testCase.case_id}: variants must be an array`,
  );
  assert.ok(
    testCase.variants.length > 0,
    `${testCase.case_id}: must have at least one variant`,
  );

  const labels = testCase.variants
    .map(
      (variant: import("../types.ts").CalibrationVariant) =>
        variant.expected_binary_label,
    )
    .sort();
  assert.deepEqual(
    labels,
    ["negative", "positive"],
    `${testCase.case_id}: OSS pairs need positive and negative variants`,
  );

  const variantIds = new Set();
  for (const variant of testCase.variants) {
    assert.ok(
      variant.variant_id,
      `${testCase.case_id}: variant_id is required`,
    );
    assert.ok(
      !variantIds.has(variant.variant_id),
      `${testCase.case_id}: duplicate variant_id ${variant.variant_id}`,
    );
    variantIds.add(variant.variant_id);
    assert.ok(
      variant.checkout_ref,
      `${testCase.case_id}/${variant.variant_id}: checkout_ref is required`,
    );
    for (const evidenceSetId of variant.required_evidence_set_ids || []) {
      assert.ok(
        evidenceSetIds.has(evidenceSetId),
        `${testCase.case_id}/${variant.variant_id}: unknown required_evidence_set_id ${evidenceSetId}`,
      );
    }
    assert.ok(
      ["confirmed", "not_actionable", "needs_review"].includes(
        variant.expected_verdict,
      ),
      `${testCase.case_id}/${variant.variant_id}: invalid expected_verdict`,
    );

    if (variant.expected_verdict === "confirmed") {
      confirmedCount += 1;
      assert.equal(
        variant.expected_binary_label,
        "positive",
        `${testCase.case_id}/${variant.variant_id}: confirmed variants must be positive`,
      );
    } else if (variant.expected_verdict === "not_actionable") {
      notActionableCount += 1;
      assert.equal(
        variant.expected_binary_label,
        "negative",
        `${testCase.case_id}/${variant.variant_id}: not_actionable variants must be negative`,
      );
    }
  }
}

assert.equal(
  dataset.case_count,
  dataset.cases.length,
  "case_count does not match cases.length",
);
assert.equal(
  dataset.variant_count,
  dataset.cases.length * 2,
  "variant_count does not match variants.length sum",
);
assert.ok(confirmedCount > 0, "dataset needs at least one confirmed variant");
assert.ok(
  notActionableCount > 0,
  "dataset needs at least one not_actionable variant",
);

console.log(
  `calibration dataset ok: ${dataset.cases.length} cases, ${dataset.variant_count} variants, ${confirmedCount} confirmed, ${notActionableCount} not_actionable`,
);

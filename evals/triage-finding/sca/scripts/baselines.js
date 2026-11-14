#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { CORPUS, FIXTURE_ROOT } = require("./sca-result.js");

function baselineRecords(testCase) {
  const directory = path.join(FIXTURE_ROOT, testCase.case_id);
  const scanner = {
    case_id: testCase.case_id,
    component: testCase.input.component,
    advisory_ids: testCase.input.advisory_ids,
    advisories: testCase.input.advisories,
    scanner_evidence: "osv.json",
    application_assessment: null,
  };
  // These tiny fixtures have a single complete entrypoint. Include inspectable
  // lines without inferring a call graph or a negative reachability claim.
  const source = "src/application.mjs";
  const lines = fs
    .readFileSync(path.join(directory, source), "utf8")
    .split(/\r?\n/);
  return {
    scanner_only: scanner,
    scanner_with_usage_evidence: {
      ...scanner,
      evidence_kind: "source_lines_not_reachability_analysis",
      source_evidence: lines.flatMap((text, index) =>
        text.trim().length === 0
          ? []
          : [{ path: source, line: index + 1, text }],
      ),
      application_contract: fs.readFileSync(
        path.join(directory, "APPLICATION.md"),
        "utf8",
      ),
    },
  };
}

function buildBaselines() {
  return {
    schema_version: "codex-security.sca-eval-baselines/v0",
    corpus_kind: CORPUS.kind,
    cases: CORPUS.cases.map(baselineRecords),
  };
}

if (require.main === module)
  process.stdout.write(`${JSON.stringify(buildBaselines(), null, 2)}\n`);
module.exports = { baselineRecords, buildBaselines };

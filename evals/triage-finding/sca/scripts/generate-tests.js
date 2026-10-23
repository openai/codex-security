"use strict";

const path = require("node:path");
const { CORPUS } = require("./sca-result.js");

function generateTests() {
  const runtimeRoot = process.env.SCA_EVAL_RUNTIME_ROOT;
  if (!runtimeRoot)
    throw new Error(
      "Use sca/scripts/run-promptfoo.js to stage the label-free fixture runtime",
    );
  return CORPUS.cases.map((testCase) => ({
    description: `SCA synthetic smoke ${testCase.case_id}`,
    metadata: {
      suite: "sca-synthetic-smoke",
      case_id: testCase.case_id,
      advisory_family: testCase.advisory_family,
    },
    vars: {
      case_id: testCase.case_id,
      target_repo: path.join(runtimeRoot, "cases", testCase.case_id),
      input_id: testCase.input.input_id,
    },
  }));
}

module.exports = { generateTests };

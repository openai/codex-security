"use strict";

const { sha256Text } = require("../sastbench/scripts/sastbench-lib");

function variantCaseId(testCase, variant) {
  return `calibration-${sha256Text(`${testCase.case_id}\0${variant.checkout_ref}`).slice(0, 16)}`;
}

module.exports = { variantCaseId };

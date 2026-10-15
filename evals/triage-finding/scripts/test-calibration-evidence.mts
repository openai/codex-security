#!/usr/bin/env node
import assert from "node:assert/strict";
import calibrationEvidence from "../assertions/calibration-evidence.mts";

const context = {
  vars: {
    expected_evidence_terms: ["src/example.js", "abc123"],
  },
};

const passing = calibrationEvidence(
  "The finding is affected. Evidence includes src/example.js and the fixed commit abc123.",
  context,
);
assert.equal(passing.pass, true, passing.reason);
assert.equal(passing.score, 1);

const failing = calibrationEvidence(
  "The finding is affected. Evidence includes src/example.js.",
  context,
);
assert.equal(failing.pass, false, "missing evidence terms should fail");
assert.match(failing.reason, /abc123/);
assert.ok(failing.score > 0);
assert.ok(failing.score < 1);

console.log("calibration evidence assertion tests passed");

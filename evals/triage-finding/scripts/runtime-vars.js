"use strict";

const path = require("node:path");

// Resolve paths for each execution, including retries of persisted evaluations.
module.exports = (vars) => ({
  ...vars,
  triage_runtime_root: process.env.TRIAGE_RUNTIME_ROOT,
  ...(vars.calibration_repo ? {
    target_repo: path.join(vars.calibration_repo_root || process.env.CALIBRATION_TARGET_ROOT, vars.calibration_repo),
  } : {}),
});

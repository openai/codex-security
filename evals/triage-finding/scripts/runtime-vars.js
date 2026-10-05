"use strict";

const fs = require("node:fs");
const path = require("node:path");
const nodePath = fs.realpathSync(process.execPath);

// Resolve paths for each execution, including retries of persisted evaluations.
module.exports = (vars) => ({
  ...vars,
  triage_runtime_root: process.env.TRIAGE_RUNTIME_ROOT,
  triage_node_path: nodePath,
  triage_node_root: path.dirname(nodePath),
  ...(vars.calibration_repo ? {
    target_repo: path.join(vars.calibration_repo_root || process.env.CALIBRATION_TARGET_ROOT, vars.calibration_repo),
  } : {}),
});

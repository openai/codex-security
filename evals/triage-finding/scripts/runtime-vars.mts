import fs from "node:fs";
import path from "node:path";
const nodePath = fs.realpathSync(process.execPath);

// Resolve paths for each execution, including retries of persisted evaluations.
export default (vars: Record<string, unknown>) => ({
  ...vars,
  triage_runtime_root: process.env.TRIAGE_RUNTIME_ROOT,
  triage_node_path: nodePath,
  triage_node_root: path.dirname(nodePath),
  ...(vars.calibration_repo
    ? {
        target_repo: path.join(
          (vars.calibration_repo_root ||
            process.env.CALIBRATION_TARGET_ROOT) as string,
          vars.calibration_repo as string,
        ),
      }
    : {}),
});

import fs from "node:fs";
import path from "node:path";

const evalRoot = path.resolve(import.meta.dirname, "..");
const sourceRoot = path.resolve(evalRoot, "../..");

// Resolve paths for each execution, including retries of persisted evaluations.
export default (vars: Record<string, unknown>) => {
  const nodePath = fs.realpathSync(process.execPath);
  let targetRepo = vars.target_repo;
  if (vars.calibration_repo) {
    targetRepo = path.join(
      (vars.calibration_repo_root ||
        path.join(evalRoot, "artifacts", "calibration-repos")) as string,
      vars.calibration_repo as string,
    );
  } else if (
    typeof targetRepo === "string" &&
    targetRepo.startsWith("evals/triage-finding/fixtures/")
  ) {
    targetRepo = path.join(sourceRoot, targetRepo);
  }
  return {
    ...vars,
    target_repo: targetRepo,
    triage_runtime_root: path.join(sourceRoot, "plugins", "codex-security"),
    triage_fixture_root: path.join(evalRoot, "fixtures"),
    triage_node_path: nodePath,
    triage_node_root: path.dirname(nodePath),
    sastbench_git_cache_root: path.join(
      evalRoot,
      "artifacts",
      "sastbench-git-cache",
    ),
  };
};

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { runPythonJsonProbe } from "./python-probe.js";
import type { CoverageDocument } from "../../src/models.js";

type ReviewState = Pick<
  CoverageDocument,
  "surfaces" | "deferred" | "resolvedDeferred" | "explicitExclusions"
> &
  Record<string, unknown>;

export async function readReviewState(
  scanDir: string,
  stateDir?: string,
): Promise<ReviewState> {
  const { scan } = JSON.parse(
    await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
  );
  if (scan.coverageRef !== undefined)
    return JSON.parse(await readFile(join(scanDir, "coverage.json"), "utf8"));
  if (scan.reviewState !== undefined) return scan.reviewState;
  if (stateDir && scan.preservedSources) {
    const tests = fileURLToPath(
      new URL("../../../../plugins/codex-security/tests/", import.meta.url),
    );
    return runPythonJsonProbe(
      `import json,sys
from pathlib import Path
tests, state, scan = json.loads(sys.argv[2])
sys.path.insert(0, tests)
from workbench_test_support import read_review_state
print(json.dumps(read_review_state(Path(state), Path(scan))))`,
      [tests, stateDir, scanDir],
    ) as ReviewState;
  }
  const head = JSON.parse(
    await readFile(join(scanDir, "checkpoint-head.json"), "utf8"),
  );
  const checkpoint = JSON.parse(
    await readFile(join(scanDir, "checkpoints", head.checkpoint), "utf8"),
  );
  return checkpoint.reviewState;
}

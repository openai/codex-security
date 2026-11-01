import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CoverageDocument } from "../../src/models.js";

export async function readReviewState(
  scanDir: string,
): Promise<Pick<CoverageDocument, "surfaces" | "deferred">> {
  const { scan } = JSON.parse(
    await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
  );
  if (scan.coverageRef !== undefined)
    return JSON.parse(await readFile(join(scanDir, "coverage.json"), "utf8"));
  if (scan.reviewState !== undefined) return scan.reviewState;
  const head = JSON.parse(
    await readFile(join(scanDir, "checkpoint-head.json"), "utf8"),
  );
  const checkpoint = JSON.parse(
    await readFile(join(scanDir, "checkpoints", head.checkpoint), "utf8"),
  );
  return checkpoint.reviewState;
}

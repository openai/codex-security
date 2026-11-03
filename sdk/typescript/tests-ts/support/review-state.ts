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
  const draft = JSON.parse(
    await readFile(join(scanDir, "artifacts", "scan-draft.json"), "utf8"),
  );
  return draft.coverage;
}

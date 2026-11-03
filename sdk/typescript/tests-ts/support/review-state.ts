import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "bun:test";
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

/** These compact fixtures each seal one accepted source, with its full authored review. */
export async function acceptedReviewCheckpoint(scanDir: string) {
  const { scan } = JSON.parse(
    await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
  );
  const checkpoints =
    scan.preservedSources === undefined
      ? [
          `checkpoints/${JSON.parse(await readFile(join(scanDir, "checkpoint-head.json"), "utf8")).checkpoint}`,
        ]
      : Object.keys(scan.preservedSources).filter((path) =>
          path.startsWith("checkpoints/"),
        );
  expect(checkpoints).toHaveLength(1);
  const path = checkpoints[0]!;
  const draft = JSON.parse(await readFile(join(scanDir, path), "utf8"));
  return { path, reviewState: draft.reviewState ?? draft.coverage };
}

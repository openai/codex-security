import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

export async function readJson(file: string, ...parts: string[]) {
  return JSON.parse(
    await readFile(parts.length ? join(file, ...parts) : file, "utf8"),
  );
}

/** Read retained work from the draft, legacy sidecar, or sealed checkpoint. */
export async function readSavedReviewState(
  scanDirectory: string,
  stateDirectory?: string,
) {
  const { scan } = await readJson(scanDirectory, "scan-manifest.json");
  if (scan.coverageRef) return readJson(scanDirectory, scan.coverageRef);
  if (scan.reviewState) return scan.reviewState;
  if (stateDirectory && scan.preservedSources) {
    const tests = fileURLToPath(new URL("../../../tests/", import.meta.url));
    return JSON.parse(
      execFileSync(
        process.env.PYTHON?.trim() || "python3",
        [
          "-c",
          "import json, sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); from workbench_test_support import read_review_state; print(json.dumps(read_review_state(Path(sys.argv[2]), Path(sys.argv[3]))))",
          tests,
          stateDirectory,
          scanDirectory,
        ],
        { encoding: "utf8" },
      ),
    );
  }
  const { checkpoint } = await readJson(scanDirectory, "checkpoint-head.json");
  return (await readJson(scanDirectory, "checkpoints", checkpoint)).reviewState;
}

export async function snapshotScanDraft(scanDirectory: string) {
  return Promise.all(
    ["scan-manifest.json", "findings.json", "coverage.json"].map((artifact) =>
      readFile(join(scanDirectory, artifact), "utf8").catch((error) => {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw error;
      }),
    ),
  );
}

export async function readJsonLines(file: string) {
  return (await readFile(file, "utf8"))
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

export function jsonLines(rows: unknown[]) {
  return rows.map((row) => `${JSON.stringify(row)}\n`).join("");
}

export function writeJson(file: string, value: unknown) {
  return writeFile(file, JSON.stringify(value));
}

export function writeJsonLine(file: string, value: unknown) {
  return writeFile(file, `${JSON.stringify(value)}\n`);
}

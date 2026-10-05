import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

export async function readJson(file: string, ...parts: string[]) {
  return JSON.parse(
    await readFile(parts.length ? join(file, ...parts) : file, "utf8"),
  );
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

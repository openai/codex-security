import { randomUUID } from "node:crypto";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { readJson, writeJson } from "./json.js";

/** Publish canonical test fixtures through the real draft acceptance boundary. */
export async function publishScanDraft(
  scanDir: string,
  scanId: string,
  workbench: (args: string[]) => Promise<unknown>,
): Promise<void> {
  const [manifest, findings, coverage] = await Promise.all(
    ["scan-manifest.json", "findings.json", "coverage.json"].map((name) =>
      readJson(join(scanDir, name)),
    ),
  );
  await mkdir(join(scanDir, "drafts"), { recursive: true });
  const draftPath = join(scanDir, "drafts", `${randomUUID()}.json`);
  try {
    await writeJson(draftPath, { manifest, findings, coverage });
    await workbench([
      "write-scan-draft",
      "--scan-id",
      scanId,
      "--draft-path",
      draftPath,
    ]);
  } finally {
    await rm(draftPath, { force: true });
  }
}

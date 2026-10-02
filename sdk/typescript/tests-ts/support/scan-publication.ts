import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { JsonObject } from "../../src/config.js";
import type { SemanticScan } from "../../src/semantic-models.js";
import { prepareSemanticScanDraft } from "../../src/scan-semantics.js";

export async function publishDraft(
  command: (args: readonly string[], input?: string) => Promise<JsonObject>,
  registration: JsonObject,
  mode: "deep" | "standard",
  draft: SemanticScan,
) {
  const directory = registration["scanDir"] as string;
  const documents = prepareSemanticScanDraft(
    {
      targetContract: registration["contract"] as JsonObject,
      mode,
      targetRevision: registration["targetRevision"] as string,
    },
    draft,
  );
  const draftPath = join(directory, "drafts", randomUUID() + ".json");
  const checkpointPath = join(
    directory,
    "drafts",
    randomUUID() + ".checkpoint.json",
  );
  await mkdir(join(directory, "drafts"), { recursive: true, mode: 0o700 });
  await writeFile(draftPath, JSON.stringify(documents));
  await writeFile(checkpointPath, JSON.stringify(draft));
  await command([
    "write-scan-draft",
    "--scan-id",
    registration["scanId"] as string,
    "--draft-path",
    draftPath,
    "--checkpoint-path",
    checkpointPath,
  ]);
}

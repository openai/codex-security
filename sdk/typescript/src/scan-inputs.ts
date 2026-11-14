import { createHash } from "node:crypto";
import { constants, open, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { z } from "zod";
import { MODEL_FILE_SETTINGS, type JsonObject } from "./config.js";
import { isRecord } from "./record.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import { workflowDigest } from "./finding-workflow.js";
import type { KnowledgeBaseSnapshot } from "./knowledge-base.js";
import { readRegularInputFile } from "./prompt-files.js";

const KNOWLEDGE_SNAPSHOT_FILE = ".scan-knowledge.json";

const knowledgeSnapshotSchema = z.object({
  sources: z.array(z.string()),
  protectedRoots: z.array(z.string()).optional(),
  documents: z.record(z.string(), z.string()),
});

function textDigest(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export function scanInputIdentity(
  prompt: string | undefined,
  knowledge?: KnowledgeBaseSnapshot,
): JsonObject {
  return {
    scanPromptSha256: prompt?.trim() ? textDigest(prompt) : null,
    knowledgeBase:
      knowledge === undefined
        ? null
        : {
            sha256: workflowDigest(knowledge),
            documents: Object.entries(knowledge.documents).map(
              ([name, text]) => ({
                name,
                sha256: textDigest(text),
              }),
            ),
          },
  };
}

const legacyModelFileDigests = {
  model_instructions_file: "modelInstructionsFileSha256",
  experimental_compact_prompt_file: "compactPromptFileSha256",
  model_catalog_json: "modelCatalogFileSha256",
} as const;

async function modelFileInput(
  config: JsonObject,
  setting: (typeof MODEL_FILE_SETTINGS)[number],
  signal?: AbortSignal,
) {
  const path = config[setting];
  if (typeof path !== "string" || !path) return null;
  const file = await open(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    if (!(await file.stat()).isFile())
      throw new CodexSecurityError(
        `Expected a regular file for ${setting}: ${path}`,
      );
    return {
      path,
      sha256: createHash("sha256")
        .update(await file.readFile({ signal }))
        .digest("hex"),
    };
  } finally {
    await file.close();
  }
}

export async function deepModelFileInputs(
  config: JsonObject,
  signal?: AbortSignal,
): Promise<JsonObject> {
  const inputs: JsonObject = {};
  for (const setting of MODEL_FILE_SETTINGS)
    inputs[setting] = await modelFileInput(config, setting, signal);
  return inputs;
}

export async function validateDeepModelFileInputs(
  original: unknown,
  config: JsonObject,
  signal?: AbortSignal,
): Promise<void> {
  if (!isRecord(original)) return;
  const inputs = original["modelFileInputs"];
  if (inputs !== undefined && !isRecord(inputs))
    throw new CodexSecurityError(
      "Invalid model-file input receipt for the saved Deep Scan.",
    );
  for (const setting of MODEL_FILE_SETTINGS) {
    const saved = inputs?.[setting];
    const priorDigest = original[legacyModelFileDigests[setting]];
    if (saved === undefined && priorDigest === undefined) continue;
    if (
      saved !== undefined &&
      saved !== null &&
      (!isRecord(saved) ||
        typeof saved["path"] !== "string" ||
        typeof saved["sha256"] !== "string")
    )
      throw new CodexSecurityError(
        `Invalid saved Deep Scan input for ${setting}.`,
      );
    let current;
    try {
      current = await modelFileInput(config, setting, signal);
    } catch (cause) {
      signal?.throwIfAborted();
      throw new CodexSecurityError(
        `Could not read the saved Deep Scan's ${setting}: ${errorMessage(cause)}. Restore the original file and resume the scan.`,
        { cause },
      );
    }
    const expected =
      saved === undefined ? priorDigest : (saved?.["sha256"] ?? null);
    if (
      (current?.sha256 ?? null) !== expected ||
      (isRecord(saved) && current?.path !== saved["path"])
    )
      throw new CodexSecurityError(
        `The saved Deep Scan's ${setting} changed. Restore the original input and resume the scan, or start a new scan.`,
      );
  }
}

export async function saveScanKnowledge(
  scanDir: string,
  snapshot: KnowledgeBaseSnapshot,
): Promise<void> {
  // This private continuation input is separate from canonical report artifacts.
  await writeFile(
    join(scanDir, KNOWLEDGE_SNAPSHOT_FILE),
    JSON.stringify(snapshot),
    {
      flag: "wx",
      mode: 0o600,
    },
  );
}

export async function restoreScanKnowledge(
  scanDir: string,
  repository: string,
  identity: unknown,
): Promise<KnowledgeBaseSnapshot> {
  const parsedIdentity = z
    .object({
      knowledgeBase: z.object({ sha256: z.string() }),
    })
    .safeParse(identity);
  if (!parsedIdentity.success) {
    throw new CodexSecurityError(
      "This scan has no saved knowledge-base snapshot. Start a new scan with the original knowledge-base files; resuming could mix different context versions.",
    );
  }
  const path = join(scanDir, KNOWLEDGE_SNAPSHOT_FILE);
  let text: string;
  try {
    text = await readRegularInputFile(path, repository);
  } catch (error) {
    throw new CodexSecurityError(
      `Cannot restore the original scan knowledge base at ${path}: ${errorMessage(error)} Restore that file or start a new scan.`,
      { cause: error },
    );
  }
  let snapshot: KnowledgeBaseSnapshot;
  try {
    snapshot = knowledgeSnapshotSchema.parse(JSON.parse(text));
  } catch (error) {
    throw new CodexSecurityError(
      `Cannot read the saved knowledge-base snapshot: ${errorMessage(error)} Restore the original snapshot or start a new scan.`,
      { cause: error },
    );
  }
  if (workflowDigest(snapshot) !== parsedIdentity.data.knowledgeBase.sha256) {
    throw new CodexSecurityError(
      "The saved knowledge-base snapshot changed. Restore the original snapshot or start a new scan.",
    );
  }
  // Document names become staging filenames; imported state cannot escape that directory.
  if (
    Object.keys(snapshot.documents).some(
      (name) => name === "." || name === ".." || basename(name) !== name,
    )
  ) {
    throw new CodexSecurityError(
      "Saved knowledge-base documents must have plain filenames.",
    );
  }
  return snapshot;
}

import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { z } from "zod";
import type { JsonObject } from "./config.js";
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

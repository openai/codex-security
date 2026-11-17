import { createHash } from "node:crypto";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import * as z from "zod/v4";
import {
  replaceArtifactJson,
  requireArtifactRoot,
  type DiscoveryBoardContext,
} from "../artifact-io.js";
import { readJsonObject, requireRegularFile } from "./artifacts.js";

const noteId = z.string().regex(/^[a-f0-9]{64}$/);
export const readPeerNotesInput = z.strictObject({
  threadId: noteId.optional(),
});
export const postPeerNoteInput = readPeerNotesInput.extend({
  message: z.string().min(1),
});

async function readNote(directory: string, file: string) {
  const path = join(directory, file);
  await requireRegularFile(path, directory);
  return readJsonObject(path);
}

export async function postPeerNote(
  board: DiscoveryBoardContext,
  scanId: string | undefined,
  { threadId, message }: z.infer<typeof postPeerNoteInput>,
) {
  const directory = await requireArtifactRoot(
    board.root,
    "Deep Scan peer notes",
  );
  if (threadId) await readNote(directory, threadId + ".json");
  // Identical retries publish identical bytes, even when two callers race.
  const id = createHash("sha256")
    .update(JSON.stringify([scanId, board.author, threadId ?? null, message]))
    .digest("hex");
  const note = { id, threadId: threadId ?? id, author: board.author, message };
  const file = threadId ? threadId + "." + id : id;
  await replaceArtifactJson(join(directory, file + ".json"), note);
  return { id, threadId: note.threadId };
}

export async function readPeerNotes(
  board: DiscoveryBoardContext,
  { threadId }: z.infer<typeof readPeerNotesInput>,
) {
  const directory = await requireArtifactRoot(
    board.root,
    "Deep Scan peer notes",
  );
  const files = (await readdir(directory)).sort();
  if (!threadId) {
    const leads = files.filter((file) => /^[a-f0-9]{64}\.json$/.test(file));
    return {
      notes: await Promise.all(leads.map((file) => readNote(directory, file))),
    };
  }
  const lead = await readNote(directory, threadId + ".json");
  const replies = files.filter(
    (file) =>
      file.startsWith(threadId + ".") &&
      file !== threadId + ".json" &&
      file.endsWith(".json"),
  );
  return {
    notes: [
      lead,
      ...(await Promise.all(replies.map((file) => readNote(directory, file)))),
    ],
  };
}

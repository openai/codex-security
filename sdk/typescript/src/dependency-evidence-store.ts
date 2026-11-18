import { hash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
export { dependencyRecordHash as evidenceKey } from "./dependency-attempt-store.js";

export const evidenceHash = (bytes: string | Uint8Array) =>
  hash("sha256", bytes);

export const evidenceDigest = /^[0-9a-f]{64}$/u;

/** Directory and names come from the host. User-supplied references must be digests. */
export async function readSavedEvidence(
  path: string,
): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
}

export async function saveEvidence(
  directory: string,
  name: string,
  data: string,
) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = join(directory, `.${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, data, { flag: "wx", mode: 0o600 });
    await rename(temporary, join(directory, name));
  } finally {
    await rm(temporary, { force: true });
  }
}

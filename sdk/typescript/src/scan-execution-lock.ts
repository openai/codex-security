import { createHash } from "node:crypto";
import { chmod, mkdir, realpath, stat } from "node:fs/promises";
import { join } from "node:path";
import { CodexSecurityError } from "./errors.js";
import { isRecord } from "./record.js";
import { requirePrivateDirectory, sqliteDatabaseOpener } from "./runtime.js";

/** Hold one Standard scan's execution across processes, including resume. */
export async function acquireScanExecutionLock(
  stateDirectory: string,
  scanDirectory: string,
): Promise<() => void> {
  const directory = join(stateDirectory, "scan-locks");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await requirePrivateDirectory(await stat(directory), directory, "scan locks");
  const identity = createHash("sha256")
    .update(await realpath(scanDirectory))
    .digest("hex");
  const path = join(directory, `${identity}.sqlite3`);
  const database = sqliteDatabaseOpener()(path);
  try {
    if (process.platform !== "win32") await chmod(path, 0o600);
    database.exec("PRAGMA busy_timeout = 0");
    database.exec("BEGIN EXCLUSIVE");
  } catch (error) {
    database.close();
    if (
      isRecord(error) &&
      (error["errcode"] === 5 || error["code"] === "SQLITE_BUSY")
    ) {
      throw new CodexSecurityError(
        "This scan is already running in another CLI or SDK call.",
      );
    }
    throw error;
  }
  // The OS also releases the lock if the scan process exits unexpectedly.
  return () => database.close();
}

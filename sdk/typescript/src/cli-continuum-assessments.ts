import { hash } from "node:crypto";
import { lstat, readdir, realpath } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import { commandGitProtectionRoots } from "./local-git-metadata.js";
import { readRegularInputFile } from "./prompt-files.js";
import { writeAtomicJson } from "./publication-state.js";
import {
  type ProcessEnvironment,
  canonicalConfigPath,
  createWindowsOutputDirectory,
  prepareScanRegistrationOutput,
  requireModelSafeOutputDir,
  requireOutputOutsideRepositories,
  requirePrivateOutputDirectory,
  requireWindowsOutputPath,
  validatePreparedOutputDir,
} from "./runtime.js";

const snapshot = z.object({
  schemaVersion: z.literal(1),
  repositoryPath: z.string(),
  scanId: z.string(),
  environmentId: z.string().min(1),
  record: z.looseObject({ itemId: z.string() }),
});
type SavedRecord = { environmentId: string; record: unknown };

async function assessmentDirectory(
  stateDirectory: string,
  repository: string,
  scanId: string,
  create: boolean,
  environment: ProcessEnvironment,
) {
  const key = hash("sha256", JSON.stringify([repository, scanId]));
  const directory = join(
    await canonicalConfigPath(stateDirectory),
    "cli-continuum-" + key,
  );
  // Most scans have no provider. Avoid Git discovery in that case.
  if (!create) await lstat(directory);
  const roots = [
    repository,
    ...(await commandGitProtectionRoots(repository, environment)),
  ];
  const check = (path: string) =>
    requireOutputOutsideRepositories(roots, path, "state");
  check(directory);
  if (process.platform === "win32") {
    // Other writers can populate this store during setup. Check the writable
    // leaf ACL without requiring the directory to stay empty.
    requireModelSafeOutputDir(directory);
    if (create) await createWindowsOutputDirectory(directory, true);
    else await requireWindowsOutputPath(directory, true);
    return validatePreparedOutputDir(directory, check, true);
  }
  const prepared = create
    ? await prepareScanRegistrationOutput(
        directory,
        key,
        undefined,
        check,
        true,
      )
    : await validatePreparedOutputDir(directory, check, true);
  requirePrivateOutputDirectory(await lstat(prepared), prepared);
  return prepared;
}

function snapshotName(itemId: string, environmentId: string, raw: string) {
  return (
    [itemId, environmentId, raw].map((part) => hash("sha256", part)).join(".") +
    ".json"
  );
}

/** Write one immutable snapshot per distinct conclusion. Concurrent selections
 * never replace each other's results, and retries with the same result converge. */
export async function writeCliSnapshots(
  stateDirectory: string,
  repositoryPath: string,
  scanId: string,
  environmentId: string,
  records: readonly { itemId: string }[],
  environment: ProcessEnvironment,
): Promise<void> {
  const repository = await realpath(repositoryPath);
  const directory = await assessmentDirectory(
    stateDirectory,
    repository,
    scanId,
    true,
    environment,
  );
  for (const record of records) {
    const value = {
      schemaVersion: 1,
      repositoryPath: repository,
      scanId,
      environmentId,
      record,
    };
    const filename = snapshotName(
      record.itemId,
      environmentId,
      JSON.stringify(value),
    );
    await writeAtomicJson(join(directory, filename), value);
  }
}

export async function readCliSnapshots(
  stateDirectory: string,
  repositoryPath: string,
  scanId: string,
  requested: ReadonlySet<string>,
  environmentId: string | undefined,
  environment: ProcessEnvironment,
): Promise<Map<string, SavedRecord[] | null>> {
  const repository = await realpath(repositoryPath);
  const directory = await assessmentDirectory(
    stateDirectory,
    repository,
    scanId,
    false,
    environment,
  );
  const byHash = new Map(
    [...requested].map((item) => [hash("sha256", item), item]),
  );
  const destination = environmentId && hash("sha256", environmentId);
  // A corrupt snapshot can conflict with both other snapshots and the plugin cache.
  // Keep the occurrence marked invalid even if another candidate follows it.
  const records = new Map<string, SavedRecord[] | null>();
  for (const name of await readdir(directory)) {
    const [occurrence, environmentHash] = name.split(".");
    const itemId = occurrence && byHash.get(occurrence);
    if (
      !itemId ||
      records.get(itemId) === null ||
      (destination && environmentHash !== destination) ||
      !name.endsWith(".json")
    )
      continue;
    try {
      const raw = await readRegularInputFile(join(directory, name), repository);
      const saved = snapshot.parse(JSON.parse(raw));
      if (
        saved.repositoryPath !== repository ||
        saved.scanId !== scanId ||
        saved.record.itemId !== itemId ||
        snapshotName(itemId, saved.environmentId, raw) !== name
      ) {
        records.set(itemId, null);
        continue;
      }
      const batch = records.get(itemId) ?? [];
      batch.push(saved);
      records.set(itemId, batch);
    } catch {
      // An unreadable candidate could conflict with another for this occurrence.
      records.set(itemId, null);
    }
  }
  return records;
}

import { hash } from "node:crypto";
import { lstat, readdir, realpath } from "node:fs/promises";
import { join } from "node:path";
import { commandGitProtectionRoots } from "./local-git-metadata.js";
import { readRegularInputFile } from "./prompt-files.js";
import { withPublicationLock, writeAtomicJson } from "./publication-state.js";
import {
  type ProcessEnvironment,
  canonicalizeModelSafePath,
  codexSecurityStateDirectory,
  createWindowsOutputDirectory,
  prepareScanRegistrationOutput,
  requireOutputDirectoryOwnership,
  requireOutputOutsideRepositories,
  requirePrivateOutputDirectory,
  requireWindowsOutputPath,
  validateDirectoryLinks,
  validatePreparedOutputDir,
} from "./runtime.js";
import { nullIfMissingFile } from "./targets.js";

// Earlier assessments could infer a match from issue membership or keywords.
export const continuumAssessmentVersion = 4;

type Entry = {
  environmentId: string;
  record: { itemId: string };
  /** Host time when validation began. Older entries preserve file order. */
  requestedAt?: number;
};
const digest = (value: string) => hash("sha256", value);

function snapshotName(itemId: string, environmentId: string) {
  return `${digest(itemId)}.${digest(environmentId)}.json`;
}

/** One store per operation. Most scans have no assessment; discover Git metadata
 * only after locating a candidate or when preparing to write. */
export async function assessmentStore(
  environment: ProcessEnvironment,
  scanId: string,
  selectedRepository: string,
) {
  if (!/^[a-zA-Z0-9_-]+$/.test(scanId)) throw new Error("Invalid scan ID.");
  const state = codexSecurityStateDirectory(environment);
  const repositoryPath = await realpath(selectedRepository);
  const key =
    `cli-continuum-v${continuumAssessmentVersion}-` +
    digest(JSON.stringify([repositoryPath, scanId]));
  const cli = join(state, key);
  const plugin = join(state, "validation-providers");
  const scope = {
    schemaVersion: continuumAssessmentVersion,
    repositoryPath,
    scanId,
  };
  const windows = process.platform === "win32";
  let gitRoots: Promise<string[]> | undefined;
  let pluginDirectory: Promise<string> | undefined;

  async function directory(path: string, create = false) {
    gitRoots ??= commandGitProtectionRoots(repositoryPath, environment);
    const roots = [repositoryPath, ...(await gitRoots)];
    const check = (location: string) =>
      requireOutputOutsideRepositories(roots, location, "state");
    check(path);
    await validateDirectoryLinks(path, check);
    if (create && windows) {
      // Concurrent writers may populate the directory during setup.
      const location = join(await canonicalizeModelSafePath(state), key);
      check(location);
      await createWindowsOutputDirectory(location, true);
    }
    const prepared =
      create && !windows
        ? await prepareScanRegistrationOutput(
            path,
            scanId,
            undefined,
            check,
            true,
          )
        : await validatePreparedOutputDir(path, check, true);
    if (windows) await requireWindowsOutputPath(prepared, true);
    else {
      const metadata = await lstat(prepared);
      if (path === cli) requirePrivateOutputDirectory(metadata, prepared);
      else if (metadata.mode & 0o022) throw new Error("Writable plugin cache.");
    }
    return prepared;
  }

  async function read(path: string) {
    const metadata = await lstat(path, { bigint: true });
    requireOutputDirectoryOwnership({ uid: Number(metadata.uid) }, path);
    if (metadata.nlink !== 1n || (!windows && metadata.mode & 0o022n))
      throw new Error("Untrusted assessment file.");
    return readRegularInputFile(path, null, metadata);
  }

  async function readPlugin(suffix: string): Promise<unknown> {
    try {
      const name = scanId + suffix;
      if (!(await lstat(join(plugin, name)).catch(nullIfMissingFile)))
        return undefined;
      const prepared = await (pluginDirectory ??= directory(plugin));
      return JSON.parse(await read(join(prepared, name)));
    } catch {
      // An invalid binding must stay distinct from a missing one.
      return null;
    }
  }

  async function readEntries(dir: string, name: string, itemId: string) {
    const { entries, checksum, ...saved } = JSON.parse(
      await read(join(dir, name)),
    );
    if (
      saved.schemaVersion !== scope.schemaVersion ||
      saved.repositoryPath !== repositoryPath ||
      saved.scanId !== scanId ||
      !Array.isArray(entries) ||
      !entries.length ||
      digest(JSON.stringify(entries)) !== checksum ||
      entries.some(
        (entry: Entry) =>
          entry.record.itemId !== itemId ||
          snapshotName(itemId, entry.environmentId) !== name,
      )
    )
      throw new Error("Invalid assessment snapshot.");
    return entries as Entry[];
  }

  return {
    readBinding: () => readPlugin(".json"),
    readPluginResult: () => readPlugin(".json.result"),

    /** Save in explicit validation order, including a return to an earlier
     * submission. Concurrent partial selections must retain each other's results. */
    async writeSnapshots(
      environmentId: string,
      records: readonly { itemId: string }[],
      requestedAt: number,
    ) {
      const dir = await directory(cli, true);
      await withPublicationLock(dir, "snapshots", undefined, async () => {
        for (const record of records) {
          const name = snapshotName(record.itemId, environmentId);
          const previous = await readEntries(dir, name, record.itemId).catch(
            nullIfMissingFile,
          );
          const raw = JSON.stringify(record);
          const entries = previous ?? [];
          const duplicate = entries.findIndex(
            (entry) => JSON.stringify(entry.record) === raw,
          );
          if (duplicate >= 0) {
            if ((entries[duplicate]!.requestedAt ?? 0) > requestedAt) continue;
            entries.splice(duplicate, 1);
          }
          // A slower poll may return after a different submission was selected.
          // Preserve both results, ordered by the start of each CLI request.
          const next = entries.findIndex(
            (entry) => (entry.requestedAt ?? 0) > requestedAt,
          );
          entries.splice(next < 0 ? entries.length : next, 0, {
            environmentId,
            record,
            requestedAt,
          });
          await writeAtomicJson(join(dir, name), {
            ...scope,
            entries,
            checksum: digest(JSON.stringify(entries)),
          });
        }
      });
    },

    async readSnapshots(
      requested: ReadonlySet<string>,
      environmentId?: string,
    ) {
      const records = new Map<string, Entry[] | null>();
      if (!(await lstat(cli).catch(() => undefined))) return records;
      const dir = await directory(cli).catch(() => undefined);
      if (!dir) return records;
      const byHash = new Map([...requested].map((id) => [digest(id), id]));
      const destination = environmentId && digest(environmentId);
      for (const name of await readdir(dir).catch(() => [])) {
        const [occurrence, environmentHash] = name.split(".");
        const itemId = byHash.get(occurrence!);
        if (
          !itemId ||
          (destination && environmentHash !== destination) ||
          !name.endsWith(".json")
        )
          continue;
        const batch = records.get(itemId);
        if (batch === null) continue;
        try {
          const entries = await readEntries(dir, name, itemId);
          records.set(itemId, batch ? batch.concat(entries) : entries);
        } catch {
          // Corruption can conceal a conflict for this occurrence in either cache.
          records.set(itemId, null);
        }
      }
      return records;
    },
  };
}

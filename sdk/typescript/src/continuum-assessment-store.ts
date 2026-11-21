import { hash } from "node:crypto";
import { lstat, readdir, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { commandGitProtectionRoots } from "./local-git-metadata.js";
import { readRegularInputFile } from "./prompt-files.js";
import { writeAtomicJson } from "./publication-state.js";
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

/** The plugin binding predates the workbench state directory. */
export function assessmentStateDirectories(environment: ProcessEnvironment) {
  return {
    plugin:
      environment["CODEX_SECURITY_STATE_DIR"]?.trim() ||
      join(homedir(), ".codex-security"),
    cli: codexSecurityStateDirectory(environment),
  };
}

// V1 inferred finding attribution from issue membership. Prerelease v2
// could match a reasoning step without a corroborating HTTP effect.
export const continuumAssessmentVersion = 3;

type Entry = { environmentId: string; record: { itemId: string } };
const digest = (value: string) => hash("sha256", value);

function snapshotName(entry: Entry, raw: string) {
  return (
    [entry.record.itemId, entry.environmentId, raw].map(digest).join(".") +
    ".json"
  );
}

/** One store per operation. Most scans have no assessment; discover Git metadata
 * only after locating a candidate or when preparing to write. */
export async function assessmentStore(
  environment: ProcessEnvironment,
  scanId: string,
  selectedRepository: string,
) {
  if (!/^[a-zA-Z0-9_-]+$/.test(scanId)) throw new Error("Invalid scan ID.");
  const state = assessmentStateDirectories(environment);
  const repositoryPath = await realpath(selectedRepository);
  const key =
    `cli-continuum-v${continuumAssessmentVersion}-` +
    digest(JSON.stringify([repositoryPath, scanId]));
  const cli = join(state.cli, key);
  const plugin = resolve(state.plugin, "validation-providers");
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
      const location = join(await canonicalizeModelSafePath(state.cli), key);
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

  return {
    readBinding: () => readPlugin(".json"),
    readPluginResult: () => readPlugin(".json.result"),

    /** Independent immutable files allow concurrent partial batches and retries. */
    async writeSnapshots(
      environmentId: string,
      records: readonly { itemId: string }[],
    ) {
      const dir = await directory(cli, true);
      for (const record of records) {
        const value = { ...scope, environmentId, record };
        const name = snapshotName(value, JSON.stringify(value));
        await writeAtomicJson(join(dir, name), value);
      }
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
          const raw = await read(join(dir, name));
          const saved: Entry & typeof scope = JSON.parse(raw);
          if (
            saved.schemaVersion !== scope.schemaVersion ||
            saved.repositoryPath !== repositoryPath ||
            saved.scanId !== scanId ||
            typeof saved.environmentId !== "string" ||
            !saved.environmentId ||
            saved.record.itemId !== itemId ||
            snapshotName(saved, raw) !== name
          )
            throw new Error("Invalid assessment snapshot.");
          if (batch) batch.push(saved);
          else records.set(itemId, [saved]);
        } catch {
          // Corruption can conceal a conflict for this occurrence in either cache.
          records.set(itemId, null);
        }
      }
      return records;
    },
  };
}

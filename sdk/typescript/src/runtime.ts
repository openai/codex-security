import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants, existsSync, type Stats } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  rmdir,
  stat,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { createRequire } from "node:module";
import {
  basename,
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { crc32 } from "node:zlib";
import extractZip from "extract-zip";
import { parse } from "smol-toml";
import {
  CodexSecurityError,
  OutputDirectoryError,
  PluginBootstrapError,
  PluginPythonUnavailableError,
} from "./errors.js";
import type { JsonObject } from "./config.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execFile = promisify(execFileCallback);

export const MARKETPLACE_NAME = "codex-security-sdk";
export const PLUGIN_NAME = "codex-security";

const MAX_ZIP_ENTRIES = 4_096;
const MAX_ZIP_CENTRAL_DIRECTORY = 16 * 1024 * 1024;
const MAX_ZIP_ENTRY_SIZE = 128 * 1024 * 1024;
const MAX_ZIP_EXPANDED_SIZE = 512 * 1024 * 1024;
const MAX_PLUGIN_MANIFEST_SIZE = 1024 * 1024;
const MAX_PLUGIN_COPY_ENTRIES = 4_096;
const MAX_PLUGIN_COPY_FILE_SIZE = 128 * 1024 * 1024;
const MAX_PLUGIN_COPY_SIZE = 512 * 1024 * 1024;
const MODEL_UNSAFE_PATH = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;

export interface PluginInstall {
  pluginRoot: string;
  marketplaceRoot: string;
  installedRoot: string;
  marketplaceName: typeof MARKETPLACE_NAME;
  name: typeof PLUGIN_NAME;
  version: string;
}

export interface CodexCommand {
  command: string;
  prefixArgs: readonly string[];
}

export type ProcessEnvironment = Record<string, string | undefined>;

export interface PluginPythonOptions {
  configuredPath?: string;
  environment?: ProcessEnvironment;
  homeDirectory?: string;
  managedRuntimeRoots?: readonly string[];
  protectedRoot?: string;
  signal?: AbortSignal;
}

export interface WorkbenchCommandOptions {
  python: string;
  pluginRoot: string;
  environment: ProcessEnvironment;
  signal?: AbortSignal;
  failureMessage?: string;
}

export function codexSecurityStateDirectory(
  environment: ProcessEnvironment = process.env,
): string {
  const environmentValue = (requested: string): string | undefined => {
    const exact = environment[requested]?.trim();
    if (exact) return exact;
    return Object.entries(environment)
      .find(
        ([name, value]) => name.toUpperCase() === requested && value?.trim(),
      )?.[1]
      ?.trim();
  };
  const configured = environmentValue("CODEX_SECURITY_STATE_DIR");
  if (configured !== undefined) return resolve(expandHome(configured));
  const codexHome = environmentValue("CODEX_HOME") ?? join(homedir(), ".codex");
  return resolve(expandHome(codexHome), "state", "plugins", "codex-security");
}

export async function preparePersistentScanRoot(
  stateDirectory: string,
  repositoryName: string,
): Promise<string> {
  const root = join(stateDirectory, "scans", safePrefix(repositoryName));
  await mkdir(root, { recursive: true, mode: 0o700 });
  return await realpath(root);
}

export async function runWorkbench(
  options: WorkbenchCommandOptions,
  args: readonly string[],
): Promise<JsonObject> {
  let stdout: string;
  try {
    ({ stdout } = await execFile(
      options.python,
      [
        "-I",
        "-B",
        join(options.pluginRoot, "scripts", "workbench_db.py"),
        ...args,
      ],
      {
        env: Object.fromEntries(
          Object.entries(options.environment).filter(
            ([name]) =>
              name.toUpperCase() !== "OPENAI_API_KEY" &&
              name.toUpperCase() !== "CODEX_API_KEY",
          ),
        ),
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
        windowsHide: true,
        signal: options.signal,
      },
    ));
  } catch (error) {
    if (options.signal?.aborted) throw error;
    const detail = processErrorDetail(error);
    const databaseFailure =
      /\b(?:unable to open database file|attempt to write a readonly database|readonly database|disk i\/o error)\b/iu.test(
        detail,
      );
    const failure =
      options.failureMessage ?? "Could not run the Codex Security workbench";
    throw new CodexSecurityError(
      databaseFailure
        ? `${failure}: cannot open the workbench database at ${join(
            codexSecurityStateDirectory(options.environment),
            "workbench.sqlite3",
          )}. Ensure the state directory and SQLite journal files are writable, or set CODEX_SECURITY_STATE_DIR to a writable directory outside the scanned repository.`
        : `${failure}: ${detail}`,
      { cause: error },
    );
  }
  let result: unknown;
  try {
    result = JSON.parse(stdout);
  } catch (error) {
    throw new CodexSecurityError(
      "The Codex Security workbench returned invalid JSON.",
      { cause: error },
    );
  }
  if (!isRecord(result)) {
    throw new CodexSecurityError(
      "The Codex Security workbench returned an invalid response.",
    );
  }
  return result as JsonObject;
}

export function bundledPluginCandidates(moduleDirectory: string): string[] {
  const packageCandidates = [
    resolve(moduleDirectory, "_bundled_plugin"),
    resolve(moduleDirectory, "../_bundled_plugin"),
  ];
  return basename(moduleDirectory) === "src"
    ? [
        resolve(moduleDirectory, "../../../plugins/codex-security"),
        ...packageCandidates,
      ]
    : packageCandidates;
}

export async function bundledPluginRoot(): Promise<string> {
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  for (const candidate of bundledPluginCandidates(moduleDirectory)) {
    if (await hasPluginManifest(candidate)) {
      return await realpath(candidate);
    }
  }
  throw new PluginBootstrapError(
    "The bundled Codex Security plugin is missing.",
  );
}

export async function validateOutputDir(
  outputDirectory?: string,
  archiveExisting = false,
): Promise<string | null> {
  if (outputDirectory === undefined) {
    return null;
  }
  requireModelSafeOutputDir(outputDirectory);
  const path = resolve(expandHome(outputDirectory));
  try {
    const metadata = await lstat(path).catch((error: unknown) => {
      if (nodeErrorCode(error) === "ENOENT") return null;
      throw error;
    });
    if (metadata !== null) {
      if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
        throw new OutputDirectoryError(
          `Scan output is not a directory: ${path}`,
        );
      }
      if (!archiveExisting && (await readdir(path)).length !== 0) {
        throw new OutputDirectoryError(
          `Scan output directory is not empty: ${path}. To keep the existing results and start a new scan, add --archive-existing.`,
        );
      }
      requirePrivateOutputDirectory(metadata, path);
      await requireSecureOutputAncestry(path);
      const canonical = await realpath(path);
      requireModelSafeOutputDir(canonical);
      return canonical;
    }

    let parent = dirname(path);
    while (true) {
      try {
        if ((await stat(parent)).isDirectory()) {
          const canonical = resolve(
            await realpath(parent),
            relative(parent, path),
          );
          requireModelSafeOutputDir(canonical);
          await requireSecureOutputAncestry(canonical);
          return canonical;
        }
        break;
      } catch (error) {
        if (nodeErrorCode(error) !== "ENOENT") throw error;
        const next = dirname(parent);
        if (next === parent) break;
        parent = next;
      }
    }
    throw new OutputDirectoryError(
      `Unable to create scan output directory: ${path}`,
    );
  } catch (error) {
    if (error instanceof OutputDirectoryError) throw error;
    throw new OutputDirectoryError(
      `Unable to inspect scan output directory: ${outputDirectory}`,
      { cause: error },
    );
  }
}

export async function planOutputArchive(
  outputDirectory: string | null,
): Promise<string | null> {
  if (outputDirectory === null) return null;
  const entries = await readdir(outputDirectory).catch((error: unknown) => {
    if (nodeErrorCode(error) === "ENOENT") return null;
    throw error;
  });
  if (entries === null || entries.length === 0) return null;
  const timestamp = new Date()
    .toISOString()
    .replaceAll(/[-:]/g, "")
    .replace(/\.\d{3}Z$/, "");
  return `${outputDirectory}.previous-${timestamp}-${randomUUID().slice(0, 8)}`;
}

export function requireModelSafeOutputDir(path: string): void {
  if (MODEL_UNSAFE_PATH.test(path)) {
    throw new OutputDirectoryError(
      "Scan output directory must not contain control or line-separator characters.",
    );
  }
}

export async function prepareOutputDir(
  outputDirectory: string | undefined,
  repositoryName: string,
  temporaryRoot: string = tmpdir(),
  validateLocation?: (path: string) => void,
  archiveExisting = false,
  onOutputArchived?: (archiveDir: string) => void,
): Promise<string> {
  if (outputDirectory === undefined) {
    requireModelSafeOutputDir(temporaryRoot);
    requireModelSafeOutputDir(await realpath(temporaryRoot));
  }
  const path = await validateOutputDir(outputDirectory, archiveExisting);
  validateLocation?.(path ?? (await realpath(temporaryRoot)));
  if (path === null) {
    const created = await mkdtemp(
      join(temporaryRoot, `codex-security-${safePrefix(repositoryName)}-`),
    );
    if ((process.umask() & 0o700) !== 0) await chmod(created, 0o700);
    try {
      return await validatePreparedOutputDir(created, validateLocation);
    } catch (error) {
      await rmdir(created).catch(() => undefined);
      throw error;
    }
  }
  let createdRoot: string | undefined;
  try {
    let existing = await lstat(path).catch((error: unknown) => {
      if (nodeErrorCode(error) === "ENOENT") return null;
      throw error;
    });
    if (existing !== null && archiveExisting) {
      const archiveDir = await planOutputArchive(path);
      if (archiveDir !== null) {
        await rename(path, archiveDir);
        onOutputArchived?.(archiveDir);
        existing = null;
      }
    }
    if (existing === null) {
      createdRoot = await mkdir(path, { recursive: true, mode: 0o700 });
      if ((process.umask() & 0o700) !== 0) await chmod(path, 0o700);
    }
    return await validatePreparedOutputDir(path, validateLocation);
  } catch (error) {
    if (createdRoot !== undefined) {
      await removeEmptyDirectories(path, createdRoot);
    }
    if (error instanceof OutputDirectoryError) throw error;
    throw new OutputDirectoryError(
      `Unable to create scan output directory: ${path}`,
      {
        cause: error,
      },
    );
  }
}

export async function validatePreparedOutputDir(
  path: string,
  validateLocation?: (path: string) => void,
): Promise<string> {
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new OutputDirectoryError(`Scan output is not a directory: ${path}`);
  }
  const canonical = await realpath(path);
  requireModelSafeOutputDir(canonical);
  validateLocation?.(canonical);
  const entries = await readdir(canonical);
  if (entries.length !== 0) {
    throw new OutputDirectoryError(
      `Scan output directory must be empty: ${path}`,
    );
  }
  requirePrivateOutputDirectory(metadata, path);
  await requireSecureOutputAncestry(canonical);
  return canonical;
}

export function requirePrivateOutputDirectory(
  metadata: Pick<Stats, "mode" | "uid">,
  path: string,
  effectiveUid = process.geteuid?.(),
): void {
  if (process.platform === "win32") return;
  if ((metadata.mode & 0o077) !== 0) {
    throw new OutputDirectoryError(
      `Scan output directory must not be accessible to other users (chmod 700): ${path}`,
    );
  }
  if (effectiveUid !== undefined && metadata.uid !== effectiveUid) {
    throw new OutputDirectoryError(
      `Scan output directory must be owned by the current user: ${path}`,
    );
  }
}

/** Reject parents that other users can rename entries out of (non-sticky shared dirs). */
export async function requireSecureOutputAncestry(path: string): Promise<void> {
  if (process.platform === "win32") return;
  let current = dirname(resolve(path));
  while (true) {
    try {
      current = await realpath(current);
      break;
    } catch (error) {
      if (nodeErrorCode(error) !== "ENOENT") {
        throw new OutputDirectoryError(
          `Unable to inspect scan output parent directory: ${current}`,
          { cause: error },
        );
      }
      const parent = dirname(current);
      if (parent === current) {
        throw new OutputDirectoryError(
          `Unable to inspect scan output parent directory: ${current}`,
          { cause: error },
        );
      }
      current = parent;
    }
  }
  while (true) {
    let metadata: Stats;
    try {
      metadata = await lstat(current);
    } catch (error) {
      throw new OutputDirectoryError(
        `Unable to inspect scan output parent directory: ${current}`,
        { cause: error },
      );
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new OutputDirectoryError(
        `Scan output parent must be a non-symlink directory: ${current}`,
      );
    }
    // Group/world-writable parents need the sticky bit so other users cannot
    // rename or replace the private scan directory mid-scan.
    if ((metadata.mode & 0o022) !== 0 && (metadata.mode & 0o1000) === 0) {
      throw new OutputDirectoryError(
        `Scan output parent must not be group- or world-writable without the sticky bit: ${current}`,
      );
    }
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

async function removeEmptyDirectories(
  path: string,
  root: string,
): Promise<void> {
  let current = path;
  while (true) {
    try {
      await rmdir(current);
    } catch {
      return;
    }
    if (current === root) return;
    current = dirname(current);
  }
}

export async function createIsolatedHome(
  temporaryRoot: string = tmpdir(),
  validateLocation?: (path: string) => void,
): Promise<string> {
  const path = await mkdtemp(
    join(temporaryRoot, "openai-codex-security-home-"),
  );
  try {
    if ((process.umask() & 0o700) !== 0) await chmod(path, 0o700);
    return await validatePreparedOutputDir(path, validateLocation);
  } catch (error) {
    await rmdir(path).catch(() => undefined);
    throw error;
  }
}

export async function importAmbientAuth(
  ambientHome: string,
  isolatedHome: string,
): Promise<boolean> {
  const source = join(expandHome(ambientHome), "auth.json");
  let metadata;
  try {
    metadata = await stat(source);
  } catch (error) {
    if (nodeErrorCode(error) === "ENOENT") return false;
    throw new PluginBootstrapError(
      `Unable to inspect ambient Codex authentication: ${source}`,
      {
        cause: error,
      },
    );
  }
  if (!metadata.isFile()) {
    return false;
  }
  await mkdir(isolatedHome, { recursive: true, mode: 0o700 });
  const destination = join(isolatedHome, "auth.json");
  const temporary = join(
    isolatedHome,
    `.auth-${process.pid}-${Date.now()}.tmp`,
  );
  try {
    await copyFile(source, temporary, constants.COPYFILE_EXCL);
    await chmod(temporary, 0o600);
    await rename(temporary, destination);
    await chmod(destination, 0o600);
    return true;
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw new PluginBootstrapError(
      "Unable to copy ambient Codex authentication.",
      {
        cause: error,
      },
    );
  }
}

export async function extractPluginZip(
  archive: string,
  destination: string,
  signal?: AbortSignal,
): Promise<string> {
  const archivePath = resolve(expandHome(archive));
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  const staging = await realpath(
    await mkdtemp(join(dirname(destination), ".codex-security-plugin-")),
  );
  try {
    throwIfSignalAborted(signal);
    await rejectBackslashZipNames(archivePath, signal);
    let expandedSize = 0;
    const paths = new Set<string>();
    const checksums: Array<{ path: string; checksum: number }> = [];
    await extractZip(archivePath, {
      dir: staging,
      defaultDirMode: 0o700,
      defaultFileMode: 0o600,
      onEntry(entry, archive) {
        throwIfSignalAborted(signal);
        if (archive.entryCount > MAX_ZIP_ENTRIES) {
          throw new PluginBootstrapError(
            `Plugin ZIP contains too many entries: ${archive.entryCount}.`,
          );
        }
        const path = safeArchivePath(entry.fileName);
        const collisionKey = path.toLowerCase();
        if (paths.has(collisionKey)) {
          throw new PluginBootstrapError(
            `Plugin ZIP contains a duplicate path: ${entry.fileName}`,
          );
        }
        paths.add(collisionKey);
        if (((entry.externalFileAttributes >>> 16) & 0o170000) === 0o120000) {
          throw new PluginBootstrapError(
            `Plugin ZIP contains an unsafe path: ${entry.fileName}`,
          );
        }
        if (entry.uncompressedSize > MAX_ZIP_ENTRY_SIZE) {
          throw new PluginBootstrapError(
            `Plugin ZIP entry exceeds the safety limit: ${entry.fileName}`,
          );
        }
        expandedSize += entry.uncompressedSize;
        if (expandedSize > MAX_ZIP_EXPANDED_SIZE) {
          throw new PluginBootstrapError(
            "Plugin ZIP expanded size exceeds the safety limit.",
          );
        }
        const mode = (entry.externalFileAttributes >>> 16) & 0o170000;
        const directory =
          entry.fileName.endsWith("/") ||
          mode === 0o040000 ||
          (entry.versionMadeBy >>> 8 === 0 &&
            entry.externalFileAttributes === 16);
        if (!directory) {
          checksums.push({ path, checksum: entry.crc32 >>> 0 });
        }
      },
    });
    for (const { path, checksum } of checksums) {
      throwIfSignalAborted(signal);
      const bytes = await readFile(join(staging, ...path.split("/")));
      if (crc32(bytes) !== checksum) {
        throw new PluginBootstrapError(
          `Plugin ZIP entry failed CRC-32 validation: ${path}`,
        );
      }
    }
    const pluginRoot = await discoverPluginRoot(staging);
    throwIfSignalAborted(signal);
    const relativeRoot = relative(staging, pluginRoot);
    await rename(staging, destination);
    return await validatePluginRoot(join(destination, relativeRoot));
  } catch (error) {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined);
    throwIfSignalAborted(signal);
    if (error instanceof PluginBootstrapError) throw error;
    throw new PluginBootstrapError(`Invalid plugin ZIP: ${archivePath}`, {
      cause: error,
    });
  }
}

async function rejectBackslashZipNames(
  path: string,
  signal?: AbortSignal,
): Promise<void> {
  const handle = await open(path, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size < 22) {
      throw new Error("missing end of central directory");
    }
    const tailSize = Math.min(metadata.size, 65_557);
    const tail = await readExactly(
      handle,
      tailSize,
      metadata.size - tailSize,
      signal,
    );
    let end = tail.byteLength - 22;
    while (
      end >= 0 &&
      (tail.readUInt32LE(end) !== 0x06054b50 ||
        end + 22 + tail.readUInt16LE(end + 20) !== tail.byteLength)
    ) {
      end -= 1;
    }
    if (end < 0) throw new Error("missing end of central directory");
    const entries = tail.readUInt16LE(end + 10);
    const centralSize = tail.readUInt32LE(end + 12);
    const centralOffset = tail.readUInt32LE(end + 16);
    if (
      entries === 0xffff ||
      centralSize === 0xffffffff ||
      centralOffset === 0xffffffff
    ) {
      throw new Error("unsupported ZIP64 archive");
    }
    if (entries > MAX_ZIP_ENTRIES) {
      throw new PluginBootstrapError(
        `Plugin ZIP contains too many entries: ${entries}.`,
      );
    }
    if (centralSize > MAX_ZIP_CENTRAL_DIRECTORY) {
      throw new PluginBootstrapError(
        "Plugin ZIP central directory exceeds the safety limit.",
      );
    }
    const endOffset = metadata.size - tailSize + end;
    if (centralOffset + centralSize > endOffset) {
      throw new Error("invalid central directory bounds");
    }
    const central = await readExactly(
      handle,
      centralSize,
      centralOffset,
      signal,
    );
    let offset = 0;
    for (let index = 0; index < entries; index += 1) {
      if (
        offset + 46 > central.byteLength ||
        central.readUInt32LE(offset) !== 0x02014b50
      ) {
        throw new Error("invalid central directory");
      }
      const nameLength = central.readUInt16LE(offset + 28);
      const extraLength = central.readUInt16LE(offset + 30);
      const commentLength = central.readUInt16LE(offset + 32);
      const nameStart = offset + 46;
      const nameEnd = nameStart + nameLength;
      if (nameEnd > central.byteLength) {
        throw new Error("invalid central directory name");
      }
      if (central.subarray(nameStart, nameEnd).includes(0x5c)) {
        throw new PluginBootstrapError(
          "Plugin ZIP contains a backslash-qualified path.",
        );
      }
      offset = nameEnd + extraLength + commentLength;
    }
    if (offset !== central.byteLength) {
      throw new Error("invalid central directory size");
    }
  } finally {
    await handle.close();
  }
}

export async function resolvePluginPath(
  pluginPath: string | undefined,
  workspace: string,
  signal?: AbortSignal,
): Promise<string> {
  if (pluginPath === undefined) {
    return await bundledPluginRoot();
  }

  const path = resolve(expandHome(pluginPath));
  const metadata = await lstat(path).catch(() => null);
  if (metadata?.isFile() && extname(path).toLowerCase() === ".zip") {
    return await extractPluginZip(
      path,
      join(workspace, "extracted-plugin"),
      signal,
    );
  }
  if (metadata?.isDirectory() && !metadata.isSymbolicLink()) {
    throwIfSignalAborted(signal);
    return await validatePluginRoot(path);
  }
  throw new PluginBootstrapError(
    `Plugin path must be a directory or ZIP: ${path}`,
  );
}

export async function createMarketplace(
  codexHome: string,
  pluginRoot: string,
  signal?: AbortSignal,
): Promise<string> {
  throwIfSignalAborted(signal);
  const root = await realpath(pluginRoot);
  const marketplace = join(codexHome, "sdk-marketplace");
  const pluginDestination = join(marketplace, "plugins", PLUGIN_NAME);
  const projectionContract = join(
    root,
    ".internal",
    "external-promotion",
    "external-projection-contract.json",
  );
  if (
    root === (await bundledPluginRoot()) &&
    (await isRegularFile(projectionContract))
  ) {
    await copyExternalPayload(root, pluginDestination);
  } else {
    await copyPluginTree(root, pluginDestination, signal);
  }
  throwIfSignalAborted(signal);
  const manifest = {
    name: MARKETPLACE_NAME,
    interface: { displayName: "Codex Security SDK" },
    plugins: [
      {
        name: PLUGIN_NAME,
        source: { source: "local", path: `./plugins/${PLUGIN_NAME}` },
        policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
        category: "Security",
      },
    ],
  };
  const manifestPath = join(
    marketplace,
    ".agents",
    "plugins",
    "marketplace.json",
  );
  await mkdir(dirname(manifestPath), { recursive: true, mode: 0o700 });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: "utf8",
    flag: "wx",
    mode: 0o600,
    signal,
  });
  throwIfSignalAborted(signal);
  return marketplace;
}

export function resolveCodexCommand(): CodexCommand {
  const { packageName, targetTriple } = codexPlatformPackage();
  const require = createRequire(import.meta.url);
  const codexPackageJson = require.resolve("@openai/codex/package.json");
  const packageJson = createRequire(codexPackageJson).resolve(
    `${packageName}/package.json`,
  );
  const command = join(
    dirname(packageJson),
    "vendor",
    targetTriple,
    "bin",
    process.platform === "win32" ? "codex.exe" : "codex",
  );
  if (!existsSync(command)) {
    throw new PluginBootstrapError(
      `The ${packageName} package does not contain the Codex executable for ${targetTriple}.`,
    );
  }
  return { command, prefixArgs: [] };
}

export function codexPlatformPackage(
  platform: NodeJS.Platform = process.platform,
  architecture: string = process.arch,
): { packageName: string; targetTriple: string } {
  const key = `${platform}:${architecture}`;
  const target: readonly [string, string] | undefined = {
    "android:arm64": [
      "@openai/codex-linux-arm64",
      "aarch64-unknown-linux-musl",
    ],
    "android:x64": ["@openai/codex-linux-x64", "x86_64-unknown-linux-musl"],
    "darwin:arm64": ["@openai/codex-darwin-arm64", "aarch64-apple-darwin"],
    "darwin:x64": ["@openai/codex-darwin-x64", "x86_64-apple-darwin"],
    "linux:arm64": ["@openai/codex-linux-arm64", "aarch64-unknown-linux-musl"],
    "linux:x64": ["@openai/codex-linux-x64", "x86_64-unknown-linux-musl"],
    "win32:arm64": ["@openai/codex-win32-arm64", "aarch64-pc-windows-msvc"],
    "win32:x64": ["@openai/codex-win32-x64", "x86_64-pc-windows-msvc"],
  }[key] as readonly [string, string] | undefined;
  if (target === undefined) {
    throw new PluginBootstrapError(
      `Codex does not support this platform: ${platform} (${architecture}).`,
    );
  }
  return { packageName: target[0], targetTriple: target[1] };
}

export async function bootstrapPlugin(
  codexHome: string,
  pluginRoot: string,
  options: {
    codexCommand?: CodexCommand;
    runCodex?: (
      command: CodexCommand,
      args: readonly string[],
      environment: ProcessEnvironment,
      signal?: AbortSignal,
    ) => Promise<string>;
    environment?: ProcessEnvironment;
    signal?: AbortSignal;
  } = {},
): Promise<PluginInstall> {
  const root = await realpath(pluginRoot);
  const { name, version } = await pluginMetadata(root);
  const marketplace = await createMarketplace(codexHome, root, options.signal);
  const command = options.codexCommand ?? resolveCodexCommand();
  const environment = {
    ...(options.environment ?? process.env),
    CODEX_HOME: codexHome,
  };
  const run = options.runCodex ?? runCodex;
  await run(
    command,
    ["plugin", "marketplace", "add", marketplace],
    environment,
    options.signal,
  );
  await run(
    command,
    ["plugin", "add", `${PLUGIN_NAME}@${MARKETPLACE_NAME}`],
    environment,
    options.signal,
  );
  await verifyPluginRegistration(codexHome, marketplace);
  const installedRoot = await findInstalledPlugin(codexHome);
  const installed = await pluginMetadata(installedRoot);
  if (installed.name !== name || installed.version !== version) {
    throw new PluginBootstrapError(
      "Installed Codex Security plugin metadata does not match the selected plugin.",
    );
  }
  return {
    pluginRoot: root,
    marketplaceRoot: marketplace,
    installedRoot,
    marketplaceName: MARKETPLACE_NAME,
    name,
    version,
  };
}

export async function pluginMetadata(
  root: string,
): Promise<{ name: typeof PLUGIN_NAME; version: string }> {
  const manifestPath = join(root, ".codex-plugin", "plugin.json");
  let manifest: unknown;
  try {
    const expected = await lstat(manifestPath);
    if (
      !expected.isFile() ||
      expected.isSymbolicLink() ||
      expected.size > MAX_PLUGIN_MANIFEST_SIZE
    ) {
      throw new Error("plugin manifest is not a bounded regular file");
    }
    const input = await open(
      manifestPath,
      constants.O_RDONLY |
        (process.platform === "win32"
          ? 0
          : constants.O_NOFOLLOW | constants.O_NONBLOCK),
    );
    try {
      const opened = await input.stat();
      if (!samePluginFile(expected, opened)) {
        throw new Error("plugin manifest changed before reading");
      }
      const bytes = await readExactly(input, expected.size, 0);
      if (!samePluginFile(expected, await input.stat())) {
        throw new Error("plugin manifest changed while reading");
      }
      manifest = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
    } finally {
      await input.close();
    }
  } catch (error) {
    throw new PluginBootstrapError(`Invalid Codex plugin directory: ${root}`, {
      cause: error,
    });
  }
  if (!isRecord(manifest) || manifest["name"] !== PLUGIN_NAME) {
    throw new PluginBootstrapError(
      "Plugin manifest must have name 'codex-security'.",
    );
  }
  const version = manifest["version"];
  if (typeof version !== "string" || version.trim().length === 0) {
    throw new PluginBootstrapError(
      "Plugin manifest must have a non-empty version.",
    );
  }
  return { name: PLUGIN_NAME, version };
}

export async function resolvePluginPython(
  options: PluginPythonOptions = {},
): Promise<string> {
  const environment = options.environment ?? process.env;
  const protectedRoot = options.protectedRoot ?? process.cwd();
  if (options.configuredPath !== undefined) {
    return await requirePython(
      options.configuredPath,
      "configured plugin Python",
      environment,
      protectedRoot,
      options.signal,
    );
  }
  const inherited = environment["PYTHON"]?.trim();
  if (inherited) {
    return await requirePython(
      inherited,
      "PYTHON",
      environment,
      protectedRoot,
      options.signal,
    );
  }

  const home = options.homeDirectory ?? homedir();
  const managedRoots = options.managedRuntimeRoots ?? [
    join(home, ".cache", "codex-runtimes", "codex-primary-runtime"),
  ];
  const relativeCandidates =
    process.platform === "win32"
      ? [
          join("dependencies", "python", "python.exe"),
          join("dependencies", "python", "python", "python.exe"),
          join("dependencies", "python", "bin", "python.exe"),
        ]
      : [
          join("dependencies", "python", "bin", "python3"),
          join("dependencies", "python", "bin", "python"),
        ];
  for (const root of managedRoots) {
    for (const relativeCandidate of relativeCandidates) {
      const candidate = join(root, relativeCandidate);
      const resolved = await usablePython(
        candidate,
        environment,
        protectedRoot,
        options.signal,
      );
      if (resolved !== null) return resolved;
    }
  }

  for (const candidate of process.platform === "win32"
    ? ["python", "python3"]
    : ["python3", "python"]) {
    const resolved = await usablePython(
      candidate,
      environment,
      protectedRoot,
      options.signal,
    );
    if (resolved !== null) return resolved;
  }
  throw new PluginPythonUnavailableError(
    "The bundled Codex Security plugin requires Python 3.10 or later (Python 3.10 also requires tomli), but no usable interpreter was found. " +
      "Set pythonPath, --python, or PYTHON, install the Codex managed runtime, or add python3/python to PATH.",
  );
}

export function pluginExecutionEnvironment(
  python: string,
  environment: ProcessEnvironment = process.env,
): ProcessEnvironment {
  return { ...environment, PYTHON: python };
}

export async function cleanupSdkDirectory(path: string): Promise<void> {
  await rm(path, { recursive: true, force: true });
}

async function runCodex(
  command: CodexCommand,
  args: readonly string[],
  environment: ProcessEnvironment,
  signal?: AbortSignal,
): Promise<string> {
  try {
    const { stdout } = await execFile(
      command.command,
      [...command.prefixArgs, ...args],
      {
        env: environment,
        encoding: "utf8",
        signal,
      },
    );
    return stdout;
  } catch (error) {
    const detail = processErrorDetail(error);
    throw new PluginBootstrapError(`Codex plugin bootstrap failed: ${detail}`, {
      cause: error,
    });
  }
}

async function findInstalledPlugin(codexHome: string): Promise<string> {
  const root = join(
    codexHome,
    "plugins",
    "cache",
    MARKETPLACE_NAME,
    PLUGIN_NAME,
  );
  const candidates: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true }).catch(
    () => [],
  )) {
    if (entry.isDirectory()) {
      const candidate = join(root, entry.name);
      if (await hasPluginManifest(candidate)) candidates.push(candidate);
    }
  }
  if (candidates.length !== 1) {
    throw new PluginBootstrapError(
      "Codex plugin install did not produce one installed Codex Security plugin.",
    );
  }
  return await realpath(candidates[0]!);
}

async function discoverPluginRoot(root: string): Promise<string> {
  if (await hasPluginManifest(root)) return await validatePluginRoot(root);
  const children = (await readdir(root, { withFileTypes: true })).filter(
    (entry) => entry.isDirectory(),
  );
  if (children.length === 1) {
    const candidate = join(root, children[0]!.name);
    if (await hasPluginManifest(candidate))
      return await validatePluginRoot(candidate);
  }
  throw new PluginBootstrapError(
    "Plugin ZIP must contain Codex Security at its root or in one top-level directory.",
  );
}

async function validatePluginRoot(root: string): Promise<string> {
  await pluginMetadata(root);
  return await realpath(root);
}

async function verifyPluginRegistration(
  codexHome: string,
  marketplace: string,
): Promise<void> {
  const configPath = join(codexHome, "config.toml");
  let config: unknown;
  try {
    config = parse(await readFile(configPath, "utf8"));
  } catch (error) {
    throw new PluginBootstrapError(
      "Codex plugin bootstrap produced an unreadable config.toml.",
      {
        cause: error,
      },
    );
  }
  const marketplaces = isRecord(config) ? config["marketplaces"] : undefined;
  const plugins = isRecord(config) ? config["plugins"] : undefined;
  const marketplaceConfig = isRecord(marketplaces)
    ? marketplaces[MARKETPLACE_NAME]
    : undefined;
  const pluginConfig = isRecord(plugins)
    ? plugins[`${PLUGIN_NAME}@${MARKETPLACE_NAME}`]
    : undefined;
  if (!isRecord(marketplaceConfig) || !isRecord(pluginConfig)) {
    throw new PluginBootstrapError(
      "Codex plugin bootstrap did not preserve plugin registration.",
    );
  }
  const registeredSource = String(marketplaceConfig["source"] ?? "");
  if (!(await sameFile(registeredSource, marketplace))) {
    throw new PluginBootstrapError(
      "Codex plugin marketplace registration has the wrong source.",
    );
  }
  if (pluginConfig["enabled"] !== true) {
    throw new PluginBootstrapError(
      "Codex Security plugin is not enabled after bootstrap.",
    );
  }
}

async function copyPluginTree(
  source: string,
  destination: string,
  signal?: AbortSignal,
): Promise<void> {
  const pending: Array<{ source: string; destination: string }> = [
    { source, destination },
  ];
  const directories = new Map<string, Stats>();
  let entries = 0;
  let size = 0;
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  try {
    while (pending.length > 0) {
      throwIfSignalAborted(signal);
      const current = pending.pop()!;
      await requirePluginAncestors(source, current.source, directories, signal);
      const metadata = await lstat(current.source);
      if (++entries > MAX_PLUGIN_COPY_ENTRIES) {
        throw new PluginBootstrapError(
          `Plugin source exceeds the copy entry limit: ${current.source}`,
        );
      }
      if (metadata.isSymbolicLink()) {
        throw new PluginBootstrapError(
          `Plugin contains an unsafe source path: ${current.source}`,
        );
      }
      if (metadata.isDirectory()) {
        const children = await readdir(current.source);
        const afterRead = await lstat(current.source);
        if (!samePluginFile(metadata, afterRead)) {
          throw new PluginBootstrapError(
            `Plugin directory changed while it was being copied: ${current.source}`,
          );
        }
        directories.set(current.source, afterRead);
        await mkdir(current.destination, { mode: 0o700 });
        for (const child of children) {
          pending.push({
            source: join(current.source, child),
            destination: join(current.destination, child),
          });
        }
        continue;
      }
      if (!metadata.isFile()) {
        throw new PluginBootstrapError(
          `Plugin contains a non-regular file: ${current.source}`,
        );
      }
      if (metadata.size > MAX_PLUGIN_COPY_FILE_SIZE) {
        throw new PluginBootstrapError(
          `Plugin source exceeds the per-file safety limit: ${current.source}`,
        );
      }
      size += metadata.size;
      if (size > MAX_PLUGIN_COPY_SIZE) {
        throw new PluginBootstrapError(
          "Plugin source exceeds the copy safety limit.",
        );
      }
      const input = await open(
        current.source,
        constants.O_RDONLY |
          (process.platform === "win32"
            ? 0
            : constants.O_NOFOLLOW | constants.O_NONBLOCK),
      );
      let output: Awaited<ReturnType<typeof open>> | undefined;
      try {
        if (!samePluginFile(metadata, await input.stat())) {
          throw new PluginBootstrapError(
            `Plugin source changed before it could be copied: ${current.source}`,
          );
        }
        await requirePluginAncestors(
          source,
          current.source,
          directories,
          signal,
        );
        const bytes = await readExactly(input, metadata.size, 0, signal);
        if (!samePluginFile(metadata, await input.stat())) {
          throw new PluginBootstrapError(
            `Plugin source changed while it was being copied: ${current.source}`,
          );
        }
        await requirePluginAncestors(
          source,
          current.source,
          directories,
          signal,
        );
        output = await open(
          current.destination,
          constants.O_WRONLY |
            constants.O_CREAT |
            constants.O_EXCL |
            (process.platform === "win32" ? 0 : constants.O_NOFOLLOW),
          0o600,
        );
        await output.writeFile(bytes);
        await output.chmod(metadata.mode & 0o777);
      } finally {
        await output?.close();
        await input.close();
      }
    }
  } catch (error) {
    await rm(destination, { recursive: true, force: true });
    throw error;
  }
}

async function requirePluginAncestors(
  root: string,
  path: string,
  directories: ReadonlyMap<string, Stats>,
  signal?: AbortSignal,
): Promise<void> {
  const relativePath = relative(root, path);
  if (
    relativePath === ".." ||
    relativePath.startsWith(`..${sep}`) ||
    isAbsolute(relativePath)
  ) {
    throw new PluginBootstrapError(
      `Plugin source path escapes its root: ${path}`,
    );
  }
  if (relativePath === "") return;

  let ancestor = root;
  const parents = ["", ...relativePath.split(sep).slice(0, -1)];
  for (const component of parents) {
    throwIfSignalAborted(signal);
    if (component !== "") ancestor = join(ancestor, component);
    const expected = directories.get(ancestor);
    const actual = await lstat(ancestor);
    if (
      expected === undefined ||
      actual.isSymbolicLink() ||
      !actual.isDirectory() ||
      !samePluginFile(expected, actual)
    ) {
      throw new PluginBootstrapError(
        `Plugin source directory changed while it was being copied: ${ancestor}`,
      );
    }
  }
}

function samePluginFile(first: Stats, second: Stats): boolean {
  return (
    first.dev === second.dev &&
    first.ino === second.ino &&
    first.size === second.size &&
    first.mtimeMs === second.mtimeMs &&
    first.mode === second.mode &&
    first.isFile() === second.isFile() &&
    first.isDirectory() === second.isDirectory()
  );
}

async function readExactly(
  handle: Awaited<ReturnType<typeof open>>,
  length: number,
  position: number,
  signal?: AbortSignal,
): Promise<Buffer> {
  const buffer = Buffer.alloc(length);
  let offset = 0;
  while (offset < length) {
    throwIfSignalAborted(signal);
    const { bytesRead } = await handle.read(
      buffer,
      offset,
      length - offset,
      position + offset,
    );
    if (bytesRead === 0) throw new Error("unexpected end of plugin file");
    offset += bytesRead;
  }
  return buffer;
}

async function copyExternalPayload(
  source: string,
  destination: string,
): Promise<void> {
  const contractPath = join(
    source,
    ".internal",
    "external-promotion",
    "external-projection-contract.json",
  );
  let contract: unknown;
  try {
    contract = JSON.parse(await readFile(contractPath, "utf8"));
  } catch (error) {
    throw new PluginBootstrapError(
      `Invalid plugin projection contract: ${contractPath}`,
      {
        cause: error,
      },
    );
  }
  const shippedExact = isRecord(contract)
    ? contract["shippedExact"]
    : undefined;
  if (
    !Array.isArray(shippedExact) ||
    !shippedExact.every((value) => typeof value === "string")
  ) {
    throw new PluginBootstrapError(
      "Plugin projection contract must contain shippedExact paths.",
    );
  }
  const paths = [".codex-plugin/plugin.json", ...shippedExact].filter(
    (value) => !value.startsWith("sdk/"),
  );
  for (const path of paths) {
    const normalized = safeArchivePath(path);
    const sourcePath = join(source, ...normalized.split("/"));
    const destinationPath = join(destination, ...normalized.split("/"));
    const metadata = await lstat(sourcePath).catch(() => null);
    if (metadata === null || !metadata.isFile() || metadata.isSymbolicLink()) {
      throw new PluginBootstrapError(
        `Bundled plugin file is missing or unsafe: ${sourcePath}`,
      );
    }
    await mkdir(dirname(destinationPath), { recursive: true, mode: 0o700 });
    await copyFile(sourcePath, destinationPath, constants.COPYFILE_EXCL);
  }
}

function safeArchivePath(value: string): string {
  const parts = value.split("/");
  const normalized = parts
    .filter((part) => part !== "" && part !== ".")
    .join("/");
  if (
    value.length === 0 ||
    value.startsWith("/") ||
    value.startsWith("//") ||
    /^[A-Za-z]:/.test(value) ||
    parts.includes("..") ||
    value.includes("\\") ||
    value.includes("\0") ||
    parts.some((part) => part.includes(":")) ||
    normalized.length === 0
  ) {
    throw new PluginBootstrapError(
      `Plugin ZIP contains an unsafe path: ${value}`,
    );
  }
  return normalized;
}

async function requirePython(
  candidate: string,
  source: string,
  environment: ProcessEnvironment,
  protectedRoot: string,
  signal?: AbortSignal,
): Promise<string> {
  const resolved = await usablePython(
    candidate,
    environment,
    protectedRoot,
    signal,
  );
  if (resolved !== null) return resolved;
  throw new PluginPythonUnavailableError(
    `The ${source} interpreter is unavailable or unusable: ${candidate}. ` +
      "The bundled Codex Security plugin requires Python 3.10 or later for scan execution; Python 3.10 also requires tomli.",
  );
}

async function usablePython(
  candidate: string,
  environment: ProcessEnvironment = process.env,
  protectedRoot: string = process.cwd(),
  signal?: AbortSignal,
): Promise<string | null> {
  const command = await resolveTrustedExecutable(
    isPythonPathCandidate(candidate) ? expandHome(candidate) : candidate,
    environment,
    protectedRoot,
  );
  if (command === null) return null;
  try {
    const { stdout } = await execFile(
      command.executable,
      [
        "-I",
        "-c",
        "import importlib.util,sys\nif sys.version_info < (3, 10): raise SystemExit(1)\nif sys.version_info < (3, 11) and importlib.util.find_spec('tomli') is None: raise SystemExit(1)\nprint('codex-security-python-ok')",
      ],
      {
        env: command.environment,
        encoding: "utf8",
        timeout: 5_000,
        windowsHide: true,
        signal,
      },
    );
    return stdout.trim() === "codex-security-python-ok"
      ? command.executable
      : null;
  } catch (error) {
    if (signal?.aborted) throw error;
    return null;
  }
}

export function isPythonPathCandidate(candidate: string): boolean {
  return (
    candidate.includes("/") ||
    candidate.includes("\\") ||
    candidate.startsWith(".")
  );
}

async function hasPluginManifest(root: string): Promise<boolean> {
  return await isRegularFile(join(root, ".codex-plugin", "plugin.json"));
}

async function isRegularFile(path: string): Promise<boolean> {
  try {
    const metadata = await lstat(path);
    return metadata.isFile() && !metadata.isSymbolicLink();
  } catch {
    return false;
  }
}

async function sameFile(left: string, right: string): Promise<boolean> {
  try {
    const [leftMetadata, rightMetadata] = await Promise.all([
      stat(left),
      stat(right),
    ]);
    return (
      leftMetadata.dev === rightMetadata.dev &&
      leftMetadata.ino === rightMetadata.ino
    );
  } catch {
    return false;
  }
}

export function expandHome(value: string): string {
  if (value === "~") return homedir();
  if (value.startsWith("~/") || value.startsWith("~\\")) {
    return join(homedir(), value.slice(2));
  }
  return value;
}

function safePrefix(value: string): string {
  return basename(value).replace(/[^A-Za-z0-9._-]/g, "-") || "repository";
}

function processErrorDetail(error: unknown): string {
  if (isRecord(error)) {
    for (const key of ["stderr", "stdout", "message"] as const) {
      const value = error[key];
      if (typeof value === "string" && value.trim()) return value.trim();
      if (value instanceof Uint8Array) {
        const decoded = new TextDecoder().decode(value).trim();
        if (decoded) return decoded;
      }
    }
  }
  return String(error) || "unknown error";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nodeErrorCode(error: unknown): string | undefined {
  return isRecord(error) && typeof error["code"] === "string"
    ? error["code"]
    : undefined;
}

function abortReason(signal: AbortSignal): unknown {
  return (
    signal.reason ??
    new DOMException("The operation was aborted.", "AbortError")
  );
}

function throwIfSignalAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortReason(signal);
}

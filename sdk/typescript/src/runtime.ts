import { execFile as execFileCallback } from "node:child_process";
import { constants, createReadStream, existsSync, type Stats } from "node:fs";
import {
  access,
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
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { parse } from "smol-toml";
import { Unzip, UnzipInflate, type UnzipFile } from "fflate";
import {
  OutputDirectoryError,
  PluginBootstrapError,
  PluginPythonUnavailableError,
} from "./errors.js";

const execFile = promisify(execFileCallback);

export const MARKETPLACE_NAME = "codex-security-sdk";
export const PLUGIN_NAME = "codex-security";

const MAX_ZIP_ENTRIES = 4_096;
const MAX_ZIP_CENTRAL_DIRECTORY = 16 * 1024 * 1024;
const MAX_ZIP_ENTRY_SIZE = 128 * 1024 * 1024;
const MAX_ZIP_EXPANDED_SIZE = 512 * 1024 * 1024;
const CRC32_TABLE = Uint32Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) !== 0 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});

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
  signal?: AbortSignal;
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
): Promise<string | null> {
  if (outputDirectory === undefined) {
    return null;
  }
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
      if ((await readdir(path)).length !== 0) {
        throw new OutputDirectoryError(
          `Scan output directory must be empty: ${path}`,
        );
      }
      return await realpath(path);
    }

    let parent = dirname(path);
    while (true) {
      try {
        if ((await stat(parent)).isDirectory()) {
          return resolve(
            await realpath(parent),
            path.slice(parent.length).replace(/^[/\\]+/, ""),
          );
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

export async function prepareOutputDir(
  outputDirectory: string | undefined,
  repositoryName: string,
  temporaryRoot: string = tmpdir(),
  validateLocation?: (path: string) => void,
): Promise<string> {
  const path = await validateOutputDir(outputDirectory);
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
  let createdRootMetadata: Pick<Stats, "dev" | "ino"> | undefined;
  try {
    const existing = await lstat(path).catch((error: unknown) => {
      if (nodeErrorCode(error) === "ENOENT") return null;
      throw error;
    });
    if (existing === null) {
      createdRoot = await mkdir(path, { recursive: true, mode: 0o700 });
      if (createdRoot === undefined) {
        throw new OutputDirectoryError(
          `Scan output directory changed during preparation: ${path}`,
        );
      }
      if ((process.umask() & 0o700) !== 0) await chmod(path, 0o700);
      createdRootMetadata = await lstat(createdRoot);
    }
    return await validatePreparedOutputDir(path, validateLocation);
  } catch (error) {
    if (createdRoot !== undefined && createdRootMetadata !== undefined) {
      await removeEmptyDirectories(path, createdRoot, createdRootMetadata);
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
  expected?: Pick<Stats, "dev" | "ino">,
): Promise<string> {
  const before = await lstat(path);
  const canonical = await realpath(path);
  validateLocation?.(canonical);
  const entries = await readdir(canonical);
  const current = await lstat(path);
  const returned = await lstat(canonical);
  if (
    !before.isDirectory() ||
    before.isSymbolicLink() ||
    !current.isDirectory() ||
    current.isSymbolicLink() ||
    !returned.isDirectory() ||
    returned.isSymbolicLink() ||
    before.dev !== current.dev ||
    before.ino !== current.ino ||
    before.dev !== returned.dev ||
    before.ino !== returned.ino ||
    (expected !== undefined &&
      (before.dev !== expected.dev || before.ino !== expected.ino))
  ) {
    throw new OutputDirectoryError(
      `Scan output directory changed during preparation: ${path}`,
    );
  }
  if (entries.length !== 0) {
    throw new OutputDirectoryError(
      `Scan output directory must be empty: ${path}`,
    );
  }
  return canonical;
}

async function removeEmptyDirectories(
  path: string,
  root: string,
  expected: Pick<Stats, "dev" | "ino">,
): Promise<void> {
  try {
    const currentRoot = await lstat(root);
    if (
      !currentRoot.isDirectory() ||
      currentRoot.isSymbolicLink() ||
      currentRoot.dev !== expected.dev ||
      currentRoot.ino !== expected.ino
    ) {
      return;
    }
  } catch {
    return;
  }
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
  let inspected: ZipEntry[];
  try {
    inspected = await inspectZipFile(archivePath, signal);
  } catch (error) {
    throwIfSignalAborted(signal);
    if (error instanceof PluginBootstrapError) throw error;
    throw new PluginBootstrapError(`Invalid plugin ZIP: ${archivePath}`, {
      cause: error,
    });
  }

  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  const staging = await realpath(
    await mkdtemp(join(dirname(destination), ".codex-security-plugin-")),
  );
  try {
    throwIfSignalAborted(signal);
    await streamZipEntries(archivePath, staging, inspected, signal);
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

export async function resolvePluginPath(
  pluginPath: string | undefined,
  workspace: string,
  signal?: AbortSignal,
): Promise<string> {
  if (pluginPath === undefined) {
    const source = await bundledPluginRoot();
    const projectionContract = join(
      source,
      ".internal",
      "external-promotion",
      "external-projection-contract.json",
    );
    if (await isRegularFile(projectionContract)) {
      const destination = join(workspace, "bundled-plugin");
      await copyExternalPayload(source, destination);
      return await validatePluginRoot(destination);
    }
    return source;
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
    return await validatePluginRoot(path);
  }
  throw new PluginBootstrapError(
    `Plugin path must be a directory or ZIP: ${path}`,
  );
}

export async function createMarketplace(
  codexHome: string,
  pluginRoot: string,
): Promise<string> {
  const root = await validatePluginRoot(pluginRoot);
  const marketplace = join(codexHome, "sdk-marketplace");
  const pluginDestination = join(marketplace, "plugins", PLUGIN_NAME);
  await copyPluginTree(root, pluginDestination);
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
  });
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
  const root = await validatePluginRoot(pluginRoot);
  const { name, version } = await pluginMetadata(root);
  const marketplace = await createMarketplace(codexHome, root);
  const command = options.codexCommand ?? resolveCodexCommand();
  const environment = {
    ...withoutApiKeyCredentials(options.environment ?? process.env),
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

function withoutApiKeyCredentials(
  environment: ProcessEnvironment,
): ProcessEnvironment {
  const sanitized = { ...environment };
  for (const name of Object.keys(sanitized)) {
    if (
      name.toUpperCase() === "OPENAI_API_KEY" ||
      name.toUpperCase() === "CODEX_API_KEY"
    ) {
      delete sanitized[name];
    }
  }
  return sanitized;
}

export async function pluginMetadata(
  root: string,
): Promise<{ name: typeof PLUGIN_NAME; version: string }> {
  const manifestPath = join(root, ".codex-plugin", "plugin.json");
  let manifest: unknown;
  try {
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
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
  if (options.configuredPath !== undefined) {
    return await requirePython(
      options.configuredPath,
      "configured plugin Python",
      environment,
      options.signal,
    );
  }
  const inherited = environment["PYTHON"]?.trim();
  if (inherited) {
    return await requirePython(
      inherited,
      "PYTHON",
      environment,
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
        options.signal,
      );
      if (resolved !== null) return resolved;
    }
  }

  for (const candidate of process.platform === "win32"
    ? ["python", "python3"]
    : ["python3", "python"]) {
    const resolved = await usablePython(candidate, environment, options.signal);
    if (resolved !== null) return resolved;
  }
  throw new PluginPythonUnavailableError(
    "The unchanged Codex Security plugin requires Python, but no usable interpreter was found. " +
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
): Promise<void> {
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  await copyTree(source, destination);
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

async function copyTree(source: string, destination: string): Promise<void> {
  const sourceMetadata = await lstat(source);
  if (sourceMetadata.isSymbolicLink()) {
    throw new PluginBootstrapError(
      `Plugin contains a symbolic link: ${source}`,
    );
  }
  if (sourceMetadata.isDirectory()) {
    await mkdir(destination, { recursive: false, mode: 0o700 });
    for (const entry of await readdir(source)) {
      await copyTree(join(source, entry), join(destination, entry));
    }
    return;
  }
  if (!sourceMetadata.isFile()) {
    throw new PluginBootstrapError(
      `Plugin contains a non-regular file: ${source}`,
    );
  }
  await copyFile(source, destination, constants.COPYFILE_EXCL);
}

interface ZipEntry {
  localHeaderOffset: number;
  normalized: string;
  streamName: string;
  crc32: number;
  directory: boolean;
  uncompressedSize: number;
}

async function inspectZipFile(
  path: string,
  signal?: AbortSignal,
): Promise<ZipEntry[]> {
  throwIfSignalAborted(signal);
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
    const view = new DataView(tail.buffer, tail.byteOffset, tail.byteLength);
    const eocd = findEndOfCentralDirectory(view);
    const commentLength = view.getUint16(eocd + 20, true);
    if (eocd + 22 + commentLength !== tail.byteLength) {
      throw new Error("invalid end of central directory");
    }
    const disk = view.getUint16(eocd + 4, true);
    const centralDisk = view.getUint16(eocd + 6, true);
    const diskEntries = view.getUint16(eocd + 8, true);
    const entries = view.getUint16(eocd + 10, true);
    const centralSize = view.getUint32(eocd + 12, true);
    const centralOffset = view.getUint32(eocd + 16, true);
    if (
      disk !== 0 ||
      centralDisk !== 0 ||
      diskEntries !== entries ||
      entries === 0xffff ||
      centralSize === 0xffffffff ||
      centralOffset === 0xffffffff
    ) {
      throw new Error("unsupported multi-disk or ZIP64 archive");
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
    const eocdOffset = metadata.size - tailSize + eocd;
    if (centralOffset + centralSize > eocdOffset) {
      throw new Error("invalid central directory bounds");
    }
    const central = await readExactly(
      handle,
      centralSize,
      centralOffset,
      signal,
    );
    return inspectCentralDirectory(central, entries, centralOffset);
  } finally {
    await handle.close();
  }
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
    if (bytesRead === 0) throw new Error("unexpected end of ZIP archive");
    offset += bytesRead;
  }
  return buffer;
}

function inspectCentralDirectory(
  data: Uint8Array,
  entries: number,
  centralOffset: number,
): ZipEntry[] {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;
  const result = new Map<string, ZipEntry>();
  const localHeaderOffsets = new Set<number>();
  let expandedSize = 0;
  for (let index = 0; index < entries; index += 1) {
    if (
      offset + 46 > view.byteLength ||
      view.getUint32(offset, true) !== 0x02014b50
    ) {
      throw new Error("invalid central directory");
    }
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const flags = view.getUint16(offset + 8, true);
    const compression = view.getUint16(offset + 10, true);
    const crc32 = view.getUint32(offset + 16, true);
    const uncompressedSize = view.getUint32(offset + 24, true);
    const externalAttributes = view.getUint32(offset + 38, true);
    const localHeaderOffset = view.getUint32(offset + 42, true);
    const nameStart = offset + 46;
    const nameEnd = nameStart + nameLength;
    if (nameEnd > view.byteLength)
      throw new Error("invalid central directory name");
    const nameBytes = data.subarray(nameStart, nameEnd);
    const utf8Name = (flags & 0x800) !== 0;
    const name = decodeZipName(nameBytes, utf8Name);
    const streamName = utf8Name
      ? name
      : Buffer.from(nameBytes).toString("latin1");
    const normalized = safeArchivePath(name);
    if ((flags & 0x1) !== 0 || (compression !== 0 && compression !== 8)) {
      throw new PluginBootstrapError(
        `Plugin ZIP uses unsupported encryption or compression: ${name}`,
      );
    }
    const unixMode = externalAttributes >>> 16;
    if ((unixMode & 0xf000) === 0xa000) {
      throw new PluginBootstrapError(
        `Plugin ZIP contains an unsafe path: ${name}`,
      );
    }
    if (result.has(normalized)) {
      throw new PluginBootstrapError(
        `Plugin ZIP contains a duplicate path: ${name}`,
      );
    }
    if (
      localHeaderOffset >= centralOffset ||
      localHeaderOffsets.has(localHeaderOffset)
    ) {
      throw new Error("invalid local header offset");
    }
    localHeaderOffsets.add(localHeaderOffset);
    if (uncompressedSize > MAX_ZIP_ENTRY_SIZE) {
      throw new PluginBootstrapError(
        `Plugin ZIP entry exceeds the safety limit: ${name}`,
      );
    }
    expandedSize += uncompressedSize;
    if (expandedSize > MAX_ZIP_EXPANDED_SIZE) {
      throw new PluginBootstrapError(
        "Plugin ZIP expanded size exceeds the safety limit.",
      );
    }
    result.set(normalized, {
      localHeaderOffset,
      normalized,
      streamName,
      crc32,
      directory: name.endsWith("/") || (unixMode & 0xf000) === 0x4000,
      uncompressedSize,
    });
    offset = nameEnd + extraLength + commentLength;
  }
  if (offset !== data.byteLength) {
    throw new Error("invalid central directory size");
  }
  return [...result.values()].sort(
    (left, right) => left.localHeaderOffset - right.localHeaderOffset,
  );
}

async function streamZipEntries(
  archivePath: string,
  destination: string,
  inspected: readonly ZipEntry[],
  signal?: AbortSignal,
): Promise<void> {
  const setups: Promise<void>[] = [];
  const completions: Promise<void>[] = [];
  const pendingWrites: Promise<void>[] = [];
  const cancelers: Array<(error: unknown) => void> = [];
  const seen = new Set<string>();
  let entryIndex = 0;
  let callbackFailure: unknown;
  const unzip = new Unzip((file) => {
    try {
      const metadata = inspected[entryIndex++];
      if (metadata === undefined || file.name !== metadata.streamName) {
        throw new PluginBootstrapError(
          `Plugin ZIP contains an unindexed path: ${file.name}`,
        );
      }
      const normalized = metadata.normalized;
      if (seen.has(normalized)) {
        throw new PluginBootstrapError(
          `Plugin ZIP contains a duplicate path: ${file.name}`,
        );
      }
      seen.add(normalized);
      const extraction = createZipEntryExtraction(
        file,
        join(destination, ...normalized.split("/")),
        metadata,
        pendingWrites,
        signal,
      );
      setups.push(extraction.setup);
      completions.push(extraction.completion);
      cancelers.push(extraction.cancel);
      void extraction.completion.catch(() => undefined);
    } catch (error) {
      callbackFailure = error;
      file.terminate();
    }
  });
  unzip.register(UnzipInflate);
  let setupIndex = 0;
  const input = createReadStream(archivePath, {
    highWaterMark: 64 * 1024,
    signal,
  });
  try {
    for await (const chunk of input) {
      throwIfSignalAborted(signal);
      if (callbackFailure !== undefined) throw callbackFailure;
      unzip.push(chunk, false);
      await Promise.all(setups.slice(setupIndex));
      setupIndex = setups.length;
      await drainPendingWrites(pendingWrites);
    }
    unzip.push(new Uint8Array(), true);
    await Promise.all(setups.slice(setupIndex));
    await drainPendingWrites(pendingWrites);
    if (callbackFailure !== undefined) throw callbackFailure;
    await Promise.all(completions);
    if (seen.size !== inspected.length) {
      throw new PluginBootstrapError(
        "Plugin ZIP central directory does not match its file entries.",
      );
    }
  } catch (error) {
    input.destroy();
    for (const cancel of cancelers) cancel(error);
    await Promise.allSettled([...setups, ...completions, ...pendingWrites]);
    throwIfSignalAborted(signal);
    throw error;
  }
}

function createZipEntryExtraction(
  file: UnzipFile,
  target: string,
  metadata: ZipEntry,
  pendingWrites: Promise<void>[],
  signal?: AbortSignal,
): {
  setup: Promise<void>;
  completion: Promise<void>;
  cancel: (error: unknown) => void;
} {
  let resolveCompletion!: () => void;
  let rejectCompletion!: (error: unknown) => void;
  const completion = new Promise<void>((resolvePromise, reject) => {
    resolveCompletion = resolvePromise;
    rejectCompletion = reject;
  });
  let settled = false;
  let handle: Awaited<ReturnType<typeof open>> | null = null;
  let writeChain = Promise.resolve();
  let written = 0;
  let crc32 = 0xffffffff;
  const closeHandle = async (): Promise<void> => {
    const current = handle;
    handle = null;
    if (current !== null) await current.close();
  };
  const removeAbortListener = (): void =>
    signal?.removeEventListener("abort", onAbort);

  const fail = (error: unknown): void => {
    if (settled) return;
    settled = true;
    removeAbortListener();
    file.terminate();
    const close = writeChain.catch(() => undefined).then(closeHandle);
    pendingWrites.push(close);
    void close.then(
      () => rejectCompletion(error),
      () => rejectCompletion(error),
    );
  };
  const onAbort = (): void => fail(abortReason(signal!));
  if (signal?.aborted) fail(abortReason(signal));
  else signal?.addEventListener("abort", onAbort, { once: true });

  const setup = (async () => {
    if (settled) return;
    if (
      file.originalSize !== undefined &&
      file.originalSize !== metadata.uncompressedSize
    ) {
      throw new PluginBootstrapError(
        `Plugin ZIP entry size does not match its index: ${file.name}`,
      );
    }
    if (metadata.directory) {
      await mkdir(target, { recursive: true, mode: 0o700 });
      if (settled) return;
      file.ondata = (error, data, final) => {
        if (error !== null) return fail(error);
        crc32 = updateCrc32(crc32, data);
        if (data.length > 0) {
          return fail(
            new PluginBootstrapError(
              `Plugin ZIP directory contains data: ${file.name}`,
            ),
          );
        }
        if (final && !settled) {
          if ((crc32 ^ 0xffffffff) >>> 0 !== metadata.crc32) {
            return fail(
              new PluginBootstrapError(
                `Plugin ZIP entry failed CRC-32 validation: ${file.name}`,
              ),
            );
          }
          settled = true;
          removeAbortListener();
          resolveCompletion();
        }
      };
      file.start();
      return;
    }

    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    if (settled) return;
    const opened = await open(target, "wx", 0o600);
    if (settled) {
      await opened.close();
      return;
    }
    handle = opened;
    file.ondata = (error, data, final) => {
      if (error !== null) return fail(error);
      if (settled) return;
      written += data.length;
      crc32 = updateCrc32(crc32, data);
      if (written > metadata.uncompressedSize || written > MAX_ZIP_ENTRY_SIZE) {
        return fail(
          new PluginBootstrapError(
            `Plugin ZIP entry exceeds its declared size: ${file.name}`,
          ),
        );
      }
      writeChain = writeChain.then(async () => {
        if (data.length > 0) await writeAll(handle!, data);
      });
      pendingWrites.push(writeChain);
      if (final) {
        const finish = writeChain.then(async () => {
          if (written !== metadata.uncompressedSize) {
            throw new PluginBootstrapError(
              `Plugin ZIP entry size does not match its index: ${file.name}`,
            );
          }
          if ((crc32 ^ 0xffffffff) >>> 0 !== metadata.crc32) {
            throw new PluginBootstrapError(
              `Plugin ZIP entry failed CRC-32 validation: ${file.name}`,
            );
          }
          await closeHandle();
          if (!settled) {
            settled = true;
            removeAbortListener();
            resolveCompletion();
          }
        });
        pendingWrites.push(finish);
        void finish.catch(fail);
      }
    };
    file.start();
  })();
  void setup.catch(fail);
  return { setup, completion, cancel: fail };
}

async function writeAll(
  handle: Awaited<ReturnType<typeof open>>,
  data: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < data.length) {
    const { bytesWritten } = await handle.write(
      data,
      offset,
      data.length - offset,
    );
    if (bytesWritten === 0) {
      throw new PluginBootstrapError(
        "Plugin ZIP extraction stopped before a complete entry was written.",
      );
    }
    offset += bytesWritten;
  }
}

async function drainPendingWrites(writes: Promise<void>[]): Promise<void> {
  while (writes.length > 0) await Promise.all(writes.splice(0));
}

function updateCrc32(crc: number, data: Uint8Array): number {
  let value = crc;
  for (const byte of data) {
    value = CRC32_TABLE[(value ^ byte) & 0xff]! ^ (value >>> 8);
  }
  return value >>> 0;
}

function findEndOfCentralDirectory(view: DataView): number {
  const minimum = Math.max(0, view.byteLength - 65_557);
  for (let offset = view.byteLength - 22; offset >= minimum; offset -= 1) {
    if (view.getUint32(offset, true) === 0x06054b50) return offset;
  }
  throw new Error("missing end of central directory");
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
  signal?: AbortSignal,
): Promise<string> {
  const resolved = await usablePython(candidate, environment, signal);
  if (resolved !== null) return resolved;
  throw new PluginPythonUnavailableError(
    `The ${source} interpreter is unavailable or unusable: ${candidate}. ` +
      "The unchanged Codex Security plugin requires Python for scan execution.",
  );
}

async function usablePython(
  candidate: string,
  environment: ProcessEnvironment = process.env,
  signal?: AbortSignal,
): Promise<string | null> {
  let executable = candidate;
  if (isPythonPathCandidate(candidate)) {
    try {
      executable = resolve(expandHome(candidate));
      await access(
        executable,
        process.platform === "win32" ? constants.F_OK : constants.X_OK,
      );
      executable = await realpath(executable);
    } catch (error) {
      if (signal?.aborted) throw signal.reason ?? error;
      return null;
    }
  }
  try {
    const { stdout } = await execFile(
      executable,
      [
        "-c",
        "import importlib.util,sys\nif sys.version_info < (3, 10): raise SystemExit(1)\nif sys.version_info < (3, 11) and importlib.util.find_spec('tomli') is None: raise SystemExit(1)\nprint('codex-security-python-ok')",
      ],
      {
        env: environment,
        encoding: "utf8",
        timeout: 5_000,
        windowsHide: true,
        signal,
      },
    );
    return stdout.trim() === "codex-security-python-ok" ? executable : null;
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

function expandHome(value: string): string {
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

const CP437_EXTENDED =
  "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";

function decodeZipName(bytes: Uint8Array, utf8: boolean): string {
  if (utf8) return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  let decoded = "";
  for (const byte of bytes) {
    decoded +=
      byte < 0x80 ? String.fromCharCode(byte) : CP437_EXTENDED[byte - 0x80]!;
  }
  return decoded;
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

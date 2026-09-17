import { accessSync, constants as fsConstants, existsSync, promises as fs, readdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { delimiter, dirname, isAbsolute, join, resolve, win32 } from "node:path";

export async function snapshotNativeEnvironment(): Promise<Record<string, string>> {
  const environment = Object.fromEntries(
    Object.entries(process.env)
      .filter((entry): entry is [string, string] => entry[1] !== undefined)
      .map(([name, value]) => [process.platform === "win32" ? name.toUpperCase() : name, value])
  );
  const codexHome = environment.CODEX_HOME;
  if (codexHome !== undefined && codexHome.length > 0 && !codexHome.trim()) {
    delete environment.CODEX_HOME;
  } else if (codexHome !== undefined && codexHome.length > 0) {
    // Resolve symlink/.. paths before consumers normalize them or change cwd.
    environment.CODEX_HOME = await fs.realpath(codexHome);
  }
  return environment;
}

export function resolveCodexPath(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  architecture: NodeJS.Architecture = process.arch,
  originalCwd: string = process.cwd()
): string {
  const searchPath = searchPathForPlatform(env, platform);
  const configured = environmentVariable(env, "CODEX_CLI_PATH", platform)?.trim();
  if (configured && (platform !== "win32" || !isWindowsAppsPath(configured))) {
    if (isBareCommandName(configured)) {
      const executableName = platform === "win32" && !configured.toLowerCase().endsWith(".exe")
        ? `${configured}.exe`
        : configured;
      const fromSearchPath = platform === "win32"
        ? configured === "codex" || configured === "codex.exe"
          ? resolveWindowsCodexFromSearchPath(searchPath, architecture, originalCwd)
          : resolveWindowsDirectFromSearchPath(searchPath, executableName, originalCwd)
        : resolveFromSearchPath(searchPath, executableName, originalCwd);
      if (fromSearchPath) return fromSearchPath;
    }
    return absoluteCodexPath(configured, platform, originalCwd);
  }

  if (platform !== "win32") {
    return resolveFromSearchPath(searchPath, "codex", originalCwd)
      ?? resolve(originalCwd, "codex");
  }

  const managedPackageRoot = environmentVariable(env, "CODEX_MANAGED_PACKAGE_ROOT", platform)?.trim();
  if (managedPackageRoot) {
    const managedBinary = resolveWindowsPackageBinary(
      absoluteCodexPath(managedPackageRoot, platform, originalCwd),
      architecture
    );
    if (managedBinary && !isWindowsAppsPath(managedBinary)) return managedBinary;
  }

  const pathBinary = resolveWindowsCodexFromSearchPath(
    searchPath,
    architecture,
    originalCwd
  );
  if (pathBinary) return pathBinary;

  const localAppData = environmentVariable(env, "LOCALAPPDATA", platform)?.trim();
  return resolveWindowsCachedBinary(
    localAppData ? absoluteCodexPath(localAppData, platform, originalCwd) : undefined
  ) ?? resolve(originalCwd, "codex.exe");
}

function searchPathForPlatform(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform
): string | undefined {
  if (platform !== "win32") return env.PATH?.trim() ? env.PATH : undefined;
  return Object.entries(env)
    .find(([name, value]) => name.toLowerCase() === "path" && value?.trim())?.[1];
}

function environmentVariable(
  env: NodeJS.ProcessEnv,
  name: string,
  platform: NodeJS.Platform
): string | undefined {
  const value = env[name];
  if (value !== undefined || platform !== "win32") return value;
  return Object.entries(env)
    .find(([key]) => key.toUpperCase() === name)?.[1];
}

function isBareCommandName(value: string): boolean {
  return !value.includes("/")
    && !value.includes("\\")
    && !/^[A-Za-z]:/.test(value);
}

function resolveFromSearchPath(
  searchPath: string | undefined,
  executableName: string,
  originalCwd: string
): string | undefined {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const candidate = join(
      absoluteSearchDirectory(directory, originalCwd),
      executableName
    );
    if (isExecutableFile(candidate)) return candidate;
  }
  return undefined;
}

function resolveWindowsDirectFromSearchPath(
  searchPath: string | undefined,
  executableName: string,
  originalCwd: string
): string | undefined {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const candidate = join(
      absoluteSearchDirectory(directory, originalCwd),
      executableName
    );
    if (!isWindowsAppsPath(candidate) && existsSync(candidate)) return candidate;
  }
  return undefined;
}

function resolveWindowsCodexFromSearchPath(
  searchPath: string | undefined,
  architecture: NodeJS.Architecture,
  originalCwd: string
): string | undefined {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const absoluteDirectory = absoluteSearchDirectory(directory, originalCwd);
    const directBinary = join(absoluteDirectory, "codex.exe");
    if (!isWindowsAppsPath(directBinary) && existsSync(directBinary)) return directBinary;

    const packageRoot = join(absoluteDirectory, "node_modules", "@openai", "codex");
    const nativeBinary = resolveWindowsPackageBinary(packageRoot, architecture);
    if (nativeBinary && !isWindowsAppsPath(nativeBinary)) return nativeBinary;
  }
  return undefined;
}

function isWindowsAppsPath(candidate: string): boolean {
  return /(?:^|[\\/])windowsapps(?:[\\/]|$)/iu.test(candidate);
}

function resolveWindowsCachedBinary(localAppData: string | undefined): string | undefined {
  const root = localAppData?.trim();
  if (!root) return undefined;

  const cacheRoot = join(root, "OpenAI", "Codex", "bin");
  let selected: { path: string; modifiedAt: number } | undefined;
  try {
    for (const entry of readdirSync(cacheRoot, { withFileTypes: true })) {
      if (!entry.isDirectory() || !/^[a-f0-9]{8,128}$/iu.test(entry.name)) continue;
      const candidate = join(cacheRoot, entry.name, "codex.exe");
      let metadata: ReturnType<typeof statSync>;
      try {
        metadata = statSync(candidate);
      } catch {
        continue;
      }
      if (!metadata.isFile() || metadata.size === 0 || isWindowsAppsPath(candidate)) continue;
      if (
        !selected
        || metadata.mtimeMs > selected.modifiedAt
        || (metadata.mtimeMs === selected.modifiedAt && candidate > selected.path)
      ) {
        selected = { path: candidate, modifiedAt: metadata.mtimeMs };
      }
    }
  } catch {
    return undefined;
  }
  return selected?.path;
}

function isExecutableFile(value: string): boolean {
  try {
    if (!statSync(value).isFile()) return false;
    accessSync(value, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function absoluteSearchDirectory(directory: string, originalCwd: string): string {
  return resolve(originalCwd, directory || ".");
}

function absoluteCodexPath(
  value: string,
  platform: NodeJS.Platform,
  originalCwd: string
): string {
  if (platform === "win32" && isNativeWindowsRootRelativePath(value)) {
    // A rooted Windows path still depends on the original drive.
    return win32.resolve(originalCwd, value);
  }
  if (isAbsolute(value) || (platform === "win32" && win32.isAbsolute(value))) {
    return value;
  }
  return resolve(originalCwd, value);
}

function isNativeWindowsRootRelativePath(value: string): boolean {
  if (process.platform !== "win32") return false;
  const root = win32.parse(value).root;
  return root === "\\" || root === "/";
}

function resolveWindowsPackageBinary(
  packageRoot: string,
  architecture: NodeJS.Architecture
): string | undefined {
  const packageJson = join(packageRoot, "package.json");
  if (!existsSync(packageJson)) return undefined;

  const targetTriple = architecture === "arm64"
    ? "aarch64-pc-windows-msvc"
    : architecture === "x64"
      ? "x86_64-pc-windows-msvc"
      : undefined;
  if (!targetTriple) return undefined;

  try {
    const platformPackageJson = createRequire(packageJson)
      .resolve(`@openai/codex-win32-${architecture}/package.json`);
    const nativeBinary = join(
      dirname(platformPackageJson),
      "vendor",
      targetTriple,
      "bin",
      "codex.exe"
    );
    return existsSync(nativeBinary) ? nativeBinary : undefined;
  } catch {
    return undefined;
  }
}

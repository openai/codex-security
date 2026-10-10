import {
  accessSync,
  constants as fsConstants,
  existsSync,
  readdirSync,
  statSync,
} from "node:fs";
import { createRequire } from "node:module";
import {
  delimiter,
  dirname,
  isAbsolute,
  join,
  resolve,
  win32,
} from "node:path";
import {
  expandHome,
  resolveNativeCodexHome,
} from "../../../../sdk/typescript/src/codex-home.js";
import {
  resolveTrustedExecutable,
  type TrustedExecutable,
} from "../../../../sdk/typescript/src/trusted-executable.js";

export async function resolveTrustedCodex(
  environment: NodeJS.ProcessEnv,
  protectedRoot: string | readonly string[],
  platform: NodeJS.Platform = process.platform,
  originalCwd: string = process.cwd(),
  architecture: NodeJS.Architecture = process.arch,
): Promise<TrustedExecutable | null> {
  for (const candidate of codexPathCandidates(
    environment,
    platform,
    originalCwd,
    architecture,
  )) {
    if (platform === "win32" && isWindowsAppsPath(candidate)) continue;
    const codex = await resolveTrustedExecutable(
      candidate,
      environment,
      protectedRoot,
    );
    if (codex !== null) return codex;
  }
  return null;
}

export async function snapshotNativeEnvironment(): Promise<
  Record<string, string>
> {
  const environment = Object.fromEntries(
    Object.entries(process.env)
      .filter((entry): entry is [string, string] => entry[1] !== undefined)
      .map(([name, value]) => [
        process.platform === "win32" ? name.toUpperCase() : name,
        value,
      ]),
  );
  const codexHome = environment.CODEX_HOME;
  if (codexHome !== undefined && codexHome.length > 0 && !codexHome.trim()) {
    delete environment.CODEX_HOME;
  } else if (codexHome !== undefined && codexHome.length > 0) {
    // Resolve symlink/.. paths before consumers normalize them or change cwd.
    environment.CODEX_HOME = await resolveNativeCodexHome(
      codexHome,
      environment,
    );
  }
  return environment;
}

export function resolveCodexPath(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  originalCwd: string = process.cwd(),
  architecture: NodeJS.Architecture = process.arch,
): string {
  return codexPathCandidates(env, platform, originalCwd, architecture).next()
    .value!;
}

function* codexPathCandidates(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
  originalCwd: string,
  architecture: NodeJS.Architecture,
): Generator<string> {
  const requested = environmentVariable(
    env,
    "CODEX_CLI_PATH",
    platform,
  )?.trim();
  const configured =
    platform === "win32" && requested && isWindowsAppsPath(requested)
      ? undefined
      : requested;
  const command = configured || "codex";
  if (platform === "win32" && !configured) {
    const managedRoot = environmentVariable(
      env,
      "CODEX_MANAGED_PACKAGE_ROOT",
      platform,
    )?.trim();
    if (managedRoot) {
      const binary = resolveWindowsPackageBinary(
        absoluteCodexPath(managedRoot, platform, originalCwd),
        architecture,
      );
      if (binary) yield binary;
    }
  }
  if (isBareCommandName(command)) {
    const executableName =
      platform === "win32" && !command.toLowerCase().endsWith(".exe")
        ? `${command}.exe`
        : command;
    const searchPath = searchPathForPlatform(env, platform);
    yield* platform === "win32"
      ? resolveWindowsDirectFromSearchPath(
          searchPath,
          executableName,
          originalCwd,
          architecture,
        )
      : resolveFromSearchPath(searchPath, executableName, originalCwd);
  }
  if (platform === "win32" && !configured) {
    const localAppData = environmentVariable(
      env,
      "LOCALAPPDATA",
      platform,
    )?.trim();
    if (localAppData) {
      const cached = resolveWindowsCachedBinary(
        absoluteCodexPath(localAppData, platform, originalCwd),
      );
      if (cached) yield cached;
    }
  }
  yield absoluteCodexPath(
    expandHome(
      configured || (platform === "win32" ? "codex.exe" : "codex"),
      env,
    ),
    platform,
    originalCwd,
  );
}

function searchPathForPlatform(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
): string | undefined {
  if (platform !== "win32") return env.PATH?.trim() ? env.PATH : undefined;
  return Object.entries(env).find(
    ([name, value]) => name.toLowerCase() === "path" && value?.trim(),
  )?.[1];
}

function environmentVariable(
  env: NodeJS.ProcessEnv,
  name: string,
  platform: NodeJS.Platform,
): string | undefined {
  const value = env[name];
  if (value !== undefined || platform !== "win32") return value;
  return Object.entries(env).find(([key]) => key.toUpperCase() === name)?.[1];
}

function isBareCommandName(value: string): boolean {
  return (
    !value.includes("/") && !value.includes("\\") && !/^[A-Za-z]:/.test(value)
  );
}

function* resolveFromSearchPath(
  searchPath: string | undefined,
  executableName: string,
  originalCwd: string,
): Generator<string> {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const candidate = join(
      absoluteSearchDirectory(directory, originalCwd),
      executableName,
    );
    if (isExecutableFile(candidate)) yield candidate;
  }
}

function* resolveWindowsDirectFromSearchPath(
  searchPath: string | undefined,
  executableName: string,
  originalCwd: string,
  architecture: NodeJS.Architecture,
): Generator<string> {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const absoluteDirectory = absoluteWindowsSearchDirectory(
      directory,
      originalCwd,
    );
    const candidate = join(absoluteDirectory, executableName);
    if (!isWindowsAppsPath(candidate) && isExecutableFile(candidate))
      yield candidate;
    if (executableName.toLowerCase() === "codex.exe") {
      const binary = resolveWindowsPackageBinary(
        join(absoluteDirectory, "node_modules", "@openai", "codex"),
        architecture,
      );
      if (binary) yield binary;
    }
  }
}

function resolveWindowsPackageBinary(
  packageRoot: string,
  architecture: NodeJS.Architecture,
): string | undefined {
  const packageJson = join(packageRoot, "package.json");
  if (!existsSync(packageJson)) return undefined;
  const target =
    architecture === "arm64"
      ? "aarch64-pc-windows-msvc"
      : architecture === "x64"
        ? "x86_64-pc-windows-msvc"
        : undefined;
  if (!target) return undefined;
  try {
    const platformPackage = createRequire(packageJson).resolve(
      `@openai/codex-win32-${architecture}/package.json`,
    );
    const binary = join(
      dirname(platformPackage),
      "vendor",
      target,
      "bin",
      "codex.exe",
    );
    return !isWindowsAppsPath(binary) && isExecutableFile(binary)
      ? binary
      : undefined;
  } catch {
    return undefined;
  }
}

function isWindowsAppsPath(candidate: string): boolean {
  return /(?:^|[\\/])windowsapps(?:[\\/]|$)/iu.test(candidate);
}

function resolveWindowsCachedBinary(localAppData: string): string | undefined {
  const cacheRoot = join(localAppData, "OpenAI", "Codex", "bin");
  let selected: { path: string; modifiedAt: number } | undefined;
  try {
    for (const entry of readdirSync(cacheRoot, { withFileTypes: true })) {
      if (!entry.isDirectory() || !/^[a-f0-9]{8,128}$/iu.test(entry.name))
        continue;
      const candidate = join(cacheRoot, entry.name, "codex.exe");
      let metadata: ReturnType<typeof statSync>;
      try {
        metadata = statSync(candidate);
      } catch {
        continue;
      }
      if (
        !metadata.isFile() ||
        metadata.size === 0 ||
        isWindowsAppsPath(candidate)
      )
        continue;
      if (
        !selected ||
        metadata.mtimeMs > selected.modifiedAt ||
        (metadata.mtimeMs === selected.modifiedAt && candidate > selected.path)
      )
        selected = { path: candidate, modifiedAt: metadata.mtimeMs };
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

function absoluteSearchDirectory(
  directory: string,
  originalCwd: string,
): string {
  return resolve(originalCwd, directory || ".");
}

function absoluteWindowsSearchDirectory(
  directory: string,
  originalCwd: string,
): string {
  if (directory.startsWith('"') && directory.endsWith('"')) {
    directory = directory.slice(1, -1);
  }
  return absoluteSearchDirectory(directory, originalCwd);
}

function absoluteCodexPath(
  value: string,
  platform: NodeJS.Platform,
  originalCwd: string,
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

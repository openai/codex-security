import {
  accessSync,
  constants as fsConstants,
  promises as fs,
  statSync,
} from "node:fs";
import { delimiter, isAbsolute, join, resolve, win32 } from "node:path";
import {
  resolveTrustedExecutable,
  type TrustedExecutable,
} from "../../../../sdk/typescript/src/trusted-executable.js";

export async function resolveTrustedCodex(
  environment: NodeJS.ProcessEnv,
  protectedRoot: string,
  platform: NodeJS.Platform = process.platform,
  originalCwd: string = process.cwd(),
): Promise<TrustedExecutable | null> {
  for (const candidate of codexPathCandidates(
    environment,
    platform,
    originalCwd,
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
    environment.CODEX_HOME = await fs.realpath(codexHome);
  }
  return environment;
}

export function resolveCodexPath(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  originalCwd: string = process.cwd(),
): string {
  return codexPathCandidates(env, platform, originalCwd).next().value!;
}

function* codexPathCandidates(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
  originalCwd: string,
): Generator<string> {
  const configured = environmentVariable(
    env,
    "CODEX_CLI_PATH",
    platform,
  )?.trim();
  const command = configured || "codex";
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
        )
      : resolveFromSearchPath(searchPath, executableName, originalCwd);
  }
  yield absoluteCodexPath(
    configured || (platform === "win32" ? "codex.exe" : "codex"),
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
): Generator<string> {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const candidate = join(
      absoluteWindowsSearchDirectory(directory, originalCwd),
      executableName,
    );
    if (!isWindowsAppsPath(candidate) && isExecutableFile(candidate))
      yield candidate;
  }
}

function isWindowsAppsPath(candidate: string): boolean {
  return /(?:^|[\\/])windowsapps(?:[\\/]|$)/iu.test(candidate);
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
  return platform === "win32"
    ? resolve(originalCwd, value)
    : `${originalCwd}/${value}`;
}

function isNativeWindowsRootRelativePath(value: string): boolean {
  if (process.platform !== "win32") return false;
  const root = win32.parse(value).root;
  return root === "\\" || root === "/";
}

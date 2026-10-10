import { lstat, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join, parse, resolve, sep, win32 } from "node:path";
import type { ProcessEnvironment } from "./runtime.js";

/** @internal */
export function environmentEntry(
  environment: ProcessEnvironment,
  requested: string,
): string | undefined {
  const exact = environment[requested];
  if (exact !== undefined || process.platform !== "win32") return exact;
  const upper = requested.toUpperCase();
  return Object.entries(environment).find(
    ([name]) => name.toUpperCase() === upper,
  )?.[1];
}

/** @internal */
export function configuredCodexHome(environment: ProcessEnvironment): string {
  const configured = environmentEntry(environment, "CODEX_HOME");
  return resolve(
    expandHome(
      configured?.trim() ? configured : join(homedir(), ".codex"),
      environment,
    ),
  );
}

export function expandHome(
  value: string,
  environment: ProcessEnvironment = process.env,
): string {
  const home =
    (process.platform === "win32"
      ? (environmentValue(environment, "USERPROFILE") ??
        environmentValue(environment, "HOME"))
      : (environmentValue(environment, "HOME") ??
        environmentValue(environment, "USERPROFILE"))) ?? homedir();
  if (value === "~") return home;
  if (value.startsWith("~/")) return join(home, value.slice(2));
  if (value.startsWith("~\\")) {
    return join(home, ...value.slice(2).split("\\"));
  }
  return value;
}

export function environmentValue(
  environment: ProcessEnvironment,
  requested: string,
  preserveWhitespace = false,
): string | undefined {
  const value = rawEnvironmentValue(environment, requested);
  return preserveWhitespace ? value : value?.trim();
}

export function rawEnvironmentValue(
  environment: ProcessEnvironment,
  requested: string,
): string | undefined {
  const exact = environment[requested];
  if (exact !== undefined && exact.trim() !== "") return exact;
  const upper = requested.toUpperCase();
  for (const [name, value] of Object.entries(environment)) {
    if (
      name.toUpperCase() === upper &&
      value !== undefined &&
      value.trim() !== ""
    ) {
      return value;
    }
  }
  return undefined;
}

/** @internal Expand a home prefix without changing filesystem traversal. */
export function expandHomePath(
  value: string,
  environment: ProcessEnvironment,
): string {
  const path = value.startsWith("~\\") ? value.replaceAll("\\", "/") : value;
  // Expand only the home prefix; joining the suffix would collapse symlink/.. paths.
  return path.startsWith("~/")
    ? `${expandHome("~", environment)}${sep}${path.slice(2)}`
    : expandHome(path, environment);
}

/** @internal Resolve the home selected by native startup without changing its path semantics. */
export async function resolveNativeCodexHome(
  value: string,
  environment: ProcessEnvironment,
): Promise<string> {
  const home = expandHome(value, environment);
  return await realpath(home).catch((error: NodeJS.ErrnoException) => {
    const windowsRootRelative =
      process.platform === "win32" &&
      (win32.parse(home).root === "\\" || win32.parse(home).root === "/");
    // Runtime preparation creates an explicitly selected absolute home.
    if (error.code === "ENOENT" && isAbsolute(home) && !windowsRootRelative)
      return resolveMissingNativeHome(home);
    throw error;
  });
}

async function resolveMissingNativeHome(home: string): Promise<string> {
  const root = parse(home).root;
  let resolved = await realpath(root);
  const separator = process.platform === "win32" ? /[\\/]+/u : /\/+/u;
  for (const component of home.slice(root.length).split(separator)) {
    if (!component) continue;
    // Resolve each prefix before normalizing .., including after missing parents.
    const candidate = `${resolved}${sep}${component}`;
    try {
      resolved = await realpath(candidate);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const entry = await lstat(candidate).catch(
        (cause: NodeJS.ErrnoException) => {
          if (cause.code !== "ENOENT") throw cause;
          return undefined;
        },
      );
      // A dangling symlink is not a directory runtime preparation can create.
      if (entry !== undefined) throw error;
      resolved = join(resolved, component);
    }
  }
  return resolved;
}

import { homedir } from "node:os";
import { join, resolve } from "node:path";
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
  return resolve(
    expandHome(
      environmentEntry(environment, "CODEX_HOME")?.trim() ||
        join(homedir(), ".codex"),
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
): string | undefined {
  return rawEnvironmentValue(environment, requested)?.trim();
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

import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { runWithProtectedExecutableRoots } from "./shared/checkout/trusted-executable.js";

export {
  campaignCommandEnvironment,
  campaignExecutable,
  inspectTrustedExecutable,
  isWithin,
  resolveTrustedExecutable,
  type InspectedExecutable,
  type TrustedExecutable,
} from "./shared/checkout/trusted-executable.js";

async function bundledToolHelpers() {
  const { bundledPluginRoot } = await import("./bundled-plugin.js");
  const path = join(await bundledPluginRoot(), "mcp/helpers.mjs");
  return (await import(pathToFileURL(path).href)).default;
}

export async function trustedHostPathResolver(
  cwd: string,
  roots: readonly string[],
): Promise<(path: string) => string | null> {
  const { protectedHostPathResolver } = await bundledToolHelpers();
  if (typeof protectedHostPathResolver !== "function")
    throw new Error("The bundled plugin is missing host path protection.");
  return protectedHostPathResolver(cwd, roots);
}

async function campaignPathHelper() {
  const { inventoryToolPath: project } = await bundledToolHelpers();
  if (typeof project !== "function")
    throw new Error("The bundled plugin is missing campaign tool lookup.");
  return project;
}

/** Include every selected source when a campaign launches tools from a new checkout. */
export function withProtectedExecutableRoots<T>(
  roots: readonly string[],
  run: () => Promise<T>,
): Promise<T> {
  return runWithProtectedExecutableRoots(roots, run, campaignPathHelper);
}

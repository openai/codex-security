import { resolve } from "node:path";
import { expandHome } from "./runtime.js";

/** A config, SDK, or CLI path anchored to its input directory. */
export type AbsolutePath = string & { readonly __absolutePath: unique symbol };

export function resolveConfigPath(
  directory: string,
  value: string,
): AbsolutePath {
  return resolve(directory, expandHome(value)) as AbsolutePath;
}

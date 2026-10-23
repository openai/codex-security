import type { BuildOptions } from "esbuild";
export function privateDirectory(prefix: string): Promise<string>;
export function privateDirectories(...directories: string[]): Promise<void>;
export function loadSourceModule<Module = Record<string, unknown>>(
  url: URL,
  options?: BuildOptions,
): Promise<Module>;

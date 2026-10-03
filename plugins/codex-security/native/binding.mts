import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { nativeTarget } from "./platform.mjs";

export const root = dirname(fileURLToPath(import.meta.url));
export const output = join(root, "dist", nativeTarget);
export const binaryPath = join(
  output,
  process.platform === "win32" ? "windows.node" : "unix.node",
);

export interface DirectoryEntry {
  name: Buffer;
  isDirectory: boolean;
  isSymbolicLink: boolean;
  errno: number;
}

/** Paths, usernames, and home directories are uninterpreted POSIX bytes. */
export interface UnixBinding {
  /**
   * Filesystem order; known types are cached and symlinks are not followed.
   * Entry errno reports type-query errors; outer errno reports enumeration
   * failure with an empty value. With types disabled, no type query runs and
   * both flags are false with entry errno zero.
   */
  directoryEntries(
    name: Buffer,
    withTypes: boolean,
  ): { errno: number; value: DirectoryEntry[] };
  userHome(username: Buffer): { errno: number; value: Buffer | null };
}

export function loadBinding(): UnixBinding {
  return createRequire(import.meta.url)(binaryPath) as UnixBinding;
}

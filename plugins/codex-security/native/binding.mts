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

/** Usernames, home directories and environment values are uninterpreted POSIX bytes. */
export interface UnixBinding {
  unixEnvironment(name: Buffer): Buffer | null;
  userHome(username: Buffer): { errno: number; value: Buffer | null };
}

export function loadBinding(): UnixBinding {
  return createRequire(import.meta.url)(binaryPath) as UnixBinding;
}

import { createRequire } from "node:module";
import type { UnixBinding } from "../../native/binding.mjs";
import type { WindowsBinding } from "../../native/windows-binding.mjs";
import type {
  ScanReadBinding,
  ScanReadRoot,
} from "../../native/scan-read-binding.mjs";
import { nativeTarget } from "../../native/platform.mjs";
import { encodePosixPath } from "./helpers/posix-path.ts";

const binding = (name: string) =>
  createRequire(import.meta.url)(`./native/${nativeTarget}/${name}.node`);

export const unixBinding = (): UnixBinding => binding("unix");
export const windowsBinding = (): WindowsBinding => binding("windows");

export function openScanReadRoot(path: string): ScanReadRoot {
  const native: ScanReadBinding = binding(
    process.platform === "win32" ? "windows" : "unix",
  );
  return native.openScanReadRoot(
    process.platform === "win32"
      ? Buffer.from(path, "utf16le")
      : encodePosixPath(path),
  );
}

export type {
  ScanReadFile,
  ScanReadRoot,
} from "../../native/scan-read-binding.mjs";

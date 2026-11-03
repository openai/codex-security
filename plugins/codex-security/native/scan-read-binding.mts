import { createRequire } from "node:module";
import { binaryPath } from "./binding.mjs";

/** Owns a regular file opened beneath a held scan root. */
export interface ScanReadFile {
  read(size: number): Buffer;
  close(): void;
}

/** close() is idempotent; garbage collection also releases held handles. */
export interface ScanReadRoot {
  openFile(relativePath: string): ScanReadFile | null;
  verify(): void;
  close(): void;
}

export interface ScanReadBinding {
  /** POSIX path bytes on Unix; UTF-16LE code units on Windows. */
  openScanReadRoot(path: Buffer): ScanReadRoot;
}

export function loadScanReadBinding(): ScanReadBinding {
  return createRequire(import.meta.url)(binaryPath) as ScanReadBinding;
}

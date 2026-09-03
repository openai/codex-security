import { createRequire } from "node:module";
import { binaryPath } from "./binding.mjs";

export interface WindowsResult<T = number> {
  error: number;
  value: T;
}

/** Owns a synchronous Windows file. close() is idempotent; GC also closes it. */
export interface WindowsHandle {
  close(): number;
  attributes(): { error: number; attributes: number; reparseTag: number };
  identity(): { error: number; volume: string; fileId: Buffer };
  fileType(): WindowsResult;
  finalPath(flags: number): { error: number; path: Buffer };
  read(buffer: Buffer, offset: number, length: number): WindowsResult;
  write(buffer: Buffer, offset: number, length: number): WindowsResult;
  seek(distance: bigint, origin: number): WindowsResult<string>;
  size(): WindowsResult<string>;
  setEndOfFile(): number;
  flush(): number;
  rename(destination: Buffer, replace: boolean): number;
  setDisposition(deleteFile: boolean): number;
  /** Acquires an exclusive whole-file lock; contention returns Windows error 33. */
  lock(nonblocking: boolean): number;
  unlock(): number;
}

/** Paths are UTF-16LE code units without a terminator, including lone surrogates. */
export interface WindowsBinding {
  windowsArguments(): Buffer[];
  windowsEnvironment(name: Buffer): Buffer | null;
  windowsAbsolutePath(path: Buffer): WindowsResult<Buffer>;
  windowsDirectoryEntries(
    path: Buffer,
  ): WindowsResult<
    { name: Buffer; isDirectory: boolean; isSymbolicLink: boolean }[]
  >;
  openWindowsFile(
    path: Buffer,
    access: number,
    share: number,
    disposition: number,
    flags: number,
  ): { error: number; handle?: WindowsHandle | null };
  createWindowsDirectory(path: Buffer): number;
}

export { windowsFlags } from "./windows-flags.mjs";

export function loadWindowsBinding(): WindowsBinding {
  return createRequire(import.meta.url)(binaryPath) as WindowsBinding;
}

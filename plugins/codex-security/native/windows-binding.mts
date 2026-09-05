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

export const windowsFlags = {
  DELETE: 0x00010000,
  FILE_READ_ATTRIBUTES: 0x00000080,
  GENERIC_READ: 0x80000000,
  GENERIC_WRITE: 0x40000000,
  FILE_SHARE_READ: 1,
  FILE_SHARE_WRITE: 2,
  FILE_SHARE_DELETE: 4,
  CREATE_NEW: 1,
  CREATE_ALWAYS: 2,
  OPEN_EXISTING: 3,
  OPEN_ALWAYS: 4,
  FILE_ATTRIBUTE_DIRECTORY: 0x00000010,
  FILE_ATTRIBUTE_NORMAL: 0x00000080,
  FILE_ATTRIBUTE_REPARSE_POINT: 0x00000400,
  FILE_FLAG_BACKUP_SEMANTICS: 0x02000000,
  FILE_FLAG_OPEN_REPARSE_POINT: 0x00200000,
  FILE_FLAG_OVERLAPPED: 0x40000000,
  FILE_NAME_OPENED: 8,
  FILE_BEGIN: 0,
  FILE_CURRENT: 1,
  FILE_END: 2,
} as const;

export function loadWindowsBinding(): WindowsBinding {
  return createRequire(import.meta.url)(binaryPath) as WindowsBinding;
}

import { createRequire } from "node:module";
import { readSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { nativeTarget } from "./platform.mjs";

export const root = dirname(fileURLToPath(import.meta.url));
export const output = join(root, "dist", nativeTarget);
export const binaryPath = join(
  output,
  process.platform === "win32" ? "windows.node" : "unix.node",
);

export interface SyscallResult {
  value: number;
  errno: number;
}

export interface MetadataResult {
  errno: number;
  mode: number;
  device: string;
  inode: string;
}

export interface DirectoryEntry {
  name: Buffer;
  isDirectory: boolean;
  isSymbolicLink: boolean;
  errno: number;
}

/** Paths are uninterpreted POSIX bytes. */
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
  openAt(
    directory: number,
    name: Buffer,
    flags: number,
    mode: number,
  ): SyscallResult;
  duplicate(descriptor: number): SyscallResult;
  makeDirectoryAt(directory: number, name: Buffer, mode: number): SyscallResult;
  renameAt(
    oldDirectory: number,
    oldName: Buffer,
    newDirectory: number,
    newName: Buffer,
  ): SyscallResult;
  unlinkAt(directory: number, name: Buffer): SyscallResult;
  statAt(directory: number, name: Buffer): MetadataResult;
  readLinkAt(directory: number, name: Buffer): { errno: number; value: Buffer };
  fileLock(
    descriptor: number,
    unlock: boolean,
    nonblocking: boolean,
  ): SyscallResult;
  userHome(username: Buffer): { errno: number; value: Buffer | null };
}

export function loadBinding(): UnixBinding {
  return createRequire(import.meta.url)(binaryPath) as UnixBinding;
}

/** Retry the interrupted read, preserving the caller's previously read bytes. */
export function readDescriptor(
  fd: number,
  buffer: Buffer,
  offset: number,
  length: number,
  position: number | null,
): number {
  while (true) {
    try {
      return readSync(fd, buffer, offset, length, position);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EINTR") throw error;
    }
  }
}

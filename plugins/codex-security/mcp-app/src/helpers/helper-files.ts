import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  writeFileSync,
} from "node:fs";
import { windowsBinding } from "../native";
import { widePath, windowsFileSystem } from "../../../native/windows-files.mjs";
import { encodePosixPath } from "./posix-path";
import { escapeControls } from "./json";
import { parsedPath } from "./resolve-security-md";
import { decodeUtf8 } from "./utf8";

export function filesystemErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  // Keep terminal controls in filesystem diagnostics escaped.
  return error instanceof Error && ("errno" in error || "winerror" in error)
    ? escapeControls(message)
    : message;
}

export function normalizePath(path: string): string {
  if (process.platform === "win32") return parsedPath(path);
  const prefix =
    path.startsWith("//") && !path.startsWith("///")
      ? "//"
      : path.startsWith("/")
        ? "/"
        : "";
  // Remove empty/dot components without changing symlink-sensitive "..".
  return (
    prefix +
      path
        .split("/")
        .filter((part) => part && part !== ".")
        .join("/") || "."
  );
}

function readError(error: unknown, path: string, label?: string): never {
  const { code, winerror } = error as NodeJS.ErrnoException & {
    winerror?: number;
  };
  // Preserve pathlib.exists() diagnostics only for callers with missing-file labels.
  if (
    label !== undefined &&
    (["ENOENT", "ENOTDIR", "ELOOP"].includes(code ?? "") ||
      winerror === 21 ||
      winerror === 123)
  )
    throw new Error(`${label} missing: ${path}`);
  throw error;
}

export function readFile(path: string | number, label?: string): Buffer {
  if (typeof path === "number") return readFileSync(path);
  try {
    return process.platform === "win32"
      ? windowsFileSystem(windowsBinding()).readFile(widePath(path))
      : readFileSync(encodePosixPath(path));
  } catch (error) {
    return readError(error, path, label);
  }
}

function* readChunks(path: string, label?: string): Iterable<Buffer> {
  if (process.platform === "win32") {
    yield readFile(path, label);
    return;
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(encodePosixPath(path), "r");
    while (true) {
      const chunk = Buffer.allocUnsafe(64 * 1024);
      const length = readSync(descriptor, chunk, 0, chunk.length, null);
      if (length === 0) return;
      yield chunk.subarray(0, length);
    }
  } catch (error) {
    readError(error, path, label);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export function* readUtf8Lines(path: string, label?: string): Iterable<string> {
  let parts: Buffer[] = [];
  let skipLineFeed = false;
  for (const chunk of readChunks(path, label)) {
    let start = skipLineFeed && chunk[0] === 10 ? 1 : 0;
    skipLineFeed = false;
    for (let index = start; index < chunk.length; index++) {
      const byte = chunk[index];
      if (byte !== 10 && byte !== 13) continue;
      parts.push(chunk.subarray(start, index));
      yield decodeUtf8(parts.length === 1 ? parts[0]! : Buffer.concat(parts));
      parts = [];
      if (byte === 13) {
        if (chunk[index + 1] === 10) index++;
        else if (index + 1 === chunk.length) skipLineFeed = true;
      }
      start = index + 1;
    }
    if (start < chunk.length) parts.push(chunk.subarray(start));
  }
  if (parts.length)
    yield decodeUtf8(parts.length === 1 ? parts[0]! : Buffer.concat(parts));
}

export function mkdir(path: string): void {
  if (process.platform === "win32")
    windowsFileSystem(windowsBinding()).mkdir(widePath(path));
  else mkdirSync(encodePosixPath(path), { recursive: true });
}

export function writeFile(path: string, chunks: Iterable<Buffer>): void {
  if (process.platform === "win32") {
    windowsFileSystem(windowsBinding()).writeFile(widePath(path), chunks);
    return;
  }
  const descriptor = openSync(encodePosixPath(path), "w");
  try {
    for (const chunk of chunks) writeFileSync(descriptor, chunk);
  } finally {
    closeSync(descriptor);
  }
}

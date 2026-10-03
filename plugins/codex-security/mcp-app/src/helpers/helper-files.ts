import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { windowsBinding } from "../native";
import { widePath, windowsFileSystem } from "../../../native/windows-files.mjs";
import { encodePosixPath } from "./posix-path";
import { pythonRepr } from "./python-json";
import { parsedPath } from "./resolve-security-md";

export function filesystemErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  // Python OSError escapes terminal controls in filenames, unlike validation errors.
  return error instanceof Error && ("errno" in error || "winerror" in error)
    ? message.replace(/\p{Cc}/gu, (character) =>
        pythonRepr(character).slice(1, -1),
      )
    : message;
}

export function pythonPath(path: string): string {
  if (process.platform === "win32") return parsedPath(path);
  const prefix =
    path.startsWith("//") && !path.startsWith("///")
      ? "//"
      : path.startsWith("/")
        ? "/"
        : "";
  // pathlib removes dot/empty components, but preserves symlink-sensitive "..".
  return (
    prefix +
      path
        .split("/")
        .filter((part) => part && part !== ".")
        .join("/") || "."
  );
}

export function readFile(path: string | number): Buffer {
  if (typeof path === "number") return readFileSync(path);
  return process.platform === "win32"
    ? windowsFileSystem(windowsBinding()).readFile(widePath(path))
    : readFileSync(encodePosixPath(path));
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

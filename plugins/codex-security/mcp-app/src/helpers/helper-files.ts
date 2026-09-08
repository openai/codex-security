import { readFileSync } from "node:fs";
import { windowsBinding } from "../native";
import { widePath, windowsFileSystem } from "../../../native/windows-files.mjs";
import { encodePosixPath } from "./posix-path";
import { escapeControls } from "./json";
import { parsedPath } from "./resolve-security-md";

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

export function readFile(path: string | number): Buffer {
  if (typeof path === "number") return readFileSync(path);
  return process.platform === "win32"
    ? windowsFileSystem(windowsBinding()).readFile(widePath(path))
    : readFileSync(encodePosixPath(path));
}

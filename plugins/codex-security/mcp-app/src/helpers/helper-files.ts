import { readFileSync } from "node:fs";
import { windowsBinding } from "../native";
import { widePath, windowsFileSystem } from "../../../native/windows-files.mjs";
import { encodePosixPath } from "./posix-path";
import { pythonRepr } from "./python-json";

export function filesystemErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  // Python OSError escapes terminal controls in filenames, unlike validation errors.
  return error instanceof Error && ("errno" in error || "winerror" in error)
    ? message.replace(/\p{Cc}/gu, (character) =>
        pythonRepr(character).slice(1, -1),
      )
    : message;
}

export function readFile(path: string | number): Buffer {
  if (typeof path === "number") return readFileSync(path);
  return process.platform === "win32"
    ? windowsFileSystem(windowsBinding()).readFile(widePath(path))
    : readFileSync(encodePosixPath(path));
}

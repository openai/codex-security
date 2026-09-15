import { readFileSync } from "node:fs";
import { windowsBinding } from "../native";
import { widePath, windowsFileSystem } from "../../../native/windows-files.mjs";
import { encodePosixPath } from "./posix-path";

export function readFile(path: string | number): Buffer {
  if (typeof path === "number") return readFileSync(path);
  return process.platform === "win32"
    ? windowsFileSystem(windowsBinding()).readFile(widePath(path))
    : readFileSync(encodePosixPath(path));
}

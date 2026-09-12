import { windowsBinding } from "../native";
import {
  pathText,
  widePath,
  windowsFileSystem,
} from "../../../native/windows-files.mjs";
import { parsedPath } from "./resolve-security-md";
import {
  decodePosixBytes,
  encodePosixPath,
  resolvePosixPath,
  SymlinkLoopError,
} from "./posix-path";

export function resolvedPath(value: string, strict = true): string {
  if (process.platform !== "win32")
    return decodePosixBytes(
      resolvePosixPath(encodePosixPath(parsedPath(value)), strict),
    );
  try {
    return pathText(
      windowsFileSystem(windowsBinding()).realpath(widePath(value), strict),
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP")
      throw new SymlinkLoopError(`Symlink loop from ${value}`);
    throw error;
  }
}

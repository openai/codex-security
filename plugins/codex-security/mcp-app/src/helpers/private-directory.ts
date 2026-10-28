import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readlinkSync,
  statSync,
} from "node:fs";
import { dirname, isAbsolute, sep } from "node:path";
import { decodePosixBytes, encodePosixPath } from "./posix-path";
import { windowsBinding } from "../native";
import { widePath, windowsFileSystem } from "../../../native/windows-files.mjs";

export function createPrivateDirectory(path: string): void {
  if (process.platform !== "win32") path = path.replace(/\/+$/u, "") || "/";
  const nativePath =
    process.platform === "win32" ? path : encodePosixPath(path);
  if (statSync(nativePath, { throwIfNoEntry: false })?.isDirectory()) return;
  const entry = lstatSync(nativePath, { throwIfNoEntry: false });
  if (entry?.isSymbolicLink()) {
    const target =
      process.platform === "win32"
        ? readlinkSync(nativePath)
        : decodePosixBytes(readlinkSync(nativePath, { encoding: "buffer" }));
    createPrivateDirectory(
      isAbsolute(target) ? target : `${dirname(path)}${sep}${target}`,
    );
    return;
  }
  if (!entry) {
    const parent = dirname(path);
    if (parent !== path) createPrivateDirectory(parent);
  }
  let created = false;
  try {
    if (process.platform === "win32")
      windowsFileSystem(windowsBinding()).mkdirPrivate(widePath(path));
    else mkdirSync(nativePath, { mode: 0o700 });
    created = true;
  } catch (error) {
    if (!statSync(nativePath, { throwIfNoEntry: false })?.isDirectory())
      throw error;
  }
  if (
    created &&
    process.platform !== "win32" &&
    (process.umask() & 0o700) !== 0
  )
    chmodSync(nativePath, 0o700);
}

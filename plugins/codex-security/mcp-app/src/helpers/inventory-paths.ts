import {
  accessSync,
  constants,
  lstatSync,
  readdirSync,
  statSync,
} from "node:fs";
import {
  dirname,
  isAbsolute,
  parse,
  relative,
  sep,
  toNamespacedPath,
} from "node:path";
import { decodePosixBytes, encodePosixPath } from "./posix-path";
import { windowsFiles } from "./resolve-security-md";
import { isMissingPathError } from "./helper-files";

export const windows = process.platform === "win32";
export const fsPath = (path: string) =>
  windows ? toNamespacedPath(path) : encodePosixPath(path);
export const append = (parent: string, child: string) =>
  `${parent || "."}${parent.endsWith(sep) ? "" : sep}${child}`;
export const stat = (path: string) =>
  windows
    ? windowsFiles().stat(Buffer.from(path, "utf16le"))
    : statSync(fsPath(path));
export const lstat = (path: string) =>
  windows
    ? windowsFiles().stat(Buffer.from(path, "utf16le"), false)
    : lstatSync(fsPath(path));
export function exists(path: string): boolean {
  try {
    lstat(path);
    return true;
  } catch {
    return false;
  }
}
export function regular(path: string): boolean {
  try {
    return !lstat(path).isSymbolicLink() && stat(path).isFile();
  } catch (error) {
    if (isMissingPathError(error)) return false;
    throw error;
  }
}
export function directory(path: string): boolean {
  try {
    return stat(path).isDirectory();
  } catch {
    return false;
  }
}
export function inside(root: string, path: string): string {
  const result = relative(root, path);
  if (isAbsolute(result) || result === ".." || result.startsWith(`..${sep}`))
    throw new Error(`Scope must be inside repo: ${path}`);
  return result.split(sep).join("/") || ".";
}
export function rejectStreams(path: string): void {
  if (!windows) return;
  const root = parse(path).root;
  const stream = path
    .slice(root.length)
    .split(/[\\/]/u)
    .find((part) => part.includes(":"));
  if (stream)
    throw new Error(
      `Scope must not use an NTFS alternate data stream: ${stream}`,
    );
}
export function* ancestors(path: string): Iterable<string> {
  for (let current = path; ; current = dirname(current)) {
    yield current;
    if (dirname(current) === current) return;
  }
}
export function sameFile(left: string, right: string): boolean {
  try {
    if (windows) {
      const a = windowsFiles().identity(Buffer.from(left, "utf16le")),
        b = windowsFiles().identity(Buffer.from(right, "utf16le"));
      return a.volume === b.volume && a.fileId.equals(b.fileId);
    }
    const a = statSync(fsPath(left), { bigint: true }),
      b = statSync(fsPath(right), { bigint: true });
    return a.dev === b.dev && a.ino === b.ino;
  } catch {
    return false;
  }
}
export function linkedParent(scope: string, path: string): boolean {
  const parts = relative(scope, path).split(sep);
  let parent = scope;
  for (const part of parts.slice(0, -1)) {
    parent = append(parent, part);
    const info = lstat(parent);
    if (
      info.isSymbolicLink() ||
      ("isNameSurrogate" in info && info.isNameSurrogate())
    )
      return true;
  }
  return false;
}
export function* walk(path: string): Iterable<string> {
  const names = windows
    ? windowsFiles()
        .entriesWithTypes(Buffer.from(path, "utf16le"))
        .map((entry) => entry.name)
    : readdirSync(fsPath(path), { encoding: "buffer" });
  const children = names.map((name) =>
    append(path, windows ? name.toString("utf16le") : decodePosixBytes(name)),
  );
  yield* children;
  for (const child of children) {
    const info = lstat(child);
    if (
      info.isDirectory() &&
      !("isNameSurrogate" in info && info.isNameSurrogate())
    )
      yield* walk(child);
  }
}
export function executable(path: string): boolean {
  try {
    if (!windows) accessSync(fsPath(path), constants.X_OK);
    return stat(path).isFile();
  } catch {
    return false;
  }
}

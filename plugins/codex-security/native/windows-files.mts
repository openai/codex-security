import { win32 } from "node:path";
import {
  windowsFlags as flags,
  type WindowsBinding,
  type WindowsHandle,
} from "./windows-binding.mjs";

export const widePath = (path: string): Buffer => Buffer.from(path, "utf16le");
export const pathText = (path: Buffer): string => path.toString("utf16le");

export function windowsFileSystem(native: WindowsBinding) {
  function check(error: number, path: Buffer): void {
    if (error === 0) return;
    const code = new Map([
      [2, "ENOENT"],
      [3, "ENOENT"],
      [267, "ENOTDIR"],
      [1921, "ELOOP"],
    ]).get(error);
    throw Object.assign(
      new Error(`Windows filesystem error ${error}: ${pathText(path)}`),
      { code, winerror: error },
    );
  }

  function absolute(path: Buffer): Buffer {
    // GetFullPathNameW normalizes even explicit verbatim paths.
    if (pathText(path).startsWith("\\\\?\\")) return path;
    const result = native.windowsAbsolutePath(path);
    check(result.error, path);
    return result.value;
  }

  function operationPath(path: Buffer): Buffer {
    const resolved = absolute(path);
    const text = pathText(resolved);
    if (text.startsWith("\\\\?\\") || text.startsWith("\\\\.\\"))
      return resolved;
    return widePath(
      text.startsWith("\\\\")
        ? `\\\\?\\UNC\\${text.slice(2)}`
        : `\\\\?\\${text}`,
    );
  }

  function open(
    path: Buffer,
    access = 0,
    disposition: number = flags.OPEN_EXISTING,
    follow = true,
  ): WindowsHandle {
    const result = native.openWindowsFile(
      operationPath(path),
      access,
      flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE | flags.FILE_SHARE_DELETE,
      disposition,
      flags.FILE_FLAG_BACKUP_SEMANTICS |
        (follow ? 0 : flags.FILE_FLAG_OPEN_REPARSE_POINT),
    );
    check(result.error, path);
    return result.handle!;
  }

  function finalPath(path: Buffer): Buffer {
    const handle = open(path);
    try {
      const result = handle.finalPath(0);
      check(result.error, path);
      return result.path;
    } finally {
      check(handle.close(), path);
    }
  }

  function realpath(path: Buffer): Buffer {
    // Match CPython's Windows normalization of UNC and device prefixes.
    const textPath = pathText(path).replaceAll("/", "\\");
    let normalizedText = textPath;
    if (textPath.startsWith("\\\\")) {
      const first = textPath.indexOf("\\", 2);
      const end = first === -1 ? -1 : textPath.indexOf("\\", first + 1);
      if (end !== -1) {
        const tail = textPath.slice(end + 1).replace(/^\\+/u, "");
        normalizedText =
          textPath.slice(0, end + 1) +
          win32.normalize(`\\${tail}`).slice(1).replace(/\\+$/u, "");
      }
    } else {
      if (textPath[1] === ":" && textPath.slice(2, 4) === ".\\") {
        // Windows normpath retains the first drive-relative dot until a parent consumes it.
        const parts = ["."];
        for (const part of textPath.slice(4).split("\\")) {
          if (part === "" || part === ".") continue;
          if (part === ".." && parts.length && parts.at(-1) !== "..")
            parts.pop();
          else parts.push(part);
        }
        normalizedText = textPath.slice(0, 2) + parts.join("\\");
      } else normalizedText = win32.normalize(textPath);
      const root = win32.parse(normalizedText).root;
      normalizedText =
        root + normalizedText.slice(root.length).replace(/\\+$/u, "");
    }
    const normalized = widePath(normalizedText);
    const resolved = finalPath(normalized);
    if (pathText(normalized).startsWith("\\\\?\\")) return resolved;
    const text = pathText(resolved);
    const shortened = text.startsWith("\\\\?\\UNC\\")
      ? `\\\\${text.slice(8)}`
      : text.startsWith("\\\\?\\")
        ? text.slice(4)
        : text;
    // Like pathlib, remove the device prefix only if that spelling resolves too.
    const candidate = widePath(shortened);
    try {
      if (finalPath(candidate).equals(resolved)) return candidate;
    } catch {
      // Extended paths can be valid when their ordinary spelling is not.
    }
    return resolved;
  }

  function stat(path: Buffer, follow = true) {
    const handle = open(
      path,
      flags.FILE_READ_ATTRIBUTES,
      flags.OPEN_EXISTING,
      follow,
    );
    try {
      const info = handle.attributes();
      check(info.error, path);
      const type = handle.fileType();
      check(type.error, path);
      const link = !follow && info.reparseTag === 0xa000000c;
      const directory =
        (info.attributes & flags.FILE_ATTRIBUTE_DIRECTORY) !== 0;
      return {
        isDirectory: () => !link && directory,
        isFile: () => !link && !directory && type.value === 1,
        isSymbolicLink: () => link,
        isReparsePoint: () =>
          (info.attributes & flags.FILE_ATTRIBUTE_REPARSE_POINT) !== 0,
      };
    } finally {
      check(handle.close(), path);
    }
  }

  function entries(path: Buffer): Buffer[] {
    const result = native.windowsDirectoryNames(operationPath(path));
    check(result.error, path);
    return result.value;
  }

  function entriesWithTypes(path: Buffer) {
    const result = native.windowsDirectoryEntries(operationPath(path));
    check(result.error, path);
    return result.value.map(({ name, isDirectory, isSymbolicLink }) => ({
      name,
      isDirectory: () => isDirectory,
      isSymbolicLink: () => isSymbolicLink,
    }));
  }

  function mkdir(path: Buffer): void {
    const resolved = absolute(path);
    const parent = widePath(win32.dirname(pathText(resolved)));
    let error = native.createWindowsDirectory(operationPath(resolved));
    if (error === 3 && !parent.equals(resolved)) {
      mkdir(parent);
      error = native.createWindowsDirectory(operationPath(resolved));
    }
    if (error !== 0) {
      try {
        if (stat(resolved).isDirectory()) return;
      } catch {
        // Report the original creation error.
      }
      check(error, path);
    }
  }

  function readInto(path: Buffer, buffer: Buffer): number {
    const handle = open(path, flags.GENERIC_READ);
    let length = 0;
    try {
      while (length < buffer.length) {
        const result = handle.read(
          buffer,
          length,
          Math.min(buffer.length - length, 0xffffffff),
        );
        check(result.error, path);
        if (result.value === 0) break;
        length += result.value;
      }
    } finally {
      check(handle.close(), path);
    }
    return length;
  }

  function writeFile(path: Buffer, buffer: Buffer): void {
    const handle = open(path, flags.GENERIC_WRITE, flags.CREATE_ALWAYS);
    let offset = 0;
    try {
      while (offset < buffer.length) {
        const result = handle.write(
          buffer,
          offset,
          Math.min(buffer.length - offset, 0xffffffff),
        );
        check(result.error, path);
        if (result.value === 0)
          throw new Error(
            `Windows file write made no progress: ${pathText(path)}`,
          );
        offset += result.value;
      }
    } finally {
      check(handle.close(), path);
    }
  }

  return {
    absolute,
    realpath,
    stat,
    entries,
    entriesWithTypes,
    mkdir,
    readInto,
    writeFile,
  };
}

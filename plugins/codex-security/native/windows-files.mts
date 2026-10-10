import { win32 } from "node:path";
import type { WindowsBinding, WindowsHandle } from "./windows-binding.mjs";
import { windowsFlags as flags } from "./windows-flags.mjs";

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

  function withFile<T>(
    path: Buffer,
    access: number,
    action: (handle: WindowsHandle) => T,
    disposition: number = flags.OPEN_EXISTING,
    follow = true,
  ): T {
    const result = native.openWindowsFile(
      operationPath(path),
      access,
      flags.FILE_SHARE_READ | flags.FILE_SHARE_WRITE | flags.FILE_SHARE_DELETE,
      disposition,
      (access === flags.GENERIC_READ ? 0 : flags.FILE_FLAG_BACKUP_SEMANTICS) |
        (follow ? 0 : flags.FILE_FLAG_OPEN_REPARSE_POINT),
    );
    check(result.error, path);
    const handle = result.handle!;
    try {
      return action(handle);
    } finally {
      check(handle.close(), path);
    }
  }

  function realpath(path: Buffer, strict = true): Buffer {
    let current = operationPath(path);
    const missing: string[] = [];
    while (true) {
      try {
        return withFile(current, 0, (handle) => {
          const result = handle.finalPath(0);
          check(result.error, current);
          if (!missing.length) return result.path;
          // Join filename components directly so a:stream remains a filename.
          return widePath(
            `${pathText(result.path).replace(/\\$/u, "")}\\${missing.reverse().join("\\")}`,
          );
        });
      } catch (error) {
        if (strict || (error as NodeJS.ErrnoException).code !== "ENOENT")
          throw error;
        try {
          withFile(current, 0, () => {}, flags.OPEN_EXISTING, false);
        } catch (sourceError) {
          if ((sourceError as NodeJS.ErrnoException).code !== "ENOENT")
            throw sourceError;
          const text = pathText(current);
          const parent = win32.dirname(text);
          if (parent === text) throw error;
          missing.push(win32.basename(text));
          current = widePath(parent);
          continue;
        }
        // An existing entry that cannot be followed is not a missing output.
        throw error;
      }
    }
  }

  function stat(path: Buffer, follow = true) {
    return withFile(
      path,
      flags.FILE_READ_ATTRIBUTES,
      (handle) => {
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
      },
      flags.OPEN_EXISTING,
      follow,
    );
  }

  function identity(path: Buffer) {
    return withFile(path, flags.FILE_READ_ATTRIBUTES, (handle) => {
      const result = handle.identity();
      check(result.error, path);
      return { volume: result.volume, fileId: result.fileId };
    });
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
    check(native.createWindowsDirectories(operationPath(path)), path);
  }

  function mkdirPrivate(path: Buffer): void {
    check(native.createPrivateWindowsDirectory(operationPath(path)), path);
  }

  function readInto(path: Buffer, buffer: Buffer): number {
    return withFile(path, flags.GENERIC_READ, (handle) => {
      let length = 0;
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
      return length;
    });
  }

  function readFile(path: Buffer): Buffer {
    return withFile(path, flags.GENERIC_READ, (handle) => {
      const chunks: Buffer[] = [];
      while (true) {
        const chunk = Buffer.alloc(64 * 1024);
        const result = handle.read(chunk, 0, chunk.length);
        check(result.error, path);
        if (result.value === 0) return Buffer.concat(chunks);
        chunks.push(chunk.subarray(0, result.value));
      }
    });
  }

  function writeFile(
    path: Buffer,
    data: Buffer | Iterable<Buffer>,
    exclusive = false,
  ): void {
    withFile(
      path,
      flags.GENERIC_WRITE,
      (handle) => {
        for (const buffer of Buffer.isBuffer(data) ? [data] : data) {
          let offset = 0;
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
        }
      },
      exclusive ? flags.CREATE_NEW : flags.CREATE_ALWAYS,
    );
  }

  function rename(source: Buffer, destination: Buffer): void {
    withFile(
      source,
      flags.DELETE,
      (handle) => {
        check(handle.rename(operationPath(destination), true), destination);
      },
      flags.OPEN_EXISTING,
      false,
    );
  }

  function unlink(path: Buffer): void {
    withFile(
      path,
      flags.DELETE,
      (handle) => {
        check(handle.setDisposition(true), path);
      },
      flags.OPEN_EXISTING,
      false,
    );
  }

  return {
    absolute,
    realpath,
    stat,
    identity,
    entriesWithTypes,
    mkdir,
    mkdirPrivate,
    readInto,
    readFile,
    writeFile,
    rename,
    unlink,
  };
}

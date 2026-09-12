import { isUtf8 } from "node:buffer";

export function decodePosixBytes(bytes: Buffer): string {
  // Node 20's fatal TextDecoder can replace invalid bytes in longer inputs.
  if (isUtf8(bytes)) return bytes.toString("utf8");
  // Match Python's surrogateescape for undecodable POSIX path bytes.
  let value = "";
  for (let offset = 0; offset < bytes.length; ) {
    let decoded = false;
    for (let size = 1; size <= 4 && offset + size <= bytes.length; size++) {
      const part = bytes.subarray(offset, offset + size);
      if (isUtf8(part)) {
        value += part.toString("utf8");
        offset += size;
        decoded = true;
        break;
      }
    }
    if (!decoded) value += String.fromCharCode(0xdc00 + bytes[offset++]!);
  }
  return value;
}

export function encodePosixPath(value: string): Buffer {
  if (/[\ud800-\udc7f\udd00-\udfff]/u.test(value)) {
    throw new Error("UTF-8 cannot encode an unpaired surrogate");
  }
  return Buffer.concat(
    value
      .split(/([\udc80-\udcff])/u)
      .map((part) =>
        /^[\udc80-\udcff]$/u.test(part)
          ? Buffer.from([part.charCodeAt(0) - 0xdc00])
          : Buffer.from(part),
      ),
  );
}

export class SymlinkLoopError extends Error {}

export function resolvePosixPath(value: Buffer, strict = true): Buffer {
  // GNU Linux native realpath rejects file/.. and links targeting it with
  // ENOTDIR. Retain the shipped pathlib contract for those inputs.
  const seen = new Map<string, string | null>();
  // Latin-1 is a lossless internal representation of pathname bytes.
  const append = (directory: string, rest: string) =>
    rest.startsWith("/") ? rest : `${directory}/${rest}`;
  function follow(directory: string, path: string): [string, boolean] {
    if (path.startsWith("/")) directory = "/";
    const parts = path.split("/");
    for (const [index, name] of parts.entries()) {
      if (name === "" || name === ".") continue;
      if (name === "..") {
        directory = directory.slice(0, directory.lastIndexOf("/")) || "/";
        continue;
      }
      const candidate = `${directory === "/" ? "" : directory}/${name}`;
      const bytes = Buffer.from(candidate, "latin1");
      let link: boolean;
      try {
        link = lstatSync(bytes).isSymbolicLink();
      } catch (error) {
        if (strict) throw error;
        link = false;
      }
      if (!link) {
        directory = candidate;
        continue;
      }
      const cached = seen.get(candidate);
      if (cached === null) {
        if (!strict)
          return [append(candidate, parts.slice(index + 1).join("/")), false];
        throw new SymlinkLoopError(
          `Symlink loop from ${decodePosixBytes(bytes)}`,
        );
      }
      if (cached !== undefined) {
        directory = cached;
        continue;
      }
      seen.set(candidate, null);
      const [resolved, complete] = follow(
        directory,
        readlinkSync(bytes, { encoding: "buffer" }).toString("latin1"),
      );
      if (!complete)
        return [append(resolved, parts.slice(index + 1).join("/")), false];
      directory = resolved;
      seen.set(candidate, directory);
    }
    return [directory, true];
  }
  const cwd =
    value[0] === 0x2f
      ? Buffer.from("/")
      : realpathSync.native(".", { encoding: "buffer" });
  const [path] = follow(cwd.toString("latin1"), value.toString("latin1"));
  const result = Buffer.from(posix.resolve(path), "latin1");
  if (!strict) {
    try {
      statSync(result);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ELOOP")
        throw new SymlinkLoopError(
          `Symlink loop from ${decodePosixBytes(result)}`,
        );
    }
  }
  return result;
}
import { lstatSync, readlinkSync, realpathSync, statSync } from "node:fs";
import { posix } from "node:path";

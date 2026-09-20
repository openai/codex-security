const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function decodePosixBytes(bytes: Buffer): string {
  try {
    return utf8.decode(bytes);
  } catch {
    // Match Python's surrogateescape for undecodable POSIX path bytes.
    let value = "";
    for (let offset = 0; offset < bytes.length; ) {
      let decoded = false;
      for (let size = 1; size <= 4 && offset + size <= bytes.length; size++) {
        try {
          value += utf8.decode(bytes.subarray(offset, offset + size));
          offset += size;
          decoded = true;
          break;
        } catch {
          // A UTF-8 character can occupy up to four bytes.
        }
      }
      if (!decoded) value += String.fromCharCode(0xdc00 + bytes[offset++]!);
    }
    return value;
  }
}

export function encodePosixPath(value: string): Buffer {
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

export function resolvePosixPath(value: Buffer): Buffer {
  // GNU Linux native realpath rejects file/.. and links targeting it with
  // ENOTDIR. Retain the shipped pathlib contract for those inputs.
  const seen = new Map<string, string | null>();
  // Latin-1 is a lossless internal representation of pathname bytes.
  function follow(directory: string, path: string): string {
    if (path.startsWith("/")) directory = "/";
    for (const name of path.split("/")) {
      if (name === "" || name === ".") continue;
      if (name === "..") {
        directory = directory.slice(0, directory.lastIndexOf("/")) || "/";
        continue;
      }
      const candidate = `${directory === "/" ? "" : directory}/${name}`;
      const bytes = Buffer.from(candidate, "latin1");
      if (!lstatSync(bytes).isSymbolicLink()) {
        directory = candidate;
        continue;
      }
      const cached = seen.get(candidate);
      if (cached === null) {
        throw new SymlinkLoopError(
          `Symlink loop from ${decodePosixBytes(bytes)}`,
        );
      }
      if (cached !== undefined) {
        directory = cached;
        continue;
      }
      seen.set(candidate, null);
      directory = follow(
        directory,
        readlinkSync(bytes, { encoding: "buffer" }).toString("latin1"),
      );
      seen.set(candidate, directory);
    }
    return directory;
  }
  const cwd =
    value[0] === 0x2f
      ? Buffer.from("/")
      : realpathSync.native(".", { encoding: "buffer" });
  return Buffer.from(
    follow(cwd.toString("latin1"), value.toString("latin1")),
    "latin1",
  );
}
import { lstatSync, readlinkSync, realpathSync } from "node:fs";

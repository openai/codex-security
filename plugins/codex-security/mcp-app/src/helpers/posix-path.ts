import { isUtf8 } from "node:buffer";
import { lstatSync, realpathSync } from "node:fs";
import { posix } from "node:path";

export function decodePosixBytes(bytes: Buffer): string {
  // Node 20's fatal TextDecoder can replace invalid bytes in longer inputs.
  if (isUtf8(bytes)) return bytes.toString("utf8");
  // Preserve undecodable POSIX bytes as lone low surrogates.
  let value = "";
  for (let offset = 0; offset < bytes.length;) {
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

export function resolvePosixPath(value: Buffer, strict = true): Buffer {
  const missing: string[] = [];
  let current = value;
  while (true) {
    try {
      const resolved = realpathSync.native(current, { encoding: "buffer" });
      // Latin-1 preserves raw path bytes while joining missing components.
      return Buffer.from(
        posix.join(resolved.toString("latin1"), ...missing.reverse()),
        "latin1",
      );
    } catch (error) {
      if (
        strict ||
        (error as NodeJS.ErrnoException).code !== "ENOENT" ||
        lstatSync(current, { throwIfNoEntry: false }) !== undefined
      )
        throw error;
      // Existing dangling links are rejected above; only absent components
      // may be appended to a canonical existing ancestor.
      const path = current.toString("latin1");
      const name = posix.basename(path);
      // Cancelling an unresolved component can expose an unresolved symlink.
      if (name === "..") throw error;
      missing.push(name);
      current = Buffer.from(posix.dirname(path), "latin1");
    }
  }
}

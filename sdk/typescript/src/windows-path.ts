/* Generated from plugin windows-path.ts. Run `pnpm generate:models`. */
import { parse, toNamespacedPath } from "node:path";

// SQLite's default win32 VFS allows MAX_PATH * 4 UTF-8 bytes, including room for "-journal".
const SQLITE_WINDOWS_MAX_FILENAME_BYTES = 260 * 4 - 8;

export function sqliteFilename(path: string): string {
  // Ordinary paths also preserve Win32 handling of device names and trailing spaces or dots.
  if (
    process.platform !== "win32" ||
    path.length + 8 < 260 ||
    path.includes("\0")
  )
    return path;
  const root = parse(path).root;
  // Root-relative names (including ambiguous UNC spellings) must not move to the current drive.
  if (root.length < 3) return path;
  // Keep device prefixes, dot segments, and incomplete UNC roots as supplied.
  // Repeated separators below a complete root still identify the same file.
  const isDrivePath = root[1] === ":";
  const components = path.slice(isDrivePath ? root.length : 2).split(/[\\/]/u);
  if (
    (!isDrivePath && (!components[0] || !components[1])) ||
    components.some(
      (part) => part === "." || isWindowsUnsafePathComponent(part),
    )
  )
    return path;
  const namespaced = toNamespacedPath(path);
  if (
    namespaced !== path &&
    Buffer.byteLength(namespaced) > SQLITE_WINDOWS_MAX_FILENAME_BYTES
  )
    return path;
  return namespaced;
}

const UNSAFE_COMPONENT = /[<>:"|?*\u0000-\u001f]|[ .]$/u;
const RESERVED_COMPONENT =
  /^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/iu;

export function isWindowsUnsafePathComponent(value: string): boolean {
  return (
    value !== "" &&
    value !== "." &&
    (UNSAFE_COMPONENT.test(value) || RESERVED_COMPONENT.test(value))
  );
}

export function windowsUnsafePathComponent(path: string): string | undefined {
  return path
    .slice(parse(path).root.length)
    .split(/[\\/]/u)
    .find(isWindowsUnsafePathComponent);
}

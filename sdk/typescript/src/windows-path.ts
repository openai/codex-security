import { parse, win32 } from "node:path";

const UNSAFE_COMPONENT = /[<>:"|?*\u0000-\u001f]|[ .]$/u;
const RESERVED_COMPONENT =
  /^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$/iu;

// win32.parse stops at the UNC marker for extended-length share paths.
export const WINDOWS_NAMESPACED_UNC_ROOT =
  /^[\\/]{2}[?.][\\/]UNC[\\/][^\\/]+[\\/][^\\/]+[\\/]?/iu;

export function windowsVolumeRoot(path: string): string {
  return WINDOWS_NAMESPACED_UNC_ROOT.exec(path)?.[0] ?? win32.parse(path).root;
}

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

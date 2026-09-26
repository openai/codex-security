import { parse } from "node:path";

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
  const root = parse(path).root;
  return path
    .slice(root.length)
    .split(/[\\/]/u)
    .find(isWindowsUnsafePathComponent);
}

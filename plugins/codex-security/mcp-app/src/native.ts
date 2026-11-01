import { createRequire } from "node:module";
import type { UnixBinding } from "../../native/binding.mjs";
import type { WindowsBinding } from "../../native/windows-binding.mjs";
import { nativeTarget } from "../../native/platform.mjs";

const binding = (name: string) =>
  createRequire(import.meta.url)(`./native/${nativeTarget}/${name}.node`);

export const unixBinding = (): UnixBinding => binding("unix");
export const windowsBinding = (): WindowsBinding => binding("windows");

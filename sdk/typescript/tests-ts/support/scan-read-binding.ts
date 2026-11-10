import { createRequire } from "node:module";
import { join } from "node:path";
import { nativeTarget } from "../../../../plugins/codex-security/native/platform.mjs";
import type { ScanReadBinding } from "../../../../plugins/codex-security/native/scan-read-binding.mjs";
import { PLUGIN_ROOT } from "../plugin-root.js";

export function scanReadBinding(): ScanReadBinding {
  return createRequire(import.meta.url)(
    join(
      PLUGIN_ROOT,
      "mcp",
      "native",
      nativeTarget,
      process.platform === "win32" ? "windows.node" : "unix.node",
    ),
  ) as ScanReadBinding;
}

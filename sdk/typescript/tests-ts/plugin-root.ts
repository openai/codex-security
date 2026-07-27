import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const sourcePlugin = new URL(
  "../../../plugins/codex-security/",
  import.meta.url,
);
const bundledPlugin = new URL("../_bundled_plugin/", import.meta.url);
const hasSourcePlugin = existsSync(
  new URL(".codex-plugin/plugin.json", sourcePlugin),
);

export const PLUGIN_ROOT = fileURLToPath(
  hasSourcePlugin ? sourcePlugin : bundledPlugin,
);

export const INTEGRATION_TARGET = hasSourcePlugin
  ? "project/codex-security-sdk/src"
  : "sdk/typescript/src";

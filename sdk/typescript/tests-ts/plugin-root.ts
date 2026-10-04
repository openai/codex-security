import { existsSync } from "node:fs";
import { cp } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const bundledPlugin = new URL("../_bundled_plugin/", import.meta.url);
const hasMonorepoSdk = existsSync(
  new URL("../../../project/codex-security-sdk/src/", import.meta.url),
);

export const PLUGIN_ROOT = fileURLToPath(bundledPlugin);

export const INTEGRATION_TARGET = hasMonorepoSdk
  ? "project/codex-security-sdk/src"
  : "sdk/typescript/src";

export const copyCompletedScanFixture = (destination: string) =>
  cp(new URL("examples/completed-scan/", bundledPlugin), destination, {
    recursive: true,
  });

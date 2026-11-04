import { chmod } from "node:fs/promises";
import { join } from "node:path";
import { copyCompletedScanFixture } from "../plugin-root.js";
import { createApiTestFixtures } from "./temporary-directories.js";

export function createContractTestFixtures() {
  const { temporaryDirectory, cleanup } = createApiTestFixtures(
    "codex-security-contract-",
    false,
  );
  async function copyExample(): Promise<string> {
    const scanDir = join(await temporaryDirectory(), "scan");
    await copyCompletedScanFixture(scanDir);
    if (process.platform !== "win32") await chmod(scanDir, 0o700);
    return scanDir;
  }
  return { temporaryDirectory, cleanup, copyExample };
}

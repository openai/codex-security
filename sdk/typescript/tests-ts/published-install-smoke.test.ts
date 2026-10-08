import { afterEach, expect, test } from "bun:test";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { verifyInstalledPackage } from "../scripts/smoke-published-package.mjs";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const directories = createTemporaryDirectories();
afterEach(directories.cleanup);

async function installedFixture(cliVersion: string) {
  const consumer = await directories.create("published smoke ");
  const installedRoot = join(
    consumer,
    "node_modules",
    "@openai",
    "codex-security",
  );
  const bin = join(consumer, "node_modules", ".bin");
  await mkdir(installedRoot, { recursive: true });
  await mkdir(bin);
  await writeFile(
    join(installedRoot, "package.json"),
    JSON.stringify({
      name: "@openai/codex-security",
      version: "99.1.2",
    }),
  );
  const shim = join(
    bin,
    process.platform === "win32" ? "codex-security.cmd" : "codex-security",
  );
  await writeFile(
    shim,
    process.platform === "win32"
      ? `@echo off\r\nif "%~1"=="--version" (echo ${cliVersion}) else (echo Usage: codex-security)\r\n`
      : `#!/bin/sh\nif [ "$1" = "--version" ]; then printf '%s\\n' '${cliVersion}'; else printf '%s\\n' 'Usage: codex-security'; fi\n`,
  );
  await chmod(shim, 0o755);
  return { consumer, shim };
}

test("fails when the installed CLI reports a different package version", async () => {
  const { consumer } = await installedFixture("99.1.1");
  await expect(verifyInstalledPackage(consumer, process.env)).rejects.toThrow(
    "99.1.2",
  );
});

test("fails when the installed CLI cannot start", async () => {
  const { consumer, shim } = await installedFixture("99.1.2");
  await writeFile(
    shim,
    process.platform === "win32"
      ? "@echo off\r\necho synthetic CLI startup failure 1>&2\r\nexit /b 7\r\n"
      : "#!/bin/sh\nprintf '%s\\n' 'synthetic CLI startup failure' >&2\nexit 7\n",
  );
  await expect(verifyInstalledPackage(consumer, process.env)).rejects.toThrow(
    "synthetic CLI startup failure",
  );
});

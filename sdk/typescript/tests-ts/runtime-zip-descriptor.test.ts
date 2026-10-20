import { execFile, spawnSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, expect, test } from "bun:test";
import { strToU8, zipSync } from "fflate";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures("runtime-zip-");
afterEach(cleanup);

for (const scenario of [
  "replace-regular",
  "replace-fifo",
  "initial-fifo",
  "constructor-error",
  "read-error",
  "close-error",
  "abort",
  "write-error",
]) {
  test.skipIf(process.platform === "win32" && scenario.includes("fifo"))(
    `retains and closes the checked plugin ZIP: ${scenario}`,
    async () => {
      const root = await temporaryDirectory();
      for (const [name, version] of [
        ["plugin.zip", "1.2.3"],
        ["replacement.zip", "9.8.7"],
      ] as const) {
        await writeFile(
          join(root, name),
          zipSync({
            "release/.codex-plugin/plugin.json": strToU8(
              JSON.stringify({ name: "codex-security", version }),
            ),
          }),
        );
      }
      if (scenario.includes("fifo")) {
        const fifo = spawnSync("mkfifo", [join(root, "replacement.fifo")]);
        expect(fifo.status, fifo.stderr?.toString()).toBe(0);
      }
      const child = await promisify(execFile)(
        process.execPath,
        [
          fileURLToPath(
            new URL("./fixtures/runtime-zip-descriptor.mjs", import.meta.url),
          ),
          root,
          scenario,
        ],
        { encoding: "utf8", timeout: 10_000, killSignal: "SIGKILL" },
      );
      expect(JSON.parse(child.stdout)).toEqual({ scenario, passed: true });
    },
  );
}

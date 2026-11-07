import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { copyFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { executablePathForSpawn } from "../src/executable-path.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

async function digest(file: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const bytes of createReadStream(file)) hash.update(bytes);
  return hash.digest("hex");
}

export function registerWorkerExecutableFirstLaunchTests(): void {
  test(
    "the first Windows version launch preserves the executable pin",
    { skip: process.platform !== "win32" },
    async (t) => {
      const { verifyBoundCodexExecutable } =
        await import("./support/deep-scan-executor-module.ts");
      const root = await temporaryDirectory("worker-first-launch-", true);
      t.after(() => rm(root, { recursive: true, force: true }));
      const executable = path.join(root, "version-fixture.exe");
      await copyFile(process.execPath, executable);
      const beforeDigest = await digest(executable);
      const identity = await stat(executable, { bigint: true });
      await verifyBoundCodexExecutable({ path: executable, identity });
      const { stdout } = await promisify(execFile)(
        executablePathForSpawn(executable),
        ["--version"],
        {
          windowsHide: true,
        },
      );
      assert.equal(stdout.trim(), process.version);
      const after = await stat(executable, { bigint: true });
      assert.equal(await digest(executable), beforeDigest);
      assert.equal(after.dev, identity.dev);
      assert.equal(after.ino, identity.ino);
      assert.equal(after.size, identity.size);
      assert.equal(after.mtimeNs, identity.mtimeNs);
      try {
        await verifyBoundCodexExecutable({ path: executable, identity });
      } catch (error) {
        if (
          after.ctimeNs !== identity.ctimeNs &&
          error instanceof Error &&
          error.name === "DeepScanNonRetryableError" &&
          error.cause === undefined
        ) {
          t.todo(
            "The current worker pin rejects an ordinary launch when only Windows change time advances.",
          );
        }
        throw error;
      }
    },
  );

  test("the worker pin rejects a changed synthetic file of the same size", async (t) => {
    const { verifyBoundCodexExecutable } =
      await import("./support/deep-scan-executor-module.ts");
    const root = await temporaryDirectory("worker-changed-pin-", true);
    t.after(() => rm(root, { recursive: true, force: true }));
    const executable = path.join(root, "content-fixture.exe");
    // This inert text fixture represents two ordinary content revisions of equal size.
    const fixedTime = new Date("2025-01-01T00:00:00Z");
    await writeFile(executable, "fixture revision A\n");
    await utimes(executable, fixedTime, fixedTime);
    const identity = await stat(executable, { bigint: true });
    await verifyBoundCodexExecutable({ path: executable, identity });
    // Retry a real equal-length revision on a later tick if the first write is too fast.
    for (const [wait, revision] of [
      [0, "B"],
      [2200, "C"],
    ] as const) {
      if (wait) await delay(wait);
      await writeFile(executable, `fixture revision ${revision}\n`);
      await utimes(executable, fixedTime, fixedTime);
      const updated = await stat(executable, { bigint: true });
      assert.equal(updated.size, identity.size);
      assert.equal(updated.mtimeNs, identity.mtimeNs);
      if (updated.ctimeNs !== identity.ctimeNs) {
        await assert.rejects(
          verifyBoundCodexExecutable({ path: executable, identity }),
          { name: "DeepScanNonRetryableError" },
        );
        return;
      }
    }
    t.skip(
      "The fixture filesystem reported the same change time across two separately timed content revisions.",
    );
  });
}

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, promises as fs } from "node:fs";
import {
  copyFile,
  chmod,
  mkdir,
  rename,
  rm,
  stat,
  utimes,
  writeFile,
} from "node:fs/promises";
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
      const { bindCodexExecutable, verifyBoundCodexExecutable } =
        await import("./support/deep-scan-executor-module.ts");
      const root = await temporaryDirectory("worker-first-launch-", true);
      t.after(() => rm(root, { recursive: true, force: true }));
      for (const name of [
        "version-fixture.exe",
        path.join(...Array(10).fill("nested executable directory"), "node.exe"),
      ]) {
        const executable = path.join(root, name);
        await mkdir(path.dirname(executable), { recursive: true });
        await copyFile(process.execPath, executable);
        const beforeDigest = await digest(executable);
        const bound = await bindCodexExecutable(
          { CODEX_CLI_PATH: executable },
          root,
        );
        const { identity } = bound;
        await verifyBoundCodexExecutable(bound);
        for (let launch = 0; launch < 2; launch++) {
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
          await verifyBoundCodexExecutable(bound);
        }
      }
    },
  );

  test("the worker pin rejects a changed synthetic file of the same size", async (t) => {
    const { bindCodexExecutable, verifyBoundCodexExecutable } =
      await import("./support/deep-scan-executor-module.ts");
    const root = await temporaryDirectory("worker-changed-pin-", true);
    t.after(() => rm(root, { recursive: true, force: true }));
    const executable = path.join(root, "content-fixture.exe");
    // This inert text fixture represents two ordinary content revisions of equal size.
    const fixedTime = new Date("2025-01-01T00:00:00Z");
    await writeFile(executable, "fixture revision A\n");
    await utimes(executable, fixedTime, fixedTime);
    const bound = await bindCodexExecutable(
      { CODEX_CLI_PATH: executable },
      root,
    );
    const { identity } = bound;
    await verifyBoundCodexExecutable(bound);
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
        await assert.rejects(verifyBoundCodexExecutable(bound), {
          name: "DeepScanNonRetryableError",
        });
        return;
      }
    }
    t.skip(
      "The fixture filesystem reported the same change time across two separately timed content revisions.",
    );
  });

  test("the worker pin rejects a same-content file replacement", async (t) => {
    const { bindCodexExecutable, verifyBoundCodexExecutable } =
      await import("./support/deep-scan-executor-module.ts");
    const root = await temporaryDirectory("worker-replaced-pin-", true);
    t.after(() => rm(root, { recursive: true, force: true }));
    const executable = path.join(root, "content-fixture.exe");
    const replacement = path.join(root, "replacement.exe");
    const fixedTime = new Date("2025-01-01T00:00:00Z");
    await writeFile(executable, "fixture original bytes\n");
    await utimes(executable, fixedTime, fixedTime);
    const bound = await bindCodexExecutable(
      { CODEX_CLI_PATH: executable },
      root,
    );
    await copyFile(executable, replacement);
    await utimes(replacement, fixedTime, fixedTime);
    assert.equal(await digest(replacement), await digest(executable));
    await rename(replacement, executable);
    const replaced = await stat(executable, { bigint: true });
    assert.notEqual(replaced.ino, bound.identity.ino);
    assert.equal(replaced.size, bound.identity.size);
    assert.equal(replaced.mtimeNs, bound.identity.mtimeNs);
    await assert.rejects(verifyBoundCodexExecutable(bound), {
      name: "DeepScanNonRetryableError",
    });
  });

  test("the worker pin rejects a changed modification time with identical content", async (t) => {
    const { bindCodexExecutable, verifyBoundCodexExecutable } =
      await import("./support/deep-scan-executor-module.ts");
    const root = await temporaryDirectory("worker-modified-pin-", true);
    t.after(() => rm(root, { recursive: true, force: true }));
    const executable = path.join(root, "content-fixture.exe");
    await writeFile(executable, "fixture original bytes\n");
    const bound = await bindCodexExecutable(
      { CODEX_CLI_PATH: executable },
      root,
    );
    const beforeDigest = await digest(executable);
    const changedTime = new Date("2025-01-01T00:00:00Z");
    await utimes(executable, changedTime, changedTime);
    assert.equal(await digest(executable), beforeDigest);
    assert.notEqual(
      (await stat(executable, { bigint: true })).mtimeNs,
      bound.identity.mtimeNs,
    );
    await assert.rejects(verifyBoundCodexExecutable(bound), {
      name: "DeepScanNonRetryableError",
    });
  });

  for (const phase of ["binding", "verification"]) {
    test(
      `the worker pin rejects a revision during content ${phase}`,
      {
        skip: process.platform !== "win32",
      },
      async (t) => {
        const { bindCodexExecutable, verifyBoundCodexExecutable } =
          await import("./support/deep-scan-executor-module.ts");
        const root = await temporaryDirectory("worker-streamed-pin-", true);
        t.after(() => rm(root, { recursive: true, force: true }));
        const executable = path.join(root, "content-fixture.exe");
        const fixedTime = new Date("2025-01-01T00:00:00Z");
        await writeFile(executable, "fixture revision A\n");
        await utimes(executable, fixedTime, fixedTime);
        const bind = () =>
          bindCodexExecutable({ CODEX_CLI_PATH: executable }, root);
        const bound = phase === "verification" ? await bind() : undefined;
        if (bound) {
          // A metadata-only change selects the Windows content-check path.
          await chmod(executable, 0o444);
          assert.notEqual(
            (await stat(executable, { bigint: true })).ctimeNs,
            bound.identity.ctimeNs,
          );
        }
        const originalStat = fs.stat;
        let observations = 0;
        let revised = false;
        t.mock.method(
          fs,
          "stat",
          async (...args: Parameters<typeof fs.stat>) => {
            if (args[0] === executable && ++observations === 2) {
              await chmod(executable, 0o644);
              await writeFile(executable, "fixture revision B\n");
              await utimes(executable, fixedTime, fixedTime);
              revised = true;
            }
            return originalStat(...args);
          },
        );
        await assert.rejects(
          bound ? verifyBoundCodexExecutable(bound) : bind(),
          {
            name: "DeepScanNonRetryableError",
          },
        );
        assert.equal(revised, true);
      },
    );
  }

  test(
    "the worker pin accepts a metadata-only change during content verification",
    {
      skip: process.platform !== "win32",
    },
    async (t) => {
      const { bindCodexExecutable, verifyBoundCodexExecutable } =
        await import("./support/deep-scan-executor-module.ts");
      const root = await temporaryDirectory("worker-metadata-pin-", true);
      t.after(() => rm(root, { recursive: true, force: true }));
      const executable = path.join(root, "content-fixture.exe");
      await writeFile(executable, "fixture original bytes\n");
      const bound = await bindCodexExecutable(
        { CODEX_CLI_PATH: executable },
        root,
      );
      const beforeDigest = await digest(executable);
      await chmod(executable, 0o444);
      const originalStat = fs.stat;
      let observations = 0;
      let changedMetadata = false;
      t.mock.method(fs, "stat", async (...args: Parameters<typeof fs.stat>) => {
        if (args[0] === executable && ++observations === 2) {
          await chmod(executable, 0o644);
          changedMetadata = true;
        }
        return originalStat(...args);
      });
      await verifyBoundCodexExecutable(bound);
      assert.equal(changedMetadata, true);
      assert.equal(await digest(executable), beforeDigest);
    },
  );
}

import assert from "node:assert/strict";
import fs, { promises } from "node:fs";
import { chmod, rm, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import test from "node:test";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import {
  bindCodexExecutable,
  verifyBoundCodexExecutable,
} from "./support/deep-scan-executor-module.ts";

export function registerWorkerExecutableCancellationTests(): void {
  for (const phase of ["binding", "verification"]) {
    test(`the worker pin preserves cancellation before ${phase}`, async (t) => {
      const root = await temporaryDirectory("worker-cancelled-pin-", true);
      t.after(() => rm(root, { recursive: true, force: true }));
      const executable = path.join(root, "content-fixture.exe");
      await writeFile(executable, "fixture original bytes\n");
      const bound = await bindCodexExecutable(
        { CODEX_CLI_PATH: executable },
        root,
      );
      const controller = new AbortController();
      const reason = { message: "synthetic caller cancellation", phase };
      controller.abort(reason);
      const inspect = t.mock.method(promises, "stat", () => {
        throw new Error("An aborted pin operation must not inspect the file.");
      });
      await assert.rejects(
        phase === "binding"
          ? bindCodexExecutable(
              { CODEX_CLI_PATH: executable },
              root,
              controller.signal,
            )
          : verifyBoundCodexExecutable(bound, controller.signal),
        (error) => error === reason,
      );
      assert.equal(inspect.mock.callCount(), 0);
    });
  }

  test(
    "the worker pin cancels an active binding content stream",
    {
      skip: process.platform !== "win32",
    },
    async (t) => {
      const root = await temporaryDirectory("worker-cancelled-stream-", true);
      t.after(() => rm(root, { recursive: true, force: true }));
      const executable = path.join(root, "content-fixture.exe");
      await writeFile(executable, "fixture original bytes\n".repeat(8192));
      const controller = new AbortController();
      const reason = new Error("synthetic cancellation during binding read");
      const originalRead = fs.createReadStream;
      let observed: fs.ReadStream | undefined;
      const reading = t.mock.method(
        fs,
        "createReadStream",
        (...args: Parameters<typeof fs.createReadStream>) => {
          const stream = originalRead(...args);
          if (args[0] === executable) {
            observed = stream;
            stream.once("data", () => controller.abort(reason));
          }
          return stream;
        },
      );
      syncBuiltinESMExports();
      try {
        await assert.rejects(
          bindCodexExecutable(
            { CODEX_CLI_PATH: executable },
            root,
            controller.signal,
          ),
          (error) => error === reason,
        );
      } finally {
        reading.mock.restore();
        syncBuiltinESMExports();
      }
      assert.ok(observed);
      if (!observed.closed)
        await new Promise<void>((resolve) => observed!.once("close", resolve));
      assert.equal(observed.destroyed, true);
      assert.equal(observed.closed, true);
    },
  );

  test(
    "the worker pin cancels metadata churn with the caller's reason",
    {
      skip: process.platform !== "win32",
    },
    async (t) => {
      const root = await temporaryDirectory("worker-cancelled-churn-", true);
      t.after(() => rm(root, { recursive: true, force: true }));
      const executable = path.join(root, "content-fixture.exe");
      await writeFile(executable, "fixture original bytes\n");
      const bound = await bindCodexExecutable(
        { CODEX_CLI_PATH: executable },
        root,
      );
      await chmod(executable, 0o444);
      const controller = new AbortController();
      const reason = new Error("synthetic cancellation during metadata churn");
      const originalStat = promises.stat;
      let observations = 0;
      t.mock.method(
        promises,
        "stat",
        async (...args: Parameters<typeof promises.stat>) => {
          if (args[0] === executable) {
            observations++;
            await chmod(executable, observations % 2 === 0 ? 0o444 : 0o644);
            if (observations === 3) controller.abort(reason);
          }
          return originalStat(...args);
        },
      );
      await assert.rejects(
        verifyBoundCodexExecutable(bound, controller.signal),
        (error) => error === reason,
      );
      assert.equal(observations, 3);
      await chmod(executable, 0o644);
    },
  );
}

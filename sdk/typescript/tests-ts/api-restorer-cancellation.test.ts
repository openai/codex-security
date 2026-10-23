import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";

import { ScanInterruptedError } from "../src/errors.js";
import type { ScanArtifactRestorer } from "../src/runtime.js";
import { copyCompletedScan } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import {
  codexFactory,
  completedEvents,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();

afterEach(cleanup);

test.each(["abort", "close"] as const)(
  "%s cancels post-scan restoration setup before follow-up instructions",
  async (action) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await Promise.all([mkdir(repository), mkdir(codexHome)]);
    const controller = new AbortController();
    const setupStarted = Promise.withResolvers<void>();
    const releaseSetup = Promise.withResolvers<void>();
    const original = new Map<string, Buffer>();
    let setupCancelled = false;
    let turns = 0;
    let restores = 0;
    let closing: Promise<void> | undefined;
    const client = TestClient.withDependencies({
      ...scanRuntimeDependencies(codexHome, scanDir),
      prepareScanArtifactRestorer: async ({ signal }) => {
        for (const name of [
          "scan-manifest.json",
          "findings.json",
          "coverage.json",
          "report.md",
        ]) {
          original.set(name, await readFile(join(scanDir, name)));
        }
        return await new Promise<ScanArtifactRestorer>((resolve, reject) => {
          const abort = () => {
            setupCancelled = true;
            reject(signal!.reason);
          };
          signal?.addEventListener("abort", abort, { once: true });
          void releaseSetup.promise.then(() => {
            signal?.removeEventListener("abort", abort);
            resolve({
              restore: async () => {
                restores++;
              },
            });
          });
          if (signal?.aborted) abort();
          setupStarted.resolve();
        });
      },
      createCodex: codexFactory(async () => {
        turns++;
        if (turns === 1) await copyCompletedScan(root);
        return { events: completedEvents() };
      }, "thread-1"),
    });
    const scan = client
      .run(repository, {
        postScanPrompt: "Draft confirmed fixes.",
        signal: controller.signal,
      })
      .catch((error: unknown) => error);
    try {
      await Promise.race([
        setupStarted.promise,
        scan.then((result) => {
          throw new Error("Scan ended before restoration setup", {
            cause: result,
          });
        }),
      ]);
      if (action === "close") closing = client.close();
      else controller.abort();
      expect(setupCancelled).toBe(true);
      const error = await scan;
      if (action === "close")
        expect(error).toMatchObject({ message: "CodexSecurity is closed." });
      else expect(error).toBeInstanceOf(ScanInterruptedError);
      await (closing ?? client.close());
      expect(turns).toBe(1);
      expect(restores).toBe(0);
      for (const [name, contents] of original) {
        expect((await readFile(join(scanDir, name))).equals(contents)).toBe(
          true,
        );
      }
    } finally {
      controller.abort();
      releaseSetup.resolve();
      await scan;
      await (closing ?? client.close());
    }
  },
);

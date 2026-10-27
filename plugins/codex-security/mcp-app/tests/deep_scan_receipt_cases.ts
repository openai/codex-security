import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import type { JsonObject } from "../src/types.js";
import type {
  CodexWorkerRequest,
  CodexWorkerResult,
} from "../src/deep-scan/types.js";
import { readJson } from "./support/json.ts";
import {
  coordinatorFixture,
  eventually,
  FakeExecutor,
  promptContext,
  standardScanDraft,
  recordCodexSecurityWorkerScanDraft,
  createCoordinator,
} from "./deep_scan_coordinator_fixture.ts";

export async function testSharedReceiptSurvivesWorkerRetry() {
  for (const receipt of [
    "retrying worker output",
    "stable shared",
    "worker local",
  ]) {
    const { fixture, store } = await coordinatorFixture({
      workers: 3,
      maxDiscoveryRuns: 3,
      stopAfterNoNew: 10,
    });
    const published = Promise.withResolvers<string>();
    const recorded = Promise.withResolvers<void>();
    const archived = Promise.withResolvers<void>();
    const restore = Promise.withResolvers<void>();
    const reducer = new FakeExecutor();
    let recordedCount = 0;
    let retryAttempts = 0;
    let observedArchive = false;
    let restored = false;
    const executor = {
      async run(request: CodexWorkerRequest): Promise<CodexWorkerResult> {
        if (request.kind !== "discovery") {
          await archived.promise;
          restore.resolve();
          return reducer.run(request);
        }
        const info = await promptContext(request.promptPath);
        await request.onThreadStarted?.(randomUUID());
        const context = {
          ...request.artifactContext,
          scanId: fixture.run.scanId,
          repoRoot: fixture.run.targetPath,
        };
        if (info.workerLabel === "discovery-0003") {
          retryAttempts++;
          if (retryAttempts === 1) {
            // Retry archives this invalid worker result.
            await writeFile(
              path.join(request.workingDirectory, "result.json"),
              "{}\n",
            );
            const shared = path.join(
              fixture.run.scanDir,
              "artifacts/retry-window-shared.txt",
            );
            await mkdir(path.dirname(shared), { recursive: true });
            await writeFile(shared, "Synthetic stable review evidence.\n");
            published.resolve(request.workingDirectory);
            await recorded.promise;
            // Admission validates receipt files before a later retry can archive them.
            await eventually(
              () =>
                [...store.workers.values()].filter(
                  (worker) =>
                    worker.kind === "discovery" &&
                    worker.status === "succeeded",
                ).length === 2,
            );
            return {};
          }
          await recordCodexSecurityWorkerScanDraft(
            context,
            standardScanDraft(fixture.run.scanId, undefined, info.workerLabel),
          );
          restored = true;
          return {};
        }
        const retryOutput = await published.promise;
        const draft: ScanDraftInput = standardScanDraft(
          fixture.run.scanId,
          undefined,
          info.workerLabel,
        );
        let ref: string;
        if (receipt === "retrying worker output") {
          ref = path
            .relative(
              fixture.run.scanDir,
              path.join(retryOutput, "result.json"),
            )
            .split(path.sep)
            .join("/");
        } else if (receipt === "stable shared") {
          ref = "artifacts/retry-window-shared.txt";
        } else {
          ref = "artifacts/evidence.txt";
          await mkdir(path.dirname(path.join(request.workingDirectory, ref)), {
            recursive: true,
          });
          await writeFile(
            path.join(request.workingDirectory, ref),
            "Synthetic worker-local evidence.\n",
          );
        }
        (draft.reviewState.surfaces as JsonObject[])[0].receiptRefs = [ref];
        await recordCodexSecurityWorkerScanDraft(context, draft);
        const saved = await readJson(
          path.join(request.workingDirectory, "result.json"),
        );
        if (receipt !== "worker local") {
          assert.ok(
            saved.reviewState.surfaces[0].provenance.scanReceiptRefs.includes(
              ref,
            ),
          );
        }
        if (++recordedCount === 2) recorded.resolve();
        return {};
      },
    };
    const coordinator = createCoordinator(fixture, store, executor, {
      random: () => 0,
      retryDelaysMs: [1],
      clock: {
        now: () => 1_700_000_000_000,
        async sleep(_delay, signal) {
          signal.throwIfAborted();
          const output = await published.promise;
          await assert.rejects(readFile(path.join(output, "result.json")), {
            code: "ENOENT",
          });
          assert.equal(
            await readFile(
              path.join(
                path.dirname(output),
                "attempts/attempt-01/result.json",
              ),
              "utf8",
            ),
            "{}\n",
          );
          observedArchive = true;
          archived.resolve();
          await Promise.race([restore.promise, once(signal, "abort")]);
          signal.throwIfAborted();
        },
      },
    });
    try {
      coordinator.start();
      const terminal = await coordinator.wait(undefined, 5_000);
      assert.equal(observedArchive, true, receipt);
      assert.equal(terminal?.status, "succeeded", terminal?.error);
      assert.equal(retryAttempts, 2, receipt);
      assert.equal(restored, true, receipt);
    } finally {
      restore.resolve();
      archived.resolve();
      recorded.resolve();
      coordinator.cancel("test cleanup");
    }
  }
}

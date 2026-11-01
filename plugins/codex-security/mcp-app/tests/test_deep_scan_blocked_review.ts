import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import {
  coordinatorFixture,
  FakeExecutor,
  recordCodexSecurityWorkerScanDraft,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

const blockedReason = "Source access was denied before review.";

class CheckpointExecutor extends FakeExecutor {
  private readonly blockedAttempts: number;

  constructor(blockedAttempts: number) {
    super();
    this.blockedAttempts = blockedAttempts;
  }

  override async run(request: CodexWorkerRequest) {
    const result = await super.run(request);
    if (request.kind !== "discovery") return result;
    const resultPath = path.join(request.artifactContext!.root, "result.json");
    const draft = JSON.parse(await readFile(resultPath, "utf8"));
    const blocked = this.discoveryCalls <= this.blockedAttempts;
    draft.complete = !blocked;
    draft.reviewState = {
      surfaces: [],
      explicitExclusions: [],
      deferred: blocked ? [{ id: "source-access", reason: blockedReason }] : [],
      ...(!blocked && this.discoveryCalls > 1
        ? {
            resolvedDeferred: [
              {
                id: "source-access",
                reason: "Source access restored; review finished.",
              },
            ],
          }
        : {}),
    };
    // Replace the fixture's file-authored result through the real draft tool.
    await rm(resultPath);
    await recordCodexSecurityWorkerScanDraft(
      {
        root: request.workingDirectory,
        repoRoot: request.workingDirectory,
        layout: "worker",
        scanId: draft.scanId,
      },
      draft,
    );
    return {
      ...result,
      diagnostics: [
        { code: "worker_error" as const, message: "A stream retry occurred." },
      ],
    };
  }
}

try {
  for (const complete of [false, true]) {
    await test(`empty draft complete:${complete} controls publication`, async () => {
      const { fixture, store } = await coordinatorFixture();
      const executor = new CheckpointExecutor(complete ? 0 : Infinity);
      let publications = 0;
      const terminal = await runCoordinator(fixture, store, executor, {
        retryDelaysMs: [],
        onComplete: async () => {
          publications += 1;
        },
      });
      assert.equal(terminal?.status, complete ? "succeeded" : "failed");
      assert.equal(publications, complete ? 1 : 0);
      if (!complete) {
        assert.match(terminal.error!, /only a checkpoint/);
        assert.equal(executor.dedupCalls, 0);
        const worker = [...store.workers.values()][0];
        assert.notEqual(worker.status, "succeeded");
        const head = JSON.parse(
          await readFile(
            path.join(worker.artifactDir, "checkpoint-head.json"),
            "utf8",
          ),
        );
        const saved = JSON.parse(
          await readFile(
            path.join(worker.artifactDir, "checkpoints", head.checkpoint),
            "utf8",
          ),
        );
        assert.equal(saved.complete, false);
        assert.equal(saved.reviewState.deferred[0].reason, blockedReason);
      }
    });
  }

  await test("blocked checkpoint can be followed by a completed retry", async () => {
    const { fixture, store } = await coordinatorFixture();
    const executor = new CheckpointExecutor(1);
    let publications = 0;
    const terminal = await runCoordinator(fixture, store, executor, {
      retryDelaysMs: [0],
      onComplete: async () => {
        publications += 1;
      },
    });
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(executor.discoveryCalls, 2);
    assert.equal(publications, 1);
    assert.ok(
      store.workerUpdates.some((update) =>
        update.error?.includes("only a checkpoint"),
      ),
    );
  });
} finally {
  await temporaryDirectories.cleanup();
}

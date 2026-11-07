import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { after, test } from "node:test";
import type { CodexWorkerRequest } from "../src/deep-scan/types.ts";
import {
  coordinatorFixture,
  immediateClock,
  readModelFileInputs,
  runCoordinator,
  temporaryDirectories,
  validateModelFileInputs,
} from "./deep_scan_coordinator_fixture.ts";

after(temporaryDirectories.cleanup);

test("a changed model file stops discovery retries and preserves interrupted sibling work", async () => {
  const { fixture, store } = await coordinatorFixture({
    workers: 2,
    maxDiscoveryRuns: 2,
  });
  await mkdir(fixture.run.targetPath, { recursive: true });
  const path = join(fixture.run.targetPath, "instructions.md");
  const config = { model_instructions_file: path };
  await writeFile(path, "original");
  const saved = await readModelFileInputs(config);
  let turns = 0;
  let releaseFirst!: () => void;
  const siblingStarted = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  const executor = {
    validateModelFileInputs: (signal: AbortSignal) =>
      validateModelFileInputs(saved, config, signal),
    async run(request: CodexWorkerRequest): Promise<never> {
      turns++;
      if (turns === 1) {
        await siblingStarted;
        throw new Error("transient connection failure");
      }
      assert.equal(turns, 2, "the retry started a new model turn");
      releaseFirst();
      return new Promise((_, reject) =>
        request.signal.addEventListener(
          "abort",
          () => reject(new Error("sibling transport stopped")),
          { once: true },
        ),
      );
    },
  };
  await assert.rejects(
    runCoordinator(fixture, store, executor, {
      retryDelaysMs: [1],
      clock: {
        ...immediateClock,
        sleep: async () => {
          await writeFile(path, "changed");
        },
      },
    }),
    /model_instructions_file changed/u,
  );
  assert.equal(turns, 2);
  assert.equal(store.run.status, "running");
  assert.ok(store.workerUpdates.every((worker) => worker.attempt === 1));
  assert.ok(
    store.workerUpdates.some(
      (worker) =>
        worker.status === "canceled" &&
        worker.error?.startsWith("coordinator_shutdown:"),
    ),
  );
});

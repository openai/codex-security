import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { after, test } from "node:test";
import { readJson } from "./support/json.ts";
import type { CodexWorkerRequest } from "../src/deep-scan/types.ts";
import {
  coordinatorFixture,
  createCoordinator,
  FakeExecutor,
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

for (const stage of ["batch", "retry"] as const) {
  test(`a discovery deadline during ${stage} model-file validation retains accepted evidence`, async (t) => {
    const { fixture, store } = await coordinatorFixture({
      stopAfterNoNew: 99,
      maxDiscoveryRuns: 8,
    });
    const first = new FakeExecutor({ discoveryCandidateId: "accepted" });
    let turns = 0;
    let discoverySignal: AbortSignal | undefined;
    let entered!: () => void;
    const validating = new Promise<void>((resolve) => {
      entered = resolve;
    });
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const coordinator = createCoordinator(
      fixture,
      store,
      {
        async validateModelFileInputs(signal) {
          discoverySignal ??= signal;
          if (
            signal !== discoverySignal ||
            turns !== (stage === "batch" ? 1 : 2)
          )
            return;
          entered();
          return new Promise<void>((_, reject) =>
            signal.addEventListener("abort", () => reject(signal.reason), {
              once: true,
            }),
          );
        },
        async run(request) {
          if (++turns === 1) return first.run(request);
          throw new Error("transient connection failure");
        },
      },
      { discoveryTimeoutMs: 500, retryDelaysMs: [1], clock: immediateClock },
    );
    t.after(() => coordinator.cancel("fixture cleanup"));
    coordinator.start();
    await validating;
    t.mock.timers.tick(500);
    t.mock.timers.reset();
    const terminal = await coordinator.wait(undefined, 5_000);
    assert.equal(terminal?.status, "succeeded", terminal?.error);
    assert.equal(terminal.terminalReason, "capped");
    const manifest = await readJson(terminal.manifestPath);
    assert.deepEqual(
      manifest.findings.map(
        (finding: { provenance: { candidateId: string } }) =>
          finding.provenance.candidateId,
      ),
      ["accepted"],
    );
    assert.equal(turns, stage === "batch" ? 1 : 2);
    assert.equal(store.iterations[0]?.workerIds.length, 1);
    assert.deepEqual(store.finishCalls[0]?.omittedWorkerIds, []);
    assert.equal(store.failureMessages.length, 0);
    if (stage === "retry")
      assert.ok(
        store.workerUpdates.some(
          (worker) => worker.status === "canceled" && worker.attempt === 1,
        ),
      );
  });
}

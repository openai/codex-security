import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { after, test } from "node:test";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import {
  claimDedupInputs,
  createCoordinator,
  FakeExecutor,
  FakeStore,
  fixtureRun,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";
import { readJson, writeJson } from "./support/json.ts";

after(() => temporaryDirectories.cleanup());

for (const continueReduction of [false, true]) {
  for (const missingReceipt of [false, true]) {
    test(`resumes legacy candidates without rewriting accepted artifacts: continue=${continueReduction}, missingReceipt=${missingReceipt}`, async () => {
      const fixture = await fixtureRun({
        workers: 2,
        stopAfterNoNew: 10,
        maxDiscoveryRuns: 2,
      });
      const store = new FakeStore(fixture.run);
      const pending = {
        candidateId: "legacy-pending",
        reason: "The earlier worker retained this evidence.",
        candidate: { evidence: "Synthetic handler requires validation." },
      };
      const executor = new FakeExecutor({
        discoveryDeferred: missingReceipt ? [] : [pending],
      });
      if (missingReceipt) {
        const run = executor.run.bind(executor);
        executor.run = async (request) => {
          const outcome = await run(request);
          if (request.kind === "discovery") {
            const resultPath = path.join(
              request.artifactContext!.root,
              "result.json",
            );
            const result = await readJson(resultPath);
            result.coverage.surfaces.push({
              id: "legacy-decision",
              label: "Earlier worker decision",
              disposition: "rejected",
              candidateId: pending.candidateId,
              candidate: pending.candidate,
              receiptRefs: ["artifacts/missing-review.txt"],
            });
            await writeJson(resultPath, result);
          }
          return outcome;
        };
      }
      store.dedupCommitResponseGate = Promise.withResolvers<void>();
      const original = createCoordinator(fixture, store, executor);
      original.start();
      await store.dedupCommitted.promise;
      original.cancel("mcp server process restarted");
      store.dedupCommitResponseGate.resolve();
      await original.settled();

      const accepted = [...store.workers.values()].filter(
        (worker) => worker.status === "succeeded",
      );
      for (const worker of accepted) {
        const result = await readJson(worker.resultManifestPath!);
        if (worker.kind === "dedup") {
          delete result.unresolvedCandidates;
          await writeJson(worker.resultManifestPath!, result);
        } else {
          assert.equal(result.coverage.completeness, undefined);
        }
      }
      const acceptedBytes = await Promise.all(
        accepted.map((worker) => readFile(worker.resultManifestPath!, "utf8")),
      );
      store.run = {
        ...store.run,
        status: "running",
        config: {
          ...store.run.config,
          maxDiscoveryRuns: continueReduction ? 3 : 2,
        },
        persistedWorkers: structuredClone([...store.workers.values()]),
        persistedDedupInputs: store.dedupClaims.flatMap(claimDedupInputs),
      };
      const replacement = new FakeExecutor({
        discoveryDeferred: [
          {
            candidateId: "new-pending",
            reason: "The resumed worker has independent evidence.",
          },
        ],
      });
      const published: ScanDraftInput[] = [];
      const terminal = await runCoordinator(fixture, store, replacement, {
        run: store.run,
        onComplete: async (draft) =>
          void published.push(structuredClone(draft)),
      });
      assert.equal(terminal?.status, "succeeded", terminal?.error);
      assert.equal(published.length, 1);
      const retained = published[0].coverage.deferred.filter(
        (row) => row.candidateId === pending.candidateId,
      );
      assert.deepEqual(
        retained.map((row) => row.sourceWorkerId).sort(),
        [...store.dedupClaims[0].workerIds].sort(),
      );
      assert.ok(
        retained.every(
          (row) =>
            JSON.stringify(row.candidate) === JSON.stringify(pending.candidate),
        ),
      );
      assert.equal(replacement.discoveryCalls, Number(continueReduction));
      assert.equal(replacement.dedupCalls, Number(continueReduction));
      if (continueReduction) {
        const reducer = store.workers.get(store.dedupClaims.at(-1)!.id)!;
        const result = await readJson(reducer.resultManifestPath!);
        assert.equal(result.unresolvedCandidates.length, 3);
      }
      assert.deepEqual(
        await Promise.all(
          accepted.map((worker) =>
            readFile(worker.resultManifestPath!, "utf8"),
          ),
        ),
        acceptedBytes,
      );
    });
  }
}

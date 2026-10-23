import assert from "node:assert/strict";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { after, test } from "node:test";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import type { DeepScanRunState } from "../src/deep-scan/types.js";
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
import { importModule } from "./import-module.ts";

const { createDeepScanArtifacts, validateDiscoveryArtifacts } =
  await importModule({
    stdin: {
      contents: `
        export { createDeepScanArtifacts } from "./artifacts.ts";
        export { validateDiscoveryArtifacts } from "./artifact-validation.ts";
      `,
      resolveDir: path.join(import.meta.dirname, "../src/deep-scan/"),
    },
  });

after(() => temporaryDirectories.cleanup());

for (const continueReduction of [false, true]) {
  for (const { missingReceipt, reducerVersion } of [
    { missingReceipt: false, reducerVersion: "legacy" },
    { missingReceipt: true, reducerVersion: "legacy" },
    { missingReceipt: true, reducerVersion: "current" },
  ]) {
    test(`resumes ${reducerVersion} candidates without rewriting accepted artifacts: continue=${continueReduction}, missingReceipt=${missingReceipt}`, async () => {
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
      const existingPending = {
        candidateId: "existing-pending",
        reason: "Independent synthetic evidence remains unresolved.",
      };
      const executor = new FakeExecutor({
        discoveryDeferred: missingReceipt
          ? reducerVersion === "current"
            ? [existingPending]
            : []
          : [pending],
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
            await mkdir(path.join(request.artifactContext!.root, "artifacts"), {
              recursive: true,
            });
            await writeFile(
              path.join(
                request.artifactContext!.root,
                "artifacts/missing-review.txt",
              ),
              "Synthetic review evidence.\n",
            );
            await writeJson(resultPath, result);
          }
          return outcome;
        };
      }
      store.dedupCommitResponseGate = Promise.withResolvers<void>();
      const original = createCoordinator(fixture, store, executor);
      original.start();
      await Promise.race([
        store.dedupCommitted.promise,
        original
          .settled()
          .then((terminal: DeepScanRunState) =>
            assert.fail(
              terminal.error ??
                "Coordinator finished before the reducer commit.",
            ),
          ),
      ]);
      original.cancel("mcp server process restarted");
      store.dedupCommitResponseGate.resolve();
      await original.settled();

      const accepted = [...store.workers.values()].filter(
        (worker) => worker.status === "succeeded",
      );
      for (const worker of accepted) {
        const result = await readJson(worker.resultManifestPath!);
        if (worker.kind === "dedup") {
          if (reducerVersion === "legacy") {
            delete result.unresolvedCandidates;
            await writeJson(worker.resultManifestPath!, result);
          } else {
            assert.equal(result.unresolvedCandidates.length, 2);
          }
        } else {
          assert.equal(result.coverage.completeness, undefined);
          if (missingReceipt) {
            // The worker was accepted before this historical receipt disappeared.
            await rm(
              path.join(worker.artifactDir, "artifacts/missing-review.txt"),
            );
            await assert.rejects(
              validateDiscoveryArtifacts(
                createDeepScanArtifacts(fixture.run.scanDir),
                worker.resultManifestPath!,
                fixture.run.scanId,
              ),
              /requested artifact is unavailable/,
            );
          }
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
      if (reducerVersion === "current") {
        assert.deepEqual(
          published[0].coverage.deferred
            .filter((row) => row.candidateId === existingPending.candidateId)
            .map((row) => row.sourceWorkerId)
            .sort(),
          [...store.dedupClaims[0].workerIds].sort(),
        );
      }
      if (continueReduction) {
        const reducer = store.workers.get(store.dedupClaims.at(-1)!.id)!;
        const result = await readJson(reducer.resultManifestPath!);
        assert.equal(
          result.unresolvedCandidates.length,
          reducerVersion === "current" ? 5 : 3,
        );
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

for (const receipt of ["artifacts/missing.txt", "artifacts/../outside.txt"]) {
  test(`accepted candidate recovery still rejects a generic receipt: ${receipt}`, async () => {
    const fixture = await fixtureRun();
    const artifacts = createDeepScanArtifacts(fixture.run.scanDir);
    const resultPath = path.join(
      artifacts.workersRoot,
      "worker",
      "output",
      "result.json",
    );
    const result: ScanDraftInput = {
      scanId: fixture.run.scanId,
      findings: [],
      coverage: {
        surfaces: [
          {
            label: "Generic review evidence",
            disposition: "no_issue_found",
            receiptRefs: [receipt],
          },
        ],
        explicitExclusions: [],
        deferred: [],
      },
    };
    await mkdir(path.dirname(resultPath), { recursive: true });
    await writeJson(resultPath, result);
    await assert.rejects(
      validateDiscoveryArtifacts(artifacts, resultPath, fixture.run.scanId, {
        recoverCandidateReceipts: true,
      }),
      /requested artifact is unavailable|safe scan-relative|Invalid string/,
    );
  });
}

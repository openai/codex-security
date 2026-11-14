import assert from "node:assert/strict";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  partitions,
  permutations,
  sourceFixes,
  workers,
} from "./fixtures/accepted_source_bank.mjs";
import { replay } from "./fixtures/accepted_source_replay.mjs";

test("accepted sources survive completion orders and eligible batch partitions", async () => {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "accepted-source-replay-")),
  );
  let count = 0;
  try {
    for (const order of permutations(workers.map((worker) => worker.id))) {
      for (const batches of partitions(order)) {
        // Ordinary rolling runs require two successes for the first merge.
        if (batches[0].length < 2) continue;
        const runRoot = path.join(root, String(count++));
        const result = await replay(runRoot, batches);
        assert.equal(result.findings.length, 3);
        const refs = result.findings.flatMap(
          (finding) => finding.provenance.sourceFindingIds,
        );
        assert.deepEqual(refs.toSorted(), Object.keys(sourceFixes).toSorted());
        for (const finding of result.findings) {
          for (const source of finding.provenance.sourceFindings) {
            const [workerId, index] = source.id.split(":");
            const original = workers.find((worker) => worker.id === workerId)
              .result.findings[Number(index)];
            assert.deepEqual(source.finding, original);
          }
        }
        for (const worker of workers) {
          const persisted = JSON.parse(
            await readFile(
              path.join(
                runRoot,
                "artifacts",
                "deep_discovery",
                "workers",
                worker.id,
                "output",
                "result.json",
              ),
              "utf8",
            ),
          );
          assert.deepEqual(persisted, worker.result);
        }
      }
    }
    assert.equal(count, 96);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

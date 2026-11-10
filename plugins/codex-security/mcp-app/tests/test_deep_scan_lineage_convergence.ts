import assert from "node:assert/strict";
import path from "node:path";
import { readJson, writeJson } from "./support/json.ts";
import {
  iterationInputs,
  coordinatorFixture,
  FakeExecutor,
  runCoordinator,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

try {
  const { fixture, store } = await coordinatorFixture({
    workers: 1,
    stopAfterNoNew: 2,
    maxDiscoveryRuns: 4,
  });
  const executor = new FakeExecutor({
    discoveryCandidates: {
      "discovery-0001": "root-a",
      "discovery-0002": "alias-b",
      "discovery-0003": "root-a",
      "discovery-0004": "root-a",
    },
  });
  const run = executor.run.bind(executor);
  executor.run = async (request) => {
    const outcome = await run(request);
    const resultPath = path.join(request.artifactContext!.root, "result.json");
    const result = await readJson(resultPath);
    for (const finding of result.findings) {
      finding.identity = { anchor: finding.provenance.candidateId };
    }
    await writeJson(resultPath, result);
    return outcome;
  };
  const terminal = await runCoordinator(fixture, store, executor);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal.terminalReason, "saturated");
  assert.equal(store.run.noNewStreak, 2);
  const manifest = await readJson(terminal.manifestPath);
  assert.deepEqual(
    manifest.findings.map(
      (f: { identity: { anchor: string } }) => f.identity.anchor,
    ),
    ["root-a", "alias-b"],
  );
  assert.deepEqual(
    manifest.findings.map(
      (f: { provenance: { sourceFindingIds: string[] } }) =>
        f.provenance.sourceFindingIds.length,
    ),
    [3, 1],
  );

  store.run = {
    ...store.run,
    status: "running",
    terminalReason: undefined,
    manifestPath: undefined,
    persistedWorkers: structuredClone([...store.workers.values()]),
    persistedDedupInputs: store.iterations.flatMap(iterationInputs),
  };
  const replacement = new FakeExecutor();
  const resumed = await runCoordinator(fixture, store, replacement, {
    run: store.run,
  });
  assert.equal(resumed?.status, "succeeded", resumed?.error);
  assert.equal(resumed.terminalReason, "saturated");
  assert.equal(store.run.noNewStreak, 2);
  assert.equal(replacement.discoveryCalls, 0);
  assert.deepEqual(
    (await readJson(resumed.manifestPath)).findings,
    manifest.findings,
  );
} finally {
  await temporaryDirectories.cleanup();
}

console.log("deep scan lineage convergence tests passed");

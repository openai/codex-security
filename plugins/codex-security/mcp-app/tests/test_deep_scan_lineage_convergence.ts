import assert from "node:assert/strict";
import path from "node:path";
import { readJson, writeJson } from "./support/json.ts";
import {
  claimDedupInputs,
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
    if (request.kind === "discovery") {
      for (const finding of result.findings) {
        finding.identity = { anchor: finding.provenance.candidateId };
      }
    } else if (executor.dedupCalls > 1) {
      // The semantic reducer identifies the two prior identities as aliases.
      // Later observations add evidence to that same root issue.
      const [finding] = result.findings;
      result.findings = [
        {
          ...finding,
          identity: { anchor: "merged-root" },
          provenance: {
            ...finding.provenance,
            sourceFindingIds: result.findings.flatMap(
              (item: { provenance: { sourceFindingIds: string[] } }) =>
                item.provenance.sourceFindingIds,
            ),
          },
        },
      ];
    }
    await writeJson(resultPath, result);
    return outcome;
  };
  const terminal = await runCoordinator(fixture, store, executor);
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.equal(terminal.terminalReason, "saturated");
  assert.equal(store.dedupCommits[0].newFindings, 2);
  assert.ok(
    store.dedupCommits.slice(1).every((commit) => commit.newFindings === 0),
  );
  assert.equal(store.run.noNewStreak, 2);
  const manifest = await readJson(terminal.manifestPath);
  assert.equal(manifest.findings.length, 1);
  assert.equal(manifest.findings[0].identity.anchor, "merged-root");
  assert.equal(manifest.findings[0].provenance.sourceFindingIds.length, 4);

  store.run = {
    ...store.run,
    status: "running",
    terminalReason: undefined,
    manifestPath: undefined,
    persistedWorkers: structuredClone([...store.workers.values()]),
    persistedDedupInputs: store.dedupClaims.flatMap(claimDedupInputs),
  };
  const replacement = new FakeExecutor();
  const resumed = await runCoordinator(fixture, store, replacement, {
    run: store.run,
  });
  assert.equal(resumed?.status, "succeeded", resumed?.error);
  assert.equal(resumed.terminalReason, "saturated");
  assert.equal(store.run.noNewStreak, 2);
  assert.equal(replacement.discoveryCalls + replacement.dedupCalls, 0);
  assert.deepEqual(
    (await readJson(resumed.manifestPath)).findings,
    manifest.findings,
  );
} finally {
  await temporaryDirectories.cleanup();
}

console.log("deep scan lineage convergence tests passed");

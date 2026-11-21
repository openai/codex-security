import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import type { DeepScanStore } from "../src/deep-scan/types.js";
import {
  DeepScanCoordinator,
  FakeExecutor,
  FakeStore,
  fixtureRun,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

after(() => temporaryDirectories.cleanup());

for (const replaced of [
  undefined,
  "discovery",
  "previous",
  "unbound discovery",
  "unbound previous",
] as const) {
  test(`coordinator resumes accepted claim digests: ${replaced ?? "unchanged"}`, async () => {
    const { run, pluginRoot } = await fixtureRun({ maxDiscoveryRuns: 1 });
    await mkdir(run.scanDir, { recursive: true, mode: 0o700 });
    const store = new FakeStore(run);
    const original = new DeepScanCoordinator({
      run: store.run,
      store,
      pluginRoot,
      executor: new FakeExecutor(),
    });
    original.start();
    assert.equal((await original.wait(undefined, 5_000))?.status, "succeeded");
    const discovery = [...store.workers.values()].find(
      (worker) => worker.kind === "discovery",
    )!;
    const reducer = [...store.workers.values()].find(
      (worker) => worker.kind === "dedup",
    )!;
    const discoveryPath = discovery.resultManifestPath!;
    const discoveryBytes = await readFile(discoveryPath, "utf8");
    const previousBytes = await readFile(reducer.resultManifestPath!, "utf8");
    const frozenPath = join(
      reducer.artifactDir,
      "checkpoints",
      "accepted-result.json",
    );
    await mkdir(dirname(frozenPath), { recursive: true });
    await writeFile(frozenPath, previousBytes);
    const digest = (bytes: string) =>
      createHash("sha256").update(bytes).digest("hex");
    const unstartedRoot = join(
      dirname(dirname(reducer.artifactDir)),
      "dedup-0002",
    );
    store.workers.set("unstarted", {
      id: "unstarted",
      kind: "dedup",
      status: "canceled",
      mergeState: "none",
      promptPath: join(unstartedRoot, "prompt.md"),
      artifactDir: join(unstartedRoot, "output"),
      attempt: 0,
    });
    store.run = {
      ...store.run,
      status: "running",
      terminalReason: undefined,
      manifestPath: undefined,
      // Migrated rows may predate accepted attempts. Only their recorded claims bind the bytes.
      persistedWorkers: [...store.workers.values()].map((worker) => ({
        ...worker,
        acceptedResultPath: undefined,
        acceptedResultSha256: undefined,
      })),
      persistedDedupInputs: [
        {
          dedupWorkerId: reducer.id,
          discoveryWorkerId: discovery.id,
          inputOrder: 0,
          resultManifestPath: discoveryPath,
          resultManifestSha256: digest(discoveryBytes),
          attempt: discovery.attempt,
        },
      ],
      persistedMergeClaims: [
        {
          workerId: "unstarted",
          previousWorkerId: reducer.id,
          previousResultPath: frozenPath,
          previousResultSha256: digest(previousBytes),
        },
      ],
    };
    if (replaced === "unbound discovery") store.run.persistedDedupInputs = [];
    if (replaced === "unbound previous") store.run.persistedMergeClaims = [];
    if (replaced === "discovery" || replaced === "previous") {
      const path = replaced === "discovery" ? discoveryPath : frozenPath;
      const changed = JSON.parse(
        replaced === "discovery" ? discoveryBytes : previousBytes,
      );
      changed.threatModel = {
        summary: "Synthetic replacement after acceptance.",
      };
      await writeFile(path, JSON.stringify(changed));
    }
    const executor = new FakeExecutor();
    const publications: string[] = [];
    const resumed = new DeepScanCoordinator({
      run: store.run,
      store,
      pluginRoot,
      executor,
      onComplete: async (
        _draft: unknown,
        _signal: AbortSignal,
        publication: { resultPath: string },
      ) => {
        publications.push(publication.resultPath);
      },
    });
    resumed.start();
    const terminal = await resumed.wait(undefined, 5_000);
    assert.equal(executor.discoveryCalls, 0);
    if (replaced) {
      assert.equal(terminal?.status, "failed");
      assert.match(
        terminal?.error ?? "",
        replaced.startsWith("unbound")
          ? /incomplete persisted evidence|missing its accepted result digest/
          : /changed after acceptance/,
      );
      assert.deepEqual(publications, []);
    } else {
      assert.equal(terminal?.status, "succeeded", terminal?.error);
      assert.deepEqual(publications, [frozenPath]);
    }
  });
}

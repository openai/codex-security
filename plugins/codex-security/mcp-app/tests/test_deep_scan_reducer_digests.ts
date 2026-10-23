import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import type { DeepScanStore } from "../src/deep-scan/types.js";
import { importSource } from "./import-module.ts";
import {
  DeepScanCoordinator,
  FakeExecutor,
  FakeStore,
  fixtureRun,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";
import { finding, workerDraft } from "./scan-draft-fixture.ts";

const { DeepScanWorkerRunner } = (await importSource(
  "src/deep-scan/worker-runner.ts",
  { loader: { ".md": "text" } },
)) as typeof import("../src/deep-scan/worker-runner.js");
const { createDeepScanArtifacts } = (await importSource(
  "src/deep-scan/artifacts.ts",
)) as typeof import("../src/deep-scan/artifacts.js");
const { getCodexSecurityDeepReducerInputs } = (await importSource(
  "src/artifact-deep-reducer.ts",
)) as typeof import("../src/artifact-deep-reducer.js");
const { validateDiscoveryArtifacts, validateReducerArtifacts } =
  (await importSource(
    "src/deep-scan/artifact-validation.ts",
  )) as typeof import("../src/deep-scan/artifact-validation.js");
after(() => temporaryDirectories.cleanup());

for (const [replaced, phase] of [
  [undefined, "claim"],
  ["discovery", "claim"],
  ["previous", "claim"],
  ["discovery", "execution"],
  ["previous", "execution"],
  ["discovery", "recovery"],
  ["previous", "recovery"],
] as const) {
  test(`reducer checks accepted input bytes: ${replaced ?? "unchanged"} at ${phase}`, async () => {
    const { run, pluginRoot } = await fixtureRun();
    const artifacts = createDeepScanArtifacts(run.scanDir);
    await mkdir(run.scanDir, { recursive: true, mode: 0o700 });
    const resultPath = join(
      artifacts.workersRoot,
      "discovery-0001/output/result.json",
    );
    const previousPath = join(
      artifacts.dedupRoot,
      "dedup-0001/output/result.json",
    );
    const source = finding("accepted", "src/accepted.ts");
    const previous = finding("previous", "src/previous.ts");
    const replacement = finding("replacement", "src/replacement.ts");
    const result = workerDraft([source], { scanId: run.scanId });
    const discoveryBytes = JSON.stringify(result);
    const previousBytes = JSON.stringify({
      scanId: run.scanId,
      findings: [previous],
    });
    for (const path of [resultPath, previousPath])
      await mkdir(dirname(path), { recursive: true });
    await writeFile(resultPath, discoveryBytes);
    await writeFile(previousPath, previousBytes);
    const digest = (bytes: string) =>
      createHash("sha256").update(bytes).digest("hex");
    const replaceInput = async () => {
      if (replaced === "discovery") {
        await writeFile(
          resultPath,
          JSON.stringify(workerDraft([replacement], { scanId: run.scanId })),
        );
      } else if (replaced === "previous") {
        await writeFile(
          previousPath,
          JSON.stringify({ scanId: run.scanId, findings: [replacement] }),
        );
      }
    };
    if (phase === "recovery") {
      await replaceInput();
      if (replaced === "discovery") {
        await assert.rejects(
          validateDiscoveryArtifacts(
            artifacts,
            resultPath,
            run.scanId,
            true,
            true,
            dirname(resultPath),
            digest(discoveryBytes),
          ),
          /changed after acceptance/,
        );
      } else {
        const currentPath = join(
          artifacts.dedupRoot,
          "dedup-0002/output/result.json",
        );
        await mkdir(dirname(currentPath), { recursive: true });
        await writeFile(
          currentPath,
          JSON.stringify({ scanId: run.scanId, findings: [source, previous] }),
        );
        await assert.rejects(
          validateReducerArtifacts(
            {
              artifacts,
              artifactDir: dirname(previousPath),
              resultPath: previousPath,
              resultSha256: digest(previousBytes),
              reducerId: "previous",
              accepted: true,
            },
            run.scanId,
          ),
          /changed after acceptance/,
        );
        await assert.rejects(
          validateReducerArtifacts(
            {
              artifacts,
              artifactDir: dirname(currentPath),
              resultPath: currentPath,
              previousReducerResultPath: previousPath,
              previousReducerResultSha256: digest(previousBytes),
              reducerId: "current",
              accepted: true,
            },
            run.scanId,
          ),
          /changed after acceptance/,
        );
      }
      return;
    }
    const fakeStore = new FakeStore(run);
    const store: DeepScanStore = Object.assign(fakeStore, {
      async releaseCoordinator() {
        assert.fail("a reducer does not release the coordinator");
      },
      async cancel() {
        assert.fail("a reducer does not cancel its owning scan");
      },
    });
    fakeStore.workers.set("discovery", {
      id: "discovery",
      kind: "discovery",
      status: "succeeded",
      mergeState: "buffered",
      promptPath: join(dirname(resultPath), "../prompt.md"),
      artifactDir: dirname(resultPath),
      attempt: 1,
      resultManifestPath: resultPath,
      completionSequence: 1,
    });
    const claimDedup = store.claimDedup.bind(store);
    store.claimDedup = async (input) => {
      await claimDedup(input);
      if (phase === "claim") await replaceInput();
      return {
        ...run,
        persistedMergeClaims: [
          {
            workerId: input.id,
            previousWorkerId: "previous",
            previousResultPath: previousPath,
            previousResultSha256: digest(previousBytes),
          },
        ],
        persistedDedupInputs: [
          {
            dedupWorkerId: input.id,
            discoveryWorkerId: "discovery",
            inputOrder: 0,
            attempt: 1,
            resultManifestPath: resultPath,
            resultManifestSha256: digest(discoveryBytes),
          },
        ],
      };
    };
    const commitDedup = store.commitDedup.bind(store);
    store.commitDedup = async (commit) => {
      assert.equal(
        digest(await readFile(resultPath, "utf8")),
        digest(discoveryBytes),
      );
      assert.equal(
        digest(await readFile(previousPath, "utf8")),
        digest(previousBytes),
      );
      return commitDedup(commit);
    };
    let executions = 0;
    const runner = new DeepScanWorkerRunner({
      run,
      store,
      artifacts,
      pluginRoot,
      signal: new AbortController().signal,
      random: () => 0,
      clock: { now: Date.now, sleep: async () => {} },
      log: () => {},
      retryDelaysMs: [],
      executor: {
        async run(request) {
          executions += 1;
          if (phase === "execution") {
            await replaceInput();
            await assert.rejects(
              getCodexSecurityDeepReducerInputs({
                ...request.artifactContext!,
                repoRoot: run.targetPath,
                scanId: run.scanId,
              }),
              /changed after acceptance/,
            );
          }
          // Restoring accepted bytes makes a commit-time check pass, after the
          // reducer has already captured the replacement as an input.
          await writeFile(resultPath, discoveryBytes);
          await writeFile(previousPath, previousBytes);
          await writeFile(
            join(request.artifactContext!.root, "result.json"),
            JSON.stringify({
              scanId: run.scanId,
              findings: [
                phase === "claim" && replaced === "discovery"
                  ? replacement
                  : source,
                phase === "claim" && replaced === "previous"
                  ? replacement
                  : previous,
              ],
            }),
          );
          return {};
        },
      },
    });
    const pending = runner.runReducer({
      id: "reducer",
      label: "dedup-0002",
      consumed: [
        {
          id: "discovery",
          label: "discovery-0001",
          artifactDir: dirname(resultPath),
          resultPath,
          result,
          completionSequence: 1,
          attempt: 1,
        },
      ],
    });
    if (replaced && phase === "claim") {
      await assert.rejects(pending, /changed after acceptance/);
      assert.equal(executions, 0);
      assert.equal(fakeStore.dedupCommitCalls.length, 0);
    } else {
      const outcome = await pending;
      assert.ok(
        "result" in outcome,
        "unchanged accepted inputs still reduce successfully",
      );
      assert.equal(outcome.result.findings.length, 2);
      assert.equal(executions, 1);
      assert.equal(fakeStore.dedupCommitCalls.length, 1);
    }
  });
}

for (const replaced of [undefined, "discovery", "previous"] as const) {
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
      persistedWorkers: structuredClone([...store.workers.values()]),
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
    if (replaced) {
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
    assert.equal(executor.discoveryCalls + executor.dedupCalls, 0);
    if (replaced) {
      assert.equal(terminal?.status, "failed");
      assert.match(terminal?.error ?? "", /changed after acceptance/);
      assert.deepEqual(publications, []);
    } else {
      assert.equal(terminal?.status, "succeeded", terminal?.error);
      assert.deepEqual(publications, [frozenPath]);
    }
  });
}

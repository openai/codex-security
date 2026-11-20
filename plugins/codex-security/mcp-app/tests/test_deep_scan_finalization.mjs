import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  appendFile,
  mkdir,
  readFile,
  readdir,
  rename,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { afterEach, test } from "node:test";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import { importNativeModule as importModule } from "./import-module.ts";

const module = await importModule({
  stdin: {
    contents: `export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";
      export * from "./src/deep-scan/finalization.ts";
      export * from "./src/deep-scan/artifacts.ts";
      export * from "./src/artifact-scan-draft.ts";
      export { parseScanUnion } from "./src/deep-scan/artifact-validation.ts";
      export { legacyAcceptedFinding } from "./tests/legacy-accepted-finding.ts";`,
    resolveDir: path.resolve(import.meta.dirname, ".."),
  },
  loader: { ".md": "text" },
  footer: { js: "//# sourceURL=deep-scan-finalization-contract.js" },
});
const {
  DeepScanCoordinator,
  publishSelectedDeepScan,
  readSelectedDeepScanDraft,
  createDeepScanArtifacts,
  saveScanDraftCheckpoint,
  parseScanUnion,
  parseScanDraft,
  legacyAcceptedFinding,
} = module;
const scanId = "4e7b4acb-ac80-4d68-98cd-3d5ac5581cd1";

const directories = createTemporaryDirectories(true);
afterEach(directories.cleanup);

function sha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function finalizationInput(overrides = {}) {
  return {
    version: 1,
    resultPath: null,
    resultSha256: null,
    terminalReason: "capped",
    omittedWorkerIds: [],
    selectedAt: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

function draftFixture() {
  const findingSet = { scanId, complete: true, findings: [] };
  const reviewState = {
    surfaces: [],
    explicitExclusions: [],
    deferred: [{ id: "review", reason: "A dependency remains unreviewed." }],
  };
  return {
    draft: { ...findingSet, reviewState },
    reduction: {
      ...findingSet,
      sourceCoverage: { completeness: "partial", ...reviewState },
    },
  };
}

for (const rootCause of ["object", "text"]) {
  test(`replays accepted legacy finding details with ${rootCause} root cause`, async () => {
    const scanDir = await directories.create("selected-legacy-finding-");
    const finding = legacyAcceptedFinding();
    if (rootCause === "text") finding.root_cause = "Synthetic root cause";
    const saved = {
      scanId,
      findings: [finding],
      sourceCoverage: { surfaces: [], explicitExclusions: [], deferred: [] },
    };
    const contents = JSON.stringify(saved);
    const selected = path.join(scanDir, "selected.json");
    await writeFile(selected, contents);
    const draft = await readSelectedDeepScanDraft(
      createDeepScanArtifacts(scanDir),
      scanId,
      finalizationInput({
        resultPath: "selected.json",
        resultSha256: sha256(contents),
        selectedAt: "2030-01-01T00:00:00Z",
      }),
    );
    assert.deepEqual(draft.findings, saved.findings);
    assert.equal(await readFile(selected, "utf8"), contents);
    assert.throws(() => parseScanDraft(draft));

    const invalid = structuredClone(saved);
    invalid.findings[0].attackPath.dataFlow.evidence_refs = ["missing"];
    assert.throws(
      () => parseScanUnion(invalid),
      /attackPath\.dataFlow\.evidence_refs.*existing code-evidence IDs/,
    );
  });
}

for (const mode of ["normal", "symlink", "changed", "canceled"]) {
  test(`selected reducer read preserves accepted-file boundary: ${mode}`, async () => {
    const root = await directories.create("selected-reader-");
    const scanDir = path.join(root, "scan");
    await mkdir(scanDir, { mode: 0o700 });
    const selected = path.join(scanDir, "selected.json");
    const outside = path.join(root, "outside.json");
    const contents = JSON.stringify({
      scanId,
      complete: true,
      findings: [],
      sourceCoverage: {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      },
    });
    await writeFile(selected, contents);
    await writeFile(outside, contents);
    const selection = finalizationInput({
      resultPath: "selected.json",
      resultSha256: sha256(contents),
      selectedAt: "2030-01-01T00:00:00Z",
    });
    if (mode === "symlink") {
      await rename(selected, `${selected}.original`);
      await symlink(outside, selected, "file");
    }
    if (mode === "changed") await appendFile(selected, "\n");
    const controller = new AbortController();
    if (mode === "canceled")
      controller.abort(new Error("Stopped selected publication"));
    const reading = readSelectedDeepScanDraft(
      createDeepScanArtifacts(scanDir),
      scanId,
      selection,
      controller.signal,
    );
    if (mode === "normal") assert.equal((await reading).scanId, scanId);
    else
      await assert.rejects(
        reading,
        mode === "canceled"
          ? /Stopped selected publication/
          : mode === "changed"
            ? /changed after acceptance/
            : /file|directory|symlink/,
      );
  });
}

for (const terminalReason of ["capped", "saturated"]) {
  test(`replays the selected ${terminalReason} input after replaceable results change`, async () => {
    const scanDir = await directories.create("selected-finalization-");
    const artifacts = createDeepScanArtifacts(scanDir);
    const root = path.join(artifacts.dedupRoot, "dedup-0001", "output");
    await mkdir(root, { recursive: true });
    const { draft, reduction } = draftFixture();
    await saveScanDraftCheckpoint(
      { root, repoRoot: scanDir, layout: "reducer" },
      reduction,
    );
    const [name] = await readdir(path.join(root, "checkpoints"));
    const checkpoint = path.join(root, "checkpoints", name);
    const contents = await readFile(checkpoint);
    const selection = finalizationInput({
      resultPath: path.relative(scanDir, checkpoint).split(path.sep).join("/"),
      resultSha256: sha256(contents),
      terminalReason,
    });
    // A replacement result is not a new finalization selection.
    await writeFile(
      path.join(root, "result.json"),
      JSON.stringify({ ...draft, complete: false }),
    );
    assert.deepEqual(
      await readSelectedDeepScanDraft(artifacts, scanId, selection),
      draft,
    );
    assert.deepEqual(
      await readSelectedDeepScanDraft(artifacts, scanId, selection),
      draft,
    );
    await assert.rejects(
      readSelectedDeepScanDraft(
        artifacts,
        "e14e9229-653a-4385-bec0-8745f0b037cb",
        selection,
      ),
      /complete result for this scan/,
    );
    await writeFile(checkpoint, JSON.stringify({ ...draft, findings: [] }));
    await assert.rejects(
      readSelectedDeepScanDraft(artifacts, scanId, selection),
      /changed after acceptance/,
    );
  });
}

test("retains unresolved coverage for a persisted zero-success deadline selection", async () => {
  const selection = finalizationInput();
  const result = await readSelectedDeepScanDraft(
    createDeepScanArtifacts("unused"),
    scanId,
    selection,
  );
  assert.equal(result.scanId, scanId);
  assert.deepEqual(result.findings, []);
  assert.equal(result.reviewState.completeness, undefined);
  assert.equal(result.reviewState.deferred.length, 1);
  assert.deepEqual(result.scope?.limitations, [
    result.reviewState.deferred[0].reason,
  ]);
  await assert.rejects(
    readSelectedDeepScanDraft(createDeepScanArtifacts("unused"), scanId, {
      ...selection,
      terminalReason: "saturated",
    }),
    /recorded discovery deadline/,
  );
});

for (const status of ["failed", "canceled", "interrupted"]) {
  test(`saved selection does not turn a ${status} scan into success`, async () => {
    await assert.rejects(
      publishSelectedDeepScan({
        run: {
          scanId,
          scanDir: "unused",
          workflowVersion: "deep-security-scan/v2",
          status,
          finalizationInput: finalizationInput(),
        },
        artifacts: createDeepScanArtifacts("unused"),
        signal: new AbortController().signal,
        publish: async () =>
          assert.fail("Stopped work cannot publish successful results"),
        finish: async () =>
          assert.fail("Stopped work cannot finish successfully"),
      }),
      /Stopped Deep Scan/,
    );
  });
}

test("cancellation prevents selected publication and preserves its input", async () => {
  const controller = new AbortController();
  controller.abort("cost limit or user cancellation");
  const selection = finalizationInput();
  await assert.rejects(
    publishSelectedDeepScan({
      run: {
        scanId,
        scanDir: "unused",
        workflowVersion: "deep-security-scan/v2",
        status: "running",
        finalizationInput: selection,
      },
      artifacts: createDeepScanArtifacts("unused"),
      signal: controller.signal,
      publish: async () => assert.fail("Canceled work cannot publish"),
      finish: async () => assert.fail("Canceled work cannot finish"),
    }),
    (error) => error === controller.signal.reason,
  );
  assert.equal(selection.terminalReason, "capped");
});

for (const terminalReason of ["saturated", "capped"]) {
  test(`restart publishes the selected ${terminalReason} result after an output failure`, async () => {
    const scanDir = await directories.create("selected-replay-");
    const { draft, reduction } = draftFixture();
    const bytes = JSON.stringify(reduction);
    const digest = sha256(bytes);
    const resultPath = `artifacts/deep_discovery/dedup/dedup-0001/output/checkpoints/${digest}.json`;
    await mkdir(path.dirname(path.join(scanDir, resultPath)), {
      recursive: true,
    });
    await writeFile(path.join(scanDir, resultPath), bytes);
    const selection = finalizationInput({
      resultPath,
      resultSha256: digest,
      terminalReason,
    });
    let run = {
      scanId,
      scanDir,
      targetPath: scanDir,
      scope: ".",
      workflowVersion: "deep-security-scan/v2",
      status: "running",
      phase: "terminal",
      coordinatorGeneration: 3,
      finalizationInput: selection,
      terminalReason,
      createdAt: "2026-01-01T00:00:00Z",
      config: {
        workers: 2,
        subagents: 0,
        stopAfterNoNew: 2,
        stopAfterConsecutiveErrors: 2,
        maxDiscoveryRuns: 4,
        maxTimeHours: 1,
      },
      dispatchedCount: 4,
      noNewStreak: 2,
      consecutiveErrors: 0,
    };
    const mutations = [];
    const store = new Proxy(
      {
        get: async () => structuredClone(run),
        finish: async (input) => {
          mutations.push("finish");
          assert.equal(input.reason, terminalReason);
          assert.deepEqual(input.omittedWorkerIds, selection.omittedWorkerIds);
          run = {
            ...run,
            status: "succeeded",
            manifestPath: input.manifestPath,
          };
          return structuredClone(run);
        },
        fail: async () => {
          mutations.push("fail");
          run = { ...run, status: "failed" };
          return run;
        },
      },
      {
        get: (target, key) =>
          key in target
            ? target[key]
            : async () => {
                mutations.push(key);
                throw new Error(
                  `Unexpected scheduler operation: ${String(key)}`,
                );
              },
      },
    );
    let executions = 0;
    let publications = 0;
    const options = {
      store,
      executor: {
        run: async () => {
          executions++;
          throw new Error("Unexpected model work");
        },
      },
      pluginRoot: scanDir,
      threadId: "original-result-conversation",
      retryDelaysMs: [],
      // Already expired: replay must not start a discovery deadline timer.
      discoveryTimeoutMs: 1,
      onComplete: async (actual, _signal, publication) => {
        publications++;
        assert.deepEqual(actual, draft);
        assert.equal(publication.coordinatorGeneration, 3);
        assert.equal(publication.resultPath, path.join(scanDir, resultPath));
        if (publications === 1)
          throw new Error("Synthetic publication write failure");
      },
    };
    const resume = () => {
      const coordinator = new DeepScanCoordinator({
        ...options,
        run: structuredClone(run),
      });
      coordinator.start();
      return coordinator.wait();
    };
    await assert.rejects(resume(), /Synthetic publication write failure/);
    assert.equal(run.status, "running");
    assert.equal(run.terminalReason, terminalReason);
    assert.deepEqual(run.finalizationInput, selection);
    const completed = await resume();
    assert.equal(completed.status, "succeeded");
    assert.equal(completed.terminalReason, terminalReason);
    assert.equal(executions, 0);
    assert.deepEqual(mutations, ["finish"]);
    assert.equal(publications, 2);
  });
}

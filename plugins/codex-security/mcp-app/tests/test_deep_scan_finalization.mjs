import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { promises as fs, renameSync, symlinkSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const bundle = await build({
  stdin: {
    contents: `export * from "./src/deep-scan/finalization.ts";
      export * from "./src/deep-scan/artifacts.ts";
      export * from "./src/artifact-scan-draft.ts";
      export { parseDeepReduction } from "./src/deep-scan/artifact-validation.ts";
      export { legacyAcceptedFinding } from "./tests/legacy-accepted-finding.ts";`,
    resolveDir: path.resolve(import.meta.dirname, ".."),
  },
  bundle: true,
  format: "esm",
  platform: "node",
  write: false,
  footer: { js: "//# sourceURL=deep-scan-finalization-contract.js" },
});
const {
  publishSelectedDeepScan,
  readSelectedDeepScanDraft,
  createDeepScanArtifacts,
  saveScanDraftCheckpoint,
  parseDeepReduction,
  parseScanDraft,
  legacyAcceptedFinding,
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);
const scanId = "4e7b4acb-ac80-4d68-98cd-3d5ac5581cd1";

for (const rootCause of ["object", "text"]) {
  test(`replays accepted legacy finding details with ${rootCause} root cause`, async () => {
    const scanDir = await realpath(
      await mkdtemp(path.join(tmpdir(), "selected-legacy-finding-")),
    );
    try {
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
        {
          version: 1,
          resultPath: "selected.json",
          resultSha256: createHash("sha256").update(contents).digest("hex"),
          terminalReason: "capped",
          omittedWorkerIds: [],
          selectedAt: "2030-01-01T00:00:00Z",
        },
      );
      assert.deepEqual(draft.findings, saved.findings);
      assert.equal(await readFile(selected, "utf8"), contents);
      assert.throws(() => parseScanDraft(draft));
      assert.throws(() => parseDeepReduction(saved));

      const invalid = structuredClone(saved);
      invalid.findings[0].attackPath.dataFlow.evidence_refs = ["missing"];
      assert.throws(
        () => parseDeepReduction(invalid, true),
        /attackPath\.dataFlow\.evidence_refs.*existing code-evidence IDs/,
      );
    } finally {
      await rm(scanDir, { recursive: true, force: true });
    }
  });
}

for (const mode of ["normal", "symlink", "swapped", "changed", "canceled"]) {
  test(`selected reducer read preserves accepted-file boundary: ${mode}`, async (t) => {
    const root = await realpath(
      await mkdtemp(path.join(tmpdir(), "selected-reader-")),
    );
    try {
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
      const selection = {
        version: 1,
        resultPath: "selected.json",
        resultSha256: createHash("sha256").update(contents).digest("hex"),
        terminalReason: "capped",
        omittedWorkerIds: [],
        selectedAt: "2030-01-01T00:00:00Z",
      };
      const swap = () => {
        renameSync(selected, `${selected}.original`);
        symlinkSync(outside, selected, "file");
      };
      if (mode === "symlink") swap();
      if (mode === "changed") await fs.appendFile(selected, "\n");
      const controller = new AbortController();
      if (mode === "canceled")
        controller.abort(new Error("Stopped selected publication"));
      const lstat = fs.lstat;
      let swapped = false;
      const spy = t.mock.method(fs, "lstat", async (...args) => {
        const result = await lstat(...args);
        if (mode === "swapped" && args[0] === selected && !swapped) {
          swap();
          swapped = true;
        }
        return result;
      });
      syncBuiltinESMExports();
      try {
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
        if (mode === "swapped") assert.equal(swapped, true);
      } finally {
        spy.mock.restore();
        syncBuiltinESMExports();
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const terminalReason of ["capped", "saturated"]) {
  test(`replays the selected ${terminalReason} input after replaceable results change`, async () => {
    const scanDir = await realpath(
      await mkdtemp(path.join(tmpdir(), "selected-finalization-")),
    );
    try {
      const artifacts = createDeepScanArtifacts(scanDir);
      const root = path.join(artifacts.dedupRoot, "dedup-0001", "output");
      await mkdir(root, { recursive: true });
      const draft = {
        scanId,
        complete: true,
        findings: [],
        coverage: {
          completeness: "partial",
          surfaces: [],
          explicitExclusions: [],
          deferred: [
            { id: "review", reason: "A dependency remains unreviewed." },
          ],
        },
      };
      const { coverage, ...reduction } = draft;
      await saveScanDraftCheckpoint(
        { root, repoRoot: scanDir, layout: "reducer" },
        {
          ...reduction,
          sourceCoverage: coverage,
        },
      );
      delete draft.coverage.completeness;
      const [name] = await readdir(path.join(root, "checkpoints"));
      const checkpoint = path.join(root, "checkpoints", name);
      const contents = await readFile(checkpoint);
      const selection = {
        version: 1,
        resultPath: path
          .relative(scanDir, checkpoint)
          .split(path.sep)
          .join("/"),
        resultSha256: createHash("sha256").update(contents).digest("hex"),
        terminalReason,
        omittedWorkerIds: [],
        selectedAt: "2026-01-01T00:00:00Z",
      };
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
    } finally {
      await rm(scanDir, { recursive: true, force: true });
    }
  });
}

test("retains unresolved coverage for a persisted zero-success deadline selection", async () => {
  const selection = {
    version: 1,
    resultPath: null,
    resultSha256: null,
    terminalReason: "capped",
    omittedWorkerIds: [],
    selectedAt: "2026-01-01T00:00:00Z",
  };
  const result = await readSelectedDeepScanDraft(
    createDeepScanArtifacts("unused"),
    scanId,
    selection,
  );
  assert.equal(result.scanId, scanId);
  assert.deepEqual(result.findings, []);
  assert.equal(result.coverage.completeness, undefined);
  assert.equal(result.coverage.deferred.length, 1);
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
          finalizationInput: {
            version: 1,
            resultPath: null,
            resultSha256: null,
            terminalReason: "capped",
            omittedWorkerIds: [],
            selectedAt: "2026-01-01T00:00:00Z",
          },
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
  const selection = {
    version: 1,
    resultPath: null,
    resultSha256: null,
    terminalReason: "capped",
    omittedWorkerIds: [],
    selectedAt: "2026-01-01T00:00:00Z",
  };
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

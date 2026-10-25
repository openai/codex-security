import assert from "node:assert/strict";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { importModule } from "./import-module.ts";
import { scanId } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const {
  createDeepScanArtifacts,
  recordCodexSecurityWorkerScanDraft,
  validateDiscoveryArtifacts,
} = await importModule({
  stdin: {
    contents: `
      export { createDeepScanArtifacts } from "./deep-scan/artifacts.ts";
      export { validateDiscoveryArtifacts } from "./deep-scan/artifact-validation.ts";
      export { recordCodexSecurityWorkerScanDraft } from "./artifact-scan-draft.ts";
    `,
    resolveDir: path.join(import.meta.dirname, "../src"),
  },
});

const identities = [
  { label: "blank", candidateId: " " },
  { label: "empty", candidateId: "" },
  { label: "absent", candidateId: undefined },
  { label: "candidate", candidateId: "review-1" },
];
const cases = identities.flatMap((identity) =>
  ["opaque", "missing", "absent", "valid"].map((receipt) => ({
    ...identity,
    receipt,
    disposition: undefined as string | undefined,
  })),
);
for (const disposition of ["rejected", "needs_follow_up"])
  cases.push({
    label: "blank",
    candidateId: " ",
    receipt: "opaque",
    disposition,
  });

for (const { label, candidateId, receipt, disposition } of cases) {
  test(`worker exclusion receipts: identity=${label}, receipt=${receipt}, disposition=${disposition ?? "absent"}`, async (t) => {
    const directory = await temporaryDirectory("worker-exclusion-", true);
    t.after(() => rm(directory, { recursive: true, force: true }));
    const artifacts = createDeepScanArtifacts(directory);
    const root = path.join(artifacts.workersRoot, "worker-1", "output");
    await mkdir(root, { recursive: true });
    const context = {
      root,
      repoRoot: directory,
      scanId,
      layout: "worker",
      scope: ".",
    };
    const ref = "artifacts/proof.txt";
    const proof = "Synthetic decision evidence.\n";
    if (receipt === "valid") {
      await mkdir(path.join(root, "artifacts"));
      await writeFile(path.join(root, ref), proof);
    }
    const exclusion = {
      pattern: "vendor/**",
      reason: "Historical exclusion with original diagnostic text.",
      ...(candidateId === undefined ? {} : { candidateId }),
      ...(disposition === undefined ? {} : { disposition }),
      ...(receipt === "absent"
        ? {}
        : {
            receiptRefs: receipt === "opaque" ? { note: "legacy" } : [ref],
          }),
      historicalNote: { diagnostic: "Original text remains unchanged." },
    };
    await recordCodexSecurityWorkerScanDraft(context, {
      scanId,
      complete: true,
      findings: [],
      coverage: { surfaces: [], explicitExclusions: [exclusion], deferred: [] },
    });
    const resultPath = path.join(root, "result.json");
    const original = await readFile(resultPath, "utf8");
    assert.deepEqual(JSON.parse(original).coverage.explicitExclusions, [
      exclusion,
    ]);
    const validated = await validateDiscoveryArtifacts(
      artifacts,
      resultPath,
      scanId,
      { recoverCandidateReceipts: true },
    );
    assert.equal(await readFile(resultPath, "utf8"), original);
    const attempts = path.join(path.dirname(root), "attempts");
    await mkdir(attempts);
    const archived = path.join(attempts, "attempt-01");
    await rename(root, archived);
    await mkdir(root);
    await recordCodexSecurityWorkerScanDraft(context, {
      scanId,
      complete: true,
      findings: [],
      coverage: { surfaces: [], explicitExclusions: [], deferred: [] },
    });
    const recovered = JSON.parse(await readFile(resultPath, "utf8"));
    assert.equal(
      await readFile(path.join(archived, "result.json"), "utf8"),
      original,
    );
    for (const result of [validated, recovered]) {
      const row = result.coverage.explicitExclusions[0];
      assert.equal(row.reason, exclusion.reason);
      assert.deepEqual(row.historicalNote, exclusion.historicalNote);
      if (label !== "candidate") {
        assert.deepEqual(result.coverage.explicitExclusions, [exclusion]);
        assert.deepEqual(result.coverage.deferred, []);
      } else if (receipt === "missing" || receipt === "opaque") {
        assert.equal(row.disposition, "needs_follow_up");
        assert.deepEqual(row.receiptRefs, []);
        assert.equal(result.coverage.deferred.length, 1);
        assert.equal(result.coverage.deferred[0].candidateId, candidateId);
        assert.equal(
          result.coverage.deferred[0].reason,
          receipt === "opaque"
            ? "Worker candidate receipt references must be an array."
            : "Worker candidate receipt: the requested artifact is unavailable.",
        );
      } else {
        assert.deepEqual(result.coverage.deferred, []);
      }
    }
    if (label === "candidate" && receipt === "valid") {
      const retained = recovered.coverage.explicitExclusions[0].receiptRefs;
      assert.equal(retained.length, 1);
      assert.match(retained[0], /^artifacts\/retained-receipts\/[a-f0-9]{64}$/);
      assert.equal(await readFile(path.join(root, retained[0]), "utf8"), proof);
    }
  });
}

import assert from "node:assert/strict";
import { cp, mkdir, readFile, rm, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import { workerDraft, scanId } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { readDeepReductionSources } = await importSource(
  fileURLToPath(new URL("../src/artifact-deep-reducer.ts", import.meta.url)),
);
const { recordCodexSecurityWorkerScanDraft } = await importSource(
  fileURLToPath(new URL("../src/artifact-scan-draft.ts", import.meta.url)),
);

for (const ref of [
  "artifacts/review.txt",
  "artifacts/./review.txt",
  "artifacts//review.txt",
]) {
  for (const state of ["copied", "changed", "missing-archive"]) {
    test(`supported typed writer receipt origin (${ref}, ${state})`, async () => {
      const root = await temporaryDirectory("retry-receipt-origin-", true);
      try {
        const workerRoot = path.join(
          root,
          "artifacts/deep_discovery/workers/discovery-0001",
        );
        const output = path.join(workerRoot, "output");
        await mkdir(path.join(output, "artifacts"), { recursive: true });
        await writeFile(
          path.join(output, "artifacts/review.txt"),
          "Synthetic original receipt.\n",
        );
        const context = {
          root: output,
          repoRoot: root,
          scanId,
          layout: "worker",
        };
        const draft = workerDraft([], {
          complete: false,
          reviewState: {
            surfaces: [
              {
                label: "Synthetic receipt review",
                disposition: "needs_follow_up",
                receiptRefs: [ref],
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        });
        await recordCodexSecurityWorkerScanDraft(context, draft);
        const saved = JSON.parse(
          await readFile(path.join(output, "result.json"), "utf8"),
        );
        assert.equal(
          typeof saved.reviewState.surfaces[0].id,
          "string",
          "typed writer assigns implicit ID before retry snapshot",
        );
        const archive = path.join(workerRoot, "attempts/attempt-01");
        await cp(output, archive, {
          recursive: true,
          preserveTimestamps: true,
        });
        const archivedBytes = await readFile(path.join(archive, "result.json"));
        if (state === "changed")
          await writeFile(
            path.join(output, "artifacts/review.txt"),
            "Synthetic changed receipt.\n",
          );
        if (state === "missing-archive")
          await unlink(path.join(archive, "artifacts/review.txt"));
        await recordCodexSecurityWorkerScanDraft(context, {
          ...draft,
          complete: true,
        });
        const current = JSON.parse(
          await readFile(path.join(output, "result.json"), "utf8"),
        );
        assert.equal(
          current.reviewState.surfaces.length,
          1,
          "supported resumed writer retains one matching normalized surface",
        );
        assert.equal(
          current.reviewState.surfaces[0].id,
          saved.reviewState.surfaces[0].id,
        );
        assert.deepEqual(
          current.reviewState.surfaces[0].receiptRefs,
          saved.reviewState.surfaces[0].receiptRefs,
        );
        const resultPath = path.join(output, "result.json");
        const resultBytes = await readFile(resultPath);
        const sources = await readDeepReductionSources({
          root: path.join(
            root,
            "artifacts/deep_discovery/dedup/dedup-0001/output",
          ),
          repoRoot: root,
          scanId,
          layout: "reducer",
          deepReducer: {
            scanRoot: root,
            claimedWorkers: [{ id: "discovery-0001", attempt: 2, resultPath }],
          },
        });
        const surface = sources.discoveries[0].coverage.surfaces[0];
        assert.equal(
          surface.provenance.attempt,
          state === "copied" ? 1 : 2,
          "identical readable receipt retains original attempt; changed/missing evidence retains current attempt",
        );
        assert.deepEqual(
          await readFile(path.join(archive, "result.json")),
          archivedBytes,
        );
        assert.deepEqual(await readFile(resultPath), resultBytes);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

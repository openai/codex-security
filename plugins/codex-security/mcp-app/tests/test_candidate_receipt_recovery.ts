import {
  discoverCandidate,
  importDiscoverySource,
  rememberCheckpoints,
  startDiffScan,
} from "./support/discovery.ts";
import { readJson, readSavedReviewState } from "./support/json.ts";
import assert from "node:assert/strict";
import { mkdir, readFile, rm, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const options = { absWorkingDir: import.meta.dirname };
const { createScanArtifactContext } = await importSource(
  "../src/artifact-context.ts",
  options,
);
const { recordCodexSecurityScanDraftViaWorkbench: record } = await importSource(
  "../src/artifact-scan-draft.ts",
  options,
);
const discoveryApi = await importDiscoverySource();
const { recordCodexSecurityCandidateValidations } = await importSource(
  "../src/artifact-candidate-ledger.ts",
  options,
);

for (const [section, termination] of ["surfaces", "explicitExclusions"].flatMap(
  (section) =>
    ["fail-scan", "cancel-scan"].map(
      (termination) => [section, termination] as const,
    ),
)) {
  for (const receipt of [
    "valid",
    "missing",
    "replacement",
    ...(section === "explicitExclusions"
      ? ["object", "null", "array-null"]
      : []),
  ]) {
    const malformed = ["object", "null", "array-null"].includes(receipt);
    const missing = receipt === "missing" || malformed;
    for (const decision of [
      "pending",
      "suppressed",
      "not_applicable",
    ] as const) {
      if (malformed && decision !== "pending") continue;
      test(`receipt recovery precedes saved Diff decisions: section=${section}, termination=${termination}, receipt=${receipt}, ledger=${decision}`, async (t) => {
        const directory = await temporaryDirectory("candidate-receipt-", true);
        t.after(() => rm(directory, { recursive: true, force: true }));
        const { scan, workbench } = await startDiffScan(directory);
        const context = await createScanArtifactContext(
          scan.scanId,
          workbench,
          {
            requireRunning: true,
            pluginRoot: path.resolve(
              import.meta.dirname,
              "../../../../sdk/typescript/_bundled_plugin",
            ),
          },
        );
        const candidateId = await discoverCandidate(
          discoveryApi,
          context,
          "app.ts",
          "Original discovery evidence.",
        );
        await record(
          context,
          {
            scanId: scan.scanId,
            handoffClaimToken: context.handoffClaimToken,
            complete: false,
            findings: [],
            reviewState: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [
                {
                  id: "authored-gap",
                  candidateId,
                  reason: "Original authored proof gap.",
                },
              ],
            },
          },
          workbench,
        );
        if (decision !== "pending")
          await recordCodexSecurityCandidateValidations(context, {
            validations: [
              {
                candidateId,
                validation: {
                  disposition: decision,
                  method: "Static inspection",
                  confidence: "high",
                  confidence_rationale: "Synthetic evidence",
                  rubric: "Synthetic criterion",
                  evidence: "Candidate dismissed.",
                  counterevidence_or_proof_gap:
                    "Independent terminal validation.",
                  remaining_uncertainty: "",
                },
              },
            ],
          });
        const ref = "artifacts/proof/decision.txt";
        await mkdir(path.dirname(path.join(context.root, ref)), {
          recursive: true,
        });
        await writeFile(
          path.join(context.root, ref),
          "Synthetic decision evidence.\n",
        );
        const submittedGap = {
          id: "authored-gap",
          candidateId,
          reason: "Caller-supplied receipt proof gap.",
          paths: ["app.ts"],
        };
        await record(
          context,
          {
            scanId: scan.scanId,
            handoffClaimToken: context.handoffClaimToken,
            complete: true,
            findings: [],
            reviewState: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              [section]: [
                {
                  id: "authored-decision",
                  candidateId,
                  label: "Authored candidate review",
                  disposition: "rejected",
                  notes: "Authored decision with receipt.",
                  pattern: "app.ts",
                  reason: "Authored decision with receipt.",
                  receiptRefs:
                    receipt === "object"
                      ? { ref }
                      : receipt === "null"
                        ? null
                        : receipt === "array-null"
                          ? [null]
                          : [ref],
                },
              ],
              deferred: [submittedGap],
            },
          },
          workbench,
        );
        const published = await readSavedReviewState(context.root);
        const publishedGap = published.deferred.find(
          (row: { reason: string }) => row.reason === submittedGap.reason,
        );
        assert.ok(
          publishedGap,
          "The submitted proof gap is retained until verification.",
        );
        assert.deepEqual(publishedGap.paths, submittedGap.paths);
        assert.equal(published[section][0].disposition, "rejected");
        if (receipt === "missing" || receipt === "replacement")
          await unlink(path.join(context.root, ref));
        if (receipt === "replacement") {
          const replacement = "artifacts/proof/replacement.txt";
          await writeFile(
            path.join(context.root, replacement),
            "Replacement decision evidence.\n",
          );
          await record(
            context,
            {
              scanId: scan.scanId,
              handoffClaimToken: context.handoffClaimToken,
              complete: true,
              findings: [],
              reviewState: {
                completeness: "complete",
                surfaces: [],
                explicitExclusions: [],
                [section]: [
                  { ...published[section][0], receiptRefs: [replacement] },
                ],
                deferred: [],
              },
            },
            workbench,
          );
        }
        const assertUnchanged = await rememberCheckpoints(context.root);
        const ledger = path.join(
          context.root,
          "artifacts/02_discovery/candidate_ledger.jsonl",
        );
        const originalLedger = await readFile(ledger);
        for (const command of [termination, "preserve-scan-results"]) {
          await workbench([
            command,
            "--scan-id",
            scan.scanId,
            ...(command === "fail-scan"
              ? ["--message", "Synthetic interruption."]
              : []),
          ]);
          const { scan: sealed } = await readJson(
            context.root,
            "scan-manifest.json",
          );
          const pending = (sealed.review.unresolvedCandidates ?? []).filter(
            (row: { candidateId?: string }) => row.candidateId === candidateId,
          );
          assert.equal(pending.length > 0, missing, command);
          if (missing) {
            const originalGap = pending.find(
              (row: { reason: string }) => row.reason === submittedGap.reason,
            );
            assert.ok(
              originalGap,
              "The submitted proof gap survives receipt recovery.",
            );
            assert.deepEqual(originalGap.paths, submittedGap.paths);
          }
        }
        assert.deepEqual(await readFile(ledger), originalLedger);
        await assertUnchanged();
      });
    }
  }
}

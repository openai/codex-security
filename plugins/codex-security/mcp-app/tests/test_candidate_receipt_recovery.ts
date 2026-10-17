import { importDiscoverySource } from "./support/discovery.ts";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  readFile,
  readdir,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const execFileAsync = promisify(execFile);
const options = { absWorkingDir: import.meta.dirname };
const { createScanArtifactContext } = await importSource(
  "../src/artifact-context.ts",
  options,
);
const { recordCodexSecurityScanDraftViaWorkbench: record } = await importSource(
  "../src/artifact-scan-draft.ts",
  options,
);
const { recordCodexSecurityDiscoveryCandidates, listCodexSecurityCandidates } =
  await importDiscoverySource();
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
        const target = path.join(directory, "target");
        const home = path.join(directory, "home");
        await mkdir(target);
        await mkdir(home, { mode: 0o700 });
        await writeFile(
          path.join(target, "app.ts"),
          "export const value = 1;\n",
        );
        const git = async (...args: string[]) =>
          (
            await execFileAsync("git", [
              "-C",
              target,
              "-c",
              "user.name=Fixture",
              "-c",
              "user.email=fixture@example.test",
              ...args,
            ])
          ).stdout.trim();
        await git("init", "-q");
        await git("add", "app.ts");
        await git("commit", "-qm", "Synthetic fixture");
        const workbench = async (args: string[]) =>
          JSON.parse(
            (
              await execFileAsync(
                process.env.PYTHON?.trim() || "python3",
                [
                  path.join(
                    import.meta.dirname,
                    "../../scripts/workbench_db.py",
                  ),
                  ...args,
                ],
                {
                  env: {
                    ...process.env,
                    CODEX_HOME: home,
                    CODEX_SECURITY_STATE_DIR: path.join(directory, "state"),
                  },
                },
              )
            ).stdout,
          );
        const { scan } = await workbench([
          "start-prompt-only-scan",
          "--thread-id",
          "synthetic-receipt-review",
          "--target-path",
          target,
          "--scope",
          ".",
          "--mode",
          "diff",
          "--diff-target-kind",
          "commit",
          "--diff-head-revision",
          await git("rev-parse", "HEAD"),
          "--scan-root",
          path.join(directory, "scans"),
        ]);
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
        const discovery = path.join(context.root, "artifacts/02_discovery");
        await mkdir(discovery, { recursive: true });
        await writeFile(path.join(discovery, "in_scope_files.txt"), "app.ts\n");
        await recordCodexSecurityDiscoveryCandidates(
          {
            candidates: [
              {
                cwe_ids: [],
                locations: [
                  {
                    path: "app.ts",
                    start_line: 1,
                    end_line: 1,
                    role: "evidence",
                  },
                ],
                summary: "Synthetic review candidate",
                evidence: "Original discovery evidence.",
              },
            ],
          },
          context,
        );
        const candidateId = (await listCodexSecurityCandidates({}, context))
          .rows[0].candidate_id;
        await record(
          context,
          {
            scanId: scan.scanId,
            handoffClaimToken: context.handoffClaimToken,
            complete: false,
            findings: [],
            coverage: {
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
            coverage: {
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
        const coveragePath = path.join(context.root, "coverage.json");
        const published = JSON.parse(await readFile(coveragePath, "utf8"));
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
              coverage: {
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
        const checkpoints = path.join(context.root, "checkpoints");
        const originals = await Promise.all(
          (await readdir(checkpoints)).map(
            async (name) =>
              [name, await readFile(path.join(checkpoints, name))] as const,
          ),
        );
        const ledger = path.join(discovery, "candidate_ledger.jsonl");
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
          const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
          const pending = coverage.deferred.filter(
            (row: { candidateId?: string }) => row.candidateId === candidateId,
          );
          assert.equal(pending.length > 0, missing, command);
          const surfaces = coverage[section].filter(
            (row: { candidateId?: string }) => row.candidateId === candidateId,
          );
          assert.ok(surfaces.length > 0, command);
          assert.ok(
            surfaces.every(
              (row: { disposition: string }) =>
                row.disposition === (missing ? "needs_follow_up" : "rejected"),
            ),
            command,
          );
          if (missing) {
            const originalGap = pending.find(
              (row: { reason: string }) => row.reason === submittedGap.reason,
            );
            assert.ok(
              originalGap,
              "The submitted proof gap survives receipt recovery.",
            );
            assert.deepEqual(originalGap.paths, submittedGap.paths);
            assert.equal(coverage.completeness, undefined, command);
            assert.ok(
              surfaces.every(
                (row: { receiptRefs: string[] }) =>
                  row.receiptRefs.length === 0,
              ),
              command,
            );
          }
        }
        assert.deepEqual(await readFile(ledger), originalLedger);
        for (const [name, bytes] of originals)
          assert.deepEqual(await readFile(path.join(checkpoints, name)), bytes);
      });
    }
  }
}

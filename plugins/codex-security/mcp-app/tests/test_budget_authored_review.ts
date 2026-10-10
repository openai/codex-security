import { recordCodexSecurityScanDraft } from "./scan-draft-recovery-fixture.ts";
import { importDiscoverySource } from "./support/discovery.ts";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import { finding } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { recordCodexSecurityScanDraftViaWorkbench } = await importSource(
  new URL("../src/artifact-scan-draft.ts", import.meta.url).pathname,
);
const { recordCodexSecurityCandidateValidations } = await importSource(
  new URL("../src/artifact-candidate-ledger.ts", import.meta.url).pathname,
);
const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
const python = process.env.PYTHON?.trim() || "python3";
const reason = "New evidence requires another review";

async function budgetFixture(t: TestContext, modern: boolean) {
  const root = await temporaryDirectory("budget-authored-review-", true);
  t.after(() => rm(root, { recursive: true, force: true }));
  const scan = JSON.parse(
    execFileSync(
      python,
      [
        "-c",
        `
import json, sqlite3, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from workbench_test_support import begin_deep_scan, get_scan, run_workbench
root = Path(sys.argv[2])
state, target, directory = root / "state", root / "target", root / "scan"
target.mkdir(); directory.mkdir(mode=0o700)
(target / "app.py").write_text("print('synthetic source')\\n")
registered = run_workbench(state, "register-cli-scan", "--scan-dir", str(directory),
    "--repository", str(target), "--recipe-json", json.dumps({
        "config": {}, "mode": "deep", "repository": str(target),
        "target": {"kind": "repository", "paths": []}, "maxCostUsd": 0.005}))
scan_id = registered["scanId"]
begin_deep_scan(state, "synthetic-thread", "--scan-id", scan_id,
    environment={"CODEX_HOME": str(root / "codex-home")})
discovery = directory / "artifacts/02_discovery"
discovery.mkdir(parents=True, exist_ok=True)
(discovery / "in_scope_files.txt").write_text("app.py\\n")
(discovery / "candidate_ledger.jsonl").write_text(json.dumps({
    "candidate_id": "review", "cwe_ids": [], "summary": "Synthetic authorization review",
    "evidence": "Synthetic source evidence",
    "locations": [{"path": "app.py", "start_line": 1, "end_line": 1, "role": "evidence"}]
}) + "\\n")
manifest = directory / "artifacts/deep_discovery/coordinator-manifest.json"
manifest.parent.mkdir(parents=True, exist_ok=True)
manifest.write_text('{"status":"succeeded"}')
with sqlite3.connect(state / "workbench.sqlite3") as connection:
    connection.execute("UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', terminal_reason = 'saturated', manifest_path = ?, completed_at = updated_at WHERE scan_id = ?",
        (str(directory / "scan-manifest.json" if sys.argv[3] == "true" else manifest), scan_id))
print(json.dumps(get_scan(state, scan_id)["scan"]))
`,
        path.join(pluginRoot, "tests"),
        root,
        String(modern),
      ],
      { encoding: "utf8" },
    ),
  );
  const context = {
    root: scan.scanDir,
    repoRoot: scan.targetPath,
    layout: "scan" as const,
    scanId: scan.scanId,
    scope: scan.scope,
    targetContract: scan.contract,
    targetRevision: scan.targetRevision,
    status: scan.progress.status,
    mode: scan.mode,
  };

  return { root, scan, context };
}

for (const withSnapshot of [true, false]) {
  for (const modern of [false, true]) {
    for (const resolution of modern
      ? ["pending"]
      : ["pending", "new-phase", "finding", "terminal"]) {
      for (const interrupted of [false, true]) {
        test(`budget completion preserves authored review: ${modern ? "modern" : "legacy"}, ${resolution}, interrupted=${interrupted}, snapshot=${withSnapshot}`, async (t) => {
          const { root, scan, context } = await budgetFixture(t, modern);
          const ledger = path.join(
            scan.scanDir,
            "artifacts/02_discovery/candidate_ledger.jsonl",
          );
          const original = JSON.parse((await readFile(ledger, "utf8")).trim());
          const validation = {
            disposition: "suppressed",
            method: "Source review",
            confidence: "high",
            confidence_rationale: "Original source trace",
            rubric: "Synthetic review",
            evidence: "Original source evidence",
            counterevidence_or_proof_gap: "Old assessment",
            remaining_uncertainty: "",
          };
          await recordCodexSecurityCandidateValidations(context, {
            validations: [{ candidateId: original.candidate_id, validation }],
          });
          const candidate = JSON.parse((await readFile(ledger, "utf8")).trim());
          const pending = {
            id: "new-proof",
            candidateId: candidate.candidate_id,
            ...(withSnapshot ? { candidate } : {}),
            reason,
          };
          const draft = {
            scanId: scan.scanId,
            findings: [],
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [pending],
            },
          };
          const writeDraft = (
            input: Parameters<typeof recordCodexSecurityScanDraft>[1],
          ) =>
            withSnapshot
              ? recordCodexSecurityScanDraft(context, input)
              : recordCodexSecurityScanDraftViaWorkbench(
                  context,
                  input,
                  async (args: string[]) =>
                    JSON.parse(
                      execFileSync(
                        python,
                        [
                          path.join(pluginRoot, "scripts/workbench_db.py"),
                          ...args,
                        ],
                        {
                          encoding: "utf8",
                          env: {
                            ...process.env,
                            CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
                          },
                        },
                      ),
                    ),
                );
          await writeDraft(draft);
          const checkpoints = path.join(scan.scanDir, "checkpoints");
          const saved = new Map(
            await Promise.all(
              (await readdir(checkpoints)).map(
                async (name) =>
                  [name, await readFile(path.join(checkpoints, name))] as const,
              ),
            ),
          );
          const args = [
            path.join(pluginRoot, "scripts/workbench_db.py"),
            "complete-budget-exhausted-scan",
            "--scan-id",
            scan.scanId,
            "--cost-json",
            JSON.stringify({
              model: "synthetic-model",
              inputTokens: 1250,
              cachedInputTokens: 200,
              cacheWriteInputTokens: 0,
              outputTokens: 30,
              estimatedUsd: 0.00625,
            }),
            "--message",
            "Synthetic budget stop.",
          ];
          const env = {
            ...process.env,
            CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
          };
          if (interrupted) {
            for (let attempt = 0; attempt < 2; attempt++) {
              const result = spawnSync(
                python,
                [
                  "-B",
                  "-c",
                  `
import os, runpy, sys
script = sys.argv[1]; sys.argv = sys.argv[1:]
def interrupt(frame, event, arg):
    if event == 'call' and frame.f_code.co_name == 'complete_scan_locked':
        os._exit(75)
    return interrupt
sys.settrace(interrupt)
runpy.run_path(script, run_name='__main__')
`,
                  ...args,
                ],
                { encoding: "utf8", env },
              );
              assert.equal(result.status, 75, result.stderr);
              const coverage = JSON.parse(
                await readFile(
                  path.join(scan.scanDir, "coverage.json"),
                  "utf8",
                ),
              );
              assert.ok(
                coverage.deferred.some((row: any) => row.reason === reason),
              );
            }
          }
          if (resolution === "new-phase") {
            await recordCodexSecurityCandidateValidations(context, {
              validations: [
                {
                  candidateId: candidate.candidate_id,
                  validation: {
                    ...validation,
                    counterevidence_or_proof_gap:
                      "Later validation resolved the new evidence",
                  },
                },
              ],
            });
          } else if (resolution === "finding") {
            const confirmed = finding("authored-review", "app.py");
            confirmed.locations[0]!.endLine = 1;
            await writeDraft({
              ...draft,
              findings: [
                {
                  ...confirmed,
                  provenance: {
                    ...confirmed.provenance,
                    candidateId: candidate.candidate_id,
                  },
                },
              ],
              coverage: { ...draft.coverage, deferred: [] },
            });
          } else if (resolution === "terminal") {
            await writeDraft({
              ...draft,
              coverage: {
                ...draft.coverage,
                deferred: [],
                surfaces: [
                  {
                    id: "reviewed",
                    candidateId: candidate.candidate_id,
                    label: "New evidence reviewed",
                    disposition: "rejected",
                    notes: "The new proof gap is resolved",
                    receiptRefs: [],
                  },
                ],
              },
            });
          }
          const ledgerBefore = await readFile(ledger);
          const completed = JSON.parse(
            execFileSync(python, args, { encoding: "utf8", env }),
          ).scan;
          const coverage = JSON.parse(
            await readFile(path.join(scan.scanDir, "coverage.json"), "utf8"),
          );
          assert.equal(
            completed.progress.candidates.unresolved,
            Number(resolution === "pending"),
          );
          assert.equal(
            completed.findingCount,
            Number(resolution === "finding"),
          );
          if (resolution === "pending") {
            assert.deepEqual(
              coverage.deferred.find((row: any) => row.id === pending.id),
              { ...pending, candidate },
            );
            assert.ok(
              (
                await readFile(path.join(scan.scanDir, "report.md"), "utf8")
              ).includes(reason),
            );
          } else {
            assert.ok(
              !coverage.deferred.some(
                (row: any) => row.candidateId === candidate.candidate_id,
              ),
            );
          }
          assert.deepEqual(await readFile(ledger), ledgerBefore);
          for (const [name, bytes] of saved)
            assert.deepEqual(
              await readFile(path.join(checkpoints, name)),
              bytes,
            );
        });
      }
    }
  }
}

for (const scenario of ["unlinked", "worker-owned", "supplied", "finding"]) {
  test(`Deep drafts do not read an unrelated ledger: ${scenario}`, async (t) => {
    const { scan, context } = await budgetFixture(t, true);
    const ledger = path.join(
      scan.scanDir,
      "artifacts/02_discovery/candidate_ledger.jsonl",
    );
    const candidate = JSON.parse((await readFile(ledger, "utf8")).trim());
    // This artifact is irrelevant to each submitted row; publication must not read it.
    await writeFile(ledger, "incomplete unrelated artifact");
    const pending = {
      id: "review-gap",
      reason: "Authored gap",
      ...(scenario === "unlinked"
        ? {}
        : { candidateId: candidate.candidate_id }),
      ...(scenario === "worker-owned" ? { sourceWorkerId: "worker-a" } : {}),
      ...(scenario === "supplied" ? { candidate } : {}),
    };
    const reported = finding("existing", "app.py");
    reported.locations[0]!.endLine = 1;
    await recordCodexSecurityScanDraft(context, {
      scanId: scan.scanId,
      findings:
        scenario === "finding"
          ? [
              {
                ...reported,
                provenance: {
                  ...reported.provenance,
                  candidateId: candidate.candidate_id,
                  candidateReopened: true,
                },
              },
            ]
          : [],
      coverage: {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: [pending],
      },
    });
    assert.equal(
      await readFile(ledger, "utf8"),
      "incomplete unrelated artifact",
    );
    const coverage = JSON.parse(
      await readFile(path.join(scan.scanDir, "coverage.json"), "utf8"),
    );
    assert.deepEqual(coverage.deferred[0], pending);
  });
}

const { prepareCodexSecurityReviewItems } = await importSource(
  new URL("../src/artifact-inventory.ts", import.meta.url).pathname,
);
const { recordCodexSecurityDiscoveryCandidates, listCodexSecurityCandidates } =
  await importDiscoverySource();
for (const disposition of ["rejected", "not_applicable"]) {
  for (const kind of [
    "missing-pattern",
    "missing-reason",
    "structured-pattern",
    "empty-reason",
    "valid",
    "generic-metadata",
  ]) {
    test(`budget error recovery preserves unresolved evidence: ${disposition}, ${kind}`, async (t) => {
      const { root, scan } = await budgetFixture(t, false);
      const env = {
        ...process.env,
        CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
      };
      const workbench = async (args: string[]) =>
        JSON.parse(
          execFileSync(
            python,
            [path.join(pluginRoot, "scripts/workbench_db.py"), ...args],
            { encoding: "utf8", env },
          ),
        );
      const { createScanArtifactContext } = await importSource(
        new URL("../src/artifact-context.ts", import.meta.url).pathname,
      );
      const context = await createScanArtifactContext(scan.scanId, workbench, {
        requireRunning: true,
        pluginRoot: path.resolve(
          pluginRoot,
          "../../sdk/typescript/_bundled_plugin",
        ),
        pythonCommand: python,
      });
      await prepareCodexSecurityReviewItems(context);
      await recordCodexSecurityDiscoveryCandidates(
        {
          candidates: [
            {
              cwe_ids: [],
              locations: [
                {
                  path: "app.py",
                  start_line: 1,
                  end_line: 1,
                  role: "evidence",
                },
              ],
              summary: "Synthetic source review",
              evidence: "Synthetic original source evidence",
            },
          ],
        },
        context,
      );
      const rows = (await listCodexSecurityCandidates({}, context)).rows;
      assert.equal(rows.length, 1);
      const candidate = rows[0];
      const pending = {
        id: "new-proof",
        candidateId: candidate.candidate_id,
        candidate,
        reason,
      };
      const draft = {
        scanId: scan.scanId,
        complete: true,
        findings: [],
        coverage: {
          completeness: "partial",
          surfaces: [],
          explicitExclusions: [],
          deferred: [pending],
        },
      };
      await recordCodexSecurityScanDraftViaWorkbench(context, draft, workbench);
      const exclusion: Record<string, unknown> = {
        candidateId: candidate.candidate_id,
        disposition,
        pattern: "app.py",
        reason: "Synthetic completed review",
        legacy: { details: ["saved"] },
      };
      if (kind === "missing-pattern") delete exclusion.pattern;
      if (kind === "missing-reason") delete exclusion.reason;
      if (kind === "structured-pattern")
        exclusion.pattern = { legacy: "app.py" };
      if (kind === "empty-reason") exclusion.reason = "";
      if (kind === "generic-metadata")
        exclusion.candidateId = { legacy: "annotation" };
      const malformed = !["valid", "generic-metadata"].includes(kind);
      if (malformed)
        await assert.rejects(
          recordCodexSecurityScanDraftViaWorkbench(
            context,
            {
              ...draft,
              coverage: { ...draft.coverage, explicitExclusions: [exclusion] },
            },
            workbench,
          ),
          /pattern|reason/,
        );
      const file = path.join(scan.scanDir, "coverage.json");
      const coverage = JSON.parse(await readFile(file, "utf8"));
      coverage.explicitExclusions = [exclusion];
      await writeFile(file, JSON.stringify(coverage));
      const checkpoints = path.join(scan.scanDir, "checkpoints");
      const before = new Map(
        await Promise.all(
          (await readdir(checkpoints)).map(
            async (name) =>
              [name, await readFile(path.join(checkpoints, name))] as const,
          ),
        ),
      );
      const ledger = path.join(
        scan.scanDir,
        "artifacts/02_discovery/candidate_ledger.jsonl",
      );
      const originalLedger = await readFile(ledger);
      const completed = spawnSync(
        python,
        [
          path.join(pluginRoot, "scripts/workbench_db.py"),
          "complete-budget-exhausted-scan",
          "--scan-id",
          scan.scanId,
          "--cost-json",
          JSON.stringify({
            model: "synthetic-model",
            inputTokens: 1250,
            cachedInputTokens: 200,
            cacheWriteInputTokens: 0,
            outputTokens: 30,
            estimatedUsd: 0.00625,
          }),
          "--message",
          "Synthetic budget stop",
        ],
        { encoding: "utf8", env },
      );
      assert.equal(completed.status, malformed ? 1 : 0, completed.stderr);
      if (malformed) assert.match(completed.stderr, /pattern|reason/);
      for (let attempt = 0; attempt < 2; attempt++) {
        const saved = (await workbench(["get-scan", "--scan-id", scan.scanId]))
          .scan;
        assert.equal(saved.progress.status, malformed ? "failed" : "complete");
        assert.equal(
          saved.progress.candidates.unresolved,
          kind === "valid" ? 0 : 1,
        );
        const result = JSON.parse(await readFile(file, "utf8"));
        const retained = result.deferred.filter(
          (row: any) => row.candidateId === candidate.candidate_id,
        );
        assert.equal(retained.length, kind === "valid" ? 0 : 1);
        if (retained.length) assert.deepEqual(retained[0], pending);
        const terminal = result.surfaces.filter(
          (row: any) =>
            row.candidateId === candidate.candidate_id &&
            ["rejected", "not_applicable"].includes(row.disposition),
        );
        assert.equal(terminal.length, kind === "valid" ? 1 : 0);
        if (kind === "generic-metadata")
          assert.deepEqual(result.explicitExclusions, [exclusion]);
        assert.deepEqual(await readFile(ledger), originalLedger);
        for (const [name, bytes] of before)
          assert.deepEqual(await readFile(path.join(checkpoints, name)), bytes);
        if (malformed && attempt === 0)
          await workbench(["recover-scan-results", "--scan-id", scan.scanId]);
      }
    });
  }
}

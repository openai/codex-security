import { importDiscoverySource } from "./support/discovery.ts";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const execFileAsync = promisify(execFile);
const { createScanArtifactContext } = await importSource(
  "../src/artifact-context.ts",
  { absWorkingDir: import.meta.dirname },
);
const { recordCodexSecurityScanDraftViaWorkbench: record } = await importSource(
  "../src/artifact-scan-draft.ts",
  { absWorkingDir: import.meta.dirname },
);
const { recordCodexSecurityDiscoveryCandidates, listCodexSecurityCandidates } =
  await importDiscoverySource();
const { recordCodexSecurityCandidateValidations } = await importSource(
  "../src/artifact-candidate-ledger.ts",
  { absWorkingDir: import.meta.dirname },
);

for (const collision of [false, true]) {
  for (const sourceWorkerId of [undefined, "imported-owner"]) {
    test(`candidate dismissal preserves an independent surface: collision=${collision}, owner=${sourceWorkerId}`, async (t) => {
      const directory = await temporaryDirectory(
        "candidate-surface-identity-",
        true,
      );
      t.after(() => rm(directory, { recursive: true, force: true }));
      const target = path.join(directory, "target");
      const home = path.join(directory, "home");
      await mkdir(target);
      await mkdir(home, { mode: 0o700 });
      await writeFile(path.join(target, "app.ts"), "export const value = 1;\n");
      const git = async (...args: string[]) => {
        const { stdout } = await execFileAsync("git", [
          "-C",
          target,
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.test",
          ...args,
        ]);
        return stdout.trim();
      };
      await git("init", "-q");
      await git("add", "app.ts");
      await git("commit", "-qm", "Synthetic fixture");
      const revision = await git("rev-parse", "HEAD");
      const workbench = async (args: string[]) => {
        const { stdout } = await execFileAsync(
          process.env.PYTHON?.trim() || "python3",
          [
            path.join(import.meta.dirname, "../../scripts/workbench_db.py"),
            ...args,
          ],
          {
            env: {
              ...process.env,
              CODEX_HOME: home,
              CODEX_SECURITY_STATE_DIR: path.join(directory, "state"),
            },
          },
        );
        return JSON.parse(stdout);
      };
      const { scan } = await workbench([
        "start-prompt-only-scan",
        "--thread-id",
        "synthetic-independent-review",
        "--target-path",
        target,
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        revision,
        "--scan-root",
        path.join(directory, "scans"),
      ]);
      const context = await createScanArtifactContext(scan.scanId, workbench, {
        requireRunning: true,
        pluginRoot: path.resolve(
          import.meta.dirname,
          "../../../../sdk/typescript/_bundled_plugin",
        ),
      });
      const candidateId = "candidate-3c527b024e10b356";
      const surface = {
        id: collision ? candidateId : "independent-review",
        label: "Independent directory review",
        disposition: "needs_follow_up",
        notes: "Unrelated independent coverage is unfinished.",
        receiptRefs: [],
        ...(sourceWorkerId === undefined ? {} : { sourceWorkerId }),
      };
      const draft = {
        scanId: scan.scanId,
        handoffClaimToken: context.handoffClaimToken,
        complete: false,
        findings: [],
        coverage: {
          completeness: "partial",
          surfaces: [surface],
          explicitExclusions: [],
          deferred: [],
        },
      };
      await record(context, draft, workbench);
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
              evidence: "Synthetic evidence",
            },
          ],
        },
        context,
      );
      const listed = await listCodexSecurityCandidates({}, context);
      assert.equal(listed.rows[0].candidate_id, candidateId);
      await recordCodexSecurityCandidateValidations(context, {
        validations: [
          {
            candidateId,
            validation: {
              disposition: "suppressed",
              method: "Static inspection",
              confidence: "high",
              confidence_rationale: "Synthetic evidence",
              rubric: "Synthetic criterion",
              evidence: "Candidate dismissed.",
              counterevidence_or_proof_gap: "Synthetic counterevidence.",
              remaining_uncertainty: "",
            },
          },
        ],
      });
      await record(
        context,
        {
          ...draft,
          complete: true,
          coverage: {
            ...draft.coverage,
            completeness: "complete",
            surfaces: [],
          },
        },
        workbench,
      );
      const snapshot = async () =>
        JSON.parse(
          await readFile(path.join(context.root, "coverage.json"), "utf8"),
        );
      const snapshots = [await snapshot()];
      const checkpoints = path.join(context.root, "checkpoints");
      const originals = await Promise.all(
        (await readdir(checkpoints)).map(
          async (name) =>
            [name, await readFile(path.join(checkpoints, name))] as const,
        ),
      );
      for (const command of ["fail-scan", "preserve-scan-results"]) {
        await workbench([
          command,
          "--scan-id",
          scan.scanId,
          ...(command === "fail-scan"
            ? ["--message", "Synthetic interruption."]
            : []),
        ]);
        snapshots.push(await snapshot());
      }
      for (const [index, coverage] of snapshots.entries()) {
        const stage = ["publication", "fail-scan", "preserve-scan-results"][
          index
        ];
        assert.deepEqual(
          coverage.surfaces.find(
            (row: { id: string }) => row.id === surface.id,
          ),
          surface,
          stage,
        );
        assert.equal(coverage.completeness, "partial", stage);
        const decisions = coverage.surfaces.filter(
          (row: { candidateId?: string }) => row.candidateId === candidateId,
        );
        assert.equal(decisions.length, 1, stage);
        assert.equal(decisions[0].disposition, "rejected", stage);
        assert.equal(
          coverage.deferred.filter(
            (row: { candidateId?: string }) => row.candidateId === candidateId,
          ).length,
          0,
          stage,
        );
      }
      for (const [name, bytes] of originals)
        assert.deepEqual(await readFile(path.join(checkpoints, name)), bytes);
    });
  }
}

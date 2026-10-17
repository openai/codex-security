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
  {
    absWorkingDir: import.meta.dirname,
  },
);
const { recordCodexSecurityScanDraftViaWorkbench: record } = await importSource(
  "../src/artifact-scan-draft.ts",
  {
    absWorkingDir: import.meta.dirname,
  },
);
const { recordCodexSecurityDiscoveryCandidates, listCodexSecurityCandidates } =
  await importDiscoverySource();

for (const shared of [false, true]) {
  for (const disposition of ["rejected", "not_applicable"] as const) {
    test(`accepted Diff finding retains shared terminal surface evidence: shared=${shared}, disposition=${disposition}`, async (t) => {
      const directory = await temporaryDirectory(
        "candidate-shared-surface-",
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
        "synthetic-shared-review",
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
      const discovery = path.join(context.root, "artifacts/02_discovery");
      await mkdir(discovery, { recursive: true });
      await writeFile(path.join(discovery, "in_scope_files.txt"), "app.ts\n");
      await recordCodexSecurityDiscoveryCandidates(
        {
          candidates: ["a", "b"].map((instance) => ({
            cwe_ids: [],
            locations: [
              { path: "app.ts", start_line: 1, end_line: 1, role: "evidence" },
            ],
            instance,
            summary: `Candidate ${instance}`,
            evidence: `Evidence ${instance}`,
          })),
        },
        context,
      );
      const listed = await listCodexSecurityCandidates({}, context);
      assert.equal(listed.rows.length, 2);
      const acceptedId = listed.rows.find(
        (row: { summary: string }) => row.summary === "Candidate a",
      )!.candidate_id;
      const pendingId = listed.rows.find(
        (row: { summary: string }) => row.summary === "Candidate b",
      )!.candidate_id;
      const receipt = "artifacts/proof/shared.txt";
      await mkdir(path.join(context.root, "artifacts/proof"), {
        recursive: true,
      });
      await writeFile(
        path.join(context.root, receipt),
        "Synthetic shared evidence.\n",
      );
      const surface = {
        id: "shared",
        candidateId: acceptedId,
        label: "Shared candidate evidence",
        disposition,
        notes: "This evidence is also needed by candidate b.",
        receiptRefs: [receipt],
      };
      await record(
        context,
        {
          scanId: scan.scanId,
          handoffClaimToken: context.handoffClaimToken,
          complete: true,
          findings: [
            {
              ruleId: "synthetic-review",
              title: "Synthetic finding",
              summary: "Synthetic evidence",
              taxonomy: { category: "synthetic", cwe: [] },
              severity: { level: "low" },
              confidence: { level: "high", rationale: "Synthetic evidence" },
              locations: [{ path: "app.ts", startLine: 1 }],
              remediation: "Apply synthetic fix",
              provenance: { source: "local_plugin", candidateId: acceptedId },
            },
          ],
          coverage: {
            completeness: "partial",
            surfaces: [surface],
            explicitExclusions: [],
            deferred: [
              {
                id: "b-work",
                candidateId: pendingId,
                reason: "Candidate b review remains.",
                ...(shared ? { surfaceIds: [surface.id] } : {}),
              },
            ],
          },
        },
        workbench,
      );
      const snapshot = async () => ({
        coverage: JSON.parse(
          await readFile(path.join(context.root, "coverage.json"), "utf8"),
        ),
        findings: JSON.parse(
          await readFile(path.join(context.root, "findings.json"), "utf8"),
        ),
      });
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
      for (const [index, { coverage, findings }] of snapshots.entries()) {
        const stage = ["publication", "fail-scan", "preserve-scan-results"][
          index
        ];
        const retained = coverage.surfaces.find(
          (row: { id: string }) => row.id === surface.id,
        );
        assert.equal(
          Boolean(retained),
          shared,
          `shared evidence survives ${stage}`,
        );
        const pending = coverage.deferred.filter(
          (row: { candidateId?: string }) => row.candidateId === pendingId,
        );
        assert.equal(pending.length, 1, stage);
        assert.equal(
          findings.findings.filter(
            (row: { provenance: { candidateId?: string } }) =>
              row.provenance.candidateId === acceptedId,
          ).length,
          1,
          stage,
        );
        if (shared) {
          assert.equal(retained.disposition, "reported", stage);
          assert.equal(retained.notes, surface.notes, stage);
          assert.deepEqual(retained.receiptRefs, surface.receiptRefs, stage);
          assert.ok(pending[0].surfaceIds.includes(retained.id), stage);
        }
      }
      for (const [name, bytes] of originals)
        assert.deepEqual(await readFile(path.join(checkpoints, name)), bytes);
    });
  }
}

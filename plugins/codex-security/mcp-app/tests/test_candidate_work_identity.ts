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
const { createScanArtifactContext } = await importSource(
  "../src/artifact-context.ts",
  { absWorkingDir: import.meta.dirname },
);
const { recordCodexSecurityScanDraftViaWorkbench: record } = await importSource(
  "../src/artifact-scan-draft.ts",
  { absWorkingDir: import.meta.dirname },
);

for (const collision of [false, true]) {
  for (const missingReceipt of [false, true]) {
    for (const disposition of ["rejected", "not_applicable"] as const) {
      test(`candidate receipt recovery retains a general closure (collision=${collision}, missing=${missingReceipt}, disposition=${disposition})`, async (t) => {
        const directory = await temporaryDirectory(
          "candidate-work-identity-",
          true,
        );
        t.after(() => rm(directory, { recursive: true, force: true }));
        const target = path.join(directory, "target");
        const home = path.join(directory, "home");
        await mkdir(target);
        await mkdir(home, { mode: 0o700 });
        await writeFile(path.join(target, "app.py"), "synthetic source\n");
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
          "start-headless-standard-scan",
          "--thread-id",
          "synthetic-general-review",
          "--target-path",
          target,
          "--scope",
          ".",
          "--scan-root",
          path.join(directory, "scans"),
        ]);
        const context = await createScanArtifactContext(
          scan.scanId,
          workbench,
          {
            requireRunning: true,
          },
        );
        const first = await record(
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
                { id: "general-review", reason: "Independent general review." },
              ],
            },
          },
          workbench,
        );
        const generalId = first.coverage.deferred[0]!.id;
        const closure = {
          id: generalId,
          reason: "Independent general review completed.",
        };
        const receipt = path.join(context.root, "artifacts/receipt.txt");
        await mkdir(path.dirname(receipt), { recursive: true });
        await writeFile(receipt, "Synthetic candidate review evidence.\n");
        await record(
          context,
          {
            scanId: scan.scanId,
            handoffClaimToken: context.handoffClaimToken,
            complete: true,
            findings: [],
            coverage: {
              completeness: "complete",
              surfaces: [
                {
                  id: "candidate-decision",
                  label: "Candidate review",
                  candidateId: collision ? generalId : "candidate-review",
                  disposition,
                  notes: "Candidate review completed separately.",
                  receiptRefs: ["artifacts/receipt.txt"],
                },
              ],
              explicitExclusions: [],
              deferred: [],
              resolvedDeferred: [closure],
            },
          },
          workbench,
        );
        if (missingReceipt) await unlink(receipt);
        await workbench([
          "prepare-scan-completion",
          "--scan-id",
          scan.scanId,
          "--claim-token",
          context.handoffClaimToken!,
        ]);
        const coveragePath = path.join(context.root, "coverage.json");
        const saved = await readFile(coveragePath);
        const coverage = JSON.parse(saved.toString());
        assert.deepEqual(coverage.resolvedDeferred, [closure]);
        assert.equal(
          coverage.surfaces[0].disposition,
          missingReceipt ? "needs_follow_up" : disposition,
        );
        await workbench([
          "prepare-scan-completion",
          "--scan-id",
          scan.scanId,
          "--claim-token",
          context.handoffClaimToken!,
        ]);
        assert.deepEqual(await readFile(coveragePath), saved);
      });
    }
  }
}

const { recordCodexSecurityDiscoveryCandidates, listCodexSecurityCandidates } =
  await importDiscoverySource();

for (const collision of [false, true]) {
  test(`later Diff discovery preserves an already requested generic closure (collision=${collision})`, async (t) => {
    const directory = await temporaryDirectory("late-discovery-closure-", true);
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
      "synthetic-late-discovery",
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
    const task = {
      id: collision ? candidateId : "general-review",
      reason: "Independent generic review task.",
    };
    const draft = {
      scanId: scan.scanId,
      handoffClaimToken: context.handoffClaimToken,
      complete: false,
      findings: [],
      coverage: {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: [task],
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
              { path: "app.ts", start_line: 1, end_line: 1, role: "evidence" },
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
    const closure = {
      id: task.id,
      reason: "Independent generic task completed.",
    };
    await record(
      context,
      {
        ...draft,
        complete: true,
        coverage: {
          ...draft.coverage,
          completeness: "complete",
          deferred: [],
          resolvedDeferred: [closure],
        },
      },
      workbench,
    );
    const snapshots = [
      JSON.parse(
        await readFile(path.join(context.root, "coverage.json"), "utf8"),
      ),
    ];
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
      snapshots.push(
        JSON.parse(
          await readFile(path.join(context.root, "coverage.json"), "utf8"),
        ),
      );
    }
    for (const [stage, coverage] of snapshots.entries()) {
      assert.deepEqual(
        coverage.resolvedDeferred,
        [closure],
        `closure survives ${["publication", "fail-scan", "preserve-scan-results"][stage]}`,
      );
      const pending = coverage.deferred.filter(
        (row: { candidateId?: string }) => row.candidateId === candidateId,
      );
      assert.equal(pending.length, 1);
      assert.notEqual(pending[0].id, closure.id);
    }
    for (const [name, bytes] of originals)
      assert.deepEqual(await readFile(path.join(checkpoints, name)), bytes);
  });
}

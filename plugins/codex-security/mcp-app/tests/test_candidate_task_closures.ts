import assert from "node:assert/strict";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import {
  discoveryPluginRoot,
  importDiscoverySource,
} from "./support/discovery.ts";
import { fixture } from "./scan-draft-recovery-fixture.ts";

const { recordCodexSecurityDiscoveryCandidates, listCodexSecurityCandidates } =
  await importDiscoverySource();

for (const replayRows of [false, true]) {
  for (const collision of [false, true]) {
    test(`discovered candidate stays pending when a separate task closes (same semantic ID=${collision}, replay rows=${replayRows})`, async (t) => {
      const f = await fixture(t, "diff");
      f.context.pluginRoot = discoveryPluginRoot;
      const git = (...args: string[]) =>
        execFileSync(
          "git",
          [
            "-C",
            f.root,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            ...args,
          ],
          { encoding: "utf8" },
        ).trim();
      git("init", "-q");
      await writeFile(path.join(f.root, "app.ts"), "export const value = 0;\n");
      git("add", "app.ts");
      git("commit", "-qm", "Synthetic baseline");
      const baseRevision = git("rev-parse", "HEAD");
      await writeFile(path.join(f.root, "app.ts"), "export const value = 1;\n");
      git("commit", "-qam", "Synthetic update");
      const headRevision = git("rev-parse", "HEAD");
      f.context.targetRevision = headRevision;
      f.context.targetContract = {
        ...f.context.targetContract,
        diffTarget: { kind: "range", baseRevision, headRevision },
      };
      const discovery = path.join(f.root, "artifacts/02_discovery");
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
              summary: "Synthetic candidate requiring review.",
              evidence: "Synthetic source evidence.",
            },
          ],
        },
        f.context,
      );
      const listed = await listCodexSecurityCandidates({}, f.context);
      const candidateId = listed.rows[0].candidate_id;
      const task = {
        id: collision ? candidateId : "general-review",
        reason: "Independent general review task.",
      };
      const first = await f.write(f.draft({ deferred: [task] }));
      const generic = first.coverage.deferred.find(
        (row: Record<string, unknown>) => row.reason === task.reason,
      );
      const candidate = first.coverage.deferred.find(
        (row: Record<string, unknown>) => row.candidateId === candidateId,
      );
      assert.ok(generic);
      assert.ok(candidate);
      assert.notEqual(generic.id, candidate.id);
      for (const input of [
        f.draft(),
        ...(replayRows ? [f.draft({ deferred: first.coverage.deferred })] : []),
      ]) {
        const replay = await f.write(input);
        assert.deepEqual(replay.coverage.deferred, first.coverage.deferred);
      }
      const checkpoints = path.join(f.root, "checkpoints");
      const originals = await Promise.all(
        (await readdir(checkpoints)).map(
          async (name) =>
            [name, await readFile(path.join(checkpoints, name))] as const,
        ),
      );
      const candidateClosure = f.draft(
        {
          resolvedDeferred: [
            { id: candidate.id, reason: "Candidate review remains." },
          ],
        },
        true,
      );
      await assert.rejects(f.write(candidateClosure), /cannot close candidate/);
      const closure = {
        id: generic.id,
        reason: "General review task finished.",
      };
      for (const input of [
        f.draft({ resolvedDeferred: [closure] }, true),
        f.draft({}, true),
        f.draft(),
      ]) {
        const result = await f.write(input);
        assert.deepEqual(result.coverage.resolvedDeferred, [closure]);
        assert.deepEqual(result.coverage.deferred, [candidate]);
        assert.equal(result.coverage.completeness, "partial");
        assert.equal(
          result.coverage.surfaces[0].disposition,
          "needs_follow_up",
        );
      }
      await assert.rejects(f.write(candidateClosure), /cannot close candidate/);
      for (const [name, bytes] of originals)
        assert.deepEqual(await readFile(path.join(checkpoints, name)), bytes);
    });
  }
}

for (const layout of ["standard", "worker"] as const) {
  for (const removeOwner of [false, true]) {
    test(`${layout}: generic task metadata changes preserve its closable ID (remove owner=${removeOwner})`, async (t) => {
      const f = await fixture(t, layout);
      const original = {
        id: "review-task",
        sourceWorkerId: "imported-owner",
        reason: "Independent authorization review.",
      };
      const updated = {
        id: original.id,
        reason: original.reason,
        ...(removeOwner ? {} : { sourceWorkerId: "corrected-owner" }),
      };
      await f.write(f.draft({ deferred: [original] }));
      for (const input of [f.draft({ deferred: [updated] }), f.draft()]) {
        const result = await f.write(input);
        assert.deepEqual(result.coverage.deferred, [updated]);
      }
      const closure = {
        id: original.id,
        reason: "Independent review finished.",
      };
      for (const input of [
        f.draft({ resolvedDeferred: [closure] }, true),
        f.draft({}, true),
      ]) {
        const result = await f.write(input);
        assert.deepEqual(result.coverage.deferred, []);
        assert.deepEqual(result.coverage.resolvedDeferred, [closure]);
      }
    });
  }
}

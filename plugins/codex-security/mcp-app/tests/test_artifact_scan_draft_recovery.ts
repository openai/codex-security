import { readJson, writeJson } from "./support/json.ts";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { hash } from "node:crypto";
import { promises as fsPromises } from "node:fs";
import {
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  utimes,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual, promisify } from "node:util";
import {
  draftApi,
  fixture,
  interruptDraftWrite,
  surfaceDisposition,
} from "./scan-draft-recovery-fixture.ts";

const { recordCodexSecurityScanDraftViaWorkbench, saveScanDraftCheckpoint } =
  draftApi;
const execFileAsync = promisify(execFile);
const generic = { reason: "Review remains.", paths: ["src/example.py"] };
const close = (id: string, reason = "Review completed.") => ({ id, reason });
const findingFor = (candidateId: string) => ({
  ruleId: "fixture.review",
  title: "Synthetic review finding",
  summary: "The candidate outcome must survive publication.",
  severity: { level: "low" },
  confidence: { level: "high", rationale: "Synthetic persistence fixture." },
  taxonomy: { category: "other", cwe: [] },
  locations: [{ path: "src/example.py", startLine: 1 }],
  remediation: "Complete the review.",
  provenance: { source: "local_plugin", candidateId },
});

for (const observation of ["checkpoint head", "worker result"]) {
  test(`worker: reopening survives replacement of the ${observation} during a read`, async (t) => {
    const f = await fixture(t, "worker");
    const task = { id: "review", ...generic };
    const headPath = path.join(f.root, "checkpoint-head.json");
    const resultPath = path.join(f.root, "result.json");
    await f.write(f.draft({ deferred: [task] }));
    const reopenedHead = await readJson(headPath);
    await f.write(f.draft({ resolvedDeferred: [close(task.id)] }, true));
    assert.deepEqual((await f.read()).deferred, []);
    const checkpoints = path.join(f.root, "checkpoints");
    for (const name of await readdir(checkpoints)) {
      const checkpointPath = path.join(checkpoints, name);
      const checkpoint = await readJson(checkpointPath);
      const time = checkpoint.coverage.deferred.length ? 50 : 100;
      await utimes(checkpointPath, time, time);
    }

    const replacementPath = path.join(f.root, "replacement.json");
    if (observation === "checkpoint head") {
      await utimes(headPath, 100, 100);
      await utimes(resultPath, 200, 200);
      await writeJson(replacementPath, reopenedHead);
    } else {
      await writeJson(headPath, reopenedHead);
      await utimes(headPath, 200, 200);
      await utimes(resultPath, 100, 100);
      await writeJson(replacementPath, f.draft({ deferred: [task] }, true));
    }
    await utimes(replacementPath, 300, 300);

    let replaced = false;
    const replaceOnce = async (destination: string) => {
      if (replaced) return;
      replaced = true;
      await rename(replacementPath, destination);
    };
    const originalLstat = fsPromises.lstat;
    const originalReadFile = fsPromises.readFile;
    const originalOpen = fsPromises.open;
    if (observation === "checkpoint head") {
      t.mock.method(fsPromises, "lstat", (async (
        filename: Parameters<typeof originalLstat>[0],
        ...args: [options?: import("node:fs").StatOptions]
      ) => {
        const metadata = await originalLstat(filename, ...args);
        if (filename === headPath) await replaceOnce(headPath);
        return metadata;
      }) as typeof fsPromises.lstat);
    } else {
      // Replace after returning the old file's bytes, for both pathname and
      // descriptor readers. Its observation time must still belong to those bytes.
      t.mock.method(fsPromises, "readFile", (async (
        ...args: Parameters<typeof originalReadFile>
      ) => {
        const contents = await originalReadFile(...args);
        if (args[0] === resultPath) await replaceOnce(resultPath);
        return contents;
      }) as typeof fsPromises.readFile);
      t.mock.method(fsPromises, "open", (async (
        filename: Parameters<typeof originalOpen>[0],
        ...args: [flags: string | number, mode?: string | number]
      ) => {
        const handle = await originalOpen(filename, ...args);
        if (filename === resultPath) {
          const read = handle.readFile.bind(handle);
          handle.readFile = (async (...readArgs: Parameters<typeof read>) => {
            const contents = await read(...readArgs);
            await replaceOnce(resultPath);
            return contents;
          }) as typeof handle.readFile;
        }
        return handle;
      }) as typeof fsPromises.open);
    }
    const result = await f.write(f.draft({}, true));
    assert.equal(replaced, true);
    for (const coverage of [result.coverage, await f.read()]) {
      assert.deepEqual(coverage.deferred, [task]);
      assert.deepEqual(coverage.resolvedDeferred ?? [], []);
      assert.equal(coverage.completeness, "partial");
    }
  });
}

for (const headTime of [1, 2, 3]) {
  test(`worker: stopped recovery retains accepted coverage with head time ${headTime}`, async (t) => {
    const f = await fixture(t, "worker");
    const surface = (id: string) => ({
      id,
      label: id,
      disposition: "no_issue_found",
      receiptRefs: [],
    });
    await f.write(f.draft({ surfaces: [surface("existing")] }, true));
    const added = {
      surfaces: [surface("newly-reviewed")],
      explicitExclusions: [
        { pattern: "vendor/**", reason: "External dependency." },
      ],
      openQuestions: [
        { question: "Should a later review include dependencies?" },
      ],
    };
    const resultPath = path.join(f.root, "result.json");
    await interruptDraftWrite(resultPath, () =>
      f.write(
        f.draft(
          { ...added, surfaces: [surface("existing"), ...added.surfaces] },
          true,
        ),
      ),
    );
    const headPath = path.join(f.root, "checkpoint-head.json");
    const head = await readJson(headPath);
    const selectedPath = path.join(f.root, "checkpoints", head.checkpoint);
    const selected = await readJson(selectedPath);
    assert.deepEqual(selected.coverage.surfaces, [
      surface("existing"),
      ...added.surfaces,
    ]);
    await utimes(resultPath, 2, 2);
    await utimes(headPath, headTime, headTime);
    await utimes(selectedPath, headTime, headTime);
    const originals = new Map<string, Buffer>();
    for (const filename of [
      resultPath,
      headPath,
      ...(await readdir(path.join(f.root, "checkpoints"))).map((name) =>
        path.join(f.root, "checkpoints", name),
      ),
    ]) {
      originals.set(filename, await readFile(filename));
    }
    const { stdout } = await execFileAsync(
      process.env.PYTHON?.trim() || "python3",
      [
        "-c",
        `import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from workbench_saved_results import merge_saved_results
root,output=Path(sys.argv[2]),Path(sys.argv[3])
worker={"id":"worker","kind":"discovery","artifact_dir":str(output),"result_manifest_path":None,"attempt":1}
binding={"status":"interrupted","allowedTargetKinds":["git_revision"],"target":{"kind":"git_revision","repository":"synthetic","revision":"head"},"scope":{"includePaths":["."],"excludePaths":[]},"coverageMode":"repository"}
first=merge_saved_results(root,sys.argv[4],binding,[worker],[],stopped=True,reason="interrupted")
replay=merge_saved_results(root,sys.argv[4],binding,[worker],[],stopped=True,reason="interrupted",frozen_source_digests=first[0]["scan"]["preservedSources"])
print(json.dumps([first[2],replay[2]]))`,
        path.join(import.meta.dirname, "../../scripts"),
        path.dirname(f.root),
        f.root,
        f.context.scanId!,
      ],
    );
    const [coverage, replay] = JSON.parse(stdout);
    assert.deepEqual(replay, coverage);
    for (const [field, rows] of Object.entries(added)) {
      assert.equal(
        (coverage[field] ?? []).some((row: Record<string, unknown>) =>
          Object.entries(rows[0]).every(([key, value]) =>
            isDeepStrictEqual(row[key], value),
          ),
        ),
        headTime >= 2,
      );
    }
    assert.ok(
      coverage.surfaces.some(
        (row: Record<string, unknown>) => row.id === "existing",
      ),
    );
    for (const [filename, contents] of originals) {
      assert.deepEqual(await readFile(filename), contents);
    }
  });
}

for (const updateSavedSurface of [false, true]) {
  test(`worker: repeated progress preserves independent evidence, saved surface update=${updateSavedSurface}`, async (t) => {
    const f = await fixture(t, "worker");
    const reopened = { id: "reopened-review", ...generic, surfaceIds: ["api"] };
    const stillClosed = { id: "closed-review", ...generic };
    const independentSurface = {
      id: "configuration",
      label: "Configuration",
      disposition: "no_issue_found",
      notes: "Initial review.",
    };
    await f.write(
      f.draft({
        deferred: [reopened, stillClosed],
        surfaces: updateSavedSurface ? [independentSurface] : [],
      }),
    );
    await f.write(
      f.draft(
        { resolvedDeferred: [close(reopened.id), close(stillClosed.id)] },
        true,
      ),
    );
    const independent = { id: "independent-review", ...generic };
    const finding = {
      ...findingFor("new-finding"),
      summary: "A separate review result must survive progress publication.",
      remediation: "Complete the independent review.",
    };
    const surfaces: (Record<string, unknown> & { id: string })[] = [
      {
        id: "api",
        label: "API",
        disposition: "needs_follow_up",
        receiptRefs: [],
      },
      {
        id: "new-finding",
        candidateId: "new-finding",
        label: "Independent review",
        disposition: "reported",
      },
    ];
    if (updateSavedSurface)
      surfaces.push({ ...independentSurface, notes: "Updated review." });
    const progress = {
      ...f.draft({ deferred: [reopened, independent], surfaces }),
      findings: [finding],
    };
    for (const input of [progress, f.draft()]) {
      const result = await f.write(input);
      assert.equal(result.findingCount, 1);
      assert.equal(result.coverage.completeness, "partial");
      assert.deepEqual(result.coverage.deferred, [reopened, independent]);
      assert.deepEqual(result.coverage.resolvedDeferred, [
        close(stillClosed.id),
      ]);
      assert.deepEqual(
        result.coverage.surfaces,
        surfaces.map((surface) => ({
          ...surface,
          receiptRefs: surface.receiptRefs ?? [],
        })),
      );
      const published = await readJson(f.root, "result.json");
      assert.deepEqual(published.findings, [finding]);
      const head = await readJson(f.root, "checkpoint-head.json");
      assert.deepEqual(
        await readJson(f.root, "checkpoints", head.checkpoint),
        published,
      );
    }
    const nextTask = { id: "next-review", ...generic };
    const nextFinding = {
      ...finding,
      ruleId: "fixture.second-review",
      provenance: { ...finding.provenance, candidateId: "next-finding" },
    };
    const nextSurface = {
      id: "next-finding",
      candidateId: "next-finding",
      label: "Next review",
      disposition: "reported",
    };
    const updated = {
      ...reopened,
      reason: "Review another caller.",
      paths: ["src/example.py", "src/other.py"],
      notes: "The latest checkpoint adds a second caller.",
    };
    const nextProgress = {
      ...f.draft({ deferred: [updated, nextTask], surfaces: [nextSurface] }),
      findings: [nextFinding],
    };
    for (const input of [nextProgress, f.draft()]) {
      const result = await f.write(input);
      assert.equal(result.findingCount, 2);
      assert.equal(result.coverage.completeness, "partial");
      assert.deepEqual(
        new Set(result.coverage.deferred.map(({ id }: { id: string }) => id)),
        new Set([reopened.id, independent.id, nextTask.id]),
      );
      assert.deepEqual(
        result.coverage.deferred.find(
          ({ id }: { id: string }) => id === updated.id,
        ),
        updated,
      );
      assert.deepEqual((await f.read()).deferred, result.coverage.deferred);
      assert.deepEqual(result.coverage.resolvedDeferred, [
        close(stillClosed.id),
      ]);
      assert.deepEqual(
        new Set(result.coverage.surfaces.map(({ id }: { id: string }) => id)),
        new Set([...surfaces, nextSurface].map(({ id }: { id: string }) => id)),
      );
    }
  });
}

for (const outcome of ["rejected", "reported"]) {
  for (const surfaceLink of ["candidate", "surface", "none"]) {
    if (surfaceLink === "none" && outcome === "rejected") continue;
    test(`worker: accepted candidate outcomes survive progress ${outcome}/${surfaceLink}`, async (t) => {
      const f = await fixture(t, "worker");
      const candidateId = "accepted-candidate";
      const surface = {
        id: "accepted-surface",
        candidateId,
        label: "Accepted review",
        disposition: outcome,
      };
      const finding = {
        ...findingFor(candidateId),
        ruleId: "fixture.accepted-review",
        title: "Accepted review finding",
        summary: "A completed candidate outcome remains authoritative.",
        remediation: "Complete the independent review.",
      };
      const genericTask = { id: "generic-review", ...generic };
      await f.write({
        ...f.draft(
          {
            surfaces: surfaceLink === "none" ? [] : [surface],
            deferred: [genericTask],
          },
          true,
        ),
        findings: outcome === "reported" ? [finding] : [],
      });
      const candidate = { title: "Additional candidate evidence" };
      const update = {
        id: surface.id,
        ...(surfaceLink === "surface" ? {} : { candidateId }),
        label: surface.label,
        disposition: outcome === "reported" ? "rejected" : "needs_follow_up",
      };
      const progress = f.draft({
        surfaces: [update],
        deferred: [
          { id: "candidate-review", candidateId, candidate, ...generic },
        ],
      });
      for (const input of [progress, f.draft()]) {
        const result = await f.write(input);
        assert.equal(result.findingCount, outcome === "reported" ? 1 : 0);
        assert.deepEqual(result.coverage.deferred, [genericTask]);
        assert.deepEqual(
          result.coverage.surfaces.map(surfaceDisposition),
          surfaceLink === "none"
            ? []
            : [{ id: surface.id, disposition: outcome }],
        );
        if (outcome === "rejected") {
          assert.deepEqual(result.coverage.surfaces[0].candidate, candidate);
        } else {
          const saved = await readJson(f.root, "result.json");
          assert.deepEqual(saved.findings[0].provenance.originalCandidates, [
            candidate,
          ]);
        }
      }
    });
  }
}

for (const layout of ["standard", "diff", "worker"] as const) {
  test(`${layout}: moving a saved task stops blocking its former surface`, async (t) => {
    const f = await fixture(t, layout);
    const first = {
      id: "first",
      label: "First",
      disposition: "needs_follow_up",
    };
    const second = {
      id: "second",
      label: "Second",
      disposition: "needs_follow_up",
    };
    const a = { id: "a", ...generic, surfaceIds: [first.id] };
    const b = { id: "b", ...generic, surfaceIds: [first.id] };
    await f.write(f.draft({ surfaces: [first, second], deferred: [a, b] }));
    const moved = { ...a, surfaceIds: [second.id] };
    await f.write(f.draft({ deferred: [moved] }));
    for (const input of [
      f.draft(
        {
          surfaces: [{ ...first, disposition: "no_issue_found" }],
          resolvedDeferred: [close(b.id)],
        },
        true,
      ),
      f.draft({}, true),
    ]) {
      const result = await f.write(input);
      assert.deepEqual(result.coverage.deferred, [moved]);
      assert.equal(
        result.coverage.surfaces.find(
          ({ id }: { id: string }) => id === first.id,
        ).disposition,
        "no_issue_found",
      );
      assert.equal(
        result.coverage.surfaces.find(
          ({ id }: { id: string }) => id === second.id,
        ).disposition,
        "needs_follow_up",
      );
    }
  });

  test(`${layout}: a legacy ID-less checkpoint retains one closable task`, async (t) => {
    const f = await fixture(t, layout);
    await saveScanDraftCheckpoint(
      f.context,
      f.draft({ deferred: [generic] }),
      false,
    );
    let id;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const result = await f.write(f.draft({}, true));
      assert.equal(result.coverage.deferred.length, 1);
      id ??= result.coverage.deferred[0].id;
      assert.equal(result.coverage.deferred[0].id, id);
    }
    await f.write(f.draft({ resolvedDeferred: [close(id)] }, true));
    const retried = await f.write(f.draft({}, true));
    assert.deepEqual(retried.coverage.deferred, []);
    assert.deepEqual(retried.coverage.resolvedDeferred, [close(id)]);
  });

  for (const hasPublishedId of [false, true]) {
    test(`${layout}: a legacy ID-less surface stays closed, published ID=${hasPublishedId}`, async (t) => {
      const f = await fixture(t, layout);
      const surface = { label: "Uploads", disposition: "needs_follow_up" };
      if (hasPublishedId) {
        await f.write(
          f.draft({ surfaces: [{ ...surface, id: "surface_uploads" }] }),
        );
      }
      await saveScanDraftCheckpoint(
        f.context,
        f.draft({ surfaces: [surface], deferred: [generic] }),
        false,
      );
      const restored = await f.write(f.draft({}, true));
      assert.equal(restored.coverage.surfaces.length, 1);
      const restoredSurface = restored.coverage.surfaces[0];
      if (hasPublishedId) assert.equal(restoredSurface.id, "surface_uploads");
      const resolved = f.draft(
        {
          surfaces: [{ ...restoredSurface, disposition: "no_issue_found" }],
          resolvedDeferred: [close(restored.coverage.deferred[0].id)],
        },
        true,
      );
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const result = await f.write(resolved);
        assert.equal(result.coverage.completeness, "complete");
        assert.deepEqual(result.coverage.surfaces, resolved.coverage.surfaces);
        assert.deepEqual(result.coverage.deferred, []);
      }
    });
  }

  test(`${layout}: inheriting a candidate outcome keeps newer follow-up work`, async (t) => {
    const f = await fixture(t, layout);
    const surface = { id: "api", label: "API", disposition: "needs_follow_up" };
    await f.write(
      f.draft({
        deferred: [
          {
            id: "candidate-review",
            candidateId: "candidate-review",
            ...generic,
          },
        ],
        surfaces: [surface],
      }),
    );
    await f.write({
      ...f.draft({ surfaces: [surface] }),
      findings: [findingFor("candidate-review")],
    });
    const result = await f.write(f.draft({}, true));
    assert.equal(result.findingCount, 1);
    assert.equal(result.coverage.completeness, "partial");
    assert.deepEqual(result.coverage.surfaces.map(surfaceDisposition), [
      { id: surface.id, disposition: surface.disposition },
    ]);
  });

  for (const outcome of ["reported", "rejected", "not_applicable"]) {
    test(`${layout}: redundant candidate closure requires its ordinary ${outcome} outcome`, async (t) => {
      const f = await fixture(t, layout);
      const pending = {
        id: "candidate-task",
        candidateId: "candidate-review",
        ...generic,
      };
      const independent = { id: "independent-review", ...generic };
      await f.write(f.draft({ deferred: [pending, independent] }));
      const terminal = f.draft(
        { resolvedDeferred: [close(pending.id), close(pending.candidateId)] },
        true,
      );
      await assert.rejects(f.write(terminal), /cannot close candidate/);
      assert.deepEqual((await f.read()).deferred, [pending, independent]);
      terminal.findings = [findingFor("unrelated-candidate")];
      await assert.rejects(f.write(terminal), /cannot close candidate/);
      assert.deepEqual((await f.read()).deferred, [pending, independent]);
      terminal.findings = [];
      if (outcome === "reported")
        terminal.findings = [findingFor(pending.candidateId)];
      else
        terminal.coverage.surfaces = [
          {
            id: "candidate-surface",
            candidateId: pending.candidateId,
            label: "Candidate",
            disposition: outcome,
          },
        ];
      for (const input of [terminal, f.draft({}, true)]) {
        const result = await f.write(input);
        assert.equal(result.findingCount, outcome === "reported" ? 1 : 0);
        assert.deepEqual(result.coverage.deferred, [independent]);
        assert.deepEqual(result.coverage.resolvedDeferred ?? [], []);
      }
    });
  }

  test(`${layout}: duplicate task IDs cannot close independent deferred work`, async (t) => {
    const f = await fixture(t, layout);
    const first = { id: "review", ...generic };
    const second = { ...first, paths: ["src/other.py"] };
    await assert.rejects(
      f.write(f.draft({ deferred: [first, second] })),
      /coverage.deferred repeats review/,
    );
    assert.deepEqual(await readdir(f.root), []);
    second.id = "other-review";
    await f.write(f.draft({ deferred: [first, second] }));
    await f.write(f.draft({ resolvedDeferred: [close(first.id)] }, true));
    assert.deepEqual((await f.read()).deferred, [second]);
  });

  for (const savedIn of ["canonical result", "checkpoint"]) {
    test(`${layout}: a closure cannot erase distinct legacy tasks from a ${savedIn}`, async (t) => {
      const f = await fixture(t, layout);
      const tasks = [
        { id: "review", ...generic },
        { id: "review", reason: "Review storage.", paths: ["src/storage.py"] },
      ];
      if (savedIn === "checkpoint") {
        await saveScanDraftCheckpoint(
          f.context,
          f.draft({ deferred: tasks }),
          false,
        );
      } else {
        await f.write(f.draft({ deferred: [tasks[0]] }));
        await rm(path.join(f.root, "checkpoint-head.json"), { force: true });
        await rm(path.join(f.root, "checkpoints"), { recursive: true });
        const filename = path.join(
          f.root,
          layout === "worker" ? "result.json" : "coverage.json",
        );
        const saved = await readJson(filename);
        (layout === "worker" ? saved.coverage : saved).deferred = tasks;
        await writeJson(filename, saved);
      }
      const snapshot = async (
        directory = f.root,
      ): Promise<[string, string][]> => {
        const files: [string, string][] = [];
        for (const entry of await readdir(directory, { withFileTypes: true })) {
          const filename = path.join(directory, entry.name);
          if (entry.isDirectory()) files.push(...(await snapshot(filename)));
          else files.push([filename, await readFile(filename, "utf8")]);
        }
        return files.sort(([left], [right]) => left.localeCompare(right));
      };
      const original = await snapshot();
      for (let attempt = 0; attempt < 2; attempt += 1) {
        await assert.rejects(
          f.write(f.draft({ resolvedDeferred: [close("review")] }, true)),
          /cannot close ambiguous saved deferred work: review/,
        );
        assert.deepEqual(await snapshot(), original);
      }
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const recovered = await f.write(f.draft({}, true));
        assert.equal(recovered.coverage.completeness, "partial");
        assert.deepEqual(recovered.coverage.deferred, tasks);
        assert.deepEqual(recovered.coverage.resolvedDeferred ?? [], []);
        const beforeClosure = await snapshot();
        await assert.rejects(
          f.write(f.draft({ resolvedDeferred: [close("review")] }, true)),
          /cannot close ambiguous saved deferred work: review/,
        );
        assert.deepEqual(await snapshot(), beforeClosure);
      }
    });
  }

  test(`${layout}: returned deferred IDs support closure, retries and explicit reopening`, async (t) => {
    const f = await fixture(t, layout);
    const initial = await f.write(f.draft({ deferred: [generic] }));
    const original = initial.coverage.deferred[0];
    assert.equal(typeof original.id, "string");
    assert.deepEqual(initial.coverage, await f.read());
    const enriched = { ...original, notes: "Both callers were inspected." };
    const updatedDraft = await f.write(f.draft({ deferred: [enriched] }));
    assert.deepEqual(updatedDraft.coverage.deferred, [enriched]);
    const checkpointRoot = path.join(f.root, "checkpoints");
    const originals = await Promise.all(
      (await readdir(checkpointRoot)).map(async (name) => [
        name,
        await readFile(path.join(checkpointRoot, name), "utf8"),
      ]),
    );
    const closure = close(original.id);
    await f.write(f.draft({ resolvedDeferred: [closure] }, true));
    const updated = close(
      original.id,
      "A second review confirmed the decision.",
    );
    await f.write(f.draft({ resolvedDeferred: [updated] }, true));
    await f.write(f.draft({}, true));
    const saved = await f.read();
    assert.equal(saved.completeness, "complete");
    assert.deepEqual(saved.deferred, []);
    assert.deepEqual(saved.resolvedDeferred, [updated]);
    for (const [name, contents] of originals)
      assert.equal(
        await readFile(path.join(checkpointRoot, name), "utf8"),
        contents,
      );
    const reopened = { ...original, reason: "A new caller needs review." };
    await f.write(f.draft({ deferred: [reopened] }, true));
    for (const complete of [false, true]) {
      await f.write(f.draft({}, complete));
      const pending = await f.read();
      assert.equal(pending.completeness, "partial");
      assert.deepEqual(pending.deferred, [reopened]);
      assert.deepEqual(pending.resolvedDeferred ?? [], []);
    }
  });

  for (const payload of ["candidate", "finding"] as const) {
    test(`${layout}: generic closure preserves ${payload} evidence until its explicit outcome`, async (t) => {
      const f = await fixture(t, layout);
      const pending = {
        id: "caller-review",
        candidateId: "candidate-review",
        ...generic,
        [payload]: {
          title: "Caller validation.",
          evidence: "Check both callers.",
        },
      };
      const independent = { id: "source-review", ...generic };
      await f.write(f.draft({ deferred: [pending, independent] }));
      const closure = close(independent.id);
      await f.write(f.draft({ resolvedDeferred: [closure] }, true));
      await f.write(f.draft({}, true));
      assert.deepEqual((await f.read()).deferred, [pending]);
      await f.write(
        f.draft(
          {
            surfaces: [
              {
                id: "candidate-outcome",
                candidateId: pending.candidateId,
                label: "Caller",
                disposition: "rejected",
              },
            ],
          },
          true,
        ),
      );
      await f.write(f.draft({}, true));
      const saved = await f.read();
      assert.deepEqual(saved.deferred, []);
      assert.deepEqual(saved.resolvedDeferred, [closure]);
      assert.deepEqual(
        saved.surfaces.find(
          (row: Record<string, unknown>) =>
            row.candidateId === pending.candidateId,
        )[payload],
        (pending as Record<string, unknown>)[payload],
      );
    });
  }

  for (const payload of ["generic", "candidate", "finding"] as const) {
    test(`${layout}: ID-less ${payload} checkpoints cannot borrow a saved identity`, async (t) => {
      const f = await fixture(t, layout);
      const evidence =
        payload === "generic"
          ? {}
          : { [payload]: { title: "Caller validation." } };
      const named = {
        id: "caller-review",
        ...generic,
        ...evidence,
        paths: [...generic.paths, "src/alternate.py"],
        notes: "Both callers remain pending.",
        ...(payload === "generic" ? {} : { candidateId: "candidate-review" }),
      };
      const raw = { ...generic, ...evidence };
      await f.write(f.draft({ deferred: [named] }));
      await interruptDraftWrite(
        path.join(
          f.root,
          layout === "worker" ? "result.json" : "coverage.json",
        ),
        () => f.write(f.draft({ deferred: [raw] })),
      );
      await f.write(f.draft({}, true));
      const saved = await f.read();
      assert.equal(saved.completeness, "partial");
      assert.deepEqual(
        saved.deferred.find(
          (row: Record<string, unknown>) => row.id === named.id,
        ),
        named,
      );
      const independent = saved.deferred.find(
        (row: Record<string, unknown>) => row.id !== named.id,
      );
      assert.ok(independent);
      assert.deepEqual(independent, { ...raw, id: independent.id });
      const outcome =
        payload === "generic"
          ? { resolvedDeferred: [close(named.id)] }
          : {
              surfaces: [
                {
                  candidateId: named.candidateId,
                  label: "Caller",
                  disposition: "rejected",
                },
              ],
            };
      await f.write(f.draft(outcome, true));
      await f.write(f.draft({}, true));
      assert.deepEqual((await f.read()).deferred, [independent]);
    });
  }

  for (const submittedId of [undefined, "api", "other-api"]) {
    test(`${layout}: surface closeout requires matching ID ${submittedId ?? "omitted"}`, async (t) => {
      const f = await fixture(t, layout);
      const surface = {
        id: "api",
        label: "API",
        disposition: "needs_follow_up",
        receiptRefs: ["artifacts/api-review.md"],
      };
      const other = {
        ...surface,
        id: "another-api",
        notes: "Independent entry point.",
      };
      await f.write(
        f.draft({
          surfaces: [surface, other],
          deferred: [
            { id: "api-review", ...generic, surfaceIds: [surface.id] },
          ],
        }),
      );
      await f.write(
        f.draft(
          {
            resolvedDeferred: [close("api-review")],
            surfaces: [
              {
                ...(submittedId ? { id: submittedId } : {}),
                label: surface.label,
                disposition: "no_issue_found",
              },
            ],
          },
          true,
        ),
      );
      await f.write(f.draft({}, true));
      const saved = await f.read();
      assert.deepEqual(saved.deferred, []);
      assert.deepEqual(
        saved.surfaces.find(
          (row: Record<string, unknown>) => row.id === other.id,
        ),
        other,
      );
      assert.equal(saved.completeness, "partial");
      assert.deepEqual(
        saved.surfaces.find(
          (row: Record<string, unknown>) => row.id === surface.id,
        ),
        submittedId === surface.id
          ? { ...surface, disposition: "no_issue_found" }
          : surface,
      );
    });
  }

  for (const payload of ["generic", "candidate"] as const) {
    test(`${layout}: closing one task retains ${payload} work on a shared surface`, async (t) => {
      const f = await fixture(t, layout);
      const first = { id: "review-a", ...generic, surfaceIds: ["shared"] };
      const remaining = {
        id: "review-b",
        ...generic,
        surfaceIds: ["shared"],
        ...(payload === "candidate"
          ? {
              candidateId: "candidate-b",
              candidate: { title: "Pending caller." },
            }
          : {}),
      };
      const surface = {
        id: "shared",
        label: "Shared entry point",
        disposition: "needs_follow_up",
        notes: "The second caller still needs review.",
        receiptRefs: ["artifacts/pending.md"],
      };
      await f.write(
        f.draft({ surfaces: [surface], deferred: [first, remaining] }),
      );
      const closure = close(first.id);
      for (const resolvedDeferred of [[closure], [closure], undefined]) {
        await f.write(
          f.draft(
            resolvedDeferred
              ? {
                  resolvedDeferred,
                  surfaces: [
                    {
                      ...surface,
                      disposition: "no_issue_found",
                      notes: "The first caller is reviewed.",
                      receiptRefs: ["artifacts/reviewed.md"],
                    },
                  ],
                }
              : {},
            true,
          ),
        );
        const saved = await f.read();
        assert.equal(saved.completeness, "partial");
        assert.deepEqual(saved.deferred, [remaining]);
        assert.deepEqual(saved.resolvedDeferred, [closure]);
        assert.deepEqual(saved.surfaces, [
          {
            ...surface,
            receiptRefs: ["artifacts/reviewed.md", "artifacts/pending.md"],
          },
        ]);
      }
    });
  }

  for (const observation of ["terminal", "progress", "surface-only", "tied"]) {
    test(`${layout}: explicit surface follow-up survives ${observation} checkpoint recovery`, async (t) => {
      const f = await fixture(t, layout);
      const pending = { id: "api-review", ...generic, surfaceIds: ["api"] };
      const surface = {
        id: "api",
        label: "API",
        disposition: "needs_follow_up",
        receiptRefs: ["artifacts/original.md"],
      };
      await f.write(f.draft({ deferred: [pending], surfaces: [surface] }));
      const closed = f.draft(
        {
          resolvedDeferred: [close(pending.id)],
          surfaces: [{ ...surface, disposition: "no_issue_found" }],
        },
        true,
      );
      await f.write(closed);
      const checkpoints = path.join(f.root, "checkpoints");
      for (const name of await readdir(checkpoints)) {
        const file = path.join(checkpoints, name);
        const row = await readJson(file);
        const time = row.coverage.resolvedDeferred?.length ? 2 : 1;
        await utimes(file, time, time);
      }
      for (const name of layout === "worker"
        ? ["result.json", "checkpoint-head.json"]
        : [
            "coverage.json",
            "scan-manifest.json",
            "findings.json",
            "checkpoint-head.json",
          ])
        await utimes(path.join(f.root, name), 2, 2);
      const before = new Set(await readdir(checkpoints));
      const followUp = {
        ...surface,
        notes: "A new caller needs review.",
        receiptRefs: ["artifacts/new-caller.md"],
      };
      const deferred =
        observation === "surface-only"
          ? []
          : [{ ...pending, reason: followUp.notes }];
      await saveScanDraftCheckpoint(
        f.context,
        f.draft(
          { deferred, surfaces: [followUp] },
          observation === "terminal" || observation === "tied",
        ),
        false,
      );
      for (const name of await readdir(checkpoints)) {
        if (!before.has(name)) {
          const time = observation === "tied" ? 2 : 3;
          await utimes(path.join(checkpoints, name), time, time);
        }
      }
      for (const complete of [true, false, true]) {
        await f.write(f.draft({}, complete));
        const saved = await f.read();
        assert.equal(saved.completeness, "partial");
        assert.deepEqual(saved.deferred, deferred);
        assert.equal(saved.surfaces.length, 1);
        assert.equal(saved.surfaces[0].id, surface.id);
        assert.equal(saved.surfaces[0].disposition, "needs_follow_up");
        assert.equal(saved.surfaces[0].notes, followUp.notes);
        assert.ok(
          saved.surfaces[0].receiptRefs.includes("artifacts/new-caller.md"),
        );
      }
      await f.write(closed);
      const saved = await f.read();
      assert.equal(saved.completeness, "complete");
      assert.deepEqual(saved.deferred, []);
      assert.equal(saved.surfaces[0].disposition, "no_issue_found");
    });
  }

  for (const destination of layout === "worker"
    ? ["result.json", "checkpoint-head.json"]
    : ["coverage.json", "scan-manifest.json"]) {
    test(`${layout}: recover explicit work after ${destination} publication fails`, async (t) => {
      const f = await fixture(t, layout);
      const originalRename = fsPromises.rename;
      let publicationTime = 0;
      // Keep successive publications distinct on coarse filesystem clocks.
      t.mock.method(
        fsPromises,
        "rename",
        async (...args: Parameters<typeof originalRename>) => {
          await originalRename(...args);
          publicationTime += 1;
          await utimes(args[1], publicationTime, publicationTime);
        },
      );
      const pending = { id: "review", ...generic };
      const closing = f.draft({ resolvedDeferred: [close(pending.id)] }, true);
      const fail = (input: ScanDraftInput) =>
        interruptDraftWrite(path.join(f.root, destination), () =>
          f.write(input),
        );
      await f.write(f.draft({ deferred: [pending] }));
      await fail(closing);
      await f.write(f.draft({}, true));
      assert.deepEqual((await f.read()).deferred, []);
      assert.deepEqual((await f.read()).resolvedDeferred, [close(pending.id)]);
      const checkpointRoot = path.join(f.root, "checkpoints");
      const originalClosures: [string, number, Buffer, boolean][] = [];
      for (const name of await readdir(checkpointRoot)) {
        const file = path.join(checkpointRoot, name);
        const saved = await readJson(file);
        if (saved.coverage.resolvedDeferred?.length)
          originalClosures.push([
            file,
            (await stat(file)).mtimeMs,
            await readFile(file),
            // Raw scopes forbid bound paths; normalized snapshots have them.
            layout === "worker" || Array.isArray(saved.scope?.includePaths),
          ]);
      }
      const reopened = {
        ...pending,
        reason: "A newly inspected caller needs review.",
      };
      await fail(f.draft({ deferred: [reopened] }, true));
      await f.write(f.draft({}, true));
      const saved = await f.read();
      assert.equal(saved.completeness, "partial");
      assert.deepEqual(saved.deferred, [reopened]);
      assert.deepEqual(saved.resolvedDeferred ?? [], []);
      await fail(closing);
      for (const [file, modified, bytes, fixedTime] of originalClosures) {
        assert.deepEqual(await readFile(file), bytes);
        if (fixedTime) assert.equal((await stat(file)).mtimeMs, modified);
      }
      await f.write(f.draft({}, true));
      const accepted = layout !== "worker" || destination === "result.json";
      assert.deepEqual((await f.read()).deferred, accepted ? [] : [reopened]);
      await f.write(closing);
      await f.write(f.draft({}, true));
      assert.deepEqual((await f.read()).deferred, []);
      assert.deepEqual((await f.read()).resolvedDeferred, [close(pending.id)]);
    });
  }
}

test("worker: inherited closures cannot erase ambiguous legacy tasks", async (t) => {
  const f = await fixture(t, "worker");
  const tasks = [
    { id: "review", ...generic },
    { id: "review", reason: "Review storage.", paths: ["src/storage.py"] },
  ];
  await saveScanDraftCheckpoint(f.context, f.draft({ deferred: tasks }), false);
  await saveScanDraftCheckpoint(
    f.context,
    f.draft({ resolvedDeferred: [close("review")] }, true),
  );
  const checkpoints = path.join(f.root, "checkpoints");
  for (const name of await readdir(checkpoints)) {
    const filename = path.join(checkpoints, name);
    const saved = await readJson(filename);
    const timestamp = saved.coverage.deferred.length ? 100 : 200;
    await utimes(filename, timestamp, timestamp);
  }
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const recovered = await f.write(f.draft({}, true));
    assert.equal(recovered.coverage.completeness, "partial");
    assert.deepEqual(recovered.coverage.deferred, tasks);
    assert.deepEqual(recovered.coverage.resolvedDeferred ?? [], []);
  }
});

for (const layout of ["standard", "diff"] as const) {
  for (const taskCount of [1, 2]) {
    test(`${layout}: an upgraded checkpoint retains ${taskCount} older canonical task IDs`, async (t) => {
      const f = await fixture(t, layout);
      await f.write(f.draft({ deferred: [generic] }));
      const legacyId = `deferred-${hash(
        "sha256",
        JSON.stringify([generic.reason, generic.paths, []]),
      ).slice(0, 16)}`;
      const coverage = await f.read();
      const named = Array.from({ length: taskCount }, (_, index) => ({
        id: index === 0 ? legacyId : `${legacyId}-${index + 1}`,
        paths: generic.paths,
        reason: generic.reason,
      }));
      coverage.deferred = named;
      await writeJson(path.join(f.root, "coverage.json"), coverage);
      await rm(path.join(f.root, "checkpoint-head.json"), { force: true });
      await rm(path.join(f.root, "checkpoints"), {
        recursive: true,
        force: true,
      });
      await saveScanDraftCheckpoint(
        f.context,
        f.draft({ deferred: Array.from({ length: taskCount }, () => generic) }),
        false,
      );
      const resumed = await f.write(f.draft({}, true));
      assert.deepEqual(resumed.coverage.deferred, named);
      const partlyClosed = await f.write(
        f.draft({ resolvedDeferred: [close(legacyId)] }, true),
      );
      assert.deepEqual(partlyClosed.coverage.deferred, named.slice(1));
      if (taskCount > 1)
        await f.write(
          f.draft(
            {
              resolvedDeferred: named
                .slice(1)
                .map(({ id }: { id: string }) => close(id)),
            },
            true,
          ),
        );
      const retried = await f.write(f.draft({}, true));
      assert.deepEqual(retried.coverage.deferred, []);
      assert.deepEqual(
        new Set(
          retried.coverage.resolvedDeferred.map(({ id }: { id: string }) => id),
        ),
        new Set(named.map(({ id }: { id: string }) => id)),
      );
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  test(`${layout}: a staged explicit surface closeout survives omitted and repeated retries`, async (t) => {
    const f = await fixture(t, layout);
    const surface = {
      id: "api",
      label: "API",
      disposition: "needs_follow_up",
      receiptRefs: ["artifacts/api-review.md"],
    };
    await f.write(
      f.draft({
        surfaces: [surface],
        deferred: [{ id: "review", ...generic, surfaceIds: [surface.id] }],
      }),
    );
    const resolvedDeferred = [close("review")];
    const closed = f.draft(
      {
        resolvedDeferred,
        surfaces: [
          {
            id: surface.id,
            label: surface.label,
            disposition: "no_issue_found",
          },
        ],
      },
      true,
    );
    await assert.rejects(
      recordCodexSecurityScanDraftViaWorkbench(
        f.context,
        closed,
        async (args: string[]) => {
          const checkpoint = await readJson(
            args[args.indexOf("--checkpoint-path") + 1],
          );
          await saveScanDraftCheckpoint(f.context, checkpoint);
          throw new Error("interrupted draft write");
        },
      ),
      /interrupted draft write/,
    );
    for (const coverage of [{}, { resolvedDeferred }, {}]) {
      await f.write(f.draft(coverage, true));
      const saved = await f.read();
      assert.equal(saved.completeness, "complete");
      assert.deepEqual(saved.deferred, []);
      assert.deepEqual(saved.resolvedDeferred, resolvedDeferred);
      assert.deepEqual(saved.surfaces, [
        { ...surface, disposition: "no_issue_found" },
      ]);
    }
  });
}

for (const layout of ["standard", "diff", "worker"] as const) {
  for (const interrupted of [false, true]) {
    test(`${layout}: returned surface IDs support closeout after first-write interruption=${interrupted}`, async (t) => {
      const f = await fixture(t, layout);
      const input = f.draft({
        surfaces: [{ label: "API", disposition: "needs_follow_up" }],
        deferred: [generic],
      });
      const original = structuredClone(input);
      if (interrupted) {
        await interruptDraftWrite(
          path.join(
            f.root,
            layout === "worker" ? "result.json" : "findings.json",
          ),
          () => f.write(input),
        );
      }
      const initial = await f.write(input);
      const [surface] = initial.coverage.surfaces;
      const [task] = initial.coverage.deferred;
      assert.equal(typeof surface.id, "string");
      assert.equal(typeof task.id, "string");
      assert.deepEqual(initial.coverage, await f.read());
      assert.deepEqual(input, original);
      for (const name of await readdir(path.join(f.root, "checkpoints"))) {
        const checkpoint = await readJson(f.root, "checkpoints", name);
        assert.equal(checkpoint.coverage.surfaces[0].id, surface.id);
        assert.deepEqual(checkpoint.coverage.surfaces[0].receiptRefs, []);
        assert.equal(checkpoint.coverage.deferred[0].id, task.id);
      }
      const linked = await f.write(
        f.draft({
          surfaces: [surface],
          deferred: [
            {
              ...task,
              surfaceIds: [surface.id],
              notes: "Both callers inspected.",
            },
          ],
        }),
      );
      assert.equal(linked.coverage.deferred.length, 1);
      assert.equal(linked.coverage.deferred[0].id, task.id);
      const terminal = await f.write(
        f.draft(
          {
            surfaces: [{ ...surface, disposition: "no_issue_found" }],
            resolvedDeferred: [close(task.id)],
          },
          true,
        ),
      );
      assert.equal(terminal.coverage.completeness, "complete");
      assert.deepEqual(terminal.coverage.deferred, []);
      assert.deepEqual(terminal.coverage.surfaces, [
        { ...surface, disposition: "no_issue_found", receiptRefs: [] },
      ]);
      await f.write(f.draft({}, true));
      assert.deepEqual(await f.read(), terminal.coverage);
    });
  }
}

test("worker: duplicate authored surface IDs preserve each observation", async (t) => {
  const f = await fixture(t, "worker");
  const rows = [
    { id: "api", label: "First API", disposition: "needs_follow_up" },
    { id: "api", label: "Second API", disposition: "needs_follow_up" },
    { id: "api-2", label: "Existing API", disposition: "needs_follow_up" },
  ];
  const initial = await f.write(f.draft({ surfaces: rows }));
  assert.deepEqual(
    initial.coverage.surfaces.map(({ id }: { id: string }) => id),
    ["api", "api-3", "api-2"],
  );
  assert.deepEqual(
    (await f.write(f.draft({ surfaces: rows }))).coverage.surfaces,
    initial.coverage.surfaces,
  );
  const updated = initial.coverage.surfaces.map(
    (row: Record<string, unknown>) =>
      row.id === "api-3" ? { ...row, disposition: "no_issue_found" } : row,
  );
  const saved = await f.write(f.draft({ surfaces: updated }));
  assert.equal(saved.coverage.surfaces.length, 3);
  assert.equal(
    saved.coverage.surfaces.find(({ id }: { id: string }) => id === "api")
      .disposition,
    "needs_follow_up",
  );
  assert.equal(
    saved.coverage.surfaces.find(({ id }: { id: string }) => id === "api-3")
      .disposition,
    "no_issue_found",
  );
});

test("worker: surface IDs remain valid independently of candidate names", async (t) => {
  const f = await fixture(t, "worker");
  const candidate = {
    candidateId: "Candidate A",
    label: "API",
    disposition: "needs_follow_up",
  };
  const initial = await f.write(f.draft({ surfaces: [candidate] }));
  const [surface] = initial.coverage.surfaces;
  assert.match(surface.id, /^[a-z0-9][a-z0-9._/-]*$/u);
  assert.equal(surface.candidateId, candidate.candidateId);
  await f.write(
    f.draft({ surfaces: [{ ...surface, disposition: "rejected" }] }, true),
  );
  const retried = await f.write(f.draft({}, true));
  assert.deepEqual(retried.coverage.surfaces, [
    { ...surface, disposition: "rejected" },
  ]);
});

test("worker: generated surface IDs preserve distinct observations and reserved identities", async (t) => {
  const f = await fixture(t, "worker");
  const first = {
    label: "API",
    disposition: "needs_follow_up",
    notes: "First caller.",
  };
  const second = { ...first, notes: "Second caller." };
  const input = f.draft({ surfaces: [first, second] });
  const initial = await f.write(input);
  const ids = initial.coverage.surfaces.map(({ id }: { id: string }) => id);
  assert.ok(ids.every((id: string) => typeof id === "string"));
  assert.equal(new Set(ids).size, 2);
  assert.deepEqual(
    (await f.write(input)).coverage.surfaces,
    initial.coverage.surfaces,
  );
  const changed = { ...first, notes: "A newly found caller." };
  const updated = await f.write(f.draft({ surfaces: [changed] }));
  assert.equal(updated.coverage.surfaces.length, 3);
  assert.ok(
    updated.coverage.surfaces.some(
      (row: Record<string, unknown>) =>
        row.id === ids[0] && row.notes === first.notes,
    ),
  );
  const other = await fixture(t, "worker");
  const reserved = [
    first,
    second,
    { ...changed, id: ids[0] },
    { label: "Candidate", disposition: "needs_follow_up", candidateId: ids[1] },
  ];
  const saved = (await other.write(other.draft({ surfaces: reserved })))
    .coverage.surfaces;
  assert.equal(new Set(saved.map(({ id }: { id: string }) => id)).size, 4);
  assert.equal(saved[2].id, ids[0]);
  assert.equal(saved[3].candidateId, ids[1]);
  assert.notEqual(saved[0].id, ids[0]);
  assert.notEqual(saved[3].id, ids[1]);
  for (const input of [other.draft({ surfaces: [saved[3]] }), other.draft()]) {
    const retained = (await other.write(input)).coverage.surfaces;
    assert.equal(retained.length, saved.length);
    assert.deepEqual(
      retained.find(
        (row: Record<string, unknown>) => row.notes === second.notes,
      ),
      saved[1],
    );
  }
  assert.notEqual(saved[1].id, ids[1]);
});

test("worker: archived closures cannot discard a later explicitly reopened task", async (t) => {
  const f = await fixture(t, "worker");
  const pending = { id: "review", ...generic };
  await f.write(f.draft({ deferred: [pending] }));
  await f.write(f.draft({ resolvedDeferred: [close(pending.id)] }, true));
  const attempts = path.join(path.dirname(f.root), "attempts");
  await mkdir(attempts);
  await rename(f.root, path.join(attempts, "attempt-01"));
  await mkdir(f.root);
  await f.write(f.draft({ deferred: [pending] }, true));
  await rename(f.root, path.join(attempts, "attempt-02"));
  await mkdir(f.root);
  await f.write(f.draft({}, true));
  assert.deepEqual((await f.read()).deferred, [pending]);
  assert.deepEqual((await f.read()).resolvedDeferred ?? [], []);
});

for (const layout of ["standard", "diff"] as const) {
  for (const selectedTime of [150, 200, 300]) {
    test(`${layout}: parent checkpoint selection at ${selectedTime} orders a closure`, async (t) => {
      const f = await fixture(t, layout);
      const pending = { id: "review", ...generic };
      await f.write(f.draft({ deferred: [pending] }));
      const closed = f.draft(
        { resolvedDeferred: [{ id: pending.id, reason: "Callers reviewed." }] },
        true,
      );
      await f.write(closed);
      await f.write(f.draft({ deferred: [pending] }));
      let selected;
      for (const name of await readdir(path.join(f.root, "checkpoints"))) {
        const file = path.join(f.root, "checkpoints", name);
        const value = await readJson(file);
        const time = value.coverage.resolvedDeferred?.length ? 100 : 200;
        await utimes(file, time, time);
        if (value.complete && value.coverage.resolvedDeferred?.length)
          selected = name;
      }
      assert.ok(selected);
      for (const name of [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
      ])
        await utimes(path.join(f.root, name), 200, 200);
      const head = path.join(f.root, "checkpoint-head.json");
      await writeJson(head, { checkpoint: selected });
      await utimes(head, selectedTime, selectedTime);
      await f.write(f.draft({}, true));
      const saved = await f.read();
      if (selectedTime > 200) {
        assert.deepEqual(saved.deferred, []);
        assert.deepEqual(
          saved.resolvedDeferred,
          closed.coverage.resolvedDeferred,
        );
        assert.equal(saved.completeness, "complete");
      } else {
        assert.deepEqual(saved.deferred, [pending]);
        assert.equal(saved.resolvedDeferred, undefined);
        assert.equal(saved.completeness, "partial");
      }
    });
  }
}

for (const payload of ["generic", "candidate"] as const) {
  test(`worker: legacy unnamed ${payload} evidence remains pending after a named closeout`, async (t) => {
    const f = await fixture(t, "worker");
    const raw = {
      ...generic,
      ...(payload === "candidate"
        ? { candidate: { title: "Caller review." } }
        : {}),
    };
    const named = {
      ...raw,
      id: "named-review",
      notes: "Saved caller context.",
      ...(payload === "candidate" ? { candidateId: "named-candidate" } : {}),
    };
    await f.write(f.draft({ deferred: [named] }));
    await saveScanDraftCheckpoint(
      f.context,
      f.draft({ deferred: [raw] }),
      false,
    );
    const outcome =
      payload === "generic"
        ? { resolvedDeferred: [close(named.id)] }
        : {
            surfaces: [
              {
                candidateId: named.candidateId,
                label: "Caller",
                disposition: "rejected",
              },
            ],
          };
    await f.write(f.draft(outcome, true));
    await f.write(f.draft({}, true));
    const saved = await f.read();
    assert.equal(saved.completeness, "partial");
    assert.ok(saved.deferred.length > 0);
    for (const { id, ...row } of saved.deferred) {
      assert.notEqual(id, named.id);
      assert.deepEqual(row, raw);
    }
  });
}

for (const complete of [false, true]) {
  for (const malformed of [false, true]) {
    test(`worker: retain a valid ${complete ? "terminal" : "progress"} draft before reading an invalid result, malformed=${malformed}`, async (t) => {
      const f = await fixture(t, "worker");
      const destination = path.join(f.root, "result.json");
      await writeFile(
        destination,
        malformed
          ? "{broken"
          : JSON.stringify({
              ...f.draft(),
              scanId: "7b95abf2-dc04-47a9-9950-53b5c2057f50",
            }),
      );
      const submitted = f.draft(
        { deferred: [{ id: "pending", ...generic }] },
        complete,
      );
      await assert.rejects(
        f.write(submitted),
        malformed ? /stored JSON is malformed/ : /belongs to a different scan/,
      );
      const files = await readdir(path.join(f.root, "checkpoints"));
      assert.equal(files.length, 1);
      assert.deepEqual(
        await readJson(f.root, "checkpoints", files[0]),
        submitted,
      );
      await rm(destination);
      await f.write(f.draft({}, true));
      assert.deepEqual((await f.read()).deferred, submitted.coverage.deferred);
    });
  }
}

for (const saved of ["missing", "malformed", "different scan"]) {
  test(`worker: reject an unknown closure without a checkpoint, saved result=${saved}`, async (t) => {
    const f = await fixture(t, "worker");
    if (saved !== "missing")
      await writeFile(
        path.join(f.root, "result.json"),
        saved === "malformed"
          ? "{broken"
          : JSON.stringify({
              ...f.draft(),
              scanId: "7b95abf2-dc04-47a9-9950-53b5c2057f50",
            }),
      );
    await assert.rejects(
      f.write(
        f.draft(
          {
            resolvedDeferred: [
              { id: "unknown", reason: "Unsupported closure." },
            ],
          },
          true,
        ),
      ),
      saved === "malformed"
        ? /stored JSON is malformed/
        : saved === "different scan"
          ? /belongs to a different scan/
          : /names no saved generic deferral/,
    );
    assert.deepEqual(
      await readdir(f.root),
      saved === "missing" ? [] : ["result.json"],
    );
  });
}

for (const layout of ["standard", "diff", "worker"] as const) {
  for (const added of [false, true]) {
    test(`${layout}: ignored progress reconciles an interrupted raw terminal checkpoint, added=${added}`, async (t) => {
      const f = await fixture(t, layout);
      const existing = findingFor("candidate-a");
      const pending = { id: "pending-review", ...generic };
      await f.write({
        ...f.draft({ deferred: [pending] }),
        findings: [existing],
      });
      const later = {
        ...findingFor("candidate-b"),
        title: "Later finding",
        locations: [{ path: "src/example.py", startLine: 2 }],
      };
      // A raw checkpoint is durable before its reconciled checkpoint and result are written.
      await saveScanDraftCheckpoint(
        f.context,
        { ...f.draft({}, true), findings: added ? [later] : [] },
        false,
      );
      const result = await f.write(
        f.draft({
          surfaces: [
            {
              id: "candidate-a",
              candidateId: "candidate-a",
              label: "Late rejection",
              disposition: "rejected",
              receiptRefs: [],
            },
          ],
        }),
      );
      assert.equal(result.findingCount, added ? 2 : 1);
      assert.equal(result.coverage.completeness, "partial");
      assert.deepEqual(result.coverage.surfaces, []);
      assert.deepEqual(result.coverage.deferred, [pending]);
      assert.deepEqual((await f.read()).deferred, [pending]);
    });
  }
}

for (const explicit of ["neither", "scope", "threatModel", "both"]) {
  test(`worker: terminal recovery preserves ordered metadata, explicit=${explicit}`, async (t) => {
    const f = await fixture(t, "worker");
    const pending = { id: "review", ...generic };
    const metadata = (name: string) => ({
      scope: { summary: `${name} scope` },
      threatModel: { summary: `${name} model` },
    });
    await f.write({
      ...f.draft({ deferred: [pending] }),
      ...metadata("older"),
    });
    const checkpoints = path.join(f.root, "checkpoints");
    for (const name of await readdir(checkpoints))
      await utimes(path.join(checkpoints, name), 100, 100);
    await utimes(path.join(f.root, "result.json"), 100, 100);
    await utimes(path.join(f.root, "checkpoint-head.json"), 100, 100);
    const terminal = {
      ...f.draft({ deferred: [pending] }, true),
      ...(explicit === "scope" || explicit === "both"
        ? { scope: metadata("terminal").scope }
        : {}),
      ...(explicit === "threatModel" || explicit === "both"
        ? { threatModel: metadata("terminal").threatModel }
        : {}),
    };
    await saveScanDraftCheckpoint(f.context, terminal, false);
    for (const name of await readdir(checkpoints)) {
      const checkpoint = await readJson(checkpoints, name);
      if (checkpoint.complete)
        await utimes(path.join(checkpoints, name), 200, 200);
    }
    await saveScanDraftCheckpoint(f.context, {
      ...f.draft({ deferred: [pending] }),
      ...metadata("newer"),
    });
    await utimes(path.join(f.root, "checkpoint-head.json"), 300, 300);
    for (let replay = 0; replay < 2; replay++) {
      await f.write(f.draft());
      const saved = await readJson(f.root, "result.json");
      assert.deepEqual(saved.scope, terminal.scope ?? metadata("newer").scope);
      assert.deepEqual(
        saved.threatModel,
        terminal.threatModel ?? metadata("newer").threatModel,
      );
      assert.deepEqual(saved.coverage.deferred, [pending]);
    }
  });
}

for (const metadata of [
  "omitted",
  "empty",
  "explicit",
  "absent",
  "latest",
  "current",
]) {
  test(`deep: interrupted terminal preserves retained metadata, model=${metadata}`, async (t) => {
    const f = await fixture(t, "deep");
    const oldModel = { summary: "Earlier model" };
    const latestModel = { summary: "Latest saved model" };
    const terminalModel =
      metadata === "empty"
        ? { summary: "Explicit model", assets: [], trustBoundaries: [] }
        : metadata === "explicit"
          ? { summary: "Explicit model" }
          : undefined;
    const stale = { id: "old-work", reason: "Earlier review" };
    await f.write({
      ...f.draft({ deferred: [stale] }),
      findings: [findingFor("old-finding")],
      scope: { summary: "Earlier scope" },
      ...(metadata === "absent" ? {} : { threatModel: oldModel }),
    });
    const checkpoints = path.join(f.root, "checkpoints");
    for (const name of await readdir(checkpoints))
      await utimes(path.join(checkpoints, name), 100, 100);
    for (const name of [
      "findings.json",
      "coverage.json",
      "scan-manifest.json",
      "checkpoint-head.json",
    ])
      await utimes(path.join(f.root, name), 100, 100);
    if (metadata === "latest") {
      await saveScanDraftCheckpoint(f.context, {
        ...f.draft(),
        threatModel: latestModel,
        scope: { summary: "Latest saved scope" },
      });
      for (const name of await readdir(checkpoints)) {
        const saved = await readJson(checkpoints, name);
        if (saved.threatModel?.summary === latestModel.summary)
          await utimes(path.join(checkpoints, name), 150, 150);
      }
    }
    // Legacy writers could stop after saving raw terminal input, before publication.
    await saveScanDraftCheckpoint(f.context, {
      ...f.draft({}, true),
      ...(terminalModel === undefined ? {} : { threatModel: terminalModel }),
    });
    const originalCheckpoints = new Map<string, string>();
    for (const name of await readdir(checkpoints)) {
      const filename = path.join(checkpoints, name);
      const contents = await readFile(filename, "utf8");
      originalCheckpoints.set(name, contents);
      if (JSON.parse(contents).complete) await utimes(filename, 200, 200);
    }
    for (let replay = 0; replay < 2; replay++) {
      const result = await f.write({
        ...f.draft(),
        ...(metadata === "current"
          ? { threatModel: { summary: "Current progress model" } }
          : {}),
      });
      const saved = (await readJson(f.root, "scan-manifest.json")).scan;
      assert.deepEqual(
        saved.threatModel,
        terminalModel ??
          (metadata === "absent"
            ? undefined
            : metadata === "latest"
              ? latestModel
              : oldModel),
      );
      assert.equal(
        saved.scope.summary,
        metadata === "latest" ? "Latest saved scope" : "Earlier scope",
      );
      assert.notEqual(saved.complete, false);
      assert.equal(result.findingCount, 0);
      assert.deepEqual(result.coverage.deferred, []);
      assert.deepEqual(result.coverage.surfaces, []);
      assert.deepEqual((await readJson(f.root, "findings.json")).findings, []);
    }
    for (const [name, contents] of originalCheckpoints)
      assert.equal(
        await readFile(path.join(checkpoints, name), "utf8"),
        contents,
      );
  });
}

for (const layout of ["standard", "diff", "worker"] as const) {
  test(`${layout}: progress survives a raw terminal checkpoint with unresolved saved work`, async (t) => {
    const f = await fixture(t, layout);
    await f.write(
      f.draft({
        deferred: [{ candidateId: "candidate-a", reason: "Review remains." }],
      }),
    );
    await saveScanDraftCheckpoint(f.context, f.draft({}, true), false);
    await f.write({ ...f.draft(), findings: [findingFor("candidate-a")] });
    const retried = await f.write(f.draft({}, true));
    assert.equal(retried.findingCount, 1);
  });

  test(`${layout}: late progress can explicitly reopen a closed ID by candidate alias`, async (t) => {
    const f = await fixture(t, layout);
    await f.write(f.draft({ deferred: [{ id: "review", ...generic }] }));
    await f.write(f.draft({ resolvedDeferred: [close("review")] }, true));
    const reopened = { id: "follow-up", candidateId: "review", ...generic };
    const result = await f.write(f.draft({ deferred: [reopened] }));
    assert.equal(result.coverage.completeness, "partial");
    assert.ok(
      result.coverage.deferred.some(
        (row: { candidateId?: string }) => row.candidateId === "review",
      ),
    );
    assert.deepEqual(result.coverage.resolvedDeferred ?? [], []);
    const replay = await f.write(f.draft());
    assert.deepEqual(replay.coverage.deferred, result.coverage.deferred);
    assert.deepEqual(replay.coverage.resolvedDeferred ?? [], []);
  });

  test(`${layout}: interrupted reopening survives later empty progress`, async (t) => {
    const f = await fixture(t, layout);
    const task = { id: "review", ...generic };
    await f.write(f.draft({ deferred: [task] }));
    await f.write(f.draft({ resolvedDeferred: [close(task.id)] }, true));
    await interruptDraftWrite(
      path.join(f.root, layout === "worker" ? "result.json" : "findings.json"),
      () => f.write(f.draft({ deferred: [task] })),
    );
    await f.write(f.draft());
    for (const coverage of [
      await f.read(),
      (await f.write(f.draft({}, true))).coverage,
    ]) {
      assert.equal(coverage.completeness, "partial");
      assert.deepEqual(coverage.deferred, [task]);
      assert.deepEqual(coverage.resolvedDeferred ?? [], []);
    }
  });

  for (const reopened of [false, true]) {
    test(`${layout}: accepted progress remains incomplete after a terminal draft, reopened=${reopened}`, async (t) => {
      const f = await fixture(t, layout);
      const task = { id: "review", ...generic };
      await f.write(f.draft({ deferred: [task] }, true));
      if (reopened)
        await f.write(f.draft({ resolvedDeferred: [close(task.id)] }, true));
      for (const input of [f.draft({ deferred: [task] }), f.draft()]) {
        await f.write(input);
        const published = await readJson(
          f.root,
          layout === "worker" ? "result.json" : "scan-manifest.json",
        );
        assert.equal(
          layout === "worker" ? published.complete : published.scan.complete,
          false,
        );
        if (layout === "worker") {
          const head = await readJson(f.root, "checkpoint-head.json");
          const checkpoint = await readJson(
            f.root,
            "checkpoints",
            head.checkpoint,
          );
          assert.equal(checkpoint.complete, false);
          assert.deepEqual(checkpoint.coverage.deferred, [task]);
        }
      }
      await f.write(f.draft({ resolvedDeferred: [close(task.id)] }, true));
      const finished = await readJson(
        f.root,
        layout === "worker" ? "result.json" : "scan-manifest.json",
      );
      assert.notEqual(
        layout === "worker" ? finished.complete : finished.scan.complete,
        false,
      );
    });
  }

  test(`${layout}: ignored late progress keeps an accepted terminal marker`, async (t) => {
    const f = await fixture(t, layout);
    const terminal = {
      ...f.draft({}, true),
      findings: [findingFor("accepted")],
    };
    await f.write(terminal);
    const checkpointRoot = path.join(f.root, "checkpoints");
    const checkpoints = new Map(
      await Promise.all(
        (await readdir(checkpointRoot)).map(
          async (name) =>
            [
              name,
              await readFile(path.join(checkpointRoot, name), "utf8"),
            ] as const,
        ),
      ),
    );
    await f.write({
      ...f.draft({ deferred: [{ id: "late", ...generic }] }),
      findings: [findingFor("late-finding")],
    });
    for (const [name, contents] of checkpoints)
      assert.equal(
        await readFile(path.join(checkpointRoot, name), "utf8"),
        contents,
      );
    const selected = await readJson(f.root, "checkpoint-head.json");
    const selectedDraft = await readJson(checkpointRoot, selected.checkpoint);
    assert.notEqual(selectedDraft.complete, false);
    assert.deepEqual(selectedDraft.coverage.deferred, []);
    assert.deepEqual(
      selectedDraft.findings.map(
        (row: ReturnType<typeof findingFor>) => row.provenance.candidateId,
      ),
      ["accepted"],
    );
    if (layout !== "worker") {
      await recordCodexSecurityScanDraftViaWorkbench(
        f.context,
        f.draft({ deferred: [{ id: "late", ...generic }] }),
        async (args: string[]) => {
          const checkpoint = JSON.parse(
            await readFile(args[args.indexOf("--checkpoint-path") + 1], "utf8"),
          );
          assert.deepEqual(checkpoint.coverage.deferred, []);
          assert.deepEqual(
            checkpoint.findings.map(
              (row: ReturnType<typeof findingFor>) =>
                row.provenance.candidateId,
            ),
            ["accepted"],
          );
          return { status: "draft_written" };
        },
      );
    }
    const replay = await f.write(terminal);
    assert.equal(replay.findingCount, 1);
    assert.equal(replay.coverage.completeness, "complete");
    const published = await readJson(
      f.root,
      layout === "worker" ? "result.json" : "scan-manifest.json",
    );
    assert.notEqual(
      layout === "worker" ? published.complete : published.scan.complete,
      false,
    );
    assert.deepEqual((await f.read()).deferred, []);
  });

  for (const reverse of [false, true]) {
    test(`${layout}: reject cross-row candidate identity ownership, reverse=${reverse}`, async (t) => {
      const f = await fixture(t, layout);
      const deferred = [
        { id: "candidate-a", ...generic },
        { id: "candidate-task", candidateId: "candidate-a", ...generic },
      ];
      if (reverse) deferred.reverse();
      await assert.rejects(
        f.write(f.draft({ deferred })),
        /coverage\.deferred repeats candidate-a/,
      );
      assert.deepEqual(await readdir(f.root), []);
      await f.write(
        f.draft({
          deferred: [
            { id: "candidate-a", candidateId: "candidate-a", ...generic },
          ],
        }),
      );
      await f.write(
        f.draft(
          {
            surfaces: [
              {
                id: "outcome",
                candidateId: "candidate-a",
                label: "Candidate",
                disposition: "rejected",
              },
            ],
          },
          true,
        ),
      );
      assert.deepEqual((await f.read()).deferred, []);
    });
  }

  for (const together of [false, true]) {
    test(`${layout}: distinct candidate IDs retain separate findings at the same location, together=${together}`, async (t) => {
      const f = await fixture(t, layout);
      if (!together)
        await f.write({ ...f.draft(), findings: [findingFor("candidate-a")] });
      const terminal = {
        ...f.draft({}, true),
        findings: [
          ...(together ? [findingFor("candidate-a")] : []),
          findingFor("candidate-b"),
        ],
      };
      for (let retry = 0; retry < 2; retry++) {
        const result = await f.write(terminal);
        assert.equal(result.findingCount, 2);
        const saved = JSON.parse(
          await readFile(
            path.join(
              f.root,
              layout === "worker" ? "result.json" : "findings.json",
            ),
            "utf8",
          ),
        );
        assert.deepEqual(
          new Set(
            saved.findings.map(
              (row: ReturnType<typeof findingFor>) =>
                row.provenance.candidateId,
            ),
          ),
          new Set(["candidate-a", "candidate-b"]),
        );
        if (layout !== "worker")
          assert.equal(
            new Set(
              saved.findings.map((row: { identity: unknown }) =>
                JSON.stringify(row.identity),
              ),
            ).size,
            2,
          );
      }
    });
  }

  for (const alias of ["id", "candidateId"]) {
    for (const outcome of ["rejected", "reported"]) {
      test(`${layout}: legacy candidate identity collisions retain independent generic work, alias=${alias}, outcome=${outcome}`, async (t) => {
        const f = await fixture(t, layout);
        const surfaceId =
          alias === "candidateId" ? "candidate-a" : "generic-surface";
        const task = {
          id: alias === "candidateId" ? "candidate-a" : "candidate-task",
          ...generic,
          surfaceIds: [surfaceId],
        };
        const other = {
          id: "other-review",
          ...generic,
          surfaceIds: [surfaceId],
        };
        const followUp = {
          id: surfaceId,
          label: "Independent review",
          disposition: "needs_follow_up",
          receiptRefs: [],
        };
        await saveScanDraftCheckpoint(
          f.context,
          f.draft({
            deferred: [
              task,
              { id: "candidate-task", candidateId: "candidate-a", ...generic },
              other,
            ],
            surfaces: [followUp],
          }),
          false,
        );
        for (let attempt = 0; attempt < 2; attempt += 1) {
          const restored = await f.write(f.draft());
          assert.equal(restored.coverage.deferred.length, 3);
          assert.ok(
            restored.coverage.deferred.some(
              (row: Record<string, unknown>) =>
                row.candidateId === "candidate-a",
            ),
          );
          assert.ok(
            restored.coverage.deferred.some((row: Record<string, unknown>) =>
              isDeepStrictEqual(row, task),
            ),
          );
        }
        const terminal = {
          ...f.draft(
            {
              resolvedDeferred: [close(other.id)],
              surfaces: [
                { ...followUp, disposition: "no_issue_found" },
                {
                  id: "outcome",
                  candidateId: "candidate-a",
                  label: "Candidate",
                  disposition: outcome,
                },
              ],
            },
            true,
          ),
          findings: outcome === "reported" ? [findingFor("candidate-a")] : [],
        };
        for (const input of [terminal, f.draft({}, true), f.draft()]) {
          const result = await f.write(input);
          assert.deepEqual(result.coverage.deferred, [task]);
          assert.equal(result.coverage.completeness, "partial");
          assert.equal(result.findingCount, outcome === "reported" ? 1 : 0);
          assert.deepEqual(
            result.coverage.surfaces.filter(
              ({ id }: { id: string }) => id === followUp.id,
            ),
            [followUp],
          );
          if (outcome === "rejected")
            assert.equal(
              result.coverage.surfaces.find(
                ({ id }: { id: string }) => id === "outcome",
              ).disposition,
              outcome,
            );
        }
        await assert.rejects(
          f.write(f.draft({ resolvedDeferred: [close(task.id)] }, true)),
          /ambiguous saved deferred work/,
        );
      });
    }
  }
}

for (const title of [
  ".env exposes state",
  "/admin access check",
  "_debug leaks state",
]) {
  test(`standard: generated identities remain readable for ${title}`, async (t) => {
    const f = await fixture(t, "standard");
    const finding = findingFor("unused");
    Reflect.deleteProperty(finding.provenance, "candidateId");
    finding.title = title;
    const draft = { ...f.draft({}, true), findings: [finding] };
    await f.write(draft);
    const saved = JSON.parse(
      await readFile(path.join(f.root, "findings.json"), "utf8"),
    );
    assert.match(saved.findings[0].identity.anchor, /^[a-z0-9][a-z0-9._/-]*$/);
    assert.equal((await f.write(draft)).findingCount, 1);
  });
}

test("worker: malformed deferred identity remains evidence without poisoning the accepted finding", async (t) => {
  const f = await fixture(t, "worker");
  const previous = {
    ...findingFor("candidate-a"),
    identity: { anchor: ".invalid" },
  };
  await f.write(
    f.draft({
      deferred: [{ candidateId: "candidate-a", ...generic, finding: previous }],
    }),
  );
  await f.write({
    ...f.draft({}, true),
    findings: [findingFor("candidate-a")],
  });
  const saved = JSON.parse(
    await readFile(path.join(f.root, "result.json"), "utf8"),
  );
  assert.equal(draftApi.scanDraftInputSchema.safeParse(saved).success, true);
  assert.deepEqual(saved.findings[0].provenance.previousFindings, [previous]);
  assert.equal(
    (
      await f.write({
        ...f.draft({}, true),
        findings: [findingFor("candidate-a")],
      })
    ).findingCount,
    1,
  );
});

async function recoverPublishedFindings(
  f: Awaited<ReturnType<typeof fixture>>,
  stopped: boolean | "first" = false,
): Promise<
  Array<
    ReturnType<typeof findingFor> & {
      identity: { anchor: string; instance?: string };
    }
  >
> {
  const { stdout } = await execFileAsync(
    process.env.PYTHON?.trim() || "python3",
    [
      "-c",
      `import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from finalize_scan_contract import _recover_unsealed_findings
root=Path(sys.argv[2])
manifest=json.loads((root/"scan-manifest.json").read_text())
findings=json.loads((root/"findings.json").read_text())
if sys.argv[4] != "false":
    from workbench_saved_results import merge_saved_results
    coverage=json.loads((root/"coverage.json").read_text())
    scan=manifest["scan"]
    binding={"status":"interrupted","target":scan["target"],"scope":scan["scope"],"allowedTargetKinds":[scan["target"]["kind"]],"coverageMode":coverage["mode"]}
    first=merge_saved_results(root,sys.argv[3],binding,[],[],stopped=True,reason="stopped")
    replay=merge_saved_results(root,sys.argv[3],binding,[],[],stopped=True,reason="stopped",frozen_source_digests=first[0]["scan"]["preservedSources"])
    manifest,findings,_=replay if sys.argv[4] == "true" else first
manifest["scan"]["id"]=findings["scanId"]=sys.argv[3]
_recover_unsealed_findings(manifest,findings,Path(sys.argv[1]).parent/"schemas",root,[])
print(json.dumps(findings["findings"]))`,
      fileURLToPath(new URL("../../scripts", import.meta.url)),
      f.root,
      f.context.scanId!,
      String(stopped),
    ],
  );
  return JSON.parse(stdout);
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const sequence of ["BA", "BAA", "ABA"]) {
    if (layout === "deep" && sequence !== "BA") continue;
    test(`${layout}: stopped publication and frozen replay retain candidates from ${sequence}`, async (t) => {
      const f = await fixture(t, layout);
      await f.write({
        ...f.draft({}, true),
        findings: [...sequence].map((candidate, index) => ({
          ...findingFor(candidate),
          severity: { level: index === sequence.length - 1 ? "high" : "low" },
        })),
      });
      const { stdout } = await execFileAsync(
        process.env.PYTHON?.trim() || "python3",
        [
          "-c",
          `import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from workbench_saved_results import merge_saved_results
from finalize_scan_contract import _recover_unsealed_findings
root=Path(sys.argv[2])
manifest=json.loads((root/"scan-manifest.json").read_text())
coverage=json.loads((root/"coverage.json").read_text())
scan=manifest["scan"]
binding={"status":"interrupted","target":scan["target"],"scope":scan["scope"],"allowedTargetKinds":[scan["target"]["kind"]],"coverageMode":coverage["mode"]}
first=merge_saved_results(root,sys.argv[3],binding,[],[],stopped=True,reason="stopped")
replay=merge_saved_results(root,sys.argv[3],binding,[],[],stopped=True,reason="stopped",frozen_source_digests=first[0]["scan"]["preservedSources"])
stages=[]
for manifest,findings,_ in [first,replay]:
    manifest["scan"]["id"]=findings["scanId"]=sys.argv[3]
    _recover_unsealed_findings(manifest,findings,Path(sys.argv[1]).parent/"schemas",root,[])
    stages.append({f["provenance"]["candidateId"]:{"severity":f["severity"]["level"],"identity":f["identity"]} for f in findings["findings"]})
    assert len(findings["findings"])==2,findings
print(json.dumps(stages))`,
          fileURLToPath(new URL("../../scripts", import.meta.url)),
          f.root,
          f.context.scanId!,
        ],
      );
      const stages = JSON.parse(stdout);
      assert.deepEqual(stages[0], stages[1]);
      assert.equal(stages[0].A.severity, "high");
      assert.equal(stages[0].B.severity, "low");
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  for (const order of ["AB", "BA"]) {
    test(`${layout}: repeated publication preserves candidate identity aliases in ${order}`, async (t) => {
      const f = await fixture(t, layout);
      const input = {
        ...f.draft({}, true),
        findings: [...order].map(findingFor),
      };
      let expected: unknown;
      for (let publication = 0; publication < 3; publication++) {
        await f.write(input);
        for (const stopped of ["first", true] as const) {
          const findings = await recoverPublishedFindings(f, stopped);
          assert.equal(findings.length, 2);
          const identities = Object.fromEntries(
            findings.map((row) => [row.provenance.candidateId, row.identity]),
          );
          assert.deepEqual(Object.keys(identities).sort(), ["A", "B"]);
          expected ??= identities;
          assert.deepEqual(identities, expected);
        }
      }
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  test(`${layout}: repeated observations of one candidate retain the strongest finding`, async (t) => {
    const f = await fixture(t, layout);
    await f.write({
      ...f.draft({}, true),
      findings: [
        findingFor("candidate-a"),
        { ...findingFor("candidate-a"), severity: { level: "high" } },
      ],
    });
    const findings = await recoverPublishedFindings(f);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity.level, "high");
  });
  for (const sibling of [false, true]) {
    test(`${layout}: a stronger successor reuses retained candidate identity, sibling=${sibling}`, async (t) => {
      const f = await fixture(t, layout);
      await f.write({
        ...f.draft({}, true),
        findings: [
          ...(sibling ? [findingFor("candidate-other")] : []),
          findingFor("candidate-a"),
          { ...findingFor("candidate-a"), severity: { level: "medium" } },
        ],
      });
      const before = await recoverPublishedFindings(f);
      const originalIdentity = before.find(
        (row) => row.provenance.candidateId === "candidate-a",
      )!.identity;
      await f.write({
        ...f.draft({}, true),
        findings: [
          { ...findingFor("candidate-a"), severity: { level: "high" } },
        ],
      });
      const findings = await recoverPublishedFindings(f);
      assert.equal(findings.length, sibling ? 2 : 1);
      const successor = findings.find(
        (row) => row.provenance.candidateId === "candidate-a",
      );
      assert.ok(successor);
      assert.equal(successor.severity.level, "high");
      assert.deepEqual(successor.identity, originalIdentity);
    });
  }
  test(`${layout}: sequential candidates cannot reuse retained sibling identities`, async (t) => {
    const f = await fixture(t, layout);
    const candidates = ["candidate-a", "candidate-b", "candidate-c"];
    for (const candidate of candidates)
      await f.write({
        ...f.draft({}, true),
        findings: [findingFor(candidate)],
      });
    const findings = await recoverPublishedFindings(f);
    assert.equal(findings.length, 3);
    assert.deepEqual(
      new Set(findings.map((row) => row.provenance.candidateId)),
      new Set(candidates),
    );
  });
}

for (const layout of ["standard", "diff"] as const) {
  test(`${layout}: conflicting saved instances do not select the last candidate identity`, async (t) => {
    const f = await fixture(t, layout);
    const first = {
      ...findingFor("candidate-a"),
      identity: { anchor: "synthetic-review-finding", instance: "first" },
    };
    const second = {
      ...findingFor("candidate-a"),
      identity: { anchor: "synthetic-review-finding", instance: "second" },
      summary: "An independent report must remain published.",
    };
    await f.write({
      ...f.draft({}, true),
      findings: [
        first,
        second,
        { ...findingFor("candidate-a"), severity: { level: "high" } },
      ],
    });
    const findings = await recoverPublishedFindings(f);
    assert.ok(findings.some((finding) => finding.summary === second.summary));
    assert.ok(findings.some((finding) => finding.severity.level === "high"));
  });
}

for (const layout of ["standard", "diff"] as const) {
  for (const first of ["none", "candidate", "explicit"]) {
    for (const second of ["none", "candidate", "explicit"]) {
      for (const separate of [false, true]) {
        test(`${layout}: observation metadata ${first}/${second} deduplicates, separate=${separate}`, async (t) => {
          const f = await fixture(t, layout);
          const observations = [first, second].map((metadata, index) => {
            const finding: ReturnType<typeof findingFor> & {
              identity?: { anchor: string; instance?: string };
            } = findingFor("candidate-a");
            if (metadata === "none")
              Reflect.deleteProperty(finding.provenance, "candidateId");
            if (metadata === "explicit")
              finding.identity = {
                anchor: "synthetic-review-finding",
                ...(separate ? {} : { instance: "synthetic-review-finding" }),
              };
            finding.severity.level = index === 0 ? "high" : "low";
            return finding;
          });
          if (separate) {
            for (const finding of observations)
              await f.write({ ...f.draft({}, true), findings: [finding] });
          } else {
            await f.write({ ...f.draft({}, true), findings: observations });
          }
          const findings = await recoverPublishedFindings(f);
          assert.equal(findings.length, 1);
          assert.equal(findings[0].severity.level, separate ? "low" : "high");
        });
      }
    }
  }
}

for (const layout of ["standard", "diff"] as const) {
  test(`${layout}: candidate metadata can follow an identityless weaker observation`, async (t) => {
    const f = await fixture(t, layout);
    const unknown = findingFor("candidate-a");
    Reflect.deleteProperty(unknown.provenance, "candidateId");
    await f.write({
      ...f.draft({}, true),
      findings: [
        unknown,
        { ...findingFor("candidate-a"), severity: { level: "high" } },
      ],
    });
    const findings = await recoverPublishedFindings(f);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity.level, "high");
  });
}

for (const layout of ["standard", "diff"] as const) {
  for (const explicitFirst of [false, true]) {
    test(`${layout}: candidate identity reuse distinguishes locations, explicit first=${explicitFirst}`, async (t) => {
      const f = await fixture(t, layout);
      const generated = findingFor("shared-candidate");
      const explicit = {
        ...findingFor("shared-candidate"),
        identity: { anchor: "synthetic-review-finding", instance: "original" },
        locations: [{ path: "src/independent.py", startLine: 2 }],
      };
      await f.write({
        ...f.draft({}, true),
        findings: explicitFirst ? [explicit, generated] : [generated, explicit],
      });
      const saved = await readJson(f.root, "findings.json");
      for (const findings of [
        saved.findings,
        await recoverPublishedFindings(f),
      ]) {
        assert.equal(findings.length, 2);
        assert.deepEqual(
          findings.find(
            (finding: typeof explicit) =>
              finding.locations[0]!.path === "src/independent.py",
          ).identity,
          explicit.identity,
        );
        assert.notDeepEqual(
          findings.find(
            (finding: typeof generated) =>
              finding.locations[0]!.path === "src/example.py",
          ).identity,
          explicit.identity,
        );
      }
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  for (const equivalent of ["end line", "location order"]) {
    test(`${layout}: candidate identity reuse preserves equivalent ${equivalent}`, async (t) => {
      const f = await fixture(t, layout);
      const generated = findingFor("shared-candidate");
      if (equivalent === "location order")
        generated.locations.push({ path: "src/second.py", startLine: 2 });
      const explicit = {
        ...structuredClone(generated),
        identity: { anchor: "synthetic-review-finding", instance: "original" },
        locations:
          equivalent === "end line"
            ? [{ path: "src/example.py", startLine: 1, endLine: 1 }]
            : [...generated.locations].reverse(),
      };
      await f.write({ ...f.draft({}, true), findings: [generated, explicit] });
      const saved = await readJson(f.root, "findings.json");
      for (const finding of saved.findings)
        assert.deepEqual(finding.identity, explicit.identity);
      const recovered = await recoverPublishedFindings(f);
      assert.equal(recovered.length, 1);
      assert.deepEqual(recovered[0]!.identity, explicit.identity);
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  for (const owners of [
    [undefined, "worker-a"],
    ["worker-a", undefined],
    ["worker-a", "worker-b"],
    ["", "worker-a"],
    ["worker-a", ""],
    ["", ""],
    [undefined, { note: "synthetic metadata" }],
    [{ note: "synthetic metadata" }, undefined],
    [undefined, ["synthetic metadata"]],
    [["synthetic metadata"], undefined],
    ["worker-a", { note: "synthetic metadata" }],
    [["synthetic metadata"], "worker-a"],
  ]) {
    for (const separate of owners.every((owner) => typeof owner === "string")
      ? [false]
      : [false, true]) {
      test(`${layout}: optional worker ownership ${JSON.stringify(owners)} retains candidate identity, separate=${separate}`, async (t) => {
        const f = await fixture(t, layout);
        const observations = owners.map((workerId, index) => ({
          ...findingFor("shared-candidate"),
          severity: { level: index === 0 ? "low" : "high" },
          provenance: {
            ...findingFor("shared-candidate").provenance,
            ...(workerId === undefined ? {} : { workerId }),
          },
        }));
        if (separate) {
          for (const finding of observations)
            await f.write({ ...f.draft({}, true), findings: [finding] });
        } else {
          await f.write({ ...f.draft({}, true), findings: observations });
        }
        for (const stopped of [false, "first", true] as const) {
          const findings = await recoverPublishedFindings(f, stopped);
          const distinct = owners.every(
            (owner) => typeof owner === "string" && owner.length > 0,
          );
          assert.equal(findings.length, distinct ? 2 : 1);
          assert.equal(
            findings.filter((finding) => finding.severity.level === "high")
              .length,
            1,
          );
        }
      });
    }
  }
}

for (const layout of ["standard", "diff"] as const) {
  for (const owners of [
    ["worker-a", undefined, "worker-b"],
    ["worker-b", undefined, "worker-a"],
    [undefined, "worker-a", "worker-b"],
    [undefined, "worker-b", "worker-a"],
    ["worker-a", "worker-b", undefined],
    ["worker-b", "worker-a", undefined],
  ]) {
    test(`${layout}: unknown ownership does not bridge worker identities ${owners.join("/")}`, async (t) => {
      const f = await fixture(t, layout);
      await f.write({
        ...f.draft({}, true),
        findings: owners.map((workerId) => ({
          ...findingFor("shared-candidate"),
          provenance: {
            ...findingFor("shared-candidate").provenance,
            ...(workerId === undefined ? {} : { workerId }),
          },
        })),
      });
      const saved = await readJson(f.root, "findings.json");
      const identities = new Map(
        saved.findings.map(
          (finding: {
            provenance: { workerId?: string };
            identity: { anchor: string; instance?: string };
          }) => [finding.provenance.workerId, finding.identity],
        ),
      );
      assert.notDeepEqual(
        identities.get("worker-a"),
        identities.get("worker-b"),
      );
      assert.notDeepEqual(
        identities.get(undefined),
        identities.get("worker-a"),
      );
      assert.notDeepEqual(
        identities.get(undefined),
        identities.get("worker-b"),
      );
      for (const stopped of [false, "first", true] as const) {
        const findings = await recoverPublishedFindings(f, stopped);
        assert.equal(findings.length, 3);
        assert.deepEqual(
          new Set(
            findings.map((finding) =>
              Reflect.get(finding.provenance, "workerId"),
            ),
          ),
          new Set(owners),
        );
      }
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  for (const workerId of [
    { note: "synthetic metadata" },
    ["synthetic metadata"],
  ]) {
    test(`${layout}: structured metadata matches equivalent unowned finding, array=${Array.isArray(workerId)}`, async (t) => {
      const f = await fixture(t, layout);
      const stronger = {
        ...findingFor("shared-candidate"),
        severity: { level: "high" },
        provenance: {
          ...findingFor("shared-candidate").provenance,
          workerId,
        },
      };
      await f.write({
        ...f.draft({}, true),
        findings: [findingFor("shared-candidate"), stronger],
      });
      for (const stopped of [false, "first", true] as const) {
        const findings = await recoverPublishedFindings(f, stopped);
        assert.equal(findings.length, 1);
        assert.equal(findings[0]!.severity.level, "high");
        assert.deepEqual(
          Reflect.get(findings[0]!.provenance, "workerId"),
          workerId,
        );
      }
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  for (const workerId of [
    { note: "synthetic metadata" },
    ["synthetic metadata"],
  ]) {
    for (const history of [false, true]) {
      test(`${layout}: structured worker metadata remains recoverable, array=${Array.isArray(workerId)}, history=${history}`, async (t) => {
        const f = await fixture(t, layout);
        const original = {
          ...findingFor("shared-candidate"),
          provenance: {
            ...findingFor("shared-candidate").provenance,
            workerId,
          },
        };
        const finding = history
          ? {
              ...findingFor("shared-candidate"),
              severity: { level: "high" },
              provenance: {
                ...findingFor("shared-candidate").provenance,
                previousFindings: [original],
              },
            }
          : original;
        await f.write({ ...f.draft({}, true), findings: [finding] });
        for (const stopped of [false, "first", true] as const) {
          const findings = await recoverPublishedFindings(f, stopped);
          assert.equal(findings.length, 1);
          const retained = history
            ? Reflect.get(findings[0]!.provenance, "previousFindings")[0]
            : findings[0];
          assert.deepEqual(retained.provenance.workerId, workerId);
        }
      });
    }
  }
}

for (const [layout, history] of [
  ["deep", "empty"],
  ["deep", "outstanding"],
  ["deep", "tied"],
  ["standard", "empty"],
] as const) {
  test(`${layout}: retained terminal history stays ordered after ${history} progress`, async (t) => {
    const f = await fixture(t, layout);
    const stale = {
      id: "old-work",
      reason: "Earlier review",
      surfaceIds: ["old-surface"],
    };
    const surface = {
      id: "old-surface",
      label: "Earlier surface",
      disposition: "needs_follow_up",
      reason: "Review pending",
      receiptRefs: [],
    };
    await f.write({
      ...f.draft({ deferred: [stale], surfaces: [surface] }),
      findings: [findingFor("old-finding")],
    });
    const checkpointRoot = path.join(f.root, "checkpoints");
    const oldCheckpoints = new Set(await readdir(checkpointRoot));
    const current = { id: "new-work", reason: "Current review" };
    const pending = history === "outstanding" ? [current] : [];
    await f.write(f.draft({ deferred: pending }, true));
    const terminal = await f.read();
    assert.deepEqual(terminal.deferred, layout === "deep" ? pending : [stale]);
    const oldContents = new Map<string, string>();
    for (const name of await readdir(checkpointRoot)) {
      const filename = path.join(checkpointRoot, name);
      const old = oldCheckpoints.has(name);
      const time = old && history !== "tied" ? 100 : 200;
      await utimes(filename, time, time);
      if (old) oldContents.set(name, await readFile(filename, "utf8"));
    }
    for (const name of [
      "findings.json",
      "coverage.json",
      "scan-manifest.json",
      "checkpoint-head.json",
    ])
      await utimes(path.join(f.root, name), 200, 200);
    const result = await f.write({
      ...f.draft(),
      findings:
        history === "outstanding" ? [findingFor("current-finding")] : [],
    });
    const retainsOld = layout === "standard" || history === "tied";
    const expectedDeferred = retainsOld ? [stale] : pending;
    assert.deepEqual(result.coverage.deferred, expectedDeferred);
    assert.deepEqual(result.coverage.surfaces, retainsOld ? [surface] : []);
    assert.equal(
      result.coverage.completeness,
      expectedDeferred.length ? "partial" : "complete",
    );
    assert.deepEqual(await f.read(), result.coverage);
    const findings = await readJson(f.root, "findings.json");
    assert.deepEqual(
      findings.findings
        .map((row: ReturnType<typeof findingFor>) => row.provenance.candidateId)
        .sort(),
      history === "outstanding"
        ? ["current-finding"]
        : retainsOld
          ? ["old-finding"]
          : [],
    );
    const manifest = await readJson(f.root, "scan-manifest.json");
    if (layout === "deep" && history === "empty")
      assert.notEqual(manifest.scan.complete, false);
    for (const [name, contents] of oldContents)
      assert.equal(
        await readFile(path.join(checkpointRoot, name), "utf8"),
        contents,
      );
  });
}

for (const layout of ["worker", "standard"] as const) {
  for (const duplicate of [false, true]) {
    test(`${layout}: legacy surfaces survive interrupted terminal recovery, duplicate=${duplicate}`, async (t) => {
      const f = await fixture(t, layout);
      const surfaces = [
        {
          id: "legacy-shared",
          label: "First legacy surface",
          disposition: "needs_follow_up",
          receiptRefs: [],
        },
        {
          id: duplicate ? "legacy-shared" : "legacy-second",
          label: "Second legacy surface",
          disposition: "needs_follow_up",
          receiptRefs: [],
        },
      ];
      // Older writers accepted distinct observations with the same explicit ID.
      await saveScanDraftCheckpoint(
        f.context,
        f.draft({
          surfaces,
          deferred: [
            { id: "review", ...generic, surfaceIds: ["legacy-shared"] },
          ],
        }),
      );
      // The terminal checkpoint is durable before reconciled output publication.
      await saveScanDraftCheckpoint(
        f.context,
        f.draft({ resolvedDeferred: [close("review")] }, true),
        false,
      );
      const result = await f.write(f.draft());
      assert.equal(result.surfaceCount, 2);
      assert.deepEqual(
        result.coverage.surfaces
          .map((surface: { label: string }) => surface.label)
          .sort(),
        surfaces.map((surface) => surface.label).sort(),
      );
      assert.equal(
        new Set(
          result.coverage.surfaces.map((surface: { id: string }) => surface.id),
        ).size,
        2,
      );
      assert.deepEqual((await f.read()).surfaces, result.coverage.surfaces);
      assert.deepEqual(
        (await f.write(f.draft())).coverage.surfaces,
        result.coverage.surfaces,
      );
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  for (const firstInstance of ["first", "synthetic-review-finding"]) {
    test(`${layout}: repeated raw observations retain one identity beside explicit siblings, instance=${firstInstance}`, async (t) => {
      const f = await fixture(t, layout);
      const finding = findingFor("candidate-shared-observation");
      const explicit = [firstInstance, "second"].map((instance) => ({
        ...finding,
        identity: { anchor: "synthetic-review-finding", instance },
      }));
      const draft = {
        ...f.draft(),
        findings: [...explicit, finding, structuredClone(finding)],
      };
      await f.write(draft);
      const rows = (await readJson(f.root, "findings.json")).findings as {
        identity: { anchor: string; instance?: string };
      }[];
      assert.equal(rows.length, 4);
      assert.deepEqual(
        rows.slice(0, 2).map((row) => row.identity),
        explicit.map((row) => row.identity),
      );
      assert.deepEqual(rows[2]!.identity, rows[3]!.identity);
      assert.equal(
        new Set(rows.map((row) => JSON.stringify(row.identity))).size,
        3,
      );
      await f.write(draft);
      assert.deepEqual(
        (await readJson(f.root, "findings.json")).findings.map(
          (row: { identity: unknown }) => row.identity,
        ),
        rows.map((row) => row.identity),
      );
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  for (const firstInstance of ["first", "synthetic-review-finding"]) {
    for (const unequal of [false, true]) {
      test(`${layout}: stronger raw replay keeps generated identity beside explicit siblings, instance=${firstInstance}, unequal=${unequal}`, async (t) => {
        const f = await fixture(t, layout);
        const finding = findingFor("candidate-shared-observation");
        const explicit = [firstInstance, "second"].map((instance) => ({
          ...finding,
          identity: { anchor: "synthetic-review-finding", instance },
        }));
        const draft = {
          ...f.draft(),
          findings: [...explicit, finding, structuredClone(finding)],
        };
        await f.write(draft);
        const before = (await readJson(f.root, "findings.json")).findings as {
          identity: { anchor: string; instance?: string };
        }[];
        const stronger = {
          ...draft,
          findings: [
            ...explicit,
            { ...finding, severity: { level: "high" } },
            { ...finding, severity: { level: unequal ? "critical" : "high" } },
          ],
        };
        await f.write(stronger);
        const replay = (await readJson(f.root, "findings.json")).findings as {
          identity: { anchor: string; instance?: string };
        }[];
        assert.equal(replay.length, 4, JSON.stringify({ before, replay }));
        assert.deepEqual(
          replay.map((row) => row.identity),
          before.map((row) => row.identity),
        );
        const recovered = await recoverPublishedFindings(f);
        assert.equal(recovered.length, 3);
        const generated = recovered.find(
          (row) =>
            JSON.stringify(row.identity) ===
            JSON.stringify(before[2]!.identity),
        );
        assert.equal(generated?.severity.level, unequal ? "critical" : "high");
        await f.write(stronger);
        assert.deepEqual(
          (await readJson(f.root, "findings.json")).findings.map(
            (row: { identity: unknown }) => row.identity,
          ),
          before.map((row) => row.identity),
        );
      });
    }
  }
}

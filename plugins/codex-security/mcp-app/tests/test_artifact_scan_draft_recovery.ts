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
import { isDeepStrictEqual, promisify } from "node:util";
import {
  draftApi,
  saveScanDraftCheckpoint,
  fixture,
  interruptDraftWrite,
  surfaceDisposition,
} from "./scan-draft-recovery-fixture.ts";

const { recordCodexSecurityScanDraftViaWorkbench } = draftApi;
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

for (const layout of ["standard", "diff"] as const) {
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
      (await readdir(checkpointRoot))
        .filter((name) => name.endsWith(".json"))
        .map(async (name) => [
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
      for (const name of (await readdir(checkpoints)).filter((name) =>
        name.endsWith(".json"),
      )) {
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
      const before = new Set(
        (await readdir(checkpoints)).filter((name) => name.endsWith(".json")),
      );
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
      for (const name of (await readdir(checkpoints)).filter((name) =>
        name.endsWith(".json"),
      )) {
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
      for (const name of (await readdir(checkpointRoot)).filter((name) =>
        name.endsWith(".json"),
      )) {
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

for (const layout of ["standard", "diff"] as const) {
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
      for (const name of (
        await readdir(path.join(f.root, "checkpoints"))
      ).filter((name) => name.endsWith(".json"))) {
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
      for (const name of (
        await readdir(path.join(f.root, "checkpoints"))
      ).filter((name) => name.endsWith(".json"))) {
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

for (const layout of ["standard", "diff"] as const) {
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
    await f.write(f.draft({}, true));
    await f.write(f.draft({ deferred: [{ id: "late", ...generic }] }));
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

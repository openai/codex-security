import assert from "node:assert/strict";
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
import {
  draftApi,
  fixture,
  interruptDraftWrite,
} from "./scan-draft-fixture.mjs";

const { recordCodexSecurityScanDraftViaWorkbench, saveScanDraftCheckpoint } =
  draftApi;
const generic = { reason: "Review remains.", paths: ["src/example.py"] };
const close = (id, reason = "Review completed.") => ({ id, reason });

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
      ruleId: "fixture.review",
      title: "Synthetic review finding",
      summary: "A separate review result must survive progress publication.",
      severity: { level: "low" },
      confidence: {
        level: "high",
        rationale: "Synthetic persistence fixture.",
      },
      taxonomy: { category: "other", cwe: [] },
      locations: [{ path: "src/example.py", startLine: 1 }],
      remediation: "Complete the independent review.",
      provenance: { source: "local_plugin", candidateId: "new-finding" },
    };
    const surfaces = [
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
      assert.deepEqual(result.coverage.surfaces, surfaces);
      const published = JSON.parse(
        await readFile(path.join(f.root, "result.json"), "utf8"),
      );
      assert.deepEqual(published.findings, [finding]);
      const head = JSON.parse(
        await readFile(path.join(f.root, "checkpoint-head.json"), "utf8"),
      );
      assert.deepEqual(
        JSON.parse(
          await readFile(
            path.join(f.root, "checkpoints", head.checkpoint),
            "utf8",
          ),
        ),
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
    const nextProgress = {
      ...f.draft({ deferred: [nextTask], surfaces: [nextSurface] }),
      findings: [nextFinding],
    };
    for (const input of [nextProgress, f.draft()]) {
      const result = await f.write(input);
      assert.equal(result.findingCount, 2);
      assert.equal(result.coverage.completeness, "partial");
      assert.deepEqual(
        new Set(result.coverage.deferred.map(({ id }) => id)),
        new Set([reopened.id, independent.id, nextTask.id]),
      );
      assert.deepEqual(result.coverage.resolvedDeferred, [
        close(stillClosed.id),
      ]);
      assert.deepEqual(
        new Set(result.coverage.surfaces.map(({ id }) => id)),
        new Set([...surfaces, nextSurface].map(({ id }) => id)),
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
        ruleId: "fixture.accepted-review",
        title: "Accepted review finding",
        summary: "A completed candidate outcome remains authoritative.",
        severity: { level: "low" },
        confidence: {
          level: "high",
          rationale: "Synthetic persistence fixture.",
        },
        taxonomy: { category: "other", cwe: [] },
        locations: [{ path: "src/example.py", startLine: 1 }],
        remediation: "Complete the independent review.",
        provenance: { source: "local_plugin", candidateId },
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
          result.coverage.surfaces.map(({ id, disposition }) => ({
            id,
            disposition,
          })),
          surfaceLink === "none"
            ? []
            : [{ id: surface.id, disposition: outcome }],
        );
        if (outcome === "rejected") {
          assert.deepEqual(result.coverage.surfaces[0].candidate, candidate);
        } else {
          const saved = JSON.parse(
            await readFile(path.join(f.root, "result.json"), "utf8"),
          );
          assert.deepEqual(saved.findings[0].provenance.originalCandidates, [
            candidate,
          ]);
        }
      }
    });
  }
}

for (const layout of ["standard", "diff", "worker"]) {
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

  for (const payload of ["candidate", "finding"]) {
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
        saved.surfaces.find((row) => row.candidateId === pending.candidateId)[
          payload
        ],
        pending[payload],
      );
    });
  }

  for (const payload of ["generic", "candidate", "finding"]) {
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
        saved.deferred.find((row) => row.id === named.id),
        named,
      );
      const independent = saved.deferred.find((row) => row.id !== named.id);
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
        saved.surfaces.find((row) => row.id === other.id),
        other,
      );
      assert.equal(saved.completeness, "partial");
      assert.deepEqual(
        saved.surfaces.find((row) => row.id === surface.id),
        submittedId === surface.id
          ? { ...surface, disposition: "no_issue_found" }
          : surface,
      );
    });
  }

  for (const payload of ["generic", "candidate"]) {
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
        receiptRefs: [],
      };
      await f.write(
        f.draft({ surfaces: [surface], deferred: [first, remaining] }),
      );
      const closure = close(first.id);
      for (const resolvedDeferred of [[closure], [closure], undefined]) {
        await f.write(
          f.draft({ ...(resolvedDeferred ? { resolvedDeferred } : {}) }, true),
        );
        const saved = await f.read();
        assert.equal(saved.completeness, "partial");
        assert.deepEqual(saved.deferred, [remaining]);
        assert.deepEqual(saved.resolvedDeferred, [closure]);
        assert.deepEqual(saved.surfaces, [surface]);
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
        const row = JSON.parse(await readFile(file, "utf8"));
        const time = row.coverage.resolvedDeferred?.length ? 2 : 1;
        await utimes(file, time, time);
      }
      for (const name of layout === "worker"
        ? ["result.json", "checkpoint-head.json"]
        : ["coverage.json", "scan-manifest.json", "findings.json"])
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
      const pending = { id: "review", ...generic };
      const closing = f.draft({ resolvedDeferred: [close(pending.id)] }, true);
      const fail = (input) =>
        interruptDraftWrite(path.join(f.root, destination), () =>
          f.write(input),
        );
      await f.write(f.draft({ deferred: [pending] }));
      await fail(closing);
      await f.write(f.draft({}, true));
      assert.deepEqual((await f.read()).deferred, []);
      assert.deepEqual((await f.read()).resolvedDeferred, [close(pending.id)]);
      const checkpointRoot = path.join(f.root, "checkpoints");
      const originalClosures = [];
      for (const name of await readdir(checkpointRoot)) {
        const file = path.join(checkpointRoot, name);
        const saved = JSON.parse(await readFile(file, "utf8"));
        if (saved.coverage.resolvedDeferred?.length)
          originalClosures.push([file, (await stat(file)).mtimeMs]);
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
      for (const [file, modified] of originalClosures)
        assert.equal((await stat(file)).mtimeMs, modified);
      await f.write(f.draft({}, true));
      const accepted =
        destination === "result.json" || destination === "scan-manifest.json";
      assert.deepEqual((await f.read()).deferred, accepted ? [] : [reopened]);
      await f.write(closing);
      await f.write(f.draft({}, true));
      assert.deepEqual((await f.read()).deferred, []);
      assert.deepEqual((await f.read()).resolvedDeferred, [close(pending.id)]);
    });
  }
}

for (const layout of ["standard", "diff"]) {
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
        async (args) => {
          const checkpoint = JSON.parse(
            await readFile(args[args.indexOf("--checkpoint-path") + 1], "utf8"),
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

for (const layout of ["standard", "diff", "worker"]) {
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
        const checkpoint = JSON.parse(
          await readFile(path.join(f.root, "checkpoints", name), "utf8"),
        );
        assert.equal(checkpoint.coverage.surfaces[0].id, surface.id);
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
    initial.coverage.surfaces.map(({ id }) => id),
    ["api", "api-3", "api-2"],
  );
  assert.deepEqual(
    (await f.write(f.draft({ surfaces: rows }))).coverage.surfaces,
    initial.coverage.surfaces,
  );
  const updated = initial.coverage.surfaces.map((row) =>
    row.id === "api-3" ? { ...row, disposition: "no_issue_found" } : row,
  );
  const saved = await f.write(f.draft({ surfaces: updated }));
  assert.equal(saved.coverage.surfaces.length, 3);
  assert.equal(
    saved.coverage.surfaces.find(({ id }) => id === "api").disposition,
    "needs_follow_up",
  );
  assert.equal(
    saved.coverage.surfaces.find(({ id }) => id === "api-3").disposition,
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
  const ids = initial.coverage.surfaces.map(({ id }) => id);
  assert.ok(ids.every((id) => typeof id === "string"));
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
      (row) => row.id === ids[0] && row.notes === first.notes,
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
  assert.equal(new Set(saved.map(({ id }) => id)).size, 4);
  assert.equal(saved[2].id, ids[0]);
  assert.equal(saved[3].candidateId, ids[1]);
  assert.notEqual(saved[0].id, ids[0]);
  assert.notEqual(saved[3].id, ids[1]);
  for (const input of [other.draft({ surfaces: [saved[3]] }), other.draft()]) {
    const retained = (await other.write(input)).coverage.surfaces;
    assert.equal(retained.length, saved.length);
    assert.deepEqual(
      retained.find((row) => row.notes === second.notes),
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

for (const layout of ["standard", "diff"]) {
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
        const value = JSON.parse(await readFile(file, "utf8"));
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
      await writeFile(head, JSON.stringify({ checkpoint: selected }));
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

for (const payload of ["generic", "candidate"]) {
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
  test(`worker: retain a valid ${complete ? "terminal" : "progress"} draft before reading a malformed result`, async (t) => {
    const f = await fixture(t, "worker");
    const destination = path.join(f.root, "result.json");
    await writeFile(destination, "{broken");
    const submitted = f.draft(
      { deferred: [{ id: "pending", ...generic }] },
      complete,
    );
    await assert.rejects(f.write(submitted), /stored JSON is malformed/);
    const files = await readdir(path.join(f.root, "checkpoints"));
    assert.equal(files.length, 1);
    assert.deepEqual(
      JSON.parse(
        await readFile(path.join(f.root, "checkpoints", files[0]), "utf8"),
      ),
      submitted,
    );
    await rm(destination);
    await f.write(f.draft({}, true));
    assert.deepEqual((await f.read()).deferred, submitted.coverage.deferred);
  });
}

for (const malformed of [false, true]) {
  test(`worker: reject an unknown closure without a checkpoint, malformed result=${malformed}`, async (t) => {
    const f = await fixture(t, "worker");
    if (malformed) await writeFile(path.join(f.root, "result.json"), "{broken");
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
      malformed
        ? /stored JSON is malformed/
        : /names no saved generic deferral/,
    );
    assert.deepEqual(await readdir(f.root), malformed ? ["result.json"] : []);
  });
}

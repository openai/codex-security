import assert from "node:assert/strict";
import {
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { build } from "esbuild";

const bundled = await build({
  absWorkingDir: path.dirname(new URL(import.meta.url).pathname),
  bundle: true,
  entryPoints: ["../src/artifact-scan-draft.ts"],
  format: "esm",
  platform: "node",
  write: false,
});
const {
  recordCodexSecurityScanDraft,
  recordCodexSecurityWorkerScanDraft,
  saveScanDraftCheckpoint,
} = await import(
  `data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].text).toString("base64")}`
);

const scanId = "7b95abf2-dc04-47a9-9950-53b5c2057f49";
const claimToken = "19bfba38-0913-4bd7-86ef-134e9a4d9a42";
const generic = { reason: "Review remains.", paths: ["src/example.py"] };

async function fixture(t, layout) {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "draft-recovery-")),
  );
  t.after(() => rm(root, { recursive: true, force: true }));
  const context = {
    root,
    repoRoot: root,
    scanId,
    layout: layout === "worker" ? "worker" : "scan",
    mode: layout,
    scope: ".",
    status: "running",
    handoffClaimToken: claimToken,
    targetRevision: "1234567890abcdef",
    targetContract: {
      target: {
        allowedKinds: [layout === "diff" ? "git_diff" : "git_worktree"],
        targetId: "target_example",
        displayName: "example",
        requiredSnapshotDigest:
          "codex-security-snapshot/v1:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] },
      diffTarget:
        layout === "diff"
          ? {
              kind: "range",
              baseRevision: "a".repeat(40),
              headRevision: "b".repeat(40),
            }
          : null,
    },
  };
  const draft = (coverage = {}, complete = false) => ({
    scanId,
    ...(layout === "worker" ? {} : { handoffClaimToken: claimToken }),
    complete,
    findings: [],
    coverage: {
      completeness:
        complete && !coverage.deferred?.length ? "complete" : "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
      ...coverage,
    },
  });
  return {
    root,
    context,
    draft,
    write: (input) =>
      layout === "worker"
        ? recordCodexSecurityWorkerScanDraft(context, input)
        : recordCodexSecurityScanDraft(context, input),
    read: async () => {
      const value = JSON.parse(
        await readFile(
          path.join(
            root,
            layout === "worker" ? "result.json" : "coverage.json",
          ),
          "utf8",
        ),
      );
      return layout === "worker" ? value.coverage : value;
    },
  };
}

for (const layout of ["standard", "diff", "worker"]) {
  for (const payload of ["candidate", "finding"]) {
    for (const sameCall of [false, true]) {
      test(`${layout}: generic work survives ${payload} rejection, same call=${sameCall}`, async (t) => {
        const f = await fixture(t, layout);
        const shared = { ...generic, surfaceIds: ["entry"] };
        const candidate = {
          ...shared,
          notes: "Candidate review.",
          [payload]: { title: "Caller validation." },
        };
        const pending = { ...shared, notes: "Independent source review." };
        await f.write(f.draft({ deferred: [candidate] }));
        const savedCandidate = (await f.read()).deferred[0];
        const rejection = {
          id: "candidate-result",
          candidateId: savedCandidate.id,
          label: "Caller",
          disposition: "rejected",
        };
        let savedGeneric;
        if (!sameCall) {
          await f.write(f.draft({ deferred: [pending] }));
          const rows = (await f.read()).deferred;
          assert.equal(rows.length, 2);
          assert.deepEqual(
            rows.find((row) => row.id === savedCandidate.id),
            savedCandidate,
          );
          savedGeneric = rows.find((row) => row.notes === pending.notes);
          assert.notEqual(savedGeneric.id, savedCandidate.id);
          assert.deepEqual(savedGeneric, { ...pending, id: savedGeneric.id });
        }
        await f.write(
          f.draft(
            {
              deferred: sameCall ? [pending] : [],
              surfaces: [rejection],
            },
            true,
          ),
        );
        const rejected = await f.read();
        assert.equal(rejected.deferred.length, 1);
        savedGeneric ??= rejected.deferred[0];
        assert.notEqual(savedGeneric.id, savedCandidate.id);
        assert.deepEqual(rejected.deferred, [
          { ...pending, id: savedGeneric.id },
        ]);
        assert.deepEqual(
          rejected.surfaces.find(
            (row) => row.candidateId === savedCandidate.id,
          )[payload],
          candidate[payload],
        );
        for (let attempt = 0; attempt < 2; attempt += 1) {
          await f.write(f.draft({}, true));
          const saved = await f.read();
          assert.equal(saved.completeness, "partial");
          assert.deepEqual(saved.deferred, [savedGeneric]);
        }
        await f.write(
          f.draft(
            {
              resolvedDeferred: [
                {
                  id: savedGeneric.id,
                  reason: "Independent review completed.",
                },
              ],
            },
            true,
          ),
        );
        const completed = await f.read();
        assert.deepEqual(completed.deferred, []);
        assert.equal(completed.completeness, "complete");
        assert.deepEqual(
          completed.surfaces.find(
            (row) => row.candidateId === savedCandidate.id,
          )[payload],
          candidate[payload],
        );
      });
    }

    for (const submitted of ["omitted", "raw", "identified"]) {
      test(`${layout}: close generic work beside a saved ${payload}, ${submitted}`, async (t) => {
        const f = await fixture(t, layout);
        const pending = {
          ...generic,
          [payload]: { title: "Pending caller review." },
        };
        await f.write(f.draft({ deferred: [generic] }));
        const savedGeneric = (await f.read()).deferred[0];
        await f.write(f.draft({ deferred: [pending] }));
        const savedCandidate = (await f.read()).deferred.find(
          (row) => payload in row,
        );
        assert.notEqual(savedCandidate.id, savedGeneric.id);
        const resolvedDeferred = [
          { id: savedGeneric.id, reason: "Generic review completed." },
        ];
        await f.write(
          f.draft(
            {
              deferred:
                submitted === "omitted"
                  ? []
                  : [submitted === "raw" ? pending : savedCandidate],
              resolvedDeferred,
            },
            true,
          ),
        );
        for (let attempt = 0; attempt < 3; attempt += 1) {
          const saved = await f.read();
          assert.equal(saved.completeness, "partial");
          assert.deepEqual(saved.deferred, [savedCandidate]);
          assert.deepEqual(saved.resolvedDeferred, resolvedDeferred);
          await f.write(f.draft({}, true));
        }
      });
    }
  }

  test(`${layout}: changed generic evidence reopens its saved identity`, async (t) => {
    const f = await fixture(t, layout);
    await f.write(
      f.draft({ deferred: [{ ...generic, notes: "Initial caller review." }] }),
    );
    const saved = (await f.read()).deferred[0];
    await f.write(
      f.draft(
        {
          resolvedDeferred: [
            { id: saved.id, reason: "Original callers reviewed." },
          ],
        },
        true,
      ),
    );
    await f.write(
      f.draft({
        deferred: [{ ...generic, notes: "A new caller needs review." }],
      }),
    );
    const reopened = await f.read();
    assert.equal(reopened.completeness, "partial");
    assert.deepEqual(reopened.deferred, [
      { ...generic, notes: "A new caller needs review.", id: saved.id },
    ]);
    assert.equal(reopened.resolvedDeferred, undefined);
  });

  test(`${layout}: unmatched candidate evidence survives an unrelated generic closure`, async (t) => {
    const f = await fixture(t, layout);
    await f.write(f.draft({ deferred: [generic] }));
    const saved = (await f.read()).deferred[0];
    const pending = ["First caller", "Second caller"].map((title) => ({
      ...generic,
      candidate: { title },
    }));
    for (const row of pending)
      await saveScanDraftCheckpoint(
        f.context,
        f.draft({ deferred: [row] }),
        false,
      );
    const resolvedDeferred = [
      { id: saved.id, reason: "Generic review completed." },
    ];
    await f.write(f.draft({ resolvedDeferred }, true));
    const recovered = await f.read();
    assert.equal(recovered.deferred.length, 2);
    assert.equal(new Set(recovered.deferred.map((row) => row.id)).size, 2);
    assert.equal(
      recovered.deferred.some((row) => row.id === saved.id),
      false,
    );
    assert.deepEqual(
      recovered.deferred.map((row) => row.candidate.title).sort(),
      pending.map((row) => row.candidate.title).sort(),
    );
    await f.write(f.draft({}, true));
    assert.deepEqual((await f.read()).deferred, recovered.deferred);
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

for (const layout of ["standard", "diff", "worker"]) {
  for (const explicit of [false, true]) {
    test(`${layout}: split generic work closes independently, explicit sibling=${explicit}`, async (t) => {
      const f = await fixture(t, layout);
      const broad = {
        reason: "Review callers.",
        paths: ["src/a.ts", "src/b.ts"],
      };
      await f.write(f.draft({ deferred: [broad] }));
      const original = (await f.read()).deferred[0];
      const split = broad.paths.map((file, index) => ({
        reason: broad.reason,
        paths: [file],
        ...(explicit && index === 0 ? { id: original.id } : {}),
      }));
      await f.write(f.draft({ deferred: split }));
      const saved = (await f.read()).deferred;
      const narrow = split.map((row) =>
        saved.find(
          (item) => item.paths.length === 1 && item.paths[0] === row.paths[0],
        ),
      );
      assert.equal(new Set(narrow.map((row) => row.id)).size, 2);
      if (explicit) assert.equal(narrow[0].id, original.id);
      else {
        assert.ok(narrow.every((row) => row.id !== original.id));
        assert.ok(
          saved.some((row) => row.id === original.id && row.paths.length === 2),
        );
      }
      await f.write(
        f.draft(
          {
            deferred: [narrow[1]],
            resolvedDeferred: [
              { id: narrow[0].id, reason: "First caller reviewed." },
            ],
          },
          true,
        ),
      );
      for (let attempt = 0; attempt < 2; attempt += 1) {
        const retained = (await f.read()).deferred;
        assert.ok(retained.some((row) => row.id === narrow[1].id));
        assert.ok(retained.every((row) => row.id !== narrow[0].id));
        if (!explicit)
          assert.ok(retained.some((row) => row.id === original.id));
        await f.write(f.draft({}, true));
      }
    });
  }

  for (const payload of ["candidate", "finding"]) {
    test(`${layout}: split ${payload} evidence survives the broad rejection`, async (t) => {
      const f = await fixture(t, layout);
      const broad = {
        reason: "Review callers.",
        paths: ["src/a.ts", "src/b.ts"],
        [payload]: { title: "Caller validation." },
      };
      await f.write(f.draft({ deferred: [broad] }));
      const original = (await f.read()).deferred[0];
      const split = broad.paths.map((file) => ({ ...broad, paths: [file] }));
      await f.write(f.draft({ deferred: split }));
      const narrow = (await f.read()).deferred.filter(
        (row) => row.paths.length === 1,
      );
      assert.equal(narrow.length, 2);
      assert.equal(new Set(narrow.map((row) => row.id)).size, 2);
      assert.ok(narrow.every((row) => row.id !== original.id));
      const reject = (id) => ({
        candidateId: id,
        label: "Caller review",
        disposition: "rejected",
      });
      await f.write(f.draft({ surfaces: [reject(original.id)] }, true));
      assert.deepEqual((await f.read()).deferred, narrow);
      await f.write(f.draft({ surfaces: [reject(narrow[0].id)] }, true));
      for (let attempt = 0; attempt < 2; attempt += 1) {
        assert.deepEqual((await f.read()).deferred, [narrow[1]]);
        await f.write(f.draft({}, true));
      }
    });
  }

  for (const payload of ["generic", "candidate", "finding"]) {
    test(`${layout}: duplicate ${payload} observations retain their saved identity`, async (t) => {
      const f = await fixture(t, layout);
      const row = {
        ...generic,
        ...(payload === "generic"
          ? {}
          : { [payload]: { title: "Caller validation." } }),
      };
      const reordered = Object.fromEntries(Object.entries(row).reverse());
      await f.write(f.draft({ deferred: [row] }));
      const original = (await f.read()).deferred[0];
      await f.write(f.draft({ deferred: [row, reordered] }));
      assert.ok(
        (await f.read()).deferred.every((item) => item.id === original.id),
      );
      await f.write(f.draft({ deferred: [original, reordered] }));
      assert.ok(
        (await f.read()).deferred.every((item) => item.id === original.id),
      );
    });
  }
}

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

for (const layout of ["standard", "diff", "worker"]) {
  for (const payload of ["generic", "candidate", "finding"]) {
    test(`${layout}: interrupted raw ${payload} retains its saved ID through closeout`, async (t) => {
      const f = await fixture(t, layout);
      const row = {
        ...generic,
        ...(payload === "generic"
          ? {}
          : { [payload]: { title: "Caller validation." } }),
      };
      const named = {
        id: "caller-review",
        ...(payload === "generic" ? {} : { candidateId: "candidate-review" }),
        ...row,
        paths: [...row.paths, "src/alternate.py"],
        notes: "Both callers still need review.",
        ...(payload === "generic"
          ? {}
          : {
              [payload]: { ...row[payload], evidence: "Inspect both callers." },
            }),
      };
      await f.write(f.draft({ deferred: [named] }));
      for (const name of await readdir(path.join(f.root, "checkpoints")))
        await utimes(path.join(f.root, "checkpoints", name), 1, 1);
      for (const name of layout === "worker"
        ? ["result.json", "checkpoint-head.json"]
        : ["coverage.json", "findings.json", "scan-manifest.json"])
        await utimes(path.join(f.root, name), 1, 1);
      await saveScanDraftCheckpoint(
        f.context,
        f.draft({ deferred: [row] }),
        false,
      );
      await f.write(f.draft({}, true));
      assert.deepEqual((await f.read()).deferred, [named]);
      const outcome =
        payload === "generic"
          ? {
              resolvedDeferred: [{ id: named.id, reason: "Callers reviewed." }],
            }
          : {
              surfaces: [
                {
                  candidateId: named.candidateId,
                  label: "Caller review",
                  disposition: "rejected",
                },
              ],
            };
      await f.write(f.draft(outcome, true));
      for (let attempt = 0; attempt < 2; attempt += 1) {
        assert.deepEqual((await f.read()).deferred, []);
        await f.write(f.draft({}, true));
      }
    });
  }

  for (const complete of [false, true]) {
    test(`${layout}: abbreviated generic observations preserve saved context, complete=${complete}`, async (t) => {
      const f = await fixture(t, layout);
      const broad = {
        id: "caller-review",
        reason: "Review callers.",
        paths: ["src/a.ts", "src/b.ts"],
        notes: "Both callers still need review.",
      };
      const abbreviated = { reason: broad.reason, paths: [broad.paths[0]] };
      await f.write(f.draft({ deferred: [broad] }));
      for (let attempt = 0; attempt < 2; attempt += 1) {
        await f.write(f.draft({ deferred: [abbreviated] }, complete));
        assert.deepEqual((await f.read()).deferred, [broad]);
      }
      const updated = {
        ...broad,
        paths: abbreviated.paths,
        notes: "Only the first caller remains.",
      };
      await f.write(f.draft({ deferred: [updated] }, complete));
      assert.deepEqual((await f.read()).deferred, [updated]);
      await f.write(f.draft({ deferred: [abbreviated] }, complete));
      assert.deepEqual((await f.read()).deferred, [updated]);
      await f.write(
        f.draft(
          { resolvedDeferred: [{ id: broad.id, reason: "Caller reviewed." }] },
          true,
        ),
      );
      await f.write(f.draft({}, true));
      assert.deepEqual((await f.read()).deferred, []);
    });
  }

  test(`${layout}: ambiguous summary preserves both saved contexts and closes independently`, async (t) => {
    const f = await fixture(t, layout);
    const detailed = ["First caller context.", "Second caller context."].map(
      (notes) => ({ ...generic, notes }),
    );
    await f.write(f.draft({ deferred: detailed }));
    const original = (await f.read()).deferred;
    await f.write(f.draft({ deferred: [generic] }));
    const saved = (await f.read()).deferred;
    for (const row of original)
      assert.ok(
        saved.some((item) => item.id === row.id && item.notes === row.notes),
      );
    const summary = saved.find((row) => row.notes === undefined);
    assert.ok(summary);
    assert.ok(original.every((row) => row.id !== summary.id));
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await f.write(f.draft({ deferred: [generic] }));
      assert.deepEqual((await f.read()).deferred, saved);
    }
    for (const closed of [original[0], summary, original[1]]) {
      await f.write(
        f.draft(
          {
            resolvedDeferred: [{ id: closed.id, reason: "Review completed." }],
          },
          true,
        ),
      );
      await f.write(f.draft({}, true));
      const remaining = (await f.read()).deferred;
      assert.ok(remaining.every((row) => row.id !== closed.id));
      if (closed === original[0]) {
        assert.ok(
          remaining.some(
            (row) =>
              row.id === original[1].id && row.notes === original[1].notes,
          ),
        );
        assert.ok(remaining.some((row) => row.id === summary.id));
      }
    }
    assert.deepEqual((await f.read()).deferred, []);
  });
}

for (const enriched of [false, true]) {
  test(`worker: equivalent named observations keep repeated raw IDs, extra context=${enriched}`, async (t) => {
    const f = await fixture(t, "worker");
    const original = ["first-review", "second-review"].map((id) => ({
      id,
      ...generic,
    }));
    if (enriched) {
      await f.write(
        f.draft({
          deferred: [{ ...generic, notes: "Keep the caller context." }],
        }),
      );
      original.push((await f.read()).deferred[0]);
    }
    await f.write(f.draft({ deferred: original }));
    let saved;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await f.write(f.draft({ deferred: [generic] }));
      const current = (await f.read()).deferred;
      for (const row of original)
        assert.deepEqual(
          current.find((item) => item.id === row.id),
          row,
        );
      if (saved) assert.deepEqual(current, saved);
      saved = current;
    }
  });
}

test("worker: inferred context does not choose an ambiguous candidate alias", async (t) => {
  const f = await fixture(t, "worker");
  const row = {
    id: "caller-review",
    ...generic,
    paths: [...generic.paths, "src/alternate.py"],
    candidate: { title: "Caller validation." },
  };
  await f.write(
    f.draft({
      deferred: [
        { ...row, candidateId: "first-candidate", notes: "Initial review." },
      ],
    }),
  );
  const latest = { ...row, notes: "Both callers remain pending." };
  await f.write(
    f.draft({ deferred: [{ ...latest, candidateId: "second-candidate" }] }),
  );
  const abbreviated = { ...generic, candidate: row.candidate };
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await f.write(f.draft({ deferred: [abbreviated] }));
    assert.deepEqual((await f.read()).deferred, [latest]);
  }
});

test("worker: inferred context retains an authored equal candidate ID", async (t) => {
  for (const candidateId of [undefined, "caller-review"]) {
    const f = await fixture(t, "worker");
    const named = {
      id: "caller-review",
      ...(candidateId === undefined ? {} : { candidateId }),
      ...generic,
      paths: [...generic.paths, "src/alternate.py"],
      notes: "Both callers remain pending.",
      candidate: { title: "Caller validation." },
    };
    await f.write(f.draft({ deferred: [named] }));
    const abbreviated = { ...generic, candidate: named.candidate };
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await f.write(f.draft({ deferred: [abbreviated] }));
      assert.deepEqual((await f.read()).deferred, [named]);
    }
  }
});

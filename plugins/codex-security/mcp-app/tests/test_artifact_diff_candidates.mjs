import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

async function loadModule(file) {
  const bundle = await build({
    bundle: true,
    entryPoints: [new URL(`../src/${file}`, import.meta.url).pathname],
    format: "esm",
    platform: "node",
    write: false,
  });
  return import(
    `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
  );
}

const {
  preserveDiffCandidateDecisions,
  preserveUnresolvedDiffCandidates,
  readDiffCandidates,
} = await loadModule("artifact-diff-candidates.ts");
const { recordCodexSecurityScanDraft, recordCodexSecurityWorkerScanDraft } =
  await loadModule("artifact-scan-draft.ts");
const { discoveryReductionInput } = await loadModule(
  "deep-scan/artifact-validation.ts",
);
const { recordCodexSecurityCandidateValidations } = await loadModule(
  "artifact-validation-phase.ts",
);

async function reconcileDiffCandidates(context, input) {
  const candidates = await readDiffCandidates(context);
  return preserveUnresolvedDiffCandidates(
    preserveDiffCandidateDecisions(input, candidates),
    candidates,
  );
}

async function writeLedger(context, candidates) {
  const directory = path.join(context.root, "artifacts", "02_discovery");
  await mkdir(directory, { recursive: true });
  await writeFile(
    path.join(directory, "candidate_ledger.jsonl"),
    candidates.map((row) => JSON.stringify(row)).join("\n"),
  );
}

async function readCoverage(context) {
  return JSON.parse(
    await readFile(path.join(context.root, "coverage.json"), "utf8"),
  );
}

function finding(candidateId) {
  return {
    ruleId: "synthetic-review",
    title: "Synthetic reviewed finding",
    summary: "The synthetic review has reached a final finding.",
    severity: { level: "low" },
    confidence: { level: "high", rationale: "Synthetic review evidence." },
    taxonomy: { category: "synthetic", cwe: [] },
    locations: [{ path: "src/handler.ts", startLine: 1 }],
    remediation: "Apply the synthetic remediation.",
    provenance: { source: "local_plugin", candidateId },
  };
}

function candidate(candidateId, validation, attackPath) {
  return {
    candidate_id: candidateId,
    cwe_ids: [],
    locations: [
      { path: "src/handler.ts", start_line: 1, end_line: 2, role: "evidence" },
    ],
    summary: "A synthetic candidate needs review.",
    evidence: "Synthetic candidate evidence.",
    ...(validation ? { validation: { disposition: validation } } : {}),
    ...(attackPath ? { attack_path: { decision: attackPath } } : {}),
  };
}

function draft(deferred = []) {
  return {
    scanId: "11111111-1111-4111-8111-111111111111",
    findings: [],
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred,
    },
  };
}

async function fixture(t, candidates) {
  const root = await mkdtemp(path.join(tmpdir(), "diff-candidates-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  if (candidates !== undefined) await writeLedger({ root }, candidates);
  return {
    root,
    repoRoot: root,
    layout: "scan",
    mode: "diff",
    scanId: draft().scanId,
    status: "running",
    scope: ".",
    targetContract: {
      target: {
        allowedKinds: ["git_diff"],
        targetId: "target_diff",
        displayName: "synthetic-repository",
      },
      scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] },
      diffTarget: {
        kind: "range",
        baseRevision: "base123",
        headRevision: "head456",
      },
    },
  };
}

test("diff outcomes retain unresolved candidates and exclude terminal dismissals", async (t) => {
  const outcomes = [
    [undefined, undefined, true],
    ["reportable", undefined, true],
    ["deferred", undefined, true],
    ["reportable", "deferred", true],
    ["deferred", "reportable", true],
    ["deferred", "ignore", true],
    ["suppressed", "deferred", true],
    ["not_applicable", "deferred", true],
    ["reportable", "reportable", true],
    ["reportable", "ignore", false],
    ["suppressed", undefined, false],
    ["not_applicable", undefined, false],
  ];
  const candidates = outcomes.map(([validation, attackPath], index) =>
    candidate(`candidate-${index}`, validation, attackPath),
  );
  const input = draft();
  const context = await fixture(t, candidates);
  const result = await reconcileDiffCandidates(context, input);
  const expected = candidates.filter((_, index) => outcomes[index][2]);
  assert.deepEqual(
    result.coverage.deferred.map((item) => item.candidateId),
    expected.map((item) => item.candidate_id),
  );
  assert.deepEqual(
    result.coverage.deferred.map((item) => item.candidate),
    expected,
  );
  assert.equal(result.coverage.completeness, "partial");
  assert.deepEqual(
    result.coverage.surfaces.filter(
      (item) => item.disposition === "needs_follow_up",
    ),
    expected.map((item) => ({
      candidateId: item.candidate_id,
      label: item.summary,
      disposition: "needs_follow_up",
      notes: result.coverage.deferred.find(
        (pending) => pending.candidateId === item.candidate_id,
      ).reason,
    })),
  );
  assert.deepEqual(
    result.coverage.surfaces
      .filter((item) => item.disposition !== "needs_follow_up")
      .map((item) => [item.candidateId, item.disposition]),
    [
      ["candidate-9", "rejected"],
      ["candidate-10", "rejected"],
      ["candidate-11", "not_applicable"],
    ],
  );
  assert.deepEqual(input, draft());
  assert.deepEqual(
    await reconcileDiffCandidates(context, result),
    result,
    "Repeated checkpoints must not append the same pending candidates again.",
  );
});

test("diff reconciliation enriches pending records and retains general coverage work", async (t) => {
  const pending = candidate("pending", "deferred", "deferred");
  pending.attack_path.proof_gap =
    "A synthetic runtime check remains unfinished.";
  const context = await fixture(t, [
    pending,
    candidate("rejected", "suppressed"),
    candidate("ignored", "reportable", "ignore"),
  ]);
  const general = { reason: "A source directory still needs review." };
  const result = await reconcileDiffCandidates(
    context,
    draft([
      {
        id: "pending-row",
        candidateId: "pending",
        reason: "Keep the original follow-up question.",
      },
      { candidateId: "rejected", reason: "An earlier incomplete checkpoint." },
      general,
    ]),
  );
  assert.deepEqual(result.coverage.deferred, [
    {
      id: "pending-row",
      candidateId: "pending",
      candidate: pending,
      reason: "Keep the original follow-up question.",
    },
    general,
  ]);
  const added = await reconcileDiffCandidates(context, draft());
  assert.equal(
    added.coverage.deferred[0].reason,
    pending.attack_path.proof_gap,
  );
});

for (const resolution of ["finding", "ledger rejection"]) {
  test(`general coverage row IDs remain separate from candidates through ${resolution}`, async (t) => {
    const pending = candidate("pending", "deferred");
    const context = await fixture(t, [pending]);
    const general = {
      id: pending.candidate_id,
      reason: "A separate source directory still needs review.",
      surfaceIds: ["general-review"],
    };
    const surface = {
      id: "general-review",
      label: "Separate source directory",
      disposition: "needs_follow_up",
      notes: general.reason,
      receiptRefs: [],
    };
    const initial = { ...draft([general]), complete: false };
    initial.coverage.completeness = "partial";
    initial.coverage.surfaces = [surface];
    await recordCodexSecurityScanDraft(context, initial);
    const projected = await readCoverage(context);
    assert.deepEqual(
      projected.deferred.find((item) => item.id === general.id),
      general,
    );
    assert.equal(projected.deferred.length, 2);
    assert.equal(
      projected.surfaces.filter(
        (item) =>
          item.candidateId === pending.candidate_id &&
          item.disposition === "needs_follow_up",
      ).length,
      1,
    );
    assert.deepEqual(
      projected.surfaces.find((item) => item.id === surface.id),
      surface,
    );

    const resolved = { ...draft(), complete: true };
    if (resolution === "finding")
      resolved.findings = [finding(pending.candidate_id)];
    else
      await writeLedger(context, [
        candidate(pending.candidate_id, "suppressed"),
      ]);
    await recordCodexSecurityScanDraft(context, resolved);
    for (const complete of [true, false]) {
      const saved = await readCoverage(context);
      assert.deepEqual(saved.deferred, [general]);
      assert.deepEqual(
        saved.surfaces.find((item) => item.id === surface.id),
        surface,
      );
      assert.equal(saved.completeness, "partial");
      await recordCodexSecurityScanDraft(context, { ...draft(), complete });
    }
  });
}

for (const metadata of [
  { label: "legacy-owner" },
  ["legacy-owner"],
  "",
  "  ",
]) {
  test(`non-string and blank owner metadata do not leave confirmed Diff candidates unresolved: ${JSON.stringify(metadata)}`, async (t) => {
    const pending = candidate("pending", "deferred");
    const context = await fixture(t, [pending]);
    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      complete: false,
    });
    const confirmed = finding(pending.candidate_id);
    Object.assign(confirmed.provenance, {
      sourceWorkerId: metadata,
      workerId: metadata,
    });
    for (const complete of [true, false]) {
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete,
        findings: [confirmed],
      });
      const saved = await readCoverage(context);
      assert.deepEqual(saved.deferred, []);
      assert.equal(saved.completeness, "complete");
      const findings = JSON.parse(
        await readFile(path.join(context.root, "findings.json"), "utf8"),
      ).findings;
      assert.equal(findings.length, 1);
      assert.deepEqual(findings[0].provenance.sourceWorkerId, metadata);
      assert.deepEqual(findings[0].provenance.workerId, metadata);
    }
  });
}

for (const fallback of ["workerId", "extensions"]) {
  test(`structured owner metadata allows a valid ${fallback} owner to resolve its candidate`, async (t) => {
    const context = { ...(await fixture(t)), mode: "standard" };
    const confirmed = finding("pending");
    confirmed.provenance.sourceWorkerId = { label: "legacy-owner" };
    if (fallback === "workerId")
      confirmed.provenance.workerId = "actual-worker";
    else {
      confirmed.provenance.workerId = " ";
      confirmed.extensions = { sourceWorkerId: "actual-worker" };
    }
    const unrelated = {
      candidateId: "pending",
      sourceWorkerId: "other-worker",
      reason: "Independent worker review.",
    };
    const initial = {
      ...draft([
        {
          candidateId: "pending",
          sourceWorkerId: "actual-worker",
          reason: "Candidate review.",
        },
        unrelated,
      ]),
      complete: false,
    };
    initial.coverage.completeness = "partial";
    await recordCodexSecurityScanDraft(context, initial);
    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      findings: [confirmed],
      complete: true,
    });
    assert.deepEqual(
      (await readCoverage(context)).deferred.map(
        ({ candidateId, sourceWorkerId }) => ({ candidateId, sourceWorkerId }),
      ),
      [{ candidateId: "pending", sourceWorkerId: "other-worker" }],
    );
  });
}

test("bound worker ownership overrides imported metadata and preserves its evidence", async (t) => {
  const context = { ...(await fixture(t)), layout: "worker", mode: "standard" };
  const confirmed = finding("pending");
  confirmed.provenance.sourceWorkerId = {
    label: "legacy-owner",
    details: ["retained"],
  };
  confirmed.provenance.workerId = "imported-worker";
  const initial = {
    ...draft([
      {
        candidateId: "pending",
        sourceWorkerId: "different-import",
        reason: "Review in the bound worker.",
      },
    ]),
    complete: false,
  };
  initial.coverage.completeness = "partial";
  await recordCodexSecurityWorkerScanDraft(context, initial);
  await recordCodexSecurityWorkerScanDraft(context, {
    ...draft(),
    complete: true,
    findings: [confirmed],
  });
  const saved = JSON.parse(
    await readFile(path.join(context.root, "result.json"), "utf8"),
  );
  assert.deepEqual(saved.coverage.deferred, []);
  for (const workerId of ["actual-worker", "imported-worker"]) {
    const reduced = discoveryReductionInput(saved, workerId);
    assert.equal(reduced.findings[0].provenance.sourceWorkerId, workerId);
    assert.deepEqual(
      reduced.findings[0].provenance.previousFindings[0].provenance
        .sourceWorkerId,
      confirmed.provenance.sourceWorkerId,
    );
    assert.equal(
      reduced.findings[0].provenance.previousFindings[0].provenance.workerId,
      "imported-worker",
    );
    assert.deepEqual(
      saved.findings[0].provenance.sourceWorkerId,
      confirmed.provenance.sourceWorkerId,
    );
  }
});

test("structured exclusion owner metadata does not resolve an unowned candidate", async (t) => {
  const pending = candidate("pending", "deferred");
  const context = await fixture(t, [pending]);
  const exclusion = {
    pattern: "src/other.ts",
    reason: "Keep this imported review decision.",
    candidateId: pending.candidate_id,
    sourceWorkerId: { label: "legacy-owner" },
    disposition: "rejected",
  };
  const unrelated = finding("unrelated");
  delete unrelated.provenance.candidateId;
  const initial = { ...draft(), complete: false, findings: [unrelated] };
  initial.coverage.explicitExclusions = [exclusion];
  await recordCodexSecurityScanDraft(context, initial);
  for (const complete of [true, false]) {
    const saved = await readCoverage(context);
    assert.deepEqual(saved.explicitExclusions, [exclusion]);
    assert.equal(saved.deferred.length, 1);
    assert.equal(saved.deferred[0].candidateId, pending.candidate_id);
    assert.equal(saved.completeness, "partial");
    await recordCodexSecurityScanDraft(context, { ...draft(), complete });
  }
});

test("final findings and explicit candidate resolutions are not reopened", async (t) => {
  const context = await fixture(t, [
    candidate("confirmed"),
    candidate("rejected"),
    candidate("not-applicable"),
  ]);
  const input = draft();
  input.findings = [{ extensions: { candidateId: "confirmed" } }];
  input.coverage.surfaces = [
    { candidateId: "rejected", disposition: "rejected" },
    { candidateId: "not-applicable", disposition: "not_applicable" },
  ];
  assert.deepEqual(await reconcileDiffCandidates(context, input), input);
});

test("pending diff candidates retain their authored follow-up surfaces", async (t) => {
  const pending = candidate("pending-review", "deferred");
  const context = await fixture(t, [pending]);
  const input = draft();
  input.coverage.surfaces = [
    {
      candidateId: pending.candidate_id,
      label: "Authored review boundary",
      disposition: "needs_follow_up",
      notes: "Keep the analyst's coverage evidence.",
    },
  ];
  const result = await reconcileDiffCandidates(context, input);
  assert.deepEqual(result.coverage.surfaces, input.coverage.surfaces);
  assert.equal(result.coverage.deferred.length, 1);
});

for (const mapping of ["candidateId", "surfaceIds"]) {
  test(`pending diff candidates preserve a shared reported surface linked by ${mapping}`, async (t) => {
    const pending = candidate("pending-review", "deferred");
    const context = await fixture(t, [pending]);
    const input = draft([
      {
        candidateId: pending.candidate_id,
        reason: "The second candidate still needs validation.",
        ...(mapping === "surfaceIds" ? { surfaceIds: ["shared-surface"] } : {}),
      },
    ]);
    input.findings = [{ provenance: { candidateId: "confirmed-review" } }];
    input.coverage.surfaces = [
      {
        id: "shared-surface",
        ...(mapping === "candidateId"
          ? { candidateId: pending.candidate_id }
          : {}),
        label: "Shared review boundary",
        disposition: "reported",
        notes: "The shared surface contains a retained finding.",
      },
    ];
    const result = await reconcileDiffCandidates(context, input);
    assert.deepEqual(result.coverage.surfaces, input.coverage.surfaces);
    assert.equal(result.coverage.deferred.length, 1);
    assert.equal(result.coverage.completeness, "partial");
  });
}

test("legacy diff drafts without a ledger and other modes retain their behavior", async (t) => {
  const context = await fixture(t);
  const input = draft();
  assert.equal(await reconcileDiffCandidates(context, input), input);
  assert.equal(
    await reconcileDiffCandidates({ ...context, mode: "standard" }, input),
    input,
  );
});

for (const remaining of ["none", "deferred", "surface", "explicit partial"]) {
  test(`terminal diff decisions close a saved checkpoint with ${remaining} remaining`, async (t) => {
    const pending = candidate("pending-review");
    const context = await fixture(t, [pending]);
    const checkpoint = { ...draft(), complete: false };
    if (remaining === "deferred") {
      checkpoint.coverage.completeness = "partial";
      checkpoint.coverage.deferred.push({
        reason: "An unrelated source review remains unfinished.",
      });
    }
    if (remaining === "surface") {
      checkpoint.coverage.completeness = "partial";
      checkpoint.coverage.surfaces.push({
        label: "Unrelated source review",
        disposition: "needs_follow_up",
      });
    }
    await recordCodexSecurityScanDraft(context, checkpoint);
    const savedCheckpoint = await readCoverage(context);
    assert.equal(savedCheckpoint.completeness, "partial");
    assert.ok(
      savedCheckpoint.deferred.some(
        (item) => item.candidateId === pending.candidate_id,
      ),
    );
    assert.ok(
      savedCheckpoint.surfaces.some(
        (item) =>
          item.candidateId === pending.candidate_id &&
          item.disposition === "needs_follow_up",
      ),
    );

    await writeLedger(context, [
      { ...pending, validation: { disposition: "suppressed" } },
    ]);
    const finalDraft = { ...draft(), complete: true };
    if (remaining === "explicit partial")
      finalDraft.coverage.completeness = "partial";
    await recordCodexSecurityScanDraft(context, finalDraft);
    const saved = await readCoverage(context);
    assert.equal(
      saved.completeness,
      remaining === "none" ? "complete" : "partial",
    );
    assert.equal(
      saved.deferred.some((item) => item.candidateId === pending.candidate_id),
      false,
    );
    assert.equal(
      saved.surfaces.some(
        (item) =>
          item.candidateId === pending.candidate_id &&
          item.disposition === "rejected",
      ),
      true,
    );
    if (remaining === "deferred") assert.equal(saved.deferred.length, 1);
    if (remaining === "surface") assert.equal(saved.surfaces.length, 2);
  });
}

for (const remaining of [
  "none",
  "shared checkpoint",
  "shared current",
  "shared direct candidate",
  "shared dismissed candidate",
  "generic gap",
  "current follow-up",
]) {
  test(`ledger resolution clears linked historical follow-ups with ${remaining} remaining`, async (t) => {
    const pending = candidate("linked-review");
    const other = candidate("other-review");
    const context = await fixture(t, [
      pending,
      ...(remaining === "shared direct candidate" ||
      remaining === "shared dismissed candidate"
        ? [other]
        : []),
    ]);
    const linkedSurface = {
      id: "shared-boundary",
      ...(remaining === "shared direct candidate"
        ? { candidateId: other.candidate_id }
        : remaining === "shared dismissed candidate"
          ? { candidateId: pending.candidate_id }
          : {}),
      label: "Synthetic review boundary",
      disposition: "needs_follow_up",
      notes: "The linked candidate needs validation.",
      receiptRefs: ["artifacts/review/shared.json"],
    };
    const checkpoint = {
      ...draft([
        {
          candidateId: pending.candidate_id,
          reason: "Validate the linked candidate.",
          surfaceIds: [linkedSurface.id],
        },
      ]),
      complete: false,
    };
    checkpoint.coverage.completeness = "partial";
    checkpoint.coverage.surfaces.push(linkedSurface);
    if (
      remaining === "shared direct candidate" ||
      remaining === "shared dismissed candidate"
    ) {
      checkpoint.coverage.deferred.push({
        candidateId: other.candidate_id,
        reason: "The directly linked candidate still needs validation.",
        ...(remaining === "shared dismissed candidate"
          ? { surfaceIds: [linkedSurface.id] }
          : {}),
      });
    }
    if (remaining === "generic gap") {
      checkpoint.coverage.deferred.push({
        reason: "An unrelated source review remains unfinished.",
        surfaceIds: ["generic-boundary"],
      });
      checkpoint.coverage.surfaces.push({
        id: "generic-boundary",
        label: "Unrelated source review",
        disposition: "needs_follow_up",
      });
    }
    await recordCodexSecurityScanDraft(context, checkpoint);
    const otherDeferred = {
      candidateId: other.candidate_id,
      reason: "A second candidate still needs validation.",
      surfaceIds: [linkedSurface.id],
    };
    if (remaining === "shared checkpoint") {
      await writeLedger(context, [pending, other]);
      const sharedCheckpoint = { ...draft([otherDeferred]), complete: false };
      sharedCheckpoint.coverage.completeness = "partial";
      await recordCodexSecurityScanDraft(context, sharedCheckpoint);
    }
    const shared = remaining.startsWith("shared");
    await writeLedger(context, [
      { ...pending, validation: { disposition: "suppressed" } },
      ...(shared ? [other] : []),
    ]);
    const finalDraft = {
      ...draft(remaining === "shared current" ? [otherDeferred] : []),
      complete: true,
    };
    if (remaining === "shared current" || remaining === "current follow-up")
      finalDraft.coverage.completeness = "partial";
    if (remaining === "current follow-up") {
      finalDraft.coverage.surfaces.push({
        ...linkedSurface,
        notes: "The current draft explicitly retains additional review work.",
      });
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      await recordCodexSecurityScanDraft(context, finalDraft);
      const saved = await readCoverage(context);
      assert.equal(
        saved.completeness,
        remaining === "none" ? "complete" : "partial",
      );
      assert.equal(
        saved.deferred.some(
          (item) => item.candidateId === pending.candidate_id,
        ),
        false,
      );
      assert.deepEqual(
        saved.surfaces
          .filter((surface) => surface.disposition === "needs_follow_up")
          .map((surface) => surface.id),
        remaining === "generic gap"
          ? ["generic-boundary"]
          : shared || remaining === "current follow-up"
            ? [linkedSurface.id]
            : [],
      );
      if (shared) {
        const retainedSurface = saved.surfaces.find(
          (surface) => surface.id === linkedSurface.id,
        );
        assert.equal(retainedSurface.notes, linkedSurface.notes);
        assert.deepEqual(
          retainedSurface.receiptRefs,
          linkedSurface.receiptRefs,
        );
        assert.deepEqual(
          saved.deferred.map((item) => item.candidateId),
          [other.candidate_id],
        );
      }
      if (remaining === "generic gap") assert.equal(saved.deferred.length, 1);
      if (remaining === "current follow-up") {
        assert.equal(
          saved.surfaces.find((surface) => surface.id === linkedSurface.id)
            .notes,
          finalDraft.coverage.surfaces[0].notes,
        );
      }
    }
  });
}

for (const resolution of ["finding", "exclusion"]) {
  test(`mixed ledger and current ${resolution} resolutions clear linked follow-ups`, async (t) => {
    const automatic = candidate("automatic-review");
    const linked = candidate("linked-review");
    const context = await fixture(t, [automatic, linked]);
    const checkpoint = {
      ...draft([
        {
          candidateId: linked.candidate_id,
          reason: "Validate the linked candidate.",
          surfaceIds: ["linked-boundary"],
        },
      ]),
      complete: false,
    };
    checkpoint.coverage.completeness = "partial";
    checkpoint.coverage.surfaces.push({
      id: "linked-boundary",
      label: "Synthetic review boundary",
      disposition: "needs_follow_up",
    });
    await recordCodexSecurityScanDraft(context, checkpoint);

    const resolved = { ...draft(), complete: false };
    if (resolution === "finding") {
      resolved.findings.push(finding(linked.candidate_id));
    } else {
      resolved.coverage.explicitExclusions.push({
        candidateId: linked.candidate_id,
        disposition: "rejected",
        pattern: "src/handler.ts",
        reason: "Synthetic review resolved this candidate.",
      });
    }
    await recordCodexSecurityScanDraft(context, resolved);
    await writeLedger(context, [
      { ...automatic, validation: { disposition: "suppressed" } },
      linked,
    ]);
    for (let attempt = 0; attempt < 2; attempt++) {
      await recordCodexSecurityScanDraft(context, {
        ...resolved,
        complete: true,
      });
      const saved = await readCoverage(context);
      assert.equal(saved.completeness, "complete");
      assert.deepEqual(saved.deferred, []);
      assert.deepEqual(
        saved.surfaces.map((item) => [item.candidateId, item.disposition]),
        [[automatic.candidate_id, "rejected"]],
      );
      if (resolution === "exclusion") {
        assert.equal(
          saved.explicitExclusions[0].candidateId,
          linked.candidate_id,
        );
      } else {
        const findings = JSON.parse(
          await readFile(path.join(context.root, "findings.json"), "utf8"),
        );
        assert.equal(
          findings.findings[0].provenance.candidateId,
          linked.candidate_id,
        );
      }
    }
  });
}

for (const resolution of ["finding", "exclusion"]) {
  test(`retained ${resolution} decisions keep historical references resolved on an empty final save`, async (t) => {
    const context = await fixture(t);
    const checkpoint = {
      ...draft([
        {
          candidateId: "resolved-review",
          reason: "Validate the linked candidate.",
          surfaceIds: ["linked-boundary"],
        },
      ]),
      complete: false,
    };
    checkpoint.coverage.completeness = "partial";
    checkpoint.coverage.surfaces.push({
      id: "linked-boundary",
      candidateId: "resolved-review",
      label: "Synthetic review boundary",
      disposition: "needs_follow_up",
    });
    await recordCodexSecurityScanDraft(context, checkpoint);
    const finalDraft = { ...draft(), complete: true };
    if (resolution === "finding") {
      finalDraft.findings.push(finding("resolved-review"));
    } else {
      finalDraft.coverage.explicitExclusions.push({
        candidateId: "resolved-review",
        disposition: "rejected",
        pattern: "src/handler.ts",
        reason: "The synthetic review resolved this candidate.",
      });
    }
    await recordCodexSecurityScanDraft(context, finalDraft);
    for (let attempt = 0; attempt < 2; attempt++) {
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
      });
      const saved = await readCoverage(context);
      assert.equal(saved.completeness, "complete");
      assert.deepEqual(saved.deferred, []);
      assert.deepEqual(saved.surfaces, []);
    }
  });
}

for (const disposition of ["rejected", "not_applicable"]) {
  test(`a current ${disposition} exclusion preserves unrelated historical follow-ups`, async (t) => {
    const context = await fixture(t);
    const checkpoint = {
      ...draft([
        { candidateId: "resolved-review", reason: "Candidate review." },
      ]),
      complete: false,
    };
    const unrelated = {
      id: "generic-boundary",
      label: "Independent source review",
      disposition: "needs_follow_up",
      notes: "This review remains unfinished after the candidate is resolved.",
      receiptRefs: ["artifacts/review/evidence.json"],
    };
    checkpoint.coverage.completeness = "partial";
    checkpoint.coverage.surfaces.push(unrelated);
    await recordCodexSecurityScanDraft(context, checkpoint);
    const finalDraft = { ...draft(), complete: true };
    finalDraft.coverage.explicitExclusions.push({
      candidateId: "resolved-review",
      disposition,
      pattern: "src/handler.ts",
      reason: "The synthetic candidate is resolved.",
    });
    for (let attempt = 0; attempt < 2; attempt++) {
      await recordCodexSecurityScanDraft(context, finalDraft);
      const saved = await readCoverage(context);
      assert.equal(saved.completeness, "partial");
      assert.deepEqual(saved.deferred, []);
      assert.deepEqual(saved.surfaces, [unrelated]);
    }
  });
}

for (const mapping of ["surfaceIds", "candidateId"]) {
  for (const currentSurface of [false, true]) {
    test(`pending ${mapping} links retain ${currentSurface ? "current" : "historical"} shared surface evidence after exclusion`, async (t) => {
      const context = await fixture(t);
      const shared = {
        id: "shared-boundary",
        label: "Shared review boundary",
        disposition: "needs_follow_up",
        notes: "Shared source evidence remains relevant to the pending review.",
        receiptRefs: ["artifacts/review/evidence.json"],
        ...(mapping === "candidateId"
          ? { candidateId: "resolved-review" }
          : {}),
      };
      const checkpoint = {
        ...draft([
          {
            candidateId: "resolved-review",
            reason: "Validate this synthetic candidate.",
            surfaceIds: [shared.id],
          },
        ]),
        complete: false,
      };
      checkpoint.coverage.completeness = "partial";
      checkpoint.coverage.surfaces.push(shared);
      await recordCodexSecurityScanDraft(context, checkpoint);
      const finalDraft = {
        ...draft([
          {
            candidateId: "pending-review",
            reason:
              "Another candidate still requires the shared review evidence.",
            surfaceIds: [shared.id],
          },
        ]),
        complete: true,
      };
      finalDraft.coverage.completeness = "partial";
      finalDraft.coverage.explicitExclusions.push({
        candidateId: "resolved-review",
        disposition: "rejected",
        pattern: "src/handler.ts",
        reason: "This candidate is resolved, while the other remains pending.",
      });
      const expectedSurface = currentSurface
        ? {
            ...shared,
            notes: "The current draft supplies updated review evidence.",
          }
        : shared;
      if (currentSurface) finalDraft.coverage.surfaces.push(expectedSurface);
      for (let attempt = 0; attempt < 2; attempt++) {
        await recordCodexSecurityScanDraft(context, finalDraft);
        const saved = await readCoverage(context);
        assert.equal(saved.completeness, "partial");
        assert.deepEqual(
          saved.deferred,
          finalDraft.coverage.deferred.map((item) => ({
            ...item,
            id: item.candidateId,
          })),
        );
        assert.deepEqual(saved.surfaces, [expectedSurface]);
      }
    });
  }
}

for (const disposition of ["rejected", "not_applicable"]) {
  test(`explicit ${disposition} exclusions resolve diff candidates through later drafts`, async (t) => {
    const pending = candidate("excluded-review");
    const context = await fixture(t, [pending]);
    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      complete: false,
    });
    const finalDraft = { ...draft(), complete: true };
    finalDraft.coverage.explicitExclusions.push({
      candidateId: pending.candidate_id,
      disposition,
      pattern: "src/handler.ts",
      reason: "The synthetic candidate was resolved during source review.",
    });
    await recordCodexSecurityScanDraft(context, finalDraft);
    const resolved = await readCoverage(context);
    assert.equal(resolved.completeness, "complete");
    assert.deepEqual(resolved.deferred, []);
    assert.deepEqual(resolved.explicitExclusions[0].candidate, pending);
    assert.equal(resolved.explicitExclusions[0].disposition, disposition);

    await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });
    const retained = await readCoverage(context);
    assert.equal(retained.completeness, "complete");
    assert.deepEqual(retained.deferred, []);
    assert.deepEqual(retained.explicitExclusions, resolved.explicitExclusions);
  });

  test(`new deferred review supersedes an older ${disposition} exclusion`, async (t) => {
    const pending = candidate("reopened-review");
    const context = await fixture(t, [pending]);
    const earlierExclusion = {
      candidateId: pending.candidate_id,
      disposition,
      pattern: "src/handler.ts",
      reason: "An earlier synthetic review dismissed the candidate.",
    };
    const unrelatedExclusion = {
      pattern: "vendor/**",
      reason: "The independent vendor scope remains excluded.",
    };
    const earlier = { ...draft(), complete: false };
    earlier.coverage.explicitExclusions.push(
      earlierExclusion,
      unrelatedExclusion,
    );
    await recordCodexSecurityScanDraft(context, earlier);
    const checkpoints = path.join(context.root, "checkpoints");
    const history = await Promise.all(
      (await readdir(checkpoints)).map(async (name) => [
        name,
        await readFile(path.join(checkpoints, name), "utf8"),
      ]),
    );
    assert.ok(
      history.some(([, content]) =>
        JSON.parse(content).coverage.explicitExclusions.some(
          (item) => item.reason === earlierExclusion.reason,
        ),
      ),
    );
    const currentExclusion = {
      candidateId: "another-candidate",
      disposition: "not_applicable",
      pattern: "src/other.ts",
      reason: "This current exclusion remains authoritative.",
    };
    const followup = {
      ...draft([
        {
          candidateId: pending.candidate_id,
          reason: "Later evidence requires another review.",
        },
      ]),
      complete: false,
    };
    followup.coverage.completeness = "partial";
    followup.coverage.explicitExclusions.push(currentExclusion);
    for (let attempt = 0; attempt < 2; attempt++) {
      await recordCodexSecurityScanDraft(context, followup);
      const saved = await readCoverage(context);
      assert.deepEqual(
        saved.deferred.map((item) => item.candidateId),
        [pending.candidate_id],
      );
      assert.equal(
        saved.deferred[0].reason,
        followup.coverage.deferred[0].reason,
      );
      assert.equal(saved.completeness, "partial");
      assert.deepEqual(saved.explicitExclusions, [
        currentExclusion,
        unrelatedExclusion,
      ]);
    }
    for (const [name, content] of history) {
      assert.equal(
        await readFile(path.join(checkpoints, name), "utf8"),
        content,
      );
    }
  });

  test(`terminal diff ledger resolution retains saved ${disposition} surface rationale`, async (t) => {
    const pending = candidate("resolved-review");
    const context = await fixture(t, [pending]);
    const checkpoint = { ...draft(), complete: false };
    checkpoint.coverage.completeness = "partial";
    checkpoint.coverage.surfaces.push({
      candidateId: pending.candidate_id,
      label: "Synthetic candidate review",
      disposition: "needs_follow_up",
    });
    await recordCodexSecurityScanDraft(context, checkpoint);
    await writeLedger(context, [
      { ...pending, validation: { disposition: "suppressed" } },
    ]);
    const finalDraft = { ...draft(), complete: true };
    finalDraft.coverage.surfaces.push({
      candidateId: pending.candidate_id,
      label: "Synthetic candidate review",
      disposition,
      notes: "Source review established the candidate's terminal disposition.",
    });
    await recordCodexSecurityScanDraft(context, finalDraft);
    const resolved = await readCoverage(context);
    assert.equal(resolved.completeness, "complete");
    assert.deepEqual(resolved.deferred, []);
    assert.equal(resolved.surfaces.length, 1);
    assert.equal(resolved.surfaces[0].disposition, disposition);
    assert.deepEqual(resolved.surfaces[0].candidate, pending);

    await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });
    const retained = await readCoverage(context);
    assert.equal(retained.completeness, "complete");
    assert.deepEqual(retained.deferred, []);
    assert.deepEqual(retained.surfaces, resolved.surfaces);
  });
}

for (const complete of [false, true]) {
  for (const authored of [false, true]) {
    test(`ledger transitions ${authored ? "preserve authored" : "refresh generated"} decisions in ${complete ? "final drafts" : "checkpoints"}`, async (t) => {
      const candidateId = "changing-review";
      const context = await fixture(t, [
        candidate(candidateId, "reportable", "reportable"),
      ]);
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete,
        findings: [finding(candidateId)],
      });
      const authoredDecision = {
        candidateId,
        label: "Authored final review label.",
        disposition: "rejected",
        notes: "The authored final decision remains authoritative.",
        receiptRefs: ["artifacts/review/decision.json"],
      };
      for (const [stage, validation, attackPath, expectedDisposition] of [
        ["ignored", "reportable", "ignore", "rejected"],
        ["rediscovered", undefined, undefined, "needs_follow_up"],
        ["suppressed", "suppressed", undefined, "rejected"],
        ["not_applicable", "not_applicable", undefined, "not_applicable"],
        ["deferred", "deferred", undefined, "needs_follow_up"],
        ["reportable", "reportable", "reportable", "needs_follow_up"],
      ]) {
        const reviewed = {
          ...candidate(candidateId, validation, attackPath),
          summary: `Current ${stage} candidate summary.`,
          evidence: `Current ${stage} candidate evidence.`,
        };
        if (reviewed.validation)
          reviewed.validation.counterevidence_or_proof_gap = `Current ${stage} rationale.`;
        if (attackPath === "ignore")
          reviewed.attack_path.counterevidence =
            "Current ignored counterevidence.";
        await writeLedger(context, [reviewed]);
        for (let attempt = 0; attempt < 2; attempt++) {
          const input = { ...draft(), complete };
          if (authored && stage === "ignored" && attempt === 0)
            input.coverage.surfaces.push(authoredDecision);
          await recordCodexSecurityScanDraft(context, input);
          const saved = await readCoverage(context);
          const reopened =
            !authored && expectedDisposition === "needs_follow_up";
          assert.equal(saved.completeness, reopened ? "partial" : "complete");
          assert.equal(saved.deferred.length, reopened ? 1 : 0);
          assert.equal(saved.surfaces.length, 1);
          const surface = saved.surfaces[0];
          assert.equal(
            surface.disposition,
            authored ? "rejected" : expectedDisposition,
          );
          assert.equal(
            surface.label,
            authored ? authoredDecision.label : reviewed.summary,
          );
          if (authored) {
            assert.equal(surface.notes, authoredDecision.notes);
            assert.deepEqual(surface.receiptRefs, authoredDecision.receiptRefs);
          } else {
            assert.deepEqual(surface.candidate, reviewed);
            assert.equal(
              surface.notes,
              reopened
                ? saved.deferred[0].reason
                : (reviewed.attack_path?.counterevidence ??
                    reviewed.validation.counterevidence_or_proof_gap),
            );
          }
          if (reopened) {
            assert.deepEqual(saved.deferred[0].candidate, reviewed);
            assert.equal(
              saved.deferred[0].finding.provenance.candidateId,
              candidateId,
            );
            if (stage === "reportable")
              assert.match(saved.deferred[0].reason, /no saved finding/u);
          }
          assert.deepEqual(
            JSON.parse(
              await readFile(path.join(context.root, "findings.json"), "utf8"),
            ).findings,
            [],
          );
        }
      }
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
        findings: [finding(candidateId)],
      });
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
      });
      assert.deepEqual((await readCoverage(context)).deferred, []);
      assert.equal(
        JSON.parse(
          await readFile(path.join(context.root, "findings.json"), "utf8"),
        ).findings.length,
        1,
      );
    });
  }
}

for (const [validation, attackPath, disposition] of [
  ["suppressed", undefined, "rejected"],
  ["not_applicable", undefined, "not_applicable"],
  ["reportable", "ignore", "rejected"],
]) {
  test(`terminal ${validation}/${attackPath ?? "unreviewed"} ledger decisions demote saved findings`, async (t) => {
    const pending = candidate("resolved-finding", "reportable", "reportable");
    const context = await fixture(t, [pending]);
    const earlier = {
      ...draft(),
      complete: true,
      findings: [finding(pending.candidate_id)],
    };
    await recordCodexSecurityScanDraft(context, earlier);
    const terminal = candidate(pending.candidate_id, validation, attackPath);
    const reason = "Synthetic source evidence resolved this candidate.";
    terminal.validation.counterevidence_or_proof_gap = reason;
    if (terminal.attack_path) terminal.attack_path.counterevidence = reason;
    await writeLedger(context, [terminal]);
    for (const complete of [false, true, true]) {
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete,
      });
      const saved = await readCoverage(context);
      assert.equal(saved.completeness, "complete");
      assert.deepEqual(saved.deferred, []);
      assert.equal(saved.surfaces.length, 1);
      assert.equal(saved.surfaces[0].candidateId, pending.candidate_id);
      assert.equal(saved.surfaces[0].disposition, disposition);
      assert.equal(saved.surfaces[0].notes, reason);
      assert.deepEqual(saved.surfaces[0].candidate, terminal);
      assert.equal(
        saved.surfaces[0].finding.provenance.candidateId,
        pending.candidate_id,
      );
      assert.deepEqual(
        JSON.parse(
          await readFile(path.join(context.root, "findings.json"), "utf8"),
        ).findings,
        [],
      );
    }
  });
}

for (const complete of [false, true]) {
  test(`reportable diff ledger rows remain pending until a finding is saved in a ${complete ? "final draft" : "checkpoint"}`, async (t) => {
    const pending = candidate("reportable-review");
    const context = await fixture(t, [pending]);
    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      complete: false,
    });
    const reportable = candidate(
      pending.candidate_id,
      "reportable",
      "reportable",
    );
    await writeLedger(context, [reportable]);
    await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });
    const missingFinding = await readCoverage(context);
    assert.equal(missingFinding.completeness, "partial");
    assert.equal(missingFinding.deferred.length, 1);
    assert.equal(missingFinding.deferred[0].candidateId, pending.candidate_id);
    assert.deepEqual(missingFinding.deferred[0].candidate, reportable);
    assert.match(missingFinding.deferred[0].reason, /no saved finding/u);

    const finalDraft = { ...draft(), complete };
    finalDraft.findings.push(finding(pending.candidate_id));
    await recordCodexSecurityScanDraft(context, finalDraft);
    const saved = await readCoverage(context);
    assert.equal(saved.completeness, "complete");
    assert.deepEqual(saved.deferred, []);
    assert.ok(
      saved.surfaces.every(
        (surface) => surface.disposition !== "needs_follow_up",
      ),
    );
    for (const repeatComplete of [false, true, false]) {
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: repeatComplete,
      });
      const repeated = await readCoverage(context);
      assert.equal(repeated.completeness, "complete");
      assert.deepEqual(repeated.deferred, []);
      assert.ok(
        repeated.surfaces.every(
          (surface) => surface.disposition !== "needs_follow_up",
        ),
      );
    }
    const retained = await readCoverage(context);
    assert.equal(retained.completeness, "complete");
    assert.deepEqual(retained.deferred, []);
    const findings = JSON.parse(
      await readFile(path.join(context.root, "findings.json"), "utf8"),
    );
    assert.equal(findings.findings.length, 1);
    assert.equal(
      findings.findings[0].provenance.candidateId,
      pending.candidate_id,
    );
  });
}

for (const section of ["surfaces", "explicitExclusions"]) {
  for (const disposition of ["rejected", "not_applicable"]) {
    test(`a ${disposition} ${section} checkpoint resolves inherited generated coverage`, async (t) => {
      const pending = candidate("checkpoint-decision");
      const context = await fixture(t, [pending]);
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
      });
      const generated = await readCoverage(context);
      const initial = { ...draft(), complete: true };
      Object.assign(initial.coverage, {
        completeness: generated.completeness,
        completenessBeforeCandidates: generated.completenessBeforeCandidates,
        surfaces: generated.surfaces,
        deferred: generated.deferred,
      });
      Object.assign(initial.coverage.surfaces[0], {
        receiptRefs: ["artifacts/review/retained.json"],
        analystAnnotation: "Keep this evidence annotation.",
      });
      await recordCodexSecurityScanDraft(context, initial);
      const current = { ...draft(), complete: false };
      const reason = "Current source evidence resolves this candidate.";
      const decision = {
        candidateId: pending.candidate_id,
        disposition,
        ...(section === "surfaces"
          ? {
              label: "Current review decision",
              ...(disposition === "rejected" ? { notes: reason } : {}),
              receiptRefs: ["artifacts/review/decision.json"],
            }
          : { pattern: "src/handler.ts", reason }),
      };
      current.coverage[section].push(decision);
      await recordCodexSecurityScanDraft(context, current);
      for (const complete of [false, true, false]) {
        const saved = await readCoverage(context);
        assert.equal(saved.completeness, "complete");
        assert.deepEqual(saved.deferred, []);
        assert.equal(saved.surfaces.length, 1);
        const surface = saved.surfaces[0];
        assert.equal(surface.disposition, disposition);
        assert.equal(
          surface.notes,
          section === "surfaces" ? decision.notes : reason,
        );
        assert.equal(
          surface.analystAnnotation,
          "Keep this evidence annotation.",
        );
        assert.ok(
          surface.receiptRefs.includes("artifacts/review/retained.json"),
        );
        if (section === "surfaces")
          assert.ok(
            surface.receiptRefs.includes("artifacts/review/decision.json"),
          );
        assert.deepEqual(saved[section][0].candidate, pending);
        await recordCodexSecurityScanDraft(context, { ...draft(), complete });
      }
    });
  }

  for (const remaining of ["authored", "shared with another owner"]) {
    test(`a terminal ${section} checkpoint retains ${remaining} follow-up evidence`, async (t) => {
      const pending = candidate("owned-review");
      const context = await fixture(t, [pending]);
      const initial = { ...draft(), complete: true };
      initial.coverage.completeness = "partial";
      const shared = remaining === "shared with another owner";
      const evidence = {
        id: "shared-evidence",
        candidateId: pending.candidate_id,
        label: pending.summary,
        disposition: "needs_follow_up",
        notes: shared
          ? `Candidate review is incomplete: ${pending.summary}`
          : "Keep the authored follow-up request.",
        receiptRefs: ["artifacts/review/retained.json"],
      };
      initial.coverage.surfaces.push(evidence);
      if (shared)
        initial.coverage.deferred.push({
          candidateId: pending.candidate_id,
          sourceWorkerId: "other-worker",
          reason: "The independent candidate still needs this evidence.",
          surfaceIds: [evidence.id],
        });
      await recordCodexSecurityScanDraft(context, initial);
      const current = { ...draft(), complete: false };
      current.coverage[section].push({
        candidateId: pending.candidate_id,
        disposition: "rejected",
        ...(section === "surfaces"
          ? { label: "Current source decision", notes: "Resolved locally." }
          : { pattern: "src/handler.ts", reason: "Resolved locally." }),
      });
      await recordCodexSecurityScanDraft(context, current);
      for (let attempt = 0; attempt < 2; attempt++) {
        const saved = await readCoverage(context);
        assert.equal(saved.completeness, "partial");
        assert.deepEqual(
          saved.surfaces.find((item) => item.id === evidence.id),
          evidence,
        );
        assert.equal(saved.deferred.length, shared ? 1 : 0);
        if (shared) {
          assert.equal(saved.deferred[0].sourceWorkerId, "other-worker");
          assert.deepEqual(saved.deferred[0].surfaceIds, [evidence.id]);
        }
        assert.ok(
          saved[section].some((item) => item.disposition === "rejected"),
        );
        await recordCodexSecurityScanDraft(context, {
          ...draft(),
          complete: false,
        });
      }
    });
  }
}

for (const authored of [false, true]) {
  test(`diff checkpoints refresh ledger evidence and ${authored ? "retain authored" : "update generated"} coverage`, async (t) => {
    const pending = candidate("updated-review");
    const context = await fixture(t, [pending]);
    const checkpoint = { ...draft(), complete: false };
    const authoredReason = "Retain the analyst's specific follow-up request.";
    const authoredNote = "Keep the analyst's candidate annotation.";
    const authoredSurface = {
      candidateId: pending.candidate_id,
      label: "Keep the analyst's review label.",
      disposition: "needs_follow_up",
      notes: "Keep the analyst's coverage annotation.",
    };
    if (authored) {
      checkpoint.coverage.completeness = "partial";
      checkpoint.coverage.surfaces.push(authoredSurface);
      checkpoint.coverage.deferred.push({
        candidateId: pending.candidate_id,
        reason: authoredReason,
        candidate: { ...pending, analystNote: authoredNote },
        notes: "A coverage annotation must also survive.",
      });
    }
    await recordCodexSecurityScanDraft(context, checkpoint);
    const validation = {
      ...pending,
      summary: "Updated candidate summary after validation.",
      evidence: "Updated source evidence after validation.",
      validation: {
        disposition: "deferred",
        counterevidence_or_proof_gap:
          "A synthetic validation input is missing.",
      },
    };
    const attackPath = {
      ...validation,
      summary: "Updated candidate summary after attack-path review.",
      evidence: "Updated source evidence after attack-path review.",
      attack_path: {
        decision: "deferred",
        proof_gap: "A synthetic deployment adapter is missing.",
      },
    };
    const rediscovered = {
      ...pending,
      summary: "Rediscovered candidate without phase records.",
      evidence: "New discovery evidence before phase review.",
    };
    for (const reviewed of [validation, attackPath, rediscovered]) {
      await writeLedger(context, [reviewed]);
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
      });
      const saved = await readCoverage(context);
      assert.equal(saved.completeness, "partial");
      assert.equal(saved.deferred.length, 1);
      const item = saved.deferred[0];
      assert.deepEqual(
        item.candidate,
        authored ? { ...reviewed, analystNote: authoredNote } : reviewed,
      );
      assert.equal(
        item.reason,
        authored
          ? authoredReason
          : (reviewed.attack_path?.proof_gap ??
              reviewed.validation?.counterevidence_or_proof_gap ??
              `Candidate review is incomplete: ${reviewed.summary}`),
      );
      assert.equal(
        saved.surfaces[0].label,
        authored ? authoredSurface.label : reviewed.summary,
      );
      assert.equal(
        saved.surfaces[0].notes,
        authored ? authoredSurface.notes : item.reason,
      );
      if (authored)
        assert.equal(item.notes, checkpoint.coverage.deferred[0].notes);
    }
  });
}

for (const uncertainty of ["  A runtime check is still required.\n", " \t "]) {
  test(`blank phase reasons preserve readable diff checkpoints: ${uncertainty.trim() ? "recorded uncertainty" : "fallback"}`, async (t) => {
    const pending = candidate("blank-reason");
    const context = await fixture(t, [pending]);
    const validation = {
      disposition: "deferred",
      method: "source review",
      confidence: "low",
      confidence_rationale: "The runtime behavior remains unverified.",
      rubric: "Source review",
      evidence: "Synthetic source evidence.",
      counterevidence_or_proof_gap: " \t\n ",
      remaining_uncertainty: uncertainty,
    };
    const accepted = await recordCodexSecurityCandidateValidations(context, {
      validations: [{ candidateId: pending.candidate_id, validation }],
    });
    assert.equal(accepted.rowsWritten, 1);

    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      complete: false,
    });
    await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });

    const saved = await readCoverage(context);
    const expectedReason = uncertainty.trim()
      ? uncertainty
      : `Candidate review is incomplete: ${pending.summary}`;
    assert.equal(saved.completeness, "partial");
    assert.equal(saved.deferred[0].reason, expectedReason);
    assert.equal(saved.surfaces[0].notes, expectedReason);
    assert.deepEqual(saved.deferred[0].candidate.validation, validation);
  });
}

for (const complete of [false, true]) {
  for (const inheritedFinal of [false, true]) {
    test(`explicit finding overrides survive repeated ${complete ? "final saves" : "checkpoints"}${inheritedFinal ? " after a final draft" : ""} until the ledger decision changes`, async (t) => {
      const reviewed = candidate("accepted-override", "suppressed");
      reviewed.validation.counterevidence_or_proof_gap =
        "Earlier synthetic decision.";
      const context = await fixture(t, [reviewed]);
      if (inheritedFinal) {
        const older = { ...draft(), complete: true };
        older.coverage.surfaces.push({
          candidateId: reviewed.candidate_id,
          label: "Older authored decision",
          disposition: "rejected",
          notes: "Earlier authored rationale.",
        });
        await recordCodexSecurityScanDraft(context, older);
      }
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete,
        findings: [finding(reviewed.candidate_id)],
      });
      const savedFindings = async () =>
        JSON.parse(
          await readFile(path.join(context.root, "findings.json"), "utf8"),
        ).findings;
      const expectedDecision = { validation: reviewed.validation };
      assert.deepEqual(
        (await savedFindings())[0].provenance.diffCandidateDecision,
        expectedDecision,
      );
      const checkpoints = await Promise.all(
        (await readdir(path.join(context.root, "checkpoints"))).map(
          async (name) =>
            JSON.parse(
              await readFile(
                path.join(context.root, "checkpoints", name),
                "utf8",
              ),
            ),
        ),
      );
      assert.ok(
        checkpoints.some((checkpoint) =>
          checkpoint.findings.some(
            (item) =>
              item.provenance.diffCandidateDecision?.validation
                ?.counterevidence_or_proof_gap ===
              "Earlier synthetic decision.",
          ),
        ),
      );
      for (const unrelated of [false, true, false]) {
        await recordCodexSecurityScanDraft(context, {
          ...draft(),
          complete,
          findings: unrelated
            ? [
                {
                  ...finding("unrelated-finding"),
                  identity: { anchor: "unrelated-finding" },
                },
              ]
            : [],
        });
        assert.equal(
          (await savedFindings()).filter(
            (item) => item.provenance.candidateId === reviewed.candidate_id,
          ).length,
          1,
        );
        assert.equal(
          (await readCoverage(context)).surfaces.some(
            (surface) =>
              surface.candidateId === reviewed.candidate_id &&
              surface.disposition === "rejected",
          ),
          false,
        );
      }
      const newer = {
        ...reviewed,
        validation: {
          disposition: "suppressed",
          counterevidence_or_proof_gap: "New synthetic decision evidence.",
        },
      };
      await writeLedger(context, [newer]);
      await recordCodexSecurityScanDraft(context, { ...draft(), complete });
      assert.equal(
        (await savedFindings()).some(
          (item) => item.provenance.candidateId === reviewed.candidate_id,
        ),
        false,
      );
      const terminal = (await readCoverage(context)).surfaces.find(
        (surface) => surface.candidateId === reviewed.candidate_id,
      );
      assert.equal(terminal.disposition, "rejected");
      assert.equal(
        terminal.notes,
        newer.validation.counterevidence_or_proof_gap,
      );
      assert.deepEqual(
        terminal.finding.provenance.diffCandidateDecision,
        expectedDecision,
      );
      await writeLedger(context, [reviewed]);
      await recordCodexSecurityScanDraft(context, { ...draft(), complete });
      assert.equal(
        (await savedFindings()).some(
          (item) => item.provenance.candidateId === reviewed.candidate_id,
        ),
        false,
      );
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
        findings: [finding(reviewed.candidate_id)],
      });
      const authored = { ...draft(), complete: true };
      authored.coverage.surfaces.push({
        candidateId: reviewed.candidate_id,
        label: "New authored decision",
        disposition: "not_applicable",
        notes: "A newer author decision supersedes the finding.",
      });
      await recordCodexSecurityScanDraft(context, authored);
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
      });
      assert.equal(
        (await savedFindings()).some(
          (item) => item.provenance.candidateId === reviewed.candidate_id,
        ),
        false,
      );
      assert.equal(
        (await readCoverage(context)).surfaces.find(
          (item) => item.candidateId === reviewed.candidate_id,
        ).notes,
        authored.coverage.surfaces[0].notes,
      );
    });
  }
}

for (const remaining of [
  "none",
  "authored",
  "shared",
  "generic",
  "explicit partial",
  "later partial",
  "later checkpoint partial",
  "unknown",
]) {
  test(`a checkpoint refreshes inherited final candidate coverage with ${remaining} work remaining`, async (t) => {
    const pending = candidate("inherited-pending");
    const context = await fixture(t, [pending]);
    const initial = { ...draft(), complete: true };
    if (
      ![
        "none",
        "later partial",
        "later checkpoint partial",
        "unknown",
      ].includes(remaining)
    )
      initial.coverage.completeness = "partial";
    if (remaining === "unknown") initial.coverage.completeness = "unknown";
    if (remaining === "authored" || remaining === "shared")
      initial.coverage.surfaces.push({
        id: "review-surface",
        candidateId: pending.candidate_id,
        label: pending.summary,
        disposition: "needs_follow_up",
        notes:
          remaining === "authored"
            ? "Authored follow-up evidence."
            : `Candidate review is incomplete: ${pending.summary}`,
        receiptRefs: ["artifacts/review/synthetic-receipt.json"],
      });
    if (remaining === "shared")
      initial.coverage.deferred.push({
        candidateId: "separate-review",
        reason: "The shared review is unfinished.",
        surfaceIds: ["review-surface"],
      });
    if (remaining === "generic")
      initial.coverage.deferred.push({
        reason: "General source review remains unfinished.",
      });
    await recordCodexSecurityScanDraft(context, initial);
    assert.equal(
      (await readCoverage(context)).completenessBeforeCandidates,
      remaining === "unknown"
        ? "unknown"
        : ["none", "later partial", "later checkpoint partial"].includes(
              remaining,
            )
          ? "complete"
          : undefined,
    );
    if (
      remaining === "later partial" ||
      remaining === "later checkpoint partial"
    ) {
      const authored = { ...draft(), complete: remaining === "later partial" };
      authored.coverage.completeness = "partial";
      await recordCodexSecurityScanDraft(context, authored);
      assert.equal(
        (await readCoverage(context)).completenessBeforeCandidates,
        undefined,
      );
    }
    await writeLedger(context, [
      { ...pending, validation: { disposition: "suppressed" } },
    ]);
    for (let attempt = 0; attempt < 2; attempt++) {
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: false,
      });
      const saved = await readCoverage(context);
      assert.equal(
        saved.completeness,
        remaining === "none"
          ? "complete"
          : remaining === "unknown"
            ? "unknown"
            : "partial",
      );
      assert.equal(saved.completenessBeforeCandidates, undefined);
      assert.equal(
        saved.deferred.some(
          (item) => item.candidateId === pending.candidate_id,
        ),
        false,
      );
      assert.equal(
        saved.surfaces.filter(
          (item) =>
            item.candidateId === pending.candidate_id &&
            item.disposition === "rejected",
        ).length,
        1,
      );
      if (remaining === "none") assert.equal(saved.surfaces.length, 1);
      if (remaining === "authored" || remaining === "shared") {
        const surface = saved.surfaces.find(
          (item) => item.id === "review-surface",
        );
        assert.equal(surface.disposition, "needs_follow_up");
        assert.deepEqual(
          surface.receiptRefs,
          initial.coverage.surfaces[0].receiptRefs,
        );
        assert.equal(surface.notes, initial.coverage.surfaces[0].notes);
      }
    }
  });
}

for (const resolution of ["surface", "exclusion", "finding"]) {
  test(`Diff ${resolution} resolution retains the same candidate ID owned by another worker`, async (t) => {
    const pending = candidate("shared-candidate-id");
    const context = await fixture(t, [pending]);
    const initial = { ...draft(), complete: true };
    initial.coverage.completeness = "partial";
    const decision = {
      candidateId: pending.candidate_id,
      sourceWorkerId: "other-worker",
      label: "Imported review",
      disposition: "rejected",
      notes: "The imported candidate was dismissed.",
    };
    if (resolution === "surface") initial.coverage.surfaces.push(decision);
    if (resolution === "exclusion")
      initial.coverage.explicitExclusions.push({
        ...decision,
        pattern: "src/imported.ts",
        reason: decision.notes,
      });
    if (resolution === "finding") {
      const imported = finding(pending.candidate_id);
      imported.provenance.sourceWorkerId = "other-worker";
      initial.findings.push(imported);
    }
    initial.coverage.deferred.push({
      candidateId: pending.candidate_id,
      sourceWorkerId: "pending-worker",
      reason: "Independent candidate evidence must remain.",
      analystNote: "Keep the imported annotation.",
    });
    await recordCodexSecurityScanDraft(context, initial);
    let saved = await readCoverage(context);
    assert.deepEqual(
      saved.deferred.map((item) => item.sourceWorkerId ?? null).sort(),
      [null, "pending-worker"].sort(),
    );
    assert.deepEqual(
      saved.deferred.find((item) => item.sourceWorkerId === undefined)
        .candidate,
      pending,
    );
    await writeLedger(context, [
      { ...pending, validation: { disposition: "suppressed" } },
    ]);
    for (let attempt = 0; attempt < 2; attempt++) {
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: false,
      });
      saved = await readCoverage(context);
      assert.equal(saved.deferred.length, 1);
      assert.equal(saved.deferred[0].sourceWorkerId, "pending-worker");
      assert.equal(
        saved.deferred[0].analystNote,
        "Keep the imported annotation.",
      );
      assert.equal(
        saved.deferred[0].reason,
        "Independent candidate evidence must remain.",
      );
      if (resolution === "finding") {
        const findings = JSON.parse(
          await readFile(path.join(context.root, "findings.json"), "utf8"),
        ).findings;
        assert.equal(findings.length, 1);
        assert.equal(findings[0].provenance.sourceWorkerId, "other-worker");
      }
    }
  });
}

for (const validation of ["deferred", undefined]) {
  test(`changed ${validation ?? "removed"} ledger phases reopen an explicit finding override`, async (t) => {
    const reviewed = candidate("reopened-override", "suppressed", "ignore");
    const context = await fixture(t, [reviewed]);
    const older = { ...draft(), complete: true };
    older.coverage.surfaces.push({
      candidateId: reviewed.candidate_id,
      label: "Older authored review",
      disposition: "rejected",
      notes: "An authored decision before the accepted finding.",
    });
    await recordCodexSecurityScanDraft(context, older);
    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      complete: true,
      findings: [finding(reviewed.candidate_id)],
    });
    const reopened = candidate(reviewed.candidate_id, validation);
    await writeLedger(context, [reopened]);
    for (const complete of [false, true, false]) {
      await recordCodexSecurityScanDraft(context, { ...draft(), complete });
      const saved = await readCoverage(context);
      assert.equal(saved.completeness, "partial");
      assert.equal(saved.deferred.length, 1);
      assert.deepEqual(saved.deferred[0].candidate, reopened);
      assert.equal(
        saved.deferred[0].finding.provenance.candidateId,
        reviewed.candidate_id,
      );
      assert.equal(
        JSON.parse(
          await readFile(path.join(context.root, "findings.json"), "utf8"),
        ).findings.length,
        0,
      );
    }
  });
}

test("owned surface references survive canonical ID collisions and local resolution", async (t) => {
  const local = candidate("local-review");
  const context = await fixture(t, [local]);
  const initial = draft([
    {
      candidateId: local.candidate_id,
      reason: "Local review.",
      surfaceIds: ["review-surface", "shared-evidence"],
    },
    {
      candidateId: "imported-review",
      sourceWorkerId: "other-worker",
      reason: "Independent imported review.",
      surfaceIds: ["review-surface", "shared-evidence"],
    },
  ]);
  initial.complete = true;
  initial.coverage.completeness = "partial";
  initial.coverage.surfaces = [
    {
      id: "review-surface",
      candidateId: local.candidate_id,
      label: "Local boundary",
      disposition: "needs_follow_up",
      notes: "Local source evidence.",
    },
    {
      id: "review-surface",
      sourceWorkerId: "other-worker",
      label: "Imported boundary",
      disposition: "needs_follow_up",
      notes: "Independent imported evidence.",
      receiptRefs: ["artifacts/review/imported.json"],
    },
    {
      id: "shared-evidence",
      sourceWorkerId: "evidence-worker",
      label: "Shared evidence boundary",
      disposition: "needs_follow_up",
      notes: "Both owners explicitly reference this unique surface.",
      receiptRefs: ["artifacts/review/shared.json"],
    },
  ];
  await recordCodexSecurityScanDraft(context, initial);
  const first = await readCoverage(context);
  const importedSurface = first.surfaces.find(
    (item) => item.sourceWorkerId === "other-worker",
  );
  assert.notEqual(
    importedSurface.id,
    first.surfaces.find((item) => item.sourceWorkerId === undefined).id,
  );
  assert.deepEqual(
    first.deferred.find((item) => item.sourceWorkerId === "other-worker")
      .surfaceIds,
    [importedSurface.id, "shared-evidence"],
  );
  await writeLedger(context, [
    { ...local, validation: { disposition: "suppressed" } },
  ]);
  for (const complete of [true, false, true]) {
    await recordCodexSecurityScanDraft(context, { ...draft(), complete });
    const saved = await readCoverage(context);
    const imported = saved.surfaces.find(
      (item) => item.sourceWorkerId === "other-worker",
    );
    assert.equal(
      saved.surfaces.filter((item) => item.sourceWorkerId === "other-worker")
        .length,
      1,
    );
    assert.equal(saved.deferred.length, 1);
    assert.deepEqual(imported, importedSurface);
    assert.deepEqual(saved.deferred[0].surfaceIds, [
      imported.id,
      "shared-evidence",
    ]);
    assert.deepEqual(
      saved.surfaces.find((item) => item.id === "shared-evidence"),
      first.surfaces.find((item) => item.id === "shared-evidence"),
    );
    assert.equal(saved.deferred[0].sourceWorkerId, "other-worker");
  }
});

for (const complete of [false, true]) {
  test(`id-less ${complete ? "final drafts" : "checkpoints"} retain same-label surfaces with distinct risk areas`, async (t) => {
    const context = await fixture(t, []);
    const unfinished = {
      label: "Access review",
      riskArea: "administrative-api",
      disposition: "needs_follow_up",
      notes: "The administrative boundary still needs evidence.",
      receiptRefs: ["artifacts/review/administrative.json"],
    };
    const reviewed = {
      label: unfinished.label,
      riskArea: "public-api",
      disposition: "no_issue_found",
      notes: "The public boundary review is complete.",
      receiptRefs: ["artifacts/review/public.json"],
    };
    const first = { ...draft(), complete };
    first.coverage.completeness = "partial";
    first.coverage.surfaces.push(unfinished);
    await recordCodexSecurityScanDraft(context, first);
    const second = { ...draft(), complete };
    second.coverage.surfaces.push(reviewed);
    await recordCodexSecurityScanDraft(context, second);
    const expected = await readCoverage(context);
    assert.equal(expected.completeness, "partial");
    assert.equal(expected.surfaces.length, 2);
    assert.equal(
      new Set(expected.surfaces.map((surface) => surface.id)).size,
      2,
    );
    for (const original of [unfinished, reviewed]) {
      const { id: _id, ...saved } = expected.surfaces.find(
        (surface) => surface.riskArea === original.riskArea,
      );
      assert.deepEqual(saved, original);
    }
    for (const nextComplete of [false, true, false]) {
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: nextComplete,
      });
      const saved = await readCoverage(context);
      assert.equal(saved.completeness, "partial");
      assert.deepEqual(saved.surfaces, expected.surfaces);
    }
    for (const name of await readdir(path.join(context.root, "checkpoints"))) {
      const checkpoint = JSON.parse(
        await readFile(path.join(context.root, "checkpoints", name), "utf8"),
      );
      assert.ok(
        checkpoint.coverage.surfaces.every(
          (surface) => surface.id === undefined,
        ),
      );
    }
  });
}

for (const remaining of [
  "authored",
  "shared pending",
  "shared confirmed",
  "explicit partial",
  "unknown",
]) {
  test(`confirmation checkpoints preserve ${remaining} coverage`, async (t) => {
    const pending = candidate("confirmed-coverage");
    const shared = remaining.startsWith("shared");
    const sibling = candidate("shared-review");
    const context = await fixture(t, shared ? [pending, sibling] : [pending]);
    const initial = { ...draft(), complete: true };
    if (remaining === "unknown") initial.coverage.completeness = "unknown";
    else initial.coverage.completeness = "partial";
    if (remaining === "authored" || shared)
      initial.coverage.surfaces.push({
        id: "review-evidence",
        candidateId: pending.candidate_id,
        label: pending.summary,
        disposition: "needs_follow_up",
        notes:
          remaining === "authored"
            ? "Keep this authored follow-up request."
            : `Candidate review is incomplete: ${pending.summary}`,
        receiptRefs: ["artifacts/review/retained.json"],
      });
    if (shared)
      initial.coverage.deferred.push({
        candidateId: sibling.candidate_id,
        reason: "The sibling review shares the source evidence.",
        surfaceIds: ["review-evidence"],
      });
    await recordCodexSecurityScanDraft(context, initial);
    const current = {
      ...draft(),
      complete: false,
      findings: [finding(pending.candidate_id)],
    };
    if (remaining === "shared confirmed")
      current.findings.push({
        ...finding(sibling.candidate_id),
        identity: { anchor: "shared-review" },
      });
    await recordCodexSecurityScanDraft(context, current);
    for (let attempt = 0; attempt < 2; attempt++) {
      const saved = await readCoverage(context);
      assert.equal(
        saved.completeness,
        remaining === "unknown" ? "unknown" : "partial",
      );
      assert.equal(
        saved.deferred.length,
        remaining === "shared pending" ? 1 : 0,
      );
      const surface = saved.surfaces.find(
        (item) => item.candidateId === pending.candidate_id,
      );
      assert.equal(
        surface.disposition,
        remaining === "authored" || remaining === "shared pending"
          ? "needs_follow_up"
          : "reported",
      );
      if (remaining === "authored" || shared) {
        assert.deepEqual(
          surface.receiptRefs,
          initial.coverage.surfaces[0].receiptRefs,
        );
        assert.equal(
          surface.notes,
          remaining === "shared confirmed"
            ? current.findings[0].summary
            : initial.coverage.surfaces[0].notes,
        );
      }
      assert.equal(
        JSON.parse(
          await readFile(path.join(context.root, "findings.json"), "utf8"),
        ).findings.length,
        remaining === "shared confirmed" ? 2 : 1,
      );
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: false,
      });
    }
  });
}

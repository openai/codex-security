import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
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
import { isDeepStrictEqual } from "node:util";

import { importSource } from "./import-module.ts";
import type { TestContext } from "node:test";
import type { ArtifactContext } from "../src/artifact-context.js";
type FixtureObject = Record<string, any>;
type FixtureDraft = {
  scanId: string;
  complete?: boolean;
  findings: FixtureObject[];
  coverage: FixtureObject;
};
const loadModule = (file: string) =>
  importSource(new URL(`../src/${file}`, import.meta.url).pathname);

const {
  preserveDiffCandidateDecisions,
  preserveUnresolvedDiffCandidates,
  readDiffCandidates,
} = await loadModule("artifact-diff-candidates.ts");
const { recordCodexSecurityScanDraft, recordCodexSecurityWorkerScanDraft } =
  await loadModule("artifact-scan-draft.ts");
const { discoveryReductionInput, reconcileDeepReduction } = await loadModule(
  "deep-scan/artifact-validation.ts",
);
const { recordCodexSecurityCandidateValidations } = await loadModule(
  "artifact-validation-phase.ts",
);

for (const complete of [false, true]) {
  for (const currentTerminal of [false, true]) {
    test(`unmarked saved findings survive diff replay (${complete ? "final" : "checkpoint"}, ${currentTerminal ? "new decision" : "empty"})`, async (t) => {
      const reviewed = candidate("legacy-accepted", "suppressed");
      const context = await fixture(t, [reviewed]);
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete,
        findings: [finding(reviewed.candidate_id)],
      });
      const findingsPath = path.join(context.root, "findings.json");
      const saved = JSON.parse(await readFile(findingsPath, "utf8"));
      delete saved.findings[0].provenance.diffCandidateDecision;
      await writeFile(findingsPath, JSON.stringify(saved));
      const checkpoints = path.join(context.root, "checkpoints");
      for (const name of await readdir(checkpoints)) {
        const file = path.join(checkpoints, name);
        const checkpoint = JSON.parse(await readFile(file, "utf8"));
        for (const previous of checkpoint.findings ?? [])
          delete previous.provenance.diffCandidateDecision;
        await writeFile(file, JSON.stringify(checkpoint));
      }
      const next = { ...draft(), complete };
      if (currentTerminal)
        next.coverage.surfaces.push({
          candidateId: reviewed.candidate_id,
          label: "Current authored decision",
          disposition: "rejected",
          notes: "A new review supersedes the saved finding.",
        });
      await recordCodexSecurityScanDraft(context, next);
      const actual = JSON.parse(await readFile(findingsPath, "utf8"));
      assert.equal(actual.findings.length, currentTerminal ? 0 : 1);
      if (!currentTerminal)
        assert.equal(
          actual.findings[0].provenance.candidateId,
          reviewed.candidate_id,
        );
    });
  }
}

async function reconcileDiffCandidates(
  context: ArtifactContext,
  input: FixtureDraft,
) {
  const candidates = await readDiffCandidates(context);
  return preserveUnresolvedDiffCandidates(
    preserveDiffCandidateDecisions(input, candidates),
    candidates,
  );
}

async function writeLedger(
  context: { root: string },
  candidates: FixtureObject[],
) {
  const directory = path.join(context.root, "artifacts", "02_discovery");
  await mkdir(directory, { recursive: true });
  await writeFile(
    path.join(directory, "candidate_ledger.jsonl"),
    candidates.map((row) => JSON.stringify(row)).join("\n"),
  );
}

async function readCoverage(context: { root: string }) {
  return JSON.parse(
    await readFile(path.join(context.root, "coverage.json"), "utf8"),
  );
}

function finding(candidateId: string): FixtureObject {
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

function candidate(
  candidateId: string,
  validation?: unknown,
  attackPath?: unknown,
): FixtureObject {
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

function draft(deferred: FixtureObject[] = []): FixtureDraft {
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

async function fixture(
  t: TestContext,
  candidates?: FixtureObject[],
): Promise<ArtifactContext> {
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

test("Diff candidate recovery preserves generic review closeout", async (t) => {
  const pending = candidate("pending-review");
  const context = await fixture(t, [pending]);
  const first = draft([
    {
      id: "ordinary-review",
      reason: "Review the caller.",
      surfaceIds: ["caller"],
    },
  ]);
  first.complete = false;
  first.coverage.completeness = "partial";
  first.coverage.surfaces = [
    {
      id: "caller",
      label: "Caller",
      disposition: "needs_follow_up",
      receiptRefs: ["artifacts/review/caller.json"],
    },
  ];
  await recordCodexSecurityScanDraft(context, first);
  const closed = draft();
  closed.coverage.resolvedDeferred = [
    { id: "ordinary-review", reason: "Caller review is complete." },
  ];
  closed.coverage.surfaces = [
    {
      id: "caller",
      label: "Caller",
      disposition: "no_issue_found",
      receiptRefs: [],
    },
  ];
  await recordCodexSecurityScanDraft(context, closed);
  for (const complete of [false, true]) {
    const saved = await readCoverage(context);
    assert.deepEqual(
      saved.deferred.map((item: FixtureObject) => item.candidateId),
      [pending.candidate_id],
    );
    assert.deepEqual(saved.resolvedDeferred, closed.coverage.resolvedDeferred);
    const caller = saved.surfaces.find(
      (surface: FixtureObject) => surface.id === "caller",
    );
    assert.equal(caller.disposition, "no_issue_found");
    assert.deepEqual(
      caller.receiptRefs,
      first.coverage.surfaces[0].receiptRefs,
    );
    await recordCodexSecurityScanDraft(context, { ...draft(), complete });
  }
});

for (const disposition of ["deferred", "not_applicable"]) {
  for (const authored of [false, true]) {
    test(`resubmitted canonical coverage ${authored ? "retains authored" : "refreshes generated"} decisions after ${disposition}`, async (t) => {
      const initial = candidate("resubmitted-review", "suppressed");
      initial.validation.counterevidence_or_proof_gap =
        "Earlier generated decision.";
      const context = await fixture(t, [initial]);
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
      });
      const coverage = await readCoverage(context);
      assert.equal(coverage.mode, "branch_diff");
      assert.equal(coverage.inventoryStrategy, "diff");
      assert.deepEqual(coverage.includePaths, ["."]);
      if (authored) coverage.surfaces[0].notes = "Keep this authored decision.";
      const current = {
        ...initial,
        summary: "Updated review summary.",
        validation: {
          disposition,
          counterevidence_or_proof_gap: "Current review evidence.",
        },
      };
      await writeLedger(context, [current]);
      const {
        mode: _mode,
        includePaths: _includePaths,
        excludePaths: _excludePaths,
        receiptRefs: _receiptRefs,
        inventoryStrategy: _inventoryStrategy,
        ...semanticCoverage
      } = coverage;
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        coverage: semanticCoverage,
        complete: true,
      });
      const saved = await readCoverage(context);
      assert.equal(
        saved.deferred.length,
        !authored && disposition === "deferred" ? 1 : 0,
      );
      assert.equal(
        saved.surfaces[0].disposition,
        authored
          ? "rejected"
          : disposition === "deferred"
            ? "needs_follow_up"
            : "not_applicable",
      );
      assert.equal(
        saved.surfaces[0].notes,
        authored ? "Keep this authored decision." : "Current review evidence.",
      );
      if (!authored) assert.deepEqual(saved.surfaces[0].candidate, current);
    });
  }
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
    result.coverage.deferred.map((item: FixtureObject) => item.candidateId),
    expected.map((item: FixtureObject) => item.candidate_id),
  );
  assert.deepEqual(
    result.coverage.deferred.map((item: FixtureObject) => item.candidate),
    expected,
  );
  assert.equal(result.coverage.completeness, "partial");
  assert.deepEqual(
    result.coverage.surfaces.filter(
      (item: FixtureObject) => item.disposition === "needs_follow_up",
    ),
    expected.map((item: FixtureObject) => ({
      candidateId: item.candidate_id,
      label: item.summary,
      disposition: "needs_follow_up",
      notes: result.coverage.deferred.find(
        (pending: FixtureObject) => pending.candidateId === item.candidate_id,
      ).reason,
    })),
  );
  assert.deepEqual(
    result.coverage.surfaces
      .filter((item: FixtureObject) => item.disposition !== "needs_follow_up")
      .map((item: FixtureObject) => [item.candidateId, item.disposition]),
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
      projected.deferred.find((item: FixtureObject) => item.id === general.id),
      general,
    );
    assert.equal(projected.deferred.length, 2);
    assert.equal(
      projected.surfaces.filter(
        (item: FixtureObject) =>
          item.candidateId === pending.candidate_id &&
          item.disposition === "needs_follow_up",
      ).length,
      1,
    );
    assert.deepEqual(
      projected.surfaces.find((item: FixtureObject) => item.id === surface.id),
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
        saved.surfaces.find((item: FixtureObject) => item.id === surface.id),
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
        ({ candidateId, sourceWorkerId }: FixtureObject) => ({
          candidateId,
          sourceWorkerId,
        }),
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
  assert.deepEqual(await reconcileDiffCandidates(context, input), {
    ...input,
    findings: [
      { ...input.findings[0], provenance: { diffCandidateDecision: {} } },
    ],
  });
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
        (item: FixtureObject) => item.candidateId === pending.candidate_id,
      ),
    );
    assert.ok(
      savedCheckpoint.surfaces.some(
        (item: FixtureObject) =>
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
      saved.deferred.some(
        (item: FixtureObject) => item.candidateId === pending.candidate_id,
      ),
      false,
    );
    assert.equal(
      saved.surfaces.some(
        (item: FixtureObject) =>
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
          (item: FixtureObject) => item.candidateId === pending.candidate_id,
        ),
        false,
      );
      assert.deepEqual(
        saved.surfaces
          .filter(
            (surface: FixtureObject) =>
              surface.disposition === "needs_follow_up",
          )
          .map((surface: FixtureObject) => surface.id),
        remaining === "generic gap"
          ? ["generic-boundary"]
          : shared || remaining === "current follow-up"
            ? [linkedSurface.id]
            : [],
      );
      if (shared) {
        const retainedSurface = saved.surfaces.find(
          (surface: FixtureObject) => surface.id === linkedSurface.id,
        );
        assert.equal(retainedSurface.notes, linkedSurface.notes);
        assert.deepEqual(
          retainedSurface.receiptRefs,
          linkedSurface.receiptRefs,
        );
        assert.deepEqual(
          saved.deferred.map((item: FixtureObject) => item.candidateId),
          [other.candidate_id],
        );
      }
      if (remaining === "generic gap") assert.equal(saved.deferred.length, 1);
      if (remaining === "current follow-up") {
        assert.equal(
          saved.surfaces.find(
            (surface: FixtureObject) => surface.id === linkedSurface.id,
          ).notes,
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
        saved.surfaces.map((item: FixtureObject) => [
          item.candidateId,
          item.disposition,
        ]),
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
          finalDraft.coverage.deferred.map((item: FixtureObject) => ({
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
          (item: FixtureObject) => item.reason === earlierExclusion.reason,
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
        saved.deferred.map((item: FixtureObject) => item.candidateId),
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
        const reviewed: FixtureObject = {
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
  ["not_applicable", "ignore", "not_applicable"],
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
    if (terminal.attack_path)
      terminal.attack_path.counterevidence =
        validation === "not_applicable"
          ? "Earlier attack-path rejection."
          : reason;
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

for (const authored of [false, true]) {
  test(`reopens legacy terminal rationale without overriding authored evidence: ${authored}`, async (t) => {
    const previous = candidate("legacy-terminal", "not_applicable", "ignore");
    previous.validation.counterevidence_or_proof_gap = "Validation evidence.";
    previous.attack_path.counterevidence = "Earlier attack-path evidence.";
    const context = await fixture(t, [previous]);
    await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });
    const coverage = await readCoverage(context);
    coverage.surfaces[0].notes = authored
      ? "Independent authored evidence."
      : previous.attack_path.counterevidence;
    await writeFile(
      path.join(context.root, "coverage.json"),
      JSON.stringify(coverage),
    );
    await writeLedger(context, [candidate(previous.candidate_id, "deferred")]);
    for (const complete of [false, true]) {
      await recordCodexSecurityScanDraft(context, { ...draft(), complete });
      const saved = await readCoverage(context);
      assert.equal(saved.completeness, authored ? "complete" : "partial");
      assert.equal(saved.deferred.length, authored ? 0 : 1);
      assert.equal(
        saved.surfaces[0].disposition,
        authored ? "not_applicable" : "needs_follow_up",
      );
      if (authored)
        assert.equal(saved.surfaces[0].notes, coverage.surfaces[0].notes);
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
        (surface: FixtureObject) => surface.disposition !== "needs_follow_up",
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
          (surface: FixtureObject) => surface.disposition !== "needs_follow_up",
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
      const decision: FixtureObject = {
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
          saved.surfaces.find((item: FixtureObject) => item.id === evidence.id),
          evidence,
        );
        assert.equal(saved.deferred.length, shared ? 1 : 0);
        if (shared) {
          assert.equal(saved.deferred[0].sourceWorkerId, "other-worker");
          assert.deepEqual(saved.deferred[0].surfaceIds, [evidence.id]);
        }
        assert.ok(
          saved[section].some(
            (item: FixtureObject) => item.disposition === "rejected",
          ),
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
    const validation: FixtureObject = {
      ...pending,
      summary: "Updated candidate summary after validation.",
      evidence: "Updated source evidence after validation.",
      validation: {
        disposition: "deferred",
        counterevidence_or_proof_gap:
          "A synthetic validation input is missing.",
      },
    };
    const attackPath: FixtureObject = {
      ...validation,
      summary: "Updated candidate summary after attack-path review.",
      evidence: "Updated source evidence after attack-path review.",
      attack_path: {
        decision: "deferred",
        proof_gap: "A synthetic deployment adapter is missing.",
      },
    };
    const rediscovered: FixtureObject = {
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
    const validation: FixtureObject = {
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
            (item: FixtureObject) =>
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
            (item: FixtureObject) =>
              item.provenance.candidateId === reviewed.candidate_id,
          ).length,
          1,
        );
        assert.equal(
          (await readCoverage(context)).surfaces.some(
            (surface: FixtureObject) =>
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
          (item: FixtureObject) =>
            item.provenance.candidateId === reviewed.candidate_id,
        ),
        false,
      );
      const terminal = (await readCoverage(context)).surfaces.find(
        (surface: FixtureObject) =>
          surface.candidateId === reviewed.candidate_id,
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
          (item: FixtureObject) =>
            item.provenance.candidateId === reviewed.candidate_id,
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
          (item: FixtureObject) =>
            item.provenance.candidateId === reviewed.candidate_id,
        ),
        false,
      );
      assert.equal(
        (await readCoverage(context)).surfaces.find(
          (item: FixtureObject) => item.candidateId === reviewed.candidate_id,
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
          (item: FixtureObject) => item.candidateId === pending.candidate_id,
        ),
        false,
      );
      assert.equal(
        saved.surfaces.filter(
          (item: FixtureObject) =>
            item.candidateId === pending.candidate_id &&
            item.disposition === "rejected",
        ).length,
        1,
      );
      if (remaining === "none") assert.equal(saved.surfaces.length, 1);
      if (remaining === "authored" || remaining === "shared") {
        const surface = saved.surfaces.find(
          (item: FixtureObject) => item.id === "review-surface",
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
    const decision: FixtureObject = {
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
      saved.deferred
        .map((item: FixtureObject) => item.sourceWorkerId ?? null)
        .sort(),
      [null, "pending-worker"].sort(),
    );
    assert.deepEqual(
      saved.deferred.find(
        (item: FixtureObject) => item.sourceWorkerId === undefined,
      ).candidate,
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
    (item: FixtureObject) => item.sourceWorkerId === "other-worker",
  );
  assert.notEqual(
    importedSurface.id,
    first.surfaces.find(
      (item: FixtureObject) => item.sourceWorkerId === undefined,
    ).id,
  );
  assert.deepEqual(
    first.deferred.find(
      (item: FixtureObject) => item.sourceWorkerId === "other-worker",
    ).surfaceIds,
    [importedSurface.id, "shared-evidence"],
  );
  await writeLedger(context, [
    { ...local, validation: { disposition: "suppressed" } },
  ]);
  for (const complete of [true, false, true]) {
    await recordCodexSecurityScanDraft(context, { ...draft(), complete });
    const saved = await readCoverage(context);
    const imported = saved.surfaces.find(
      (item: FixtureObject) => item.sourceWorkerId === "other-worker",
    );
    assert.equal(
      saved.surfaces.filter(
        (item: FixtureObject) => item.sourceWorkerId === "other-worker",
      ).length,
      1,
    );
    assert.equal(saved.deferred.length, 1);
    assert.deepEqual(imported, importedSurface);
    assert.deepEqual(saved.deferred[0].surfaceIds, [
      imported.id,
      "shared-evidence",
    ]);
    assert.deepEqual(
      saved.surfaces.find(
        (item: FixtureObject) => item.id === "shared-evidence",
      ),
      first.surfaces.find(
        (item: FixtureObject) => item.id === "shared-evidence",
      ),
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
    const reviewed: FixtureObject = {
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
      new Set(expected.surfaces.map((surface: FixtureObject) => surface.id))
        .size,
      2,
    );
    for (const original of [unfinished, reviewed]) {
      const { id: _id, ...saved } = expected.surfaces.find(
        (surface: FixtureObject) => surface.riskArea === original.riskArea,
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
          (surface: FixtureObject) =>
            surface.id === undefined ||
            surface.id ===
              expected.surfaces.find(
                (saved: FixtureObject) => saved.riskArea === surface.riskArea,
              )?.id,
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
        (item: FixtureObject) => item.candidateId === pending.candidate_id,
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

for (const legacy of [true, false]) {
  for (const resolution of ["finding", "rejected"] as const) {
    test(`loaded payload-linked deferral legacy=${legacy} resolves ${resolution}`, async (t) => {
      const context = await fixture(t);
      const evidence = {
        candidate_id: "saved-review",
        evidence: "Retain saved candidate evidence.",
      };
      const initial = {
        ...draft([
          {
            id: "saved-review",
            candidateId: "saved-review",
            candidate: evidence,
            reason: "Saved proof gap.",
            analystNote: "Saved annotation.",
          },
        ]),
        complete: false,
      };
      initial.coverage.completeness = "partial";
      await recordCodexSecurityScanDraft(context, initial);
      if (legacy) {
        const coveragePath = path.join(context.root, "coverage.json");
        const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
        coverage.deferred.forEach(
          (row: FixtureObject) => delete row.candidateId,
        );
        await writeFile(coveragePath, JSON.stringify(coverage));
        for (const name of await readdir(
          path.join(context.root, "checkpoints"),
        )) {
          const checkpointPath = path.join(context.root, "checkpoints", name);
          const checkpoint = JSON.parse(await readFile(checkpointPath, "utf8"));
          checkpoint.coverage.deferred.forEach(
            (row: FixtureObject) => delete row.candidateId,
          );
          await writeFile(checkpointPath, JSON.stringify(checkpoint));
        }
      }
      const next = { ...draft(), complete: true };
      if (resolution === "finding") next.findings = [finding("saved-review")];
      else
        next.coverage.surfaces.push({
          candidateId: "saved-review",
          label: "Current review",
          disposition: "rejected",
          notes: "Resolved saved candidate.",
        });
      await recordCodexSecurityScanDraft(context, next);
      const saved = await readCoverage(context);
      assert.equal(saved.deferred.length, 0);
      const savedFindings = JSON.parse(
        await readFile(path.join(context.root, "findings.json"), "utf8"),
      );
      assert.ok(
        JSON.stringify(
          resolution === "finding" ? savedFindings : saved.surfaces,
        ).includes(evidence.evidence),
      );
    });
  }
}

for (const legacyId of ["review/auth", "review\\auth", "review-auth"]) {
  test(`legacy task ID remains readable ${legacyId}`, async (t) => {
    const context = await fixture(t);
    const initial = {
      ...draft([
        {
          id: legacyId,
          candidate: { evidence: "Saved legacy payload." },
          reason: "Pending validation.",
        },
      ]),
      complete: false,
    };
    initial.coverage.completeness = "partial";
    await recordCodexSecurityScanDraft(context, initial);
    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      complete: false,
    });
    const saved = await readCoverage(context);
    assert.equal(saved.deferred[0].id, legacyId);
    assert.equal(saved.deferred[0].candidate.evidence, "Saved legacy payload.");
  });
}

for (const changed of [true, false]) {
  test(`reopened sibling findings retain all evidence changed=${changed}`, async (t) => {
    const reviewed = candidate("sibling-review", "reportable");
    const context = await fixture(t, [reviewed]);
    const first = {
      ...finding(reviewed.candidate_id),
      identity: { anchor: "shared-anchor", instance: "first" },
      summary: "First saved sibling evidence.",
    };
    const second = {
      ...finding(reviewed.candidate_id),
      identity: { anchor: "shared-anchor", instance: "second" },
      summary: "Second saved sibling evidence.",
    };
    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      complete: true,
      findings: [first, second],
    });
    if (changed)
      await writeLedger(context, [
        candidate(reviewed.candidate_id, "deferred"),
      ]);
    for (let attempt = 0; attempt < 2; attempt++) {
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: false,
      });
      const text = changed
        ? JSON.stringify((await readCoverage(context)).deferred)
        : await readFile(path.join(context.root, "findings.json"), "utf8");
      assert.ok(text.includes(first.summary));
      assert.ok(text.includes(second.summary));
    }
  });
}

for (const sharedCandidate of [true, false]) {
  test(`Deep reduction retains distinct proof gaps sharedCandidate=${sharedCandidate}`, () => {
    const rows = [
      {
        id: "first-gap",
        candidateId: "same-review",
        sourceWorkerId: "worker-one",
        reason: "First proof gap.",
        candidate: { evidence: "First source evidence." },
      },
      {
        id: "second-gap",
        candidateId: sharedCandidate ? "same-review" : "different-review",
        sourceWorkerId: "worker-one",
        reason: "Second proof gap.",
        candidate: { evidence: "Second source evidence." },
      },
    ];
    const discovery = {
      ...draft(),
      complete: true,
      unresolvedCandidates: rows,
    };
    delete (discovery as FixtureObject).coverage;
    const reducer = { ...draft(), complete: true };
    delete (reducer as FixtureObject).coverage;
    const actual = reconcileDeepReduction(
      reducer,
      [{ workerId: "worker-one", result: discovery }],
      null,
    );
    assert.deepEqual(actual.unresolvedCandidates, rows);
  });
}

const { recordCodexSecurityScanDraftViaWorkbench } = await loadModule(
  "artifact-scan-draft.ts",
);
const { createScanArtifactContext } = await loadModule("artifact-context.ts");
async function workbenchDiffFixture(t: TestContext) {
  const directory = await fixture(t);
  const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
  const python = process.env.PYTHON?.trim() || "python3";
  const initialized = JSON.parse(
    execFileSync(
      python,
      [
        "-c",
        `
import json, sys, uuid
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from workbench_test_support import initialize_git_repository, run_workbench, start_delivered_scan
root = Path(sys.argv[2])
state, target = root / "state", root / "target"
revision = initialize_git_repository(target)
workspace = str(uuid.uuid4())
run_workbench(state, "create-workspace", "--workspace-id", workspace)
run_workbench(state, "save-workspace", "--workspace-id", workspace, "--target-path", str(target),
          "--scope", ".", "--mode", "diff", "--diff-target-kind", "commit", "--diff-head-revision", revision)
started = start_delivered_scan(state, "--workspace-id", workspace, "--scan-root", str(root / "scans"))["results"]
print(json.dumps(started))
`,
        path.join(pluginRoot, "tests"),
        directory.root,
      ],
      { encoding: "utf8" },
    ),
  );
  const workbench = async (args: string[]) =>
    JSON.parse(
      execFileSync(
        python,
        [path.join(pluginRoot, "scripts/workbench_db.py"), ...args],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            CODEX_SECURITY_STATE_DIR: path.join(directory.root, "state"),
          },
        },
      ),
    );
  const context = await createScanArtifactContext(
    initialized.scanId,
    workbench,
    { requireRunning: true },
  );
  return { context, workbench };
}

for (const termination of ["complete-scan", "cancel-scan"] as const) {
  for (const receipt of ["missing", "valid", "none"] as const) {
    test(`workbench Diff ${termination} retains recovered candidate with ${receipt} receipt`, async (t) => {
      const { context, workbench } = await workbenchDiffFixture(t);
      const savedCandidate = candidate("receipt-review");
      await writeLedger(context, [savedCandidate]);
      const receiptPath = "artifacts/review/synthetic-receipt.txt";
      if (receipt === "valid") {
        await mkdir(path.join(context.root, "artifacts/review"), {
          recursive: true,
        });
        await writeFile(
          path.join(context.root, receiptPath),
          "Synthetic receipt evidence.\n",
        );
      }
      await recordCodexSecurityScanDraftViaWorkbench(
        context,
        {
          ...draft(),
          scanId: context.scanId,
          complete: termination === "complete-scan",
          coverage: {
            completeness: "partial",
            explicitExclusions: [],
            deferred: [
              {
                id: "receipt-proof-gap",
                candidateId: savedCandidate.candidate_id,
                reason: "The submitted candidate still has a proof gap.",
                candidate: {
                  ...savedCandidate,
                  analystNote: "Authored candidate annotation.",
                },
                paths: ["src/handler.ts"],
                finding: { title: "Authored deferred evidence" },
                surfaceIds: ["receipt-decision"],
              },
            ],
            surfaces: [
              {
                id: "receipt-decision",
                candidateId: savedCandidate.candidate_id,
                label: "Synthetic receipt review",
                disposition: "rejected",
                notes: "The submitted terminal decision needs its receipt.",
                receiptRefs: receipt === "none" ? [] : [receiptPath],
              },
            ],
          },
        },
        workbench,
      );
      await rm(
        path.join(
          context.root,
          "artifacts/02_discovery/candidate_ledger.jsonl",
        ),
      );
      await workbench([termination, "--scan-id", context.scanId]);
      const coverage = await readCoverage(context);
      const stopped = await workbench([
        "get-scan",
        "--scan-id",
        context.scanId,
      ]);
      const surface = coverage.surfaces.find(
        (row: FixtureObject) => row.candidateId === savedCandidate.candidate_id,
      );
      assert.equal(
        surface.disposition,
        receipt === "missing" ? "needs_follow_up" : "rejected",
      );
      assert.equal(
        stopped.scan.progress.candidates.unresolved,
        receipt === "missing" ? 1 : 0,
      );
      if (receipt === "missing") {
        const pending = coverage.deferred.find(
          (row: FixtureObject) => row.id === "receipt-proof-gap",
        );
        assert.equal(
          pending.reason,
          "The submitted candidate still has a proof gap.",
        );
        assert.deepEqual(pending.candidate, {
          ...savedCandidate,
          analystNote: "Authored candidate annotation.",
        });
        assert.deepEqual(pending.paths, ["src/handler.ts"]);
        assert.deepEqual(pending.finding, {
          title: "Authored deferred evidence",
        });
        assert.ok(
          coverage.deferred.some(
            (row: FixtureObject) =>
              row.candidateId === savedCandidate.candidate_id,
          ),
        );
        assert.ok(
          stopped.scan.warnings.some((warning: string) =>
            warning.startsWith("Skipped malformed coverage receipt"),
          ),
        );
      }
    });
  }
}

for (const disposition of ["rejected", "not_applicable"]) {
  for (const ledgerDisposition of ["reportable", undefined]) {
    for (const renewedFinding of [false, true]) {
      test(`authored checkpoint ${disposition} supersedes saved finding with ledger=${ledgerDisposition ?? "unreviewed"}, renewed=${renewedFinding}`, async (t) => {
        const reviewed = candidate("checkpoint-dismissal", ledgerDisposition);
        const context = await fixture(t, [reviewed]);
        await recordCodexSecurityScanDraft(context, {
          ...draft(),
          complete: true,
          findings: [finding(reviewed.candidate_id)],
        });
        const next = { ...draft(), complete: false };
        next.coverage.surfaces.push({
          candidateId: reviewed.candidate_id,
          label: "Authored checkpoint review",
          disposition,
          notes: "Current authored terminal rationale.",
        });
        if (renewedFinding) next.findings = [finding(reviewed.candidate_id)];
        await recordCodexSecurityScanDraft(context, next);
        for (let attempt = 0; attempt < 2; attempt++) {
          const findings = JSON.parse(
            await readFile(path.join(context.root, "findings.json"), "utf8"),
          ).findings;
          const saved = await readCoverage(context);
          assert.equal(findings.length, renewedFinding ? 1 : 0);
          const decisions = saved.surfaces.filter(
            (row: FixtureObject) => row.candidateId === reviewed.candidate_id,
          );
          if (renewedFinding) {
            assert.equal(
              decisions.filter((row: FixtureObject) =>
                ["rejected", "not_applicable"].includes(row.disposition),
              ).length,
              0,
            );
          } else {
            assert.equal(decisions.length, 1);
            assert.equal(decisions[0].disposition, disposition);
            assert.equal(
              decisions[0].notes,
              "Current authored terminal rationale.",
            );
            assert.ok(
              JSON.stringify(decisions[0]).includes(
                "The synthetic review has reached a final finding.",
              ),
            );
          }
          if (attempt === 0)
            await recordCodexSecurityScanDraft(context, {
              ...draft(),
              complete: true,
            });
        }
      });
    }
  }
}

for (const validation of ["suppressed", "not_applicable"]) {
  for (const siblings of [1, 2]) {
    test(`ledger dismissals archive every explicit sibling: ${validation}/${siblings}`, async (t) => {
      const reviewed = candidate("sibling-dismissal", "reportable");
      const context = await fixture(t, [reviewed]);
      const previous = Array.from({ length: siblings }, (_, index) => ({
        ...finding(reviewed.candidate_id),
        identity: {
          ruleId: "synthetic-review",
          anchor: "shared-candidate",
          instance: `sibling-${index}`,
        },
        summary: `Distinct saved evidence ${index}.`,
      }));
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
        findings: previous,
      });
      await writeLedger(context, [
        candidate(reviewed.candidate_id, validation),
      ]);
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: false,
      });
      for (let attempt = 0; attempt < 2; attempt++) {
        const saved = await readCoverage(context);
        const decisions = saved.surfaces.filter(
          (row: FixtureObject) => row.candidateId === reviewed.candidate_id,
        );
        assert.equal(decisions.length, 1);
        assert.equal(
          decisions[0].disposition,
          validation === "suppressed" ? "rejected" : "not_applicable",
        );
        const historical = [
          decisions[0].finding,
          ...(decisions[0].finding.provenance.previousFindings ?? []),
        ];
        for (const finding of previous)
          assert.ok(
            historical.some(
              (row: FixtureObject) =>
                row.identity.instance === finding.identity.instance &&
                row.summary === finding.summary,
            ),
          );
        assert.equal(
          JSON.parse(
            await readFile(path.join(context.root, "findings.json"), "utf8"),
          ).findings.length,
          0,
        );
        if (attempt === 0)
          await recordCodexSecurityScanDraft(context, {
            ...draft(),
            complete: true,
          });
      }
    });
  }
}

for (const owner of [undefined, "other-worker"]) {
  test(`post-final Diff checkpoint preserves ${owner ?? "local"} candidate ownership`, async (t) => {
    const pending = candidate("post-final-shared-candidate");
    const context = await fixture(t, [pending]);
    await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });
    const next = { ...draft(), complete: false };
    next.coverage.completeness = "partial";
    next.coverage.deferred.push({
      candidateId: pending.candidate_id,
      sourceWorkerId: owner,
      reason: "Imported review remains pending.",
      analystNote: "Keep independent ownership.",
    });
    await recordCodexSecurityScanDraft(context, next);
    const saved = await readCoverage(context);
    assert.deepEqual(
      saved.deferred
        .map((row: FixtureObject) => row.sourceWorkerId ?? null)
        .sort(),
      owner === undefined ? [null] : [null, owner].sort(),
    );
    if (owner !== undefined)
      assert.equal(
        saved.deferred.find(
          (row: FixtureObject) => row.sourceWorkerId === owner,
        ).analystNote,
        "Keep independent ownership.",
      );
  });
}

for (const provenance of [undefined, null, "Saved annotation", {}]) {
  for (const disposition of ["suppressed", "not_applicable"] as const) {
    test(`reopens compact Diff annotation ${JSON.stringify(provenance)}/${disposition}`, async (t) => {
      const reportable = candidate(
        "compact-history",
        "reportable",
        "reportable",
      );
      const context = await fixture(t, [reportable]);
      const canonical = finding(reportable.candidate_id);
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
        findings: [canonical],
      });
      const terminal = candidate(reportable.candidate_id, disposition);
      await writeLedger(context, [terminal]);
      const compact = {
        title: "Saved annotation",
        ...(provenance === undefined ? {} : { provenance }),
      };
      const decision = { ...draft(), complete: true };
      decision.coverage.surfaces = [
        {
          candidateId: terminal.candidate_id,
          candidate: terminal,
          label: terminal.summary,
          disposition:
            disposition === "suppressed" ? "rejected" : "not_applicable",
          notes: `Candidate review concluded: ${terminal.summary}`,
          finding: compact,
        },
      ];
      await recordCodexSecurityScanDraft(context, decision);
      await writeLedger(context, [
        candidate(terminal.candidate_id, "deferred"),
      ]);
      for (const complete of [false, true]) {
        await recordCodexSecurityScanDraft(context, { ...draft(), complete });
        const coverage = await readCoverage(context);
        const pending = coverage.deferred.find(
          (row: FixtureObject) => row.candidateId === terminal.candidate_id,
        );
        assert.ok(pending);
        assert.equal(pending.finding.title, compact.title);
        const history =
          provenance && typeof provenance === "object"
            ? pending.finding.provenance.previousFindings
            : pending.previousFindings;
        if (!(provenance && typeof provenance === "object"))
          assert.deepEqual(pending.finding, compact);
        assert.ok(
          history.some(
            (item: FixtureObject) =>
              item.provenance.candidateId === terminal.candidate_id &&
              item.summary === canonical.summary,
          ),
        );
      }
    });
  }
}

for (const multiple of [false, true]) {
  for (const shared of [false, true]) {
    test(`confirmation closes generated custom proof-gap followup, shared=${shared}, multiple=${multiple}`, async (t) => {
      const current = candidate("authored-gap");
      const context = await fixture(t, [current]);
      const initial = draft([
        {
          candidateId: current.candidate_id,
          candidate: current,
          reason: "An authored runtime proof remains missing.",
        },
      ]);
      if (multiple)
        initial.coverage.deferred.push({
          candidateId: current.candidate_id,
          candidate: current,
          reason: "An independent second proof gap remains missing.",
        });
      initial.coverage.completeness = "partial";
      await recordCodexSecurityScanDraft(context, {
        ...initial,
        complete: true,
      });
      const coverage = await readCoverage(context);
      const followup = coverage.surfaces.find(
        (row: FixtureObject) => row.candidateId === current.candidate_id,
      );
      assert.equal(
        followup.notes,
        "An authored runtime proof remains missing.",
      );
      if (shared)
        coverage.deferred.push({
          id: "independent-review",
          reason: "Independent unfinished review.",
          surfaceIds: [followup.id],
        });
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
        findings: [finding(current.candidate_id)],
        coverage: {
          completeness: coverage.completeness,
          surfaces: coverage.surfaces,
          explicitExclusions: coverage.explicitExclusions,
          deferred: coverage.deferred,
        },
      });
      const saved = await readCoverage(context);
      assert.equal(
        saved.deferred.some(
          (row: FixtureObject) => row.candidateId === current.candidate_id,
        ),
        false,
      );
      assert.equal(
        saved.surfaces.some(
          (row: FixtureObject) =>
            row.id === followup.id && row.disposition === "needs_follow_up",
        ),
        shared,
      );
      if (shared)
        assert.ok(
          saved.deferred.some(
            (row: FixtureObject) => row.id === "independent-review",
          ),
        );
    });
  }
}

for (const outcome of ["finding", "rejected", "not_applicable"] as const) {
  for (const section of [
    "deferred",
    "surfaces",
    "explicitExclusions",
  ] as const) {
    if (section !== "deferred" && outcome !== "finding") continue;
    for (const payload of [
      "candidate",
      "finding",
      "previousFindings",
      "originalCandidates",
    ] as const) {
      test(`first Diff submission archives ${payload} ${section} evidence on ${outcome}`, async (t) => {
        const reviewed = candidate("first-submission", "reportable");
        const context = await fixture(t, [reviewed]);
        const evidence = {
          title: "Saved submission annotation",
          evidence: "Original evidence only in this submission.",
          authoredNote: "Keep original diagnostic text.",
        };
        const otherEvidence = {
          ...evidence,
          evidence: "Independent second evidence in this submission.",
        };
        const pending = {
          id: "original-proof-gap",
          candidateId: reviewed.candidate_id,
          reason: "Original source review.",
          [payload]:
            payload === "previousFindings" || payload === "originalCandidates"
              ? [evidence]
              : evidence,
        };
        const otherPending = {
          ...pending,
          id: "independent-proof-gap",
          reason: "Independent source review.",
          [payload]:
            payload === "previousFindings" || payload === "originalCandidates"
              ? [otherEvidence]
              : otherEvidence,
        };
        const input = draft(
          section === "deferred" ? [pending, otherPending] : [],
        );
        if (section !== "deferred")
          input.coverage[section] = [pending, otherPending].map((row) => ({
            ...row,
            label: "Original terminal review",
            pattern: "src/handler.ts",
            disposition: "rejected",
            receiptRefs: [],
          }));
        input.coverage.completeness = "partial";
        if (outcome === "finding")
          input.findings = [finding(reviewed.candidate_id)];
        else
          input.coverage.surfaces = [
            {
              id: "authored-terminal",
              candidateId: reviewed.candidate_id,
              label: "Authored final review",
              disposition: outcome,
              receiptRefs: [],
            },
          ];
        await recordCodexSecurityScanDraft(context, input);
        const canonical =
          outcome === "finding"
            ? JSON.parse(
                await readFile(
                  path.join(context.root, "findings.json"),
                  "utf8",
                ),
              )
            : await readCoverage(context);
        const contains = (value: unknown, expected: unknown): boolean => {
          if (isDeepStrictEqual(value, expected)) return true;
          if (Array.isArray(value))
            return value.some((child) => contains(child, expected));
          return (
            value !== null &&
            typeof value === "object" &&
            Object.values(value).some((child) => contains(child, expected))
          );
        };
        for (const expected of [evidence, otherEvidence])
          assert.ok(contains(canonical, expected));
        const checkpointRoot = path.join(context.root, "checkpoints");
        for (const name of await readdir(checkpointRoot)) {
          const saved = JSON.parse(
            await readFile(path.join(checkpointRoot, name), "utf8"),
          );
          for (const expected of [evidence, otherEvidence])
            assert.ok(contains(saved, expected));
        }
        assert.equal(
          (await readCoverage(context)).deferred.some(
            (row: FixtureObject) => row.candidateId === reviewed.candidate_id,
          ),
          false,
        );
      });
    }
  }
}

for (const payload of ["complete", "compact", "omitted"] as const) {
  test(`reopened Diff submission retains earlier finding evidence: ${payload}`, async (t) => {
    const original = candidate(
      "reopened-submission",
      "reportable",
      "reportable",
    );
    const context = await fixture(t, [original]);
    const earlier = finding(original.candidate_id);
    earlier.summary = "Earlier validated finding evidence.";
    earlier.provenance.reviewEvidence =
      "Original synthetic validation details.";
    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      complete: true,
      findings: [earlier],
    });
    const checkpointRoot = path.join(context.root, "checkpoints");
    const checkpoints = await Promise.all(
      (await readdir(checkpointRoot)).map(
        async (name) =>
          [
            name,
            await readFile(path.join(checkpointRoot, name), "utf8"),
          ] as const,
      ),
    );
    await writeLedger(context, [candidate(original.candidate_id, "deferred")]);
    const newer: FixtureObject =
      payload === "compact"
        ? { title: "Current authored annotation." }
        : {
            ...finding(original.candidate_id),
            summary: "Current authored finding detail.",
          };
    const submitted = draft([
      {
        id: "current-proof-gap",
        candidateId: original.candidate_id,
        reason: "The reopened review still needs proof.",
        ...(payload === "omitted" ? {} : { finding: newer }),
      },
    ]);
    submitted.coverage.completeness = "partial";
    await recordCodexSecurityScanDraft(context, {
      ...submitted,
      complete: true,
    });
    const published = await readCoverage(context);
    const pending = published.deferred.find(
      (row: FixtureObject) => row.candidateId === original.candidate_id,
    );
    assert.ok(pending);
    const containsEarlier = (value: unknown): boolean => {
      if (Array.isArray(value)) return value.some(containsEarlier);
      if (value === null || typeof value !== "object") return false;
      const row = value as FixtureObject;
      return (
        (row.summary === earlier.summary &&
          row.provenance?.reviewEvidence ===
            earlier.provenance.reviewEvidence) ||
        Object.values(row).some(containsEarlier)
      );
    };
    assert.ok(
      containsEarlier(pending),
      "published candidate details retain earlier validation evidence",
    );
    if (payload !== "omitted")
      assert.equal(
        payload === "compact" ? pending.finding.title : pending.finding.summary,
        payload === "compact" ? newer.title : newer.summary,
      );
    for (const [name, bytes] of checkpoints)
      assert.equal(
        await readFile(path.join(checkpointRoot, name), "utf8"),
        bytes,
      );
  });
}

for (const confirmed of [false, true]) {
  test(`receipt holdback preserves only a surviving Diff terminal decision: finding=${confirmed}`, async (t) => {
    const reviewed = candidate("receipt-confirmation", "deferred");
    const context = await fixture(t, [reviewed]);
    await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });
    const saved = await readCoverage(context);
    await writeFile(
      path.join(context.root, "artifacts", "review-receipt.txt"),
      "Synthetic verified source review.\n",
    );
    saved.surfaces.push({
      id: "receipt-terminal",
      candidateId: reviewed.candidate_id,
      label: "Earlier terminal review",
      disposition: "rejected",
      notes: "Earlier terminal rationale.",
      receiptRefs: ["artifacts/review-receipt.txt"],
    });
    if (confirmed)
      await writeLedger(context, [
        candidate(reviewed.candidate_id, "reportable", "reportable"),
      ]);
    const {
      mode: _mode,
      includePaths: _include,
      excludePaths: _exclude,
      inventoryStrategy: _inventory,
      ...submittedCoverage
    } = saved;
    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      complete: true,
      coverage: submittedCoverage,
      findings: confirmed ? [finding(reviewed.candidate_id)] : [],
    });
    const published = await readCoverage(context);
    assert.equal(
      published.deferred.filter(
        (row: FixtureObject) => row.candidateId === reviewed.candidate_id,
      ).length,
      confirmed ? 0 : 1,
    );
    if (confirmed) assert.equal(published.completeness, "complete");
    else
      assert.ok(
        published.surfaces.some(
          (row: FixtureObject) => row.id === "receipt-terminal",
        ),
      );
  });
}

for (const outcome of [
  "finding",
  "rejected",
  "not_applicable",
  "pending",
] as const) {
  test(`saved Diff row-level history survives ${outcome}`, async (t) => {
    const reviewed = candidate("row-level-history", "deferred");
    const context = await fixture(t, [reviewed]);
    const history = finding(reviewed.candidate_id);
    history.summary = "Earlier evidence exists only in the deferred history.";
    const pending = {
      id: "historical-proof-gap",
      candidateId: reviewed.candidate_id,
      reason: "The saved proof remains unfinished.",
      previousFindings: [history],
    };
    const initial = draft([pending]);
    initial.complete = false;
    initial.coverage.completeness = "partial";
    await recordCodexSecurityScanDraft(context, initial);
    const next = draft();
    next.complete = true;
    if (outcome === "pending") next.coverage.completeness = "partial";
    if (outcome === "finding") {
      await writeLedger(context, [
        candidate(reviewed.candidate_id, "reportable", "reportable"),
      ]);
      next.findings = [finding(reviewed.candidate_id)];
    } else if (outcome !== "pending") {
      await writeLedger(context, [
        candidate(
          reviewed.candidate_id,
          outcome === "rejected" ? "suppressed" : outcome,
        ),
      ]);
      next.coverage.surfaces = [
        {
          id: "authored-terminal",
          candidateId: reviewed.candidate_id,
          label: "Current authored terminal decision",
          disposition: outcome,
          receiptRefs: [],
        },
      ];
    }
    await recordCodexSecurityScanDraft(context, next);
    const canonical =
      outcome === "finding"
        ? JSON.parse(
            await readFile(path.join(context.root, "findings.json"), "utf8"),
          )
        : await readCoverage(context);
    const contains = (value: unknown): boolean => {
      if (isDeepStrictEqual(value, history)) return true;
      if (Array.isArray(value)) return value.some(contains);
      return (
        value !== null &&
        typeof value === "object" &&
        Object.values(value).some(contains)
      );
    };
    assert.ok(
      contains(canonical),
      "the published history retains its original full finding",
    );
    const saved = await readCoverage(context);
    assert.equal(
      saved.deferred.some(
        (row: FixtureObject) => row.candidateId === reviewed.candidate_id,
      ),
      outcome === "pending",
    );
  });
}

for (const outcome of ["finding", "not_applicable"] as const) {
  test(`terminal exclusion evidence survives reassessment to ${outcome}`, async (t) => {
    const reviewed = candidate("exclusion-archive", "deferred");
    const context = await fixture(t, [reviewed]);
    const evidence = {
      ...reviewed,
      annotation: "Earlier exclusion-only candidate evidence.",
    };
    const old = draft();
    old.complete = false;
    old.coverage.completeness = "partial";
    old.coverage.explicitExclusions = [
      {
        candidateId: reviewed.candidate_id,
        pattern: "src/**",
        reason: "Earlier authored exclusion.",
        disposition: "rejected",
        candidate: evidence,
      },
    ];
    await recordCodexSecurityScanDraft(context, old);
    const next = draft();
    next.complete = true;
    if (outcome === "finding") {
      await writeLedger(context, [
        candidate(reviewed.candidate_id, "reportable", "reportable"),
      ]);
      next.findings = [finding(reviewed.candidate_id)];
    } else {
      await writeLedger(context, [
        candidate(reviewed.candidate_id, "not_applicable"),
      ]);
      next.coverage.surfaces = [
        {
          id: "new-authored-decision",
          candidateId: reviewed.candidate_id,
          label: "Current authored decision",
          disposition: outcome,
          receiptRefs: [],
        },
      ];
    }
    await recordCodexSecurityScanDraft(context, next);
    const saved =
      outcome === "finding"
        ? JSON.parse(
            await readFile(path.join(context.root, "findings.json"), "utf8"),
          )
        : await readCoverage(context);
    const contains = (value: unknown): boolean =>
      isDeepStrictEqual(value, evidence) ||
      (Array.isArray(value)
        ? value.some(contains)
        : value !== null &&
          typeof value === "object" &&
          Object.values(value).some(contains));
    assert.ok(
      contains(saved),
      "reassessment retains evidence unique to the prior terminal exclusion",
    );
  });
}
for (const decision of ["suppressed", "not_applicable"] as const) {
  test(`ledger-only ${decision} preserves historical candidate annotations`, async (t) => {
    const reviewed = candidate("ledger-history-archive", "deferred");
    const context = await fixture(t, [reviewed]);
    const evidence = {
      ...reviewed,
      annotation: "Additional saved candidate evidence.",
    };
    const old = draft([
      {
        id: "authored-gap",
        candidateId: reviewed.candidate_id,
        candidate: evidence,
        reason: "Saved authored proof gap.",
      },
    ]);
    old.complete = false;
    old.coverage.completeness = "partial";
    old.coverage.surfaces = [
      {
        id: "authored-followup",
        candidateId: reviewed.candidate_id,
        label: "Saved authored review",
        disposition: "needs_follow_up",
        receiptRefs: [],
      },
    ];
    await recordCodexSecurityScanDraft(context, old);
    await writeLedger(context, [candidate(reviewed.candidate_id, decision)]);
    const next = draft();
    next.complete = true;
    await recordCodexSecurityScanDraft(context, next);
    const saved = await readCoverage(context);
    const contains = (value: unknown): boolean =>
      isDeepStrictEqual(value, evidence) ||
      (Array.isArray(value)
        ? value.some(contains)
        : value !== null &&
          typeof value === "object" &&
          Object.values(value).some(contains));
    assert.ok(
      contains(saved),
      "ledger dismissal archives the saved candidate beyond its current ledger payload",
    );
    assert.equal(
      saved.deferred.some(
        (row: FixtureObject) => row.candidateId === reviewed.candidate_id,
      ),
      false,
    );
  });
}

for (const variant of ["identical", "evidence", "phases"] as const) {
  test(`first pending Diff submission retains authored candidate snapshot: ${variant}`, async (t) => {
    const current = candidate("pending-snapshot", "deferred");
    const context = await fixture(t, [current]);
    const original = structuredClone(current);
    if (variant === "evidence")
      original.evidence = "Original authored evidence only in this submission.";
    if (variant === "phases") {
      original.validation = {
        disposition: "reportable",
        evidence: "Earlier validation details.",
      };
      original.attack_path = {
        decision: "reportable",
        evidence: "Earlier attack-path details.",
      };
    }
    const input = draft([
      {
        candidateId: current.candidate_id,
        candidate: original,
        reason: "Authored proof remains pending.",
      },
    ]);
    input.coverage.completeness = "partial";
    const surfaceOriginal = structuredClone(current);
    if (variant === "evidence")
      surfaceOriginal.evidence = "Distinct surface-authored evidence.";
    if (variant === "phases")
      surfaceOriginal.validation = {
        disposition: "reportable",
        evidence: "Distinct surface validation.",
      };
    input.coverage.surfaces = [
      {
        id: "pending-surface",
        candidateId: current.candidate_id,
        label: current.summary,
        disposition: "needs_follow_up",
        candidate: surfaceOriginal,
      },
    ];
    input.coverage.deferred[0].surfaceIds = ["pending-surface"];
    await recordCodexSecurityScanDraft(context, input);
    const published = await readCoverage(context);
    const pending = published.deferred.find(
      (row: FixtureObject) => row.candidateId === current.candidate_id,
    );
    assert.deepEqual(pending.candidate, current);
    const surface = published.surfaces.find(
      (row: FixtureObject) => row.candidateId === current.candidate_id,
    );
    assert.deepEqual(surface.candidate, current);
    assert.deepEqual(
      surface.originalCandidates ?? [],
      variant === "identical" ? [] : [surfaceOriginal],
    );
    assert.deepEqual(
      pending.originalCandidates ?? [],
      variant === "identical" ? [] : [original],
    );
    for (const name of await readdir(path.join(context.root, "checkpoints"))) {
      const saved = JSON.parse(
        await readFile(path.join(context.root, "checkpoints", name), "utf8"),
      );
      const row = saved.coverage.deferred.find(
        (entry: FixtureObject) => entry.candidateId === current.candidate_id,
      );
      const surface = saved.coverage.surfaces.find(
        (entry: FixtureObject) => entry.candidateId === current.candidate_id,
      );
      assert.deepEqual(
        surface.originalCandidates ?? [],
        variant === "identical" ? [] : [surfaceOriginal],
      );
      assert.deepEqual(
        row.originalCandidates ?? [],
        variant === "identical" ? [] : [original],
      );
    }
  });
}

for (const outcome of ["reportable", "suppressed", "not_applicable"] as const) {
  test(`resolved Diff snapshot carries its saved candidate archive: ${outcome}`, async (t) => {
    const current = candidate("snapshot-resolution", "deferred");
    const context = await fixture(t, [current]);
    const authored = {
      ...current,
      evidence: "Original authored snapshot evidence.",
    };
    const first = draft([
      {
        candidateId: current.candidate_id,
        candidate: authored,
        reason: "Original authored review remains pending.",
      },
    ]);
    first.complete = false;
    first.coverage.completeness = "partial";
    await recordCodexSecurityScanDraft(context, first);
    await writeLedger(context, [
      candidate(current.candidate_id, outcome, outcome),
    ]);
    const resolved = draft();
    resolved.complete = true;
    if (outcome === "reportable")
      resolved.findings = [finding(current.candidate_id)];
    await recordCodexSecurityScanDraft(context, resolved);
    for (const replay of [false, true]) {
      if (replay) await recordCodexSecurityScanDraft(context, resolved);
      const saved =
        outcome === "reportable"
          ? JSON.parse(
              await readFile(path.join(context.root, "findings.json"), "utf8"),
            )
          : await readCoverage(context);
      const contains = (value: unknown): boolean =>
        isDeepStrictEqual(value, authored) ||
        (Array.isArray(value)
          ? value.some(contains)
          : value !== null &&
            typeof value === "object" &&
            Object.values(value).some(contains));
      assert.ok(
        contains(saved),
        "Resolution retains the original saved snapshot evidence.",
      );
      assert.equal(
        (await readCoverage(context)).deferred.some(
          (row: FixtureObject) => row.candidateId === current.candidate_id,
        ),
        false,
      );
    }
  });
}

for (const complete of [false, true]) {
  for (const transition of [
    "reopen",
    "replace",
    "unchanged",
    "authored",
  ] as const) {
    test(`generated terminal refresh retains accepted snapshot ${transition}/${complete}`, async (t) => {
      const original: FixtureObject = {
        ...candidate("generated-history", "suppressed", "ignore"),
        evidence: "Original discovery evidence.",
        validation: {
          disposition: "suppressed",
          counterevidence_or_proof_gap: "Original validation evidence.",
        },
        attack_path: {
          decision: "ignore",
          counterevidence: "Original attack-path evidence.",
        },
      };
      const context = await fixture(t, [original]);
      const first = { ...draft(), complete };
      if (transition === "authored")
        first.coverage.surfaces.push({
          candidateId: original.candidate_id,
          candidate: original,
          label: "Authored terminal review.",
          disposition: "rejected",
          notes: "Authored terminal evidence remains authoritative.",
        });
      await recordCodexSecurityScanDraft(context, first);
      const accepted = await readCoverage(context);
      assert.deepEqual(accepted.surfaces[0].candidate, original);
      const updated =
        transition === "unchanged"
          ? original
          : {
              ...candidate(
                original.candidate_id,
                transition === "replace" ? "not_applicable" : "deferred",
              ),
              evidence: "New discovery evidence.",
            };
      await writeLedger(context, [updated]);
      const current = { ...draft(), complete };
      for (const replay of [false, true]) {
        await recordCodexSecurityScanDraft(context, current);
        const published = await readCoverage(context);
        const contains = (value: unknown): boolean =>
          isDeepStrictEqual(value, original) ||
          (Array.isArray(value)
            ? value.some(contains)
            : value !== null &&
              typeof value === "object" &&
              Object.values(value).some(contains));
        assert.ok(
          contains(published),
          `prior accepted phase/evidence snapshot survives replay=${replay}`,
        );
        assert.equal(
          published.surfaces[0].disposition,
          transition === "authored" || transition === "unchanged"
            ? "rejected"
            : transition === "replace"
              ? "not_applicable"
              : "needs_follow_up",
        );
        if (transition === "authored")
          assert.equal(
            published.surfaces[0].notes,
            "Authored terminal evidence remains authoritative.",
          );
      }
    });
  }
}

for (const candidate of [
  null,
  "Historical annotation.",
  ["Historical trace."],
  {},
  { evidence: "Historical opaque trace." },
]) {
  test(`preserves opaque historical deferred candidate extensions: ${JSON.stringify(candidate)}`, async (t) => {
    const context = await fixture(t);
    const input = draft([
      {
        id: "opaque-proof",
        candidateId: "opaque-candidate",
        reason: "Saved opaque proof remains pending.",
        candidate,
      },
    ]);
    input.coverage.completeness = "partial";
    await recordCodexSecurityScanDraft(context, input);
    assert.deepEqual(
      (await readCoverage(context)).deferred[0].candidate,
      candidate,
    );
    await recordCodexSecurityScanDraft(context, draft());
    assert.deepEqual(
      (await readCoverage(context)).deferred[0].candidate,
      candidate,
    );
  });
}

for (const payload of [
  null,
  "Original opaque proof.",
  ["Original trace."],
  { evidence: "Original object proof." },
]) {
  test(`matching Diff ledger archives original opaque candidate ${JSON.stringify(payload)}`, async (t) => {
    const context = await fixture(t);
    const current = candidate("opaque-pending");
    await writeLedger(context, [current]);
    const input = draft([
      {
        id: "opaque",
        candidateId: current.candidate_id,
        reason: "Original proof gap.",
        candidate: payload,
      },
    ]);
    input.coverage.completeness = "partial";
    await recordCodexSecurityScanDraft(context, input);
    const row = (await readCoverage(context)).deferred.find(
      (entry: FixtureObject) => entry.candidateId === current.candidate_id,
    );
    assert.deepEqual(row.candidate, current);
    assert.deepEqual(row.originalCandidates, [payload]);
    for (const name of await readdir(path.join(context.root, "checkpoints"))) {
      const saved = JSON.parse(
        await readFile(path.join(context.root, "checkpoints", name), "utf8"),
      );
      const row = saved.coverage.deferred.find(
        (entry: FixtureObject) => entry.candidateId === current.candidate_id,
      );
      assert.deepEqual(row.originalCandidates, [payload]);
    }
  });
}

const { recordCodexSecurityDiscoveryCandidates } = await loadModule(
  "artifact-discovery.ts",
);
for (const resolution of ["pending", "accepted", "rejected"] as const) {
  test(`workbench Diff rediscovery preserves reopened proof until ${resolution}`, async (t) => {
    const { context, workbench } = await workbenchDiffFixture(t);
    context.pluginRoot = process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT
      ? path.resolve(process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT)
      : fileURLToPath(
          new URL(
            "../../../../sdk/typescript/_bundled_plugin/",
            import.meta.url,
          ),
        );
    const discovery = {
      candidates: [
        {
          cwe_ids: [],
          locations: [
            { path: "README.md", start_line: 1, end_line: 1, role: "evidence" },
          ],
          summary: "Synthetic candidate for phase recovery.",
          evidence: "Synthetic source evidence.",
        },
      ],
    };
    const directory = path.join(context.root, "artifacts/02_discovery");
    await mkdir(directory, { recursive: true });
    await writeFile(path.join(directory, "in_scope_files.txt"), "README.md\n");
    await recordCodexSecurityDiscoveryCandidates(discovery, context);
    const candidate = JSON.parse(
      (
        await readFile(path.join(directory, "candidate_ledger.jsonl"), "utf8")
      ).trim(),
    );
    const original = finding(candidate.candidate_id);
    original.locations = [{ path: "README.md", startLine: 1 }];
    const publish = (input = draft()) =>
      recordCodexSecurityScanDraftViaWorkbench(
        context,
        { ...input, scanId: context.scanId, complete: false },
        workbench,
      );
    await publish({ ...draft(), findings: [original] });
    await recordCodexSecurityCandidateValidations(context, {
      validations: [
        {
          candidateId: candidate.candidate_id,
          validation: {
            disposition: "deferred",
            method: "source review",
            confidence: "low",
            confidence_rationale: "Synthetic review.",
            rubric: "Source review",
            evidence: "Synthetic evidence.",
            counterevidence_or_proof_gap: "Synthetic new proof gap.",
            remaining_uncertainty: "Synthetic new proof gap.",
          },
        },
      ],
    });
    await publish();
    const before = (await readCoverage(context)).deferred.find(
      (row: FixtureObject) => row.candidateId === candidate.candidate_id,
    );
    assert.ok(before);
    await recordCodexSecurityDiscoveryCandidates(discovery, context);
    await publish();
    const pending = (await readCoverage(context)).deferred.find(
      (row: FixtureObject) => row.candidateId === candidate.candidate_id,
    );
    assert.ok(
      pending,
      "Rediscovery alone must not resolve the saved proof gap.",
    );
    assert.ok(
      pending.originalCandidates.some((saved: unknown) =>
        isDeepStrictEqual(saved, before.candidate),
      ),
      "Rediscovery retains the prior validation and proof gap.",
    );
    assert.equal(pending.finding.title, original.title);
    if (resolution === "accepted")
      await publish({ ...draft(), findings: [original] });
    if (resolution === "rejected") {
      const input = draft();
      input.coverage.surfaces.push({
        candidateId: candidate.candidate_id,
        label: "Later review",
        disposition: "rejected",
        notes: "Later review dismissed the candidate.",
      });
      await publish(input);
    }
    const checkpoints = path.join(context.root, "checkpoints");
    const originals = await Promise.all(
      (await readdir(checkpoints)).map(
        async (name) =>
          [name, await readFile(path.join(checkpoints, name), "utf8")] as const,
      ),
    );
    await workbench(["cancel-scan", "--scan-id", context.scanId]);
    for (const replay of [false, true]) {
      if (replay)
        await workbench(["preserve-scan-results", "--scan-id", context.scanId]);
      const scan = await workbench(["get-scan", "--scan-id", context.scanId]);
      const coverage = await readCoverage(context);
      assert.equal(
        scan.scan.progress.candidates.unresolved,
        resolution === "pending" ? 1 : 0,
      );
      const current = coverage.deferred.find(
        (row: FixtureObject) => row.candidateId === candidate.candidate_id,
      );
      assert.equal(Boolean(current), resolution === "pending");
      if (current)
        assert.ok(
          current.originalCandidates.some((saved: unknown) =>
            isDeepStrictEqual(saved, before.candidate),
          ),
        );
      const findings = JSON.parse(
        await readFile(path.join(context.root, "findings.json"), "utf8"),
      );
      assert.ok(
        JSON.stringify({ findings, coverage }).includes(original.summary),
        "Historical finding evidence survives.",
      );
      for (const [name, contents] of originals)
        assert.equal(
          await readFile(path.join(checkpoints, name), "utf8"),
          contents,
        );
    }
  });
}

for (const initial of ["suppressed", "not_applicable"] as const) {
  for (const next of ["pending", "ledger", "finding", "decision"] as const) {
    test(`payload-free Diff follow-up survives until ${next}: ${initial}`, async (t) => {
      const reviewed = candidate("authored-proof-gap", initial);
      const context = await fixture(t, [reviewed]);
      const authored = {
        id: "fresh-gap",
        candidateId: reviewed.candidate_id,
        reason: "New evidence requires another review of this candidate.",
      };
      const ledgerPath = path.join(
        context.root,
        "artifacts/02_discovery/candidate_ledger.jsonl",
      );
      const originalLedger = await readFile(ledgerPath);
      const first = { ...draft([authored]), complete: true };
      first.coverage.completeness = "partial";
      await recordCodexSecurityScanDraft(context, first);
      assert.deepEqual(first.coverage.deferred, [authored]);
      const originals = await Promise.all(
        (await readdir(path.join(context.root, "checkpoints"))).map(
          async (name) =>
            [
              name,
              await readFile(path.join(context.root, "checkpoints", name)),
            ] as const,
        ),
      );
      for (let retry = 0; retry < 2; retry++) {
        await recordCodexSecurityScanDraft(context, {
          ...draft(),
          complete: true,
        });
        const coverage = await readCoverage(context);
        assert.equal(coverage.deferred.length, 1);
        assert.equal(coverage.deferred[0].reason, authored.reason);
        assert.equal(coverage.deferred[0].candidateId, authored.candidateId);
        assert.deepEqual(coverage.deferred[0].candidate, reviewed);
        assert.ok(
          coverage.surfaces.every(
            (row: FixtureObject) => row.disposition === "needs_follow_up",
          ),
        );
        assert.deepEqual(await readFile(ledgerPath), originalLedger);
      }
      const current = { ...draft(), complete: true };
      if (next === "ledger")
        await writeLedger(context, [
          {
            ...reviewed,
            validation: {
              disposition: initial,
              evidence: "A later validation resolves the new proof gap.",
            },
          },
        ]);
      if (next === "finding")
        current.findings = [finding(reviewed.candidate_id)];
      if (next === "decision")
        current.coverage.surfaces.push({
          candidateId: reviewed.candidate_id,
          label: "New review",
          disposition: "rejected",
          notes: "A later authored review resolves the proof gap.",
        });
      await recordCodexSecurityScanDraft(context, current);
      for (let retry = 0; retry < 2; retry++) {
        await recordCodexSecurityScanDraft(context, {
          ...draft(),
          complete: true,
        });
        const coverage = await readCoverage(context);
        assert.equal(coverage.deferred.length, next === "pending" ? 1 : 0);
        if (next === "finding")
          assert.equal(
            JSON.parse(
              await readFile(path.join(context.root, "findings.json"), "utf8"),
            ).findings.length,
            1,
          );
        if (next === "decision")
          assert.equal(
            coverage.surfaces[0].notes,
            current.coverage.surfaces[0].notes,
          );
      }
      for (const [name, bytes] of originals)
        assert.deepEqual(
          await readFile(path.join(context.root, "checkpoints", name)),
          bytes,
        );
    });
  }
}

test("authored Diff proof gap keeps its original phase through a publication conflict", async (t) => {
  const original = candidate("conflicting-proof", "suppressed");
  const context = await fixture(t, [original]);
  const input = draft([
    {
      candidateId: original.candidate_id,
      reason: "New proof requires review.",
    },
  ]);
  input.coverage.completeness = "partial";
  const next = {
    ...original,
    validation: {
      disposition: "not_applicable",
      evidence: "A concurrent validation resolved the proof gap.",
    },
  };
  let attempts = 0;
  const result = await recordCodexSecurityScanDraft(
    context,
    input,
    async (published: FixtureObject) => {
      attempts++;
      if (attempts === 1) {
        assert.deepEqual(published.coverage.deferred[0].candidate, original);
        await writeLedger(context, [next]);
        throw Object.assign(new Error("Synthetic concurrent publication"), {
          code: "scan_draft_conflict",
        });
      }
      assert.equal(published.coverage.deferred.length, 0);
      assert.equal(
        published.coverage.surfaces[0].disposition,
        "not_applicable",
      );
    },
  );
  assert.equal(attempts, 2);
  assert.equal(result.coverage.deferred.length, 0);
  assert.equal(input.coverage.deferred[0].candidate, undefined);
});

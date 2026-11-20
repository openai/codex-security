import semverSatisfies from "semver/functions/satisfies.js";
import semverValid from "semver/functions/valid.js";
import semverValidRange from "semver/ranges/valid.js";
import { z } from "zod";
import {
  dependencyClaimReferenceSchema,
  type DependencyClaimRecord,
  type DependencyClaimReference,
} from "./dependency-stack-claims.js";
import {
  aggregateDependencyVerdict,
  dependencyUseSchema,
} from "./dependency-stack-use.js";
import {
  sampledStacksSchema,
  stackManifestSchema,
  stackPacketWorkItems,
  stackSinkMatches,
  type StackPacket,
  type StackWorkItem,
} from "./dependency-stack-packet.js";
import { effectiveStackSinks } from "./dependency-stack-advisory.js";
import { comparePythonReleases } from "./dependency-advisory-version.js";
import { dependencyGitCommitSchema } from "./dependency-source-identity.js";
import {
  inventoryReceiptSelectionSchema,
  stackJsonValue,
  type DependencyExcerpt,
} from "./dependency-stack-evidence.js";
import { CodexSecurityError } from "./errors.js";
import { isRecord } from "./record.js";

const text = z.string().trim().min(1);
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const status = z.enum(["observed", "no_match", "no_coverage"]);
const verdict = dependencyUseSchema.shape.verdict;
const useFields = dependencyUseSchema.shape;
const stackUse = z.strictObject({
  location: useFields.location,
  component: useFields.component,
  version: useFields.version,
  verdict,
  deployment: useFields.deployment,
  reason: useFields.reason,
  evidence: useFields.evidence,
  proof: useFields.proof,
});
const questionCheck = z.strictObject({
  question: text.describe("Exact deciding question from remainingQuestions."),
  checked: text.describe(
    "Where you checked and what the evidence established.",
  ),
  missingEvidence: text.describe(
    "The specific missing artifact or fact needed to answer the question.",
  ),
  claims: z
    .array(dependencyClaimReferenceSchema)
    .min(1)
    .describe(
      "Recorded claims citing the source or capture inspected for this check.",
    ),
});
const itemInput = z.strictObject({
  workItemId: text,
  verdict,
  reason: text,
  supportingClaims: z.array(dependencyClaimReferenceSchema).default([]),
  attackerControlClaim: dependencyClaimReferenceSchema
    .optional()
    .describe(
      "For an exploitable verdict, select the supporting claim whose cited evidence establishes attacker control of the deciding input on this path.",
    ),
  remainingQuestions: z.array(text).default([]),
  questionChecks: z
    .array(questionCheck)
    .optional()
    .describe(
      "For each unresolved deciding question on an observed path, record the attempted check and cite the supporting claim revisions.",
    ),
  frameIndices: z
    .array(z.number().int().nonnegative())
    .optional()
    .describe(
      "Additional original zero-based indices in this observation's leaf-first stack. The report always cites the captured matched frames.",
    ),
  use: stackUse
    .optional()
    .describe(
      "Source-backed use. Cite ranges already recorded in supportingClaims. Include the actual sink and advisory conditions in proof for an affected use or a source-based exclusion.",
    ),
});
export const stackAssessmentInputSchema = z.strictObject({
  items: z.array(itemInput).min(1),
});
export type StackAssessmentInput = z.input<typeof itemInput>;
export type StackAssessment = z.output<typeof itemInput>;
export interface StackClaimReader {
  get(ref: DependencyClaimReference): DependencyClaimRecord | undefined;
  isUsable(ref: DependencyClaimReference): boolean;
}

function fail(message: string): never {
  throw new CodexSecurityError(message);
}

const sourceCitation = z.strictObject({
  path: text,
  commit: dependencyGitCommitSchema,
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  text: z.string(),
  blob: dependencyGitCommitSchema,
  contentSha256: digest,
});
const reportedClaim = dependencyClaimReferenceSchema.extend({
  scope: stackJsonValue,
  payload: stackJsonValue,
  dependencies: z.array(dependencyClaimReferenceSchema),
  sources: z.array(sourceCitation),
  receipts: z.array(
    z.strictObject({
      receiptId: text,
      originalPayloadSha256: digest,
      server: text,
      origin: stackJsonValue,
      selection: inventoryReceiptSelectionSchema
        .omit({ receiptId: true })
        .optional(),
      result: stackJsonValue,
    }),
  ),
});

const coverageSchema = z.strictObject({
  total: z.number().int().nonnegative(),
  assessed: z.number().int().nonnegative(),
  outstanding: z.array(text),
  observed: z.number().int().nonnegative(),
  noMatch: z.array(text),
  noCoverage: z.array(text),
  scopeConflicts: z.array(text),
  truncated: z.array(text),
  truncationUnknown: z.array(text),
});
const querySchema = sampledStacksSchema.shape.queries.element;
const captured =
  querySchema.shape.groups.element.shape.observations.element.shape;
const observationCitation = z.strictObject({
  id: text,
  stackHash: text,
  framesTruncated: captured.framesTruncated,
  observedAt: captured.observedAt,
  sinkIds: captured.sinkIds,
  sinkMatches: captured.sinkMatches.unwrap(),
  sinkIndex: z.number().int().nonnegative().nullable(),
  sourceIndex: z.number().int().nonnegative().nullable(),
  frames: z.array(
    z.strictObject({
      rawIndex: z.number().int().nonnegative(),
      frame: captured.frames.element,
    }),
  ),
  bindings: captured.bindings.unwrap(),
});
export const stackReviewDecisionSchema = z.strictObject({
  workItemId: text,
  reason: text,
  followUp: text.nullable(),
});
export const stackInvestigationReportSchema = z.strictObject({
  schemaVersion: z.literal("codex-security.pipeline-stacks.report/v1"),
  cve: text,
  callerScope: stackManifestSchema.shape.callerScope,
  advisoryDetails: stackManifestSchema.shape.advisoryDetails,
  advisoryLookupError: stackManifestSchema.shape.advisoryLookupError,
  triggerAnalysis: stackManifestSchema.shape.triggerAnalysis,
  runId: text,
  attemptId: text,
  inputDigest: digest,
  toolRevision: text,
  target: z.strictObject({ repository: text, sha: dependencyGitCommitSchema }),
  verdict,
  assessments: z.array(
    itemInput.extend({
      queryId: text,
      groupId: text,
      status,
      queryScope: querySchema.shape.scope,
      scope: querySchema.shape.scope,
      scopeConflicts: z.array(text),
      truncated: z.boolean().nullable(),
      observation: observationCitation.nullable(),
    }),
  ),
  claims: z.array(reportedClaim),
  coverage: coverageSchema,
  remainingQuestions: z.array(text),
  review: z
    .strictObject({
      draftDigest: digest,
      decisions: z.array(
        stackReviewDecisionSchema.extend({ followUp: z.null() }),
      ),
    })
    .nullable(),
});
export type StackInvestigationReport = z.output<
  typeof stackInvestigationReportSchema
>;

function collectClaims(
  assessment: StackAssessment,
  claims: StackClaimReader,
): DependencyClaimRecord[] {
  const selected = new Map<string, DependencyClaimRecord>();
  const pending = [...assessment.supportingClaims];
  while (pending.length) {
    const ref = pending.pop()!;
    if (!claims.isUsable(ref))
      fail(
        `Claim ${ref.id} revision ${ref.revision} is missing or stale for this attempt.`,
      );
    const record = claims.get(ref);
    if (!record) fail(`Claim ${ref.id} revision ${ref.revision} is missing.`);
    if (selected.has(ref.id)) continue;
    for (const receipt of record.receipts) {
      const args = receipt.origin.arguments;
      if (
        receipt.server !== "stack-packet" ||
        !isRecord(args) ||
        args["workItemId"] !== assessment.workItemId
      )
        fail(
          `Claim ${ref.id} cites a receipt outside work item ${assessment.workItemId}.`,
        );
    }
    selected.set(ref.id, record);
    pending.push(...record.dependencies);
  }
  return [...selected.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export function assertStackAssessmentClaims(
  assessment: StackAssessment,
  claims: StackClaimReader,
): void {
  collectClaims(assessment, claims);
}

interface SourceRange {
  path: string;
  startLine: number;
  endLine: number;
  commit?: string | undefined;
}
function coversRange(
  excerpts: readonly DependencyExcerpt[],
  range: SourceRange,
  sha: string,
): boolean {
  let cursor = range.startLine;
  const ranges = excerpts
    .filter(
      (e) =>
        e.path === range.path &&
        e.commit === sha &&
        e.sourceIdentity?.status === "verified",
    )
    .sort((a, b) => a.startLine - b.startLine);
  for (const e of ranges) {
    if (e.startLine > cursor) break;
    cursor = Math.max(cursor, e.endLine + 1);
    if (cursor > range.endLine) return true;
  }
  return false;
}

/** Compare stable numeric PEP 440 releases. Leave other Python versions to cited source proof. */
function pythonReleaseMatches(
  version: string,
  specifier: string,
): boolean | undefined {
  let unknown = false;
  for (const term of specifier.split(",")) {
    const match = /^\s*(<=|>=|==|!=|<|>)\s*(\d+(?:\.\d+)*)\s*$/u.exec(term);
    if (!match) {
      unknown = true;
      continue;
    }
    const order = comparePythonReleases(version, match[2]!);
    if (order === undefined) return;
    const result = {
      "<": order < 0,
      ">": order > 0,
      "<=": order <= 0,
      ">=": order >= 0,
      "==": order === 0,
      "!=": order !== 0,
    }[match[1]!];
    if (!result) return false;
  }
  return unknown ? undefined : true;
}
type StackSink = StackPacket["sinks"]["sinks"][number];
function affectedVersion(
  sink: StackSink,
  version: string,
): boolean | undefined {
  if (!sink.affectedVersions.length) return;
  const results = sink.affectedVersions.map((range) => {
    if (sink.versionScheme.toLowerCase() === "semver") {
      if (!semverValid(version) || !semverValidRange(range)) return;
      return semverSatisfies(version, range);
    }
    if (sink.versionScheme.toLowerCase() === "pep440")
      return pythonReleaseMatches(version, range);
    return undefined;
  });
  return results.includes(true)
    ? true
    : results.includes(undefined)
      ? undefined
      : false;
}

function assessProof(
  row: StackAssessment,
  work: StackWorkItem,
  packet: StackPacket,
  records: readonly DependencyClaimRecord[],
) {
  const observation = work.observation;
  const frames = row.frameIndices ?? [];
  if (frames.some((index) => !observation?.frames[index]))
    fail("An assessment cites a frame outside its original observation.");
  if (row.verdict === "unknown" && !row.remainingQuestions.length)
    fail("An unknown assessment must name the deciding fact still missing.");
  if (work.scopeConflicts.length && row.verdict !== "unknown")
    fail(
      `Conflicting capture scope requires an unknown verdict. ${work.scopeConflicts.join(" ")}`,
    );
  if (!observation && row.verdict !== "unknown")
    fail(`A ${work.status} group requires a scoped unknown assessment.`);
  const excerpts = records.flatMap((claim) => claim.excerpts);
  const sha = packet.manifest.target.sha;
  for (const claim of records) {
    for (const receipt of claim.receipts) {
      const args = receipt.origin.arguments;
      if (
        !isRecord(args) ||
        args["inputDigest"] !== packet.manifest.inputDigest ||
        receipt.originalPayloadSha256 !== packet.manifest.files.stacks.sha256
      )
        fail(
          "A supporting capture receipt belongs to a different input packet.",
        );
    }
  }
  if (row.use) {
    for (const range of row.use.evidence) {
      if (range.commit !== sha || !coversRange(excerpts, range, sha))
        fail(
          `Source ${range.path}:${range.startLine}-${range.endLine} must be pinned and covered by a supporting claim.`,
        );
    }
  }
  if (row.verdict === "unknown")
    return verifyQuestionChecks(row, work, records);
  if (!observation) fail("A decided stack assessment needs an observed sink.");
  if (!records.length)
    fail("A decided assessment needs at least one exact supporting claim.");
  const mapped = stackSinkMatches(observation);
  if (!mapped.length)
    fail(
      "A decided assessment needs an observation mapped to a supplied sink.",
    );
  const bindings = observation.bindings ?? [];
  const hasBindingEvidence = (i: number) => {
    const binding = bindings[i]!;
    if (
      binding.imageDigest &&
      !/^(?:sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$/iu.test(
        binding.imageDigest,
      )
    )
      return false;
    if (
      work.scope.image_digest &&
      binding.imageDigest !== work.scope.image_digest
    )
      return false;
    if (!binding.imageDigest && binding.sourceSha !== sha) return false;
    const source = binding.evidence ?? [];
    if (
      source.length &&
      source.every((range) => coversRange(excerpts, range, sha))
    )
      return true;
    return records.some((claim) =>
      claim.receipts.some((receipt) => {
        const path = receipt.selection?.record;
        return (
          path?.length === 3 &&
          path[0] === "observation" &&
          path[1] === "bindings" &&
          path[2] === i
        );
      }),
    );
  };
  const bindingEvidence = bindings.map((binding, index) => ({
    binding,
    cited: hasBindingEvidence(index),
  }));
  // Packet decoding checks each catalog ID and its original sampled frame.
  const sinks = effectiveStackSinks(packet);
  const matches = mapped.map(({ sinkId, rawIndex }) => {
    const sink = sinks.find((s) => s.id === sinkId)!;
    const copies = bindingEvidence.filter(
      ({ binding }) =>
        binding.package === sink.package &&
        binding.frameIndices?.includes(rawIndex),
    );
    const fixed =
      copies.length > 0 &&
      copies.every(
        ({ binding, cited }) =>
          cited && affectedVersion(sink, binding.version) === false,
      );
    return { sink, rawIndex, copies, fixed };
  });
  if (row.verdict === "ruled_out" && matches.every(({ fixed }) => fixed)) {
    const use = row.use;
    if (
      use &&
      !matches.some(
        ({ sink, copies }) =>
          sink.package === use.component &&
          (!use.proof?.sink || sink.function === use.proof.sink.function) &&
          (use.version === null ||
            copies.some(({ binding }) => binding.version === use.version)),
      )
    )
      fail(
        "The reported component and version disagree with the cited fixed-version binding.",
      );
    return;
  }

  const use = row.use;
  const selectedFrames = matches.filter(
    ({ sink }) =>
      sink.package === use?.component &&
      sink.function === use?.proof?.sink?.function,
  );
  if (!use || !selectedFrames.length)
    fail("Supply an evidence-backed use and proof for the mapped sink.");
  const sourceMatchesBuild = ({
    sink,
    rawIndex,
    copies,
  }: (typeof matches)[number]) => {
    const sources = bindingEvidence.flatMap(({ binding, cited }) =>
      cited &&
      binding.sourceSha !== undefined &&
      (!binding.frameIndices?.length || binding.frameIndices.includes(rawIndex))
        ? [binding]
        : [],
    );
    // A source-based exclusion can use an observation-wide build binding to
    // verify the caller even when the dependency copy has no frame attribution.
    const builds =
      row.verdict === "ruled_out" && !copies.length
        ? bindingEvidence.filter(
            ({ binding }) =>
              binding.package === sink.package && !binding.frameIndices?.length,
          )
        : copies;
    if (!builds.length)
      return (
        work.scope.image_digest !== undefined &&
        sources.length > 0 &&
        sources.every(
          (s) =>
            s.imageDigest === work.scope.image_digest && s.sourceSha === sha,
        )
      );
    return builds.every(({ binding, cited }) => {
      if (!cited) return false;
      // A separate source record must describe the same immutable artifact.
      const sameBuild = sources.filter(
        (s) =>
          s === binding ||
          (binding.imageDigest !== undefined &&
            s.imageDigest === binding.imageDigest),
      );
      return (
        sameBuild.length > 0 && sameBuild.every((s) => s.sourceSha === sha)
      );
    });
  };
  const conditions = use.proof!.conditions;
  if (new Set(conditions.map((c) => c.label)).size !== conditions.length)
    fail("Each advisory condition must have one disposition.");
  const disproved = (sink: StackSink) =>
    sink.preconditions.some((p) =>
      conditions.some((c) => c.label === p && c.status === "ruled_out"),
    );
  if (row.verdict === "ruled_out") {
    if (matches.length === 1 && disproved(matches[0]!.sink)) {
      if (!sourceMatchesBuild(matches[0]!))
        fail(
          "A guard in the target source needs a cited build-to-source binding for this running workload.",
        );
      return;
    }
    fail(
      "An exclusion requires a cited fixed-version binding for every matched sink frame or a disproved advisory condition.",
    );
  }
  const applicable = selectedFrames.filter(({ sink }) => !disproved(sink));
  if (!applicable.length)
    fail("A required advisory condition was ruled out for this path.");
  const possible = applicable.filter(({ fixed }) => !fixed);
  if (!possible.length)
    fail("The observed dependency version falls outside the affected ranges.");
  const version = use.version;
  if (row.verdict === "potentially_exploitable") {
    if (
      version !== null &&
      possible.every(({ sink }) => affectedVersion(sink, version) === false)
    )
      fail(
        "The reported dependency version falls outside the affected ranges.",
      );
    if (!row.remainingQuestions.length)
      fail(
        "Name the remaining conditions for a potentially exploitable assessment.",
      );
    return;
  }
  const affectedFrames = possible.filter(
    ({ sink, copies }) =>
      version !== null &&
      affectedVersion(sink, version) === true &&
      copies.length > 0 &&
      copies.every(
        ({ binding, cited }) => cited && binding.version === version,
      ),
  );
  if (!affectedFrames.length)
    fail(
      "An exploitable assessment needs a cited affected running dependency binding for the matched sink frame.",
    );
  const confirmed = affectedFrames.filter(sourceMatchesBuild);
  if (!confirmed.length)
    fail(
      "An exploitable use needs a cited build-to-source binding for the running workload.",
    );
  const control = row.attackerControlClaim;
  const accessCitations = use.evidence.filter((range) =>
    range.supports.includes("access"),
  );
  if (
    !control ||
    !records.some(
      (r) =>
        r.id === control.id &&
        r.revision === control.revision &&
        r.hash === control.hash &&
        accessCitations.some((range) => coversRange(r.excerpts, range, sha)),
    )
  )
    fail(
      "An exploitable assessment needs a supporting claim with source evidence for attacker control of the deciding input.",
    );
  if (
    !confirmed.some(({ sink }) =>
      sink.preconditions.every((p) =>
        conditions.some((c) => c.label === p && c.status === "met"),
      ),
    )
  )
    fail(
      "Each advisory precondition needs a cited, met condition on this path.",
    );
}

function bindCapturedEvidence(row: StackAssessment, work: StackWorkItem) {
  const observation = work.observation;
  const indices = new Set(row.frameIndices);
  if (observation) {
    if (observation.sourceIndex != null) indices.add(observation.sourceIndex);
    if (observation.sinkIndex != null) indices.add(observation.sinkIndex);
    for (const { rawIndex } of stackSinkMatches(observation))
      indices.add(rawIndex);
  }
  const questions = new Set(row.remainingQuestions);
  for (const conflict of work.scopeConflicts)
    questions.add(`Which observation covers the requested scope? ${conflict}`);
  return {
    ...row,
    frameIndices: [...indices].sort((a, b) => a - b),
    remainingQuestions: [...questions],
  };
}

function verifyQuestionChecks(
  row: StackAssessment,
  work: StackWorkItem,
  records: readonly DependencyClaimRecord[],
) {
  if (
    !work.observation ||
    work.scopeConflicts.length ||
    stackSinkMatches(work.observation).length === 0
  )
    return;
  const remaining = new Set(row.remainingQuestions);
  const byId = new Map(records.map((record) => [record.id, record]));
  for (const check of row.questionChecks ?? []) {
    if (!remaining.delete(check.question))
      fail(
        `Question check is duplicated or does not match a remaining question: ${check.question}`,
      );
    for (const ref of check.claims) {
      const record = byId.get(ref.id);
      if (
        !record ||
        record.revision !== ref.revision ||
        record.hash !== ref.hash ||
        (!record.excerpts.length && !record.receipts.length)
      )
        fail(
          `Question check must cite a supporting claim with verified source or capture evidence: ${check.question}`,
        );
    }
  }
  if (remaining.size)
    fail(
      `Before recording unknown, investigate and cite an attempted check for each deciding question: ${[...remaining].join("; ")}`,
    );
}

export async function prepareStackAssessment(
  input: unknown,
  work: StackWorkItem,
  packet: StackPacket,
  claims: StackClaimReader,
  signal?: AbortSignal,
): Promise<StackAssessment> {
  signal?.throwIfAborted();
  const row = bindCapturedEvidence(itemInput.parse(input), work);
  if (row.workItemId !== work.id)
    fail("Assessment work item does not match the selected observation.");
  const records = collectClaims(row, claims);
  if (row.use) {
    if (row.use.verdict !== row.verdict)
      fail("The use and assessment verdicts must agree.");
    row.use.evidence = row.use.evidence.map((r) => ({
      ...r,
      commit: r.commit ?? packet.manifest.target.sha,
    }));
    assessProof(row, work, packet, records);
    dependencyUseSchema.parse(row.use);
    const facts = new Set(row.use.evidence.flatMap((range) => range.supports));
    if (row.use.deployment === "confirmed" && !facts.has("running"))
      row.use.deployment = "unknown";
    if (
      row.verdict === "exploitable" ||
      row.verdict === "potentially_exploitable"
    ) {
      if (!facts.has("affected_copy") || !facts.has("affected_use"))
        fail(
          "The supplied evidence must establish the affected copy and applicable use in code.",
        );
      if (
        row.verdict === "exploitable" &&
        (row.use.deployment !== "confirmed" || !facts.has("access"))
      )
        fail(
          "The supplied evidence must establish the running revision and caller access.",
        );
    }
  } else assessProof(row, work, packet, records);
  return row;
}

export function summarizeStackCoverage(
  packet: StackPacket,
  assessments: readonly StackAssessment[],
) {
  const items = stackPacketWorkItems(packet);
  const assessed = new Set(assessments.map((a) => a.workItemId));
  const ids = (predicate: (w: StackWorkItem) => boolean) =>
    items.filter(predicate).map((w) => w.id);
  return {
    total: items.length,
    assessed: items.filter((w) => assessed.has(w.id)).length,
    outstanding: ids((w) => !assessed.has(w.id)),
    observed: items.filter((w) => w.status === "observed").length,
    noMatch: ids((w) => w.status === "no_match"),
    noCoverage: ids((w) => w.status === "no_coverage"),
    scopeConflicts: ids((w) => w.scopeConflicts.length > 0),
    truncated: ids(
      (w) => w.truncated === true || w.observation?.framesTruncated === true,
    ),
    truncationUnknown: ids(
      (w) => w.truncated === null || w.observation?.framesTruncated === null,
    ),
  };
}

export function finalizeStackReport(
  packet: StackPacket,
  assessments: readonly StackAssessment[],
  claims: StackClaimReader,
): StackInvestigationReport {
  const items = stackPacketWorkItems(packet);
  const byId = new Map(assessments.map((a) => [a.workItemId, a]));
  if (byId.size !== items.length || byId.size !== assessments.length)
    fail(
      "Finalize requires exactly one disposition for every supplied work item.",
    );
  const selected = new Map<string, DependencyClaimRecord>();
  const paths = items.map((w) => {
    const disposition = byId.get(w.id);
    if (!disposition) fail(`Missing disposition for ${w.id}.`);
    const saved = bindCapturedEvidence(disposition, w);
    const records = collectClaims(saved, claims);
    assessProof(saved, w, packet, records);
    for (const record of records) selected.set(record.id, record);
    const o = w.observation;
    return {
      ...saved,
      queryId: w.queryId,
      groupId: w.groupId,
      status: w.status,
      queryScope: w.queryScope,
      scope: w.scope,
      scopeConflicts: w.scopeConflicts,
      truncated: w.truncated,
      observation: o && {
        id: o.id,
        stackHash: o.stackHash,
        framesTruncated: o.framesTruncated,
        observedAt: o.observedAt,
        sinkIds: o.sinkIds,
        sinkMatches: stackSinkMatches(o),
        sourceIndex: o.sourceIndex ?? null,
        sinkIndex: o.sinkIndex,
        frames: saved.frameIndices.map((rawIndex) => ({
          rawIndex,
          frame: o.frames[rawIndex]!,
        })),
        bindings: o.bindings ?? [],
      },
    };
  });
  const coverage = summarizeStackCoverage(packet, assessments);
  const { runId, attemptId, inputDigest, toolRevision, target, cve } =
    packet.manifest;
  return stackInvestigationReportSchema.parse({
    schemaVersion: "codex-security.pipeline-stacks.report/v1",
    review: null,
    runId,
    attemptId,
    inputDigest,
    toolRevision,
    target,
    cve,
    ...(packet.manifest.callerScope && {
      callerScope: packet.manifest.callerScope,
    }),
    ...(packet.manifest.advisoryDetails && {
      advisoryDetails: packet.manifest.advisoryDetails,
    }),
    ...(packet.manifest.advisoryLookupError && {
      advisoryLookupError: packet.manifest.advisoryLookupError,
    }),
    ...(packet.manifest.triggerAnalysis && {
      triggerAnalysis: packet.manifest.triggerAnalysis,
    }),
    verdict: aggregateDependencyVerdict(paths, {
      unresolved: !!(
        coverage.truncated.length ||
        coverage.truncationUnknown.length ||
        coverage.noMatch.length ||
        coverage.noCoverage.length ||
        coverage.scopeConflicts.length
      ),
    }),
    assessments: paths,
    coverage,
    remainingQuestions: [
      ...new Set(paths.flatMap((a) => a.remainingQuestions)),
    ],
    claims: [...selected.values()]
      .sort((a, b) => a.id.localeCompare(b.id))
      .map((record) => ({
        id: record.id,
        revision: record.revision,
        hash: record.hash,
        scope: record.scope,
        payload: record.payload,
        dependencies: record.dependencies,
        sources: record.excerpts.map(
          ({ path, commit, startLine, endLine, text, sourceIdentity }) => ({
            path,
            commit,
            startLine,
            endLine,
            text,
            blob: sourceIdentity?.blob,
            contentSha256: sourceIdentity?.contentSha256,
          }),
        ),
        receipts: record.receipts.map(
          ({
            receiptId,
            server,
            originalPayloadSha256,
            origin,
            selection,
            result,
          }) => ({
            receiptId,
            server,
            originalPayloadSha256,
            origin,
            selection,
            result,
          }),
        ),
      })),
  });
}

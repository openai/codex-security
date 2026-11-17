import semverSatisfies from "semver/functions/satisfies.js";
import semverValid from "semver/functions/valid.js";
import semverValidRange from "semver/ranges/valid.js";
import { z } from "zod";
import {
  dependencyClaimReferenceSchema,
  type DependencyClaimRecord,
  type DependencyClaimReference,
} from "./dependency-claims.js";
import {
  aggregateDependencyVerdict,
  dependencyUseSchema,
  validateDependencyUse,
  type DependencyExcerpt,
} from "./dependency-reachability.js";
import {
  sampledStacksSchema,
  stackPacketWorkItems,
  stackSinkMatches,
  type StackPacket,
  type StackWorkItem,
} from "./dependency-stack-packet.js";
import { dependencyGitCommitSchema } from "./dependency-source-identity.js";
import { inventoryReceiptSelectionSchema } from "./dependency-inventory.js";
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
  scope: z.json(),
  payload: z.json(),
  dependencies: z.array(dependencyClaimReferenceSchema),
  sources: z.array(sourceCitation),
  receipts: z.array(
    z.strictObject({
      receiptId: text,
      originalPayloadSha256: digest,
      server: text,
      origin: z.json(),
      selection: inventoryReceiptSelectionSchema
        .omit({ receiptId: true })
        .optional(),
      result: z.json(),
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
export const stackInvestigationReportSchema = z.strictObject({
  schemaVersion: z.literal("codex-security.pipeline-stacks.report/v1"),
  reviewPolicy: z.literal("single_agent"),
  cve: text,
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
  if (!/^\d+(?:\.\d+)*$/u.test(version)) return;
  const release = version.split(".").map(BigInt);
  let unknown = false;
  for (const term of specifier.split(",")) {
    const match = /^\s*(<=|>=|==|!=|<|>)\s*(\d+(?:\.\d+)*)\s*$/u.exec(term);
    if (!match) {
      unknown = true;
      continue;
    }
    const bound = match[2]!.split(".").map(BigInt);
    let order = 0;
    for (let i = 0; i < Math.max(bound.length, release.length); i++) {
      const a = release[i] ?? 0n;
      const b = bound[i] ?? 0n;
      if (a !== b) {
        order = a < b ? -1 : 1;
        break;
      }
    }
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
  if (row.verdict === "unknown") return;
  if (!observation) fail("A decided stack assessment needs an observed sink.");
  if (!records.length)
    fail("A decided assessment needs at least one exact supporting claim.");
  const mapped = stackSinkMatches(observation);
  const sinks = packet.sinks.sinks.filter((sink) =>
    mapped.some(
      ({ sinkId, rawIndex }) =>
        sinkId === sink.id && observation.frames[rawIndex],
    ),
  );
  if (!sinks.length)
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
  const matches = (s: StackSink) =>
    bindings.flatMap((b, i) =>
      b.package === s.package ? [{ binding: b, index: i }] : [],
    );
  if (
    row.verdict === "ruled_out" &&
    sinks.every((sink) => {
      const bound = matches(sink);
      return (
        bound.length > 0 &&
        bound.every(
          ({ binding, index }) =>
            hasBindingEvidence(index) &&
            affectedVersion(sink, binding.version) === false,
        )
      );
    })
  ) {
    if (
      row.use &&
      !bindings.some(
        (b) =>
          b.package === row.use!.component &&
          (row.use!.version === null || b.version === row.use!.version),
      )
    )
      fail(
        "The reported component and version disagree with the cited fixed-version binding.",
      );
    return;
  }

  const selected = sinks.find(
    (s) =>
      s.package === row.use?.component &&
      s.function === row.use.proof?.sink?.function,
  );
  if (!row.use || !selected)
    fail("Supply an evidence-backed use and proof for the mapped sink.");
  const sourceBindings = bindings.filter(
    (binding, index) =>
      binding.sourceSha !== undefined && hasBindingEvidence(index),
  );
  const sourceMatchesBuild =
    sourceBindings.length > 0 &&
    sourceBindings.every((binding) => binding.sourceSha === sha);
  const conditions = row.use.proof!.conditions;
  if (new Set(conditions.map((c) => c.label)).size !== conditions.length)
    fail("Each advisory condition must have one disposition.");
  const disproved = selected.preconditions.some((p) =>
    conditions.some((c) => c.label === p && c.status === "ruled_out"),
  );
  if (row.verdict === "ruled_out") {
    if (sinks.length === 1 && disproved) {
      if (!sourceMatchesBuild)
        fail(
          "A guard in the target source needs a cited build-to-source binding for this running workload.",
        );
      return;
    }
    fail(
      "An exclusion requires a cited fixed-version binding or a disproved advisory condition.",
    );
  }
  if (disproved)
    fail("A required advisory condition was ruled out for this path.");
  const bound = matches(selected);
  if (
    bound.length &&
    bound.every(
      ({ binding, index }) =>
        hasBindingEvidence(index) &&
        affectedVersion(selected, binding.version) === false,
    )
  )
    fail("The observed dependency version falls outside the affected ranges.");
  if (row.verdict === "potentially_exploitable") {
    if (!row.remainingQuestions.length)
      fail(
        "Name the remaining conditions for a potentially exploitable assessment.",
      );
    return;
  }
  if (!sourceMatchesBuild)
    fail(
      "An exploitable use needs a cited build-to-source binding for the running workload.",
    );
  if (
    bound.some(({ binding }) => binding.version !== row.use!.version) ||
    !bound.some(
      ({ binding, index }) =>
        hasBindingEvidence(index) &&
        binding.version === row.use!.version &&
        affectedVersion(selected, binding.version) === true,
    )
  )
    fail(
      "An exploitable assessment needs a cited running dependency binding for this observation.",
    );
  const control = row.attackerControlClaim;
  const accessCitations = row.use.evidence.filter((range) =>
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
    !selected.preconditions.every((p) =>
      conditions.some((c) => c.label === p && c.status === "met"),
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

export async function prepareStackAssessment(
  input: unknown,
  work: StackWorkItem,
  packet: StackPacket,
  claims: StackClaimReader,
  repository: string,
  signal?: AbortSignal,
): Promise<StackAssessment> {
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
    const use = await validateDependencyUse(row.use, repository, signal);
    if (use.verdict !== row.verdict)
      fail(
        `The supplied evidence supports only a ${use.verdict} verdict. ${use.reason}`,
      );
    row.use.reason = use.reason;
    row.use.deployment = use.deployment;
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
    reviewPolicy: "single_agent",
    runId,
    attemptId,
    inputDigest,
    toolRevision,
    target,
    cve,
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

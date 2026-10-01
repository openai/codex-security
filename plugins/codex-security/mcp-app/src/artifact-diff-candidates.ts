import { isDeepStrictEqual } from "node:util";
import {
  candidateKey,
  coverageCandidateKey,
  findingCandidateKey,
  isTerminalCandidateDecision,
  resolvedCandidateKeys,
  surfaceReferenceKey,
} from "./artifact-candidates.js";
import type { ArtifactContext } from "./artifact-context.js";
import { readArtifactJsonl } from "./artifact-io.js";
import type { ScanDraftInput } from "./artifact-scan-draft.js";
import { candidateSchemaV1 } from "./deep-scan/artifact-contracts.js";

type JsonObject = Record<string, unknown>;

export async function readDiffCandidates(context: ArtifactContext) {
  if (context.mode !== "diff") return undefined;
  const label = "diff candidate ledger";
  try {
    return await readArtifactJsonl(
      context,
      ["artifacts", "02_discovery", "candidate_ledger.jsonl"],
      label,
      candidateSchemaV1.passthrough(),
    );
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === `${label}: the requested artifact is unavailable.`
    ) {
      return undefined;
    }
    throw error;
  }
}

export type DiffCandidates = Awaited<ReturnType<typeof readDiffCandidates>>;

/** Keep generated historical decisions aligned with the current ledger. */
export function refreshDiffCandidateHistory(
  sources: ScanDraftInput[],
  candidates: DiffCandidates,
): ScanDraftInput[] {
  if (candidates === undefined) return sources;
  const ledger = new Map(
    candidates.map((candidate) => [
      candidateKey(candidate.candidate_id)!,
      candidate,
    ]),
  );
  // A newer authored decision takes precedence over an older generated checkpoint.
  const seen = new Set<string>();
  const authoredResolutions = new Set<string>();
  for (const source of sources) {
    const authored = [
      ...source.findings
        .filter((finding) => {
          const candidate = ledger.get(findingCandidateKey(finding) ?? "");
          return !candidate || !changedFindingDecision(finding, candidate);
        })
        .map((finding) => findingCandidateKey(finding)),
      ...[
        ...(source.coverage.surfaces as JsonObject[]),
        ...(source.coverage.explicitExclusions as JsonObject[]),
      ]
        .filter(
          (item) =>
            isTerminalCandidateDecision(item) && !isGeneratedDecision(item),
        )
        .map((item) => coverageCandidateKey(item)),
    ].filter((id): id is string => typeof id === "string");
    for (const id of authored) if (!seen.has(id)) authoredResolutions.add(id);
    for (const id of [
      ...source.findings.map((finding) => findingCandidateKey(finding)),
      ...authored,
      ...(source.coverage.surfaces as JsonObject[])
        .filter(isTerminalCandidateDecision)
        .map((item) => coverageCandidateKey(item)),
      ...(source.coverage.deferred as JsonObject[]).map((item) =>
        coverageCandidateKey(item),
      ),
    ])
      if (typeof id === "string") seen.add(id);
  }
  const reopened = new Map<string, JsonObject>();
  const refreshed = sources.map((source) => {
    const result = structuredClone(source);
    const deferred = result.coverage.deferred as JsonObject[];
    const closed = new Set<string>();
    for (const finding of result.findings) {
      const key = findingCandidateKey(finding);
      const candidate = ledger.get(key ?? "");
      if (
        !candidate ||
        authoredResolutions.has(key!) ||
        candidateDisposition(candidate) !== undefined ||
        !changedFindingDecision(finding, candidate)
      )
        continue;
      const pending = deferred.find(
        (item) => coverageCandidateKey(item) === key,
      ) ?? {
        candidateId: candidate.candidate_id,
        candidate,
        reason: candidateReason(candidate),
        finding,
      };
      if (!deferred.includes(pending)) deferred.push(pending);
      if (!reopened.has(key!)) reopened.set(key!, pending);
      Object.assign(result.coverage, candidatePartialCoverage(result.coverage));
    }
    result.coverage.surfaces = (result.coverage.surfaces as JsonObject[]).map(
      (surface) => {
        const key = coverageCandidateKey(surface);
        if (!key) return surface;
        const candidate = ledger.get(key);
        const pending = deferred.find(
          (item) => coverageCandidateKey(item) === key,
        );
        const generatedFollowUp = isGeneratedFollowUp(
          surface,
          pending,
          deferred,
          result.coverage.surfaces as JsonObject[],
        );
        if (!candidate || (!isGeneratedDecision(surface) && !generatedFollowUp))
          return surface;
        const disposition = candidateDisposition(candidate);
        if (generatedFollowUp && disposition === undefined) return surface;
        if (disposition === undefined && authoredResolutions.has(key))
          return surface;
        if (disposition === undefined) {
          const item = pending ?? {
            candidateId: candidate.candidate_id,
            candidate,
            reason: candidateReason(candidate),
            ...(surface.finding === undefined
              ? {}
              : { finding: surface.finding }),
          };
          if (!deferred.includes(item)) deferred.push(item);
          if (!reopened.has(key)) reopened.set(key, item);
          Object.assign(
            result.coverage,
            candidatePartialCoverage(result.coverage),
          );
        } else if (generatedFollowUp) {
          closed.add(key);
        }
        return {
          ...surface,
          candidate: candidateSnapshot(
            surface.candidate ?? pending?.candidate,
            candidate,
          ),
          ...(surface.finding === undefined && pending?.finding !== undefined
            ? { finding: pending.finding }
            : {}),
          label: candidate.summary,
          disposition: disposition ?? "needs_follow_up",
          notes:
            disposition === undefined
              ? candidateReason(candidate)
              : terminalReason(candidate),
        };
      },
    );
    result.coverage.deferred = deferred.filter(
      (item) => !closed.has(coverageCandidateKey(item) ?? ""),
    );
    if (closed.size > 0) restoreCandidateCompleteness(result.coverage);
    return result;
  });
  for (const source of refreshed) {
    source.findings = source.findings.filter((finding) => {
      const pending = reopened.get(findingCandidateKey(finding) ?? "");
      if (!pending) return true;
      pending.finding ??= finding;
      return false;
    });
  }
  return refreshed;
}

function isGeneratedFollowUp(
  surface: JsonObject,
  pending: JsonObject | undefined,
  deferred: JsonObject[],
  surfaces: JsonObject[],
): boolean {
  const candidate = object(surface.candidate ?? pending?.candidate);
  return (
    candidate !== undefined &&
    surface.disposition === "needs_follow_up" &&
    surface.label === candidate.summary &&
    surface.notes === candidateReason(candidate) &&
    !deferred.some(
      (other) =>
        coverageCandidateKey(other) !== coverageCandidateKey(surface) &&
        Array.isArray(other.surfaceIds) &&
        other.surfaceIds.some(
          (id) =>
            surfaceReferenceKey(id, other, surfaces) ===
            candidateKey(surface.id, surface.sourceWorkerId),
        ),
    )
  );
}

function isGeneratedDecision(surface: JsonObject): boolean {
  const candidate = object(surface.candidate);
  return (
    candidate !== undefined &&
    isTerminalCandidateDecision(surface) &&
    surface.candidateId === candidate.candidate_id &&
    surface.disposition === candidateDisposition(candidate) &&
    surface.label === candidate.summary &&
    surface.notes === terminalReason(candidate)
  );
}

/**
 * Project ledger dismissals before historical findings and follow-ups are merged.
 * Current findings remain authoritative if a checkpoint inherits an older final draft.
 */
export function preserveDiffCandidateDecisions(
  input: ScanDraftInput,
  candidates: DiffCandidates,
  previous: ScanDraftInput[] = [],
  currentFindings: JsonObject[] = input.findings,
): ScanDraftInput {
  if (candidates === undefined) return input;
  const resolved = resolvedCandidateKeys({
    ...input,
    findings: currentFindings,
  });
  const currentFindingKeys = new Set(
    currentFindings.map((finding) => findingCandidateKey(finding)),
  );
  const accepted = new Set(currentFindingKeys);
  accepted.delete(undefined);
  const ledger = new Map(
    candidates.map((candidate) => [
      candidateKey(candidate.candidate_id)!,
      candidate,
    ]),
  );
  const previousDecisions = new Map<
    string,
    { section: string; item: JsonObject }
  >();
  const seen = resolvedCandidateKeys({ ...input, findings: [] });
  for (const source of previous) {
    for (const finding of source.findings) {
      const key = findingCandidateKey(finding);
      const candidate = ledger.get(key ?? "");
      if (
        key &&
        !seen.has(key) &&
        candidate &&
        isDeepStrictEqual(
          object(finding.provenance)?.diffCandidateDecision,
          candidateDecision(candidate),
        )
      )
        accepted.add(key);
      if (key) seen.add(key);
    }
    for (const section of ["surfaces", "explicitExclusions"]) {
      for (const item of source.coverage[section] as JsonObject[]) {
        if (!isTerminalCandidateDecision(item)) continue;
        const key = coverageCandidateKey(item)!;
        if (!seen.has(key)) previousDecisions.set(key, { section, item });
        seen.add(key);
      }
    }
    for (const item of source.coverage.deferred as JsonObject[]) {
      const key = coverageCandidateKey(item);
      if (key) seen.add(key);
    }
  }
  const dismissed = new Set<string>();
  const retainDecision = (item: JsonObject) =>
    !isTerminalCandidateDecision(item) ||
    !accepted.has(coverageCandidateKey(item));
  const surfaces = (input.coverage.surfaces as JsonObject[]).filter(
    retainDecision,
  );
  const exclusions = (input.coverage.explicitExclusions as JsonObject[]).filter(
    retainDecision,
  );
  for (const candidate of candidates) {
    const key = candidateKey(candidate.candidate_id)!;
    const disposition = candidateDisposition(candidate);
    if (disposition === undefined || accepted.has(key)) continue;
    dismissed.add(key);
    if (resolved.has(key)) continue;
    // An authored final decision keeps its rationale on later empty saves.
    const retained = previousDecisions.get(key);
    if (retained) {
      (retained.section === "surfaces" ? surfaces : exclusions).push(
        structuredClone(retained.item),
      );
    } else {
      surfaces.push({
        candidateId: candidate.candidate_id,
        candidate,
        label: candidate.summary,
        disposition,
        notes: terminalReason(candidate),
      });
    }
    resolved.add(key);
  }
  return {
    ...input,
    findings: input.findings
      .filter((finding) => {
        const candidateId = findingCandidateKey(finding);
        return candidateId === undefined || !dismissed.has(candidateId);
      })
      .map((finding) => {
        const key = findingCandidateKey(finding);
        const candidate = ledger.get(key ?? "");
        if (!candidate || !currentFindingKeys.has(key)) return finding;
        if (
          candidateDisposition(candidate) === undefined &&
          object(finding.provenance)?.diffCandidateDecision === undefined
        )
          return finding;
        const { diffCandidateDecision: _previousDecision, ...provenance } =
          object(finding.provenance) ?? {};
        return {
          ...finding,
          provenance: {
            ...provenance,
            ...(candidateDisposition(candidate) === undefined
              ? {}
              : {
                  diffCandidateDecision: structuredClone(
                    candidateDecision(candidate),
                  ),
                }),
          },
        };
      }),
    coverage: { ...input.coverage, surfaces, explicitExclusions: exclusions },
  };
}

/** Retain unresolved diff candidates alongside the final coverage evidence. */
export function preserveUnresolvedDiffCandidates(
  input: ScanDraftInput,
  candidates: DiffCandidates,
): ScanDraftInput {
  if (candidates === undefined) return input;
  const resolvedKeys = resolvedCandidateKeys(input);
  const confirmed = new Map(
    input.findings.map((finding) => [findingCandidateKey(finding), finding]),
  );
  const inputSurfaces = input.coverage.surfaces as JsonObject[];
  const decisions = new Map(
    [...inputSurfaces, ...(input.coverage.explicitExclusions as JsonObject[])]
      .filter(isTerminalCandidateDecision)
      .map((item) => [coverageCandidateKey(item), item]),
  );
  const replacedDecisions = new Set<JsonObject>();
  const pending = new Map(
    candidates
      .filter(
        (candidate) =>
          !resolvedKeys.has(candidateKey(candidate.candidate_id)!) &&
          candidateDisposition(candidate) === undefined,
      )
      .map((candidate) => [candidateKey(candidate.candidate_id)!, candidate]),
  );
  const previous = new Map(
    (input.coverage.deferred as JsonObject[]).map((item) => [
      coverageCandidateKey(item),
      item,
    ]),
  );
  const deferred = (input.coverage.deferred as JsonObject[])
    .filter((item) => {
      const candidateId = coverageCandidateKey(item);
      return typeof candidateId !== "string" || !resolvedKeys.has(candidateId);
    })
    .map((item) => {
      const candidateId = coverageCandidateKey(item);
      const candidate =
        typeof candidateId === "string" ? pending.get(candidateId) : undefined;
      if (!candidate) return item;
      const previous = object(item.candidate);
      return {
        ...item,
        candidateId: candidate.candidate_id,
        candidate: candidateSnapshot(previous, candidate),
        reason:
          item.reason === candidateReason(previous ?? candidate)
            ? candidateReason(candidate)
            : item.reason,
      };
    });
  const recordedKeys = new Set(
    deferred.map((item) => coverageCandidateKey(item)),
  );
  for (const candidate of pending.values()) {
    if (recordedKeys.has(candidateKey(candidate.candidate_id)!)) continue;
    deferred.push({
      candidateId: candidate.candidate_id,
      candidate,
      reason: candidateReason(candidate),
      paths: [...new Set(candidate.locations.map((location) => location.path))],
    });
  }
  const surfaces = inputSurfaces
    .map((surface) => {
      const key = coverageCandidateKey(surface);
      const item = previous.get(key);
      const finding = confirmed.get(key ?? "");
      const decision = decisions.get(key);
      if (
        (finding || decision) &&
        isGeneratedFollowUp(surface, item, deferred, inputSurfaces)
      ) {
        if (finding)
          return {
            ...surface,
            disposition: "reported",
            notes: finding.summary,
          };
        if (inputSurfaces.includes(decision!)) {
          replacedDecisions.add(decision!);
          const { notes: _generatedNotes, ...generatedSurface } = surface;
          return {
            ...generatedSurface,
            ...decision,
            receiptRefs: [
              ...new Set([
                ...((surface.receiptRefs as string[]) ?? []),
                ...((decision!.receiptRefs as string[]) ?? []),
              ]),
            ],
          };
        }
        return {
          ...surface,
          disposition: decision!.disposition,
          notes: decision!.reason,
        };
      }
      const candidate = pending.get(key ?? "");
      const oldCandidate = object(item?.candidate);
      if (
        !candidate ||
        !oldCandidate ||
        surface.disposition !== "needs_follow_up" ||
        (input.coverage.deferred as JsonObject[]).some(
          (other) =>
            other !== item &&
            Array.isArray(other.surfaceIds) &&
            other.surfaceIds.some(
              (id) =>
                surfaceReferenceKey(
                  id,
                  other,
                  input.coverage.surfaces as JsonObject[],
                ) === candidateKey(surface.id, surface.sourceWorkerId),
            ),
        )
      )
        return surface;
      return {
        ...surface,
        ...(object(surface.candidate)
          ? { candidate: candidateSnapshot(surface.candidate, candidate) }
          : {}),
        ...(surface.label === oldCandidate.summary
          ? { label: candidate.summary }
          : {}),
        ...(surface.notes === candidateReason(oldCandidate)
          ? { notes: candidateReason(candidate) }
          : {}),
      };
    })
    .filter((surface) => !replacedDecisions.has(surface));
  for (const item of deferred) {
    if (typeof item.candidateId !== "string") continue;
    const candidate = pending.get(coverageCandidateKey(item) ?? "");
    if (!candidate) continue;
    const surfaceIds = Array.isArray(item.surfaceIds) ? item.surfaceIds : [];
    if (
      surfaces.some(
        (surface) =>
          coverageCandidateKey(surface) === coverageCandidateKey(item) ||
          surfaceIds.some(
            (id) =>
              surfaceReferenceKey(id, item, surfaces) ===
              candidateKey(surface.id, surface.sourceWorkerId),
          ),
      )
    )
      continue;
    surfaces.push({
      candidateId: item.candidateId,
      label: candidate.summary,
      disposition: "needs_follow_up",
      notes: item.reason,
    });
  }
  const coverage = {
    ...(deferred.length > 0
      ? candidatePartialCoverage(input.coverage)
      : input.coverage),
    deferred,
    surfaces,
  };
  restoreCandidateCompleteness(coverage);
  return { ...input, coverage };
}

function restoreCandidateCompleteness(coverage: JsonObject): void {
  if (
    coverage.completenessBeforeCandidates !== undefined &&
    coverage.completeness === "partial" &&
    (coverage.deferred as JsonObject[]).length === 0 &&
    !(coverage.surfaces as JsonObject[]).some(
      (surface) => surface.disposition === "needs_follow_up",
    )
  ) {
    coverage.completeness = coverage.completenessBeforeCandidates;
    delete coverage.completenessBeforeCandidates;
  }
}

// Retain the author's completeness only when candidate projection changes it.
function candidatePartialCoverage(coverage: JsonObject): JsonObject {
  return {
    ...coverage,
    ...(coverage.completeness === "partial"
      ? {}
      : { completenessBeforeCandidates: coverage.completeness }),
    completeness: "partial",
  };
}

function changedFindingDecision(
  finding: JsonObject,
  candidate: JsonObject,
): boolean {
  const previous = object(finding.provenance)?.diffCandidateDecision;
  return (
    previous !== undefined &&
    !isDeepStrictEqual(previous, candidateDecision(candidate))
  );
}

// This snapshot orders an explicit finding override against later ledger phase updates.
function candidateDecision(candidate: JsonObject): JsonObject {
  return {
    ...(candidate.validation === undefined
      ? {}
      : { validation: candidate.validation }),
    ...(candidate.attack_path === undefined
      ? {}
      : { attack_path: candidate.attack_path }),
  };
}

function candidateSnapshot(
  previous: unknown,
  candidate: JsonObject,
): JsonObject {
  // Discovery replacement resets phase records while retaining candidate identities.
  const {
    validation: _validation,
    attack_path: _attackPath,
    ...saved
  } = object(previous) ?? {};
  return { ...saved, ...candidate };
}

function candidateDisposition(
  candidate: JsonObject,
): "rejected" | "not_applicable" | undefined {
  const validation = object(candidate.validation)?.disposition;
  const attackPath = object(candidate.attack_path)?.decision;
  // Reportable ledger phases still need a matching saved finding.
  if (validation === "deferred" || attackPath === "deferred") return undefined;
  if (validation === "not_applicable") return "not_applicable";
  if (validation === "suppressed" || attackPath === "ignore") return "rejected";
  return undefined;
}

function terminalReason(candidate: JsonObject): string {
  const validation = object(candidate.validation);
  const attackPath = object(candidate.attack_path);
  return (
    [
      ...(attackPath?.decision === "ignore"
        ? [attackPath.counterevidence, attackPath.severity_rationale]
        : []),
      validation?.counterevidence_or_proof_gap,
    ].find(
      (value): value is string => typeof value === "string" && !!value.trim(),
    ) ?? `Candidate review concluded: ${candidate.summary}`
  );
}

function candidateReason(candidate: JsonObject): string {
  const validation = object(candidate.validation);
  const attackPath = object(candidate.attack_path);
  if (
    validation?.disposition === "reportable" &&
    attackPath?.decision === "reportable"
  ) {
    return `A reportable candidate has no saved finding: ${candidate.summary}`;
  }
  return (
    [
      attackPath?.proof_gap,
      validation?.counterevidence_or_proof_gap,
      validation?.remaining_uncertainty,
    ].find(
      (value): value is string =>
        typeof value === "string" && value.trim().length > 0,
    ) ?? `Candidate review is incomplete: ${candidate.summary}`
  );
}

function object(value: unknown): JsonObject | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

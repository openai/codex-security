import { isDeepStrictEqual } from "node:util";
import {
  candidateKey,
  coverageCandidateKey,
  findingCandidateKey,
  isCurrentCandidateFinding,
  isTerminalCandidateDecision,
  resolvedCandidateKeys,
  surfaceReferenceKey,
} from "./artifact-candidates.js";
import type { ArtifactContext } from "./artifact-context.js";
import { readArtifactJsonl } from "./artifact-io.js";
import {
  exactUnion,
  preserveFindingDetails,
  type ScanDraftInput,
} from "./artifact-scan-draft.js";
import { candidateSchemaV1 } from "./deep-scan/artifact-contracts.js";

type JsonObject = Record<string, unknown>;
type DraftCoverage = ScanDraftInput["coverage"];

export async function readDiffCandidates(context: ArtifactContext) {
  return context.mode === "diff"
    ? readCandidateLedger(context, "diff candidate ledger")
    : undefined;
}

export async function readCandidateLedger(
  context: ArtifactContext,
  label = "candidate ledger",
) {
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

function* currentFindingHistory(finding: JsonObject): Generator<JsonObject> {
  if (!isCurrentCandidateFinding(finding)) return;
  yield finding;
  const provenance = object(finding.provenance);
  for (const previous of Array.isArray(provenance?.previousFindings)
    ? provenance.previousFindings
    : []) {
    const retained = object(previous);
    if (retained) yield* currentFindingHistory(retained);
  }
}

function candidateHistory(
  sources: ScanDraftInput[],
  ledger: ReadonlyMap<string, NonNullable<DiffCandidates>[number]>,
) {
  // A newer authored decision takes precedence over an older generated checkpoint.
  const seen = new Set<string>();
  const authoredResolutions = new Set<string>();
  const pendingDecisions = new Set<string>();
  for (const source of sources) {
    const pendingKeys = new Set(
      source.coverage.deferred.map((item) => coverageCandidateKey(item)),
    );
    const authored = [
      ...source.findings
        .flatMap((finding) =>
          [...currentFindingHistory(finding)].filter(
            (retained) =>
              retained === finding ||
              !pendingKeys.has(findingCandidateKey(retained)),
          ),
        )
        .filter((finding) => {
          const candidate = ledger.get(findingCandidateKey(finding) ?? "");
          return !candidate || !changedFindingDecision(finding, candidate);
        })
        .map((finding) => findingCandidateKey(finding)),
      ...[...source.coverage.surfaces, ...source.coverage.explicitExclusions]
        .filter(
          (item) =>
            isTerminalCandidateDecision(item) && !isGeneratedDecision(item),
        )
        .map((item) => coverageCandidateKey(item)),
    ].filter((id): id is string => typeof id === "string");
    for (const id of authored) if (!seen.has(id)) authoredResolutions.add(id);
    for (const pending of source.coverage.deferred) {
      const key = coverageCandidateKey(pending);
      const saved = object(pending.candidate);
      const candidate = ledger.get(key ?? "");
      if (
        key &&
        !seen.has(key) &&
        !authored.includes(key) &&
        saved &&
        candidate &&
        candidateDisposition(candidate) !== undefined &&
        isDeepStrictEqual(
          candidateDecision(saved),
          candidateDecision(candidate),
        )
      )
        pendingDecisions.add(key);
    }
    for (const id of [
      ...source.findings.map((finding) => findingCandidateKey(finding)),
      ...authored,
      ...source.coverage.surfaces
        .filter(isTerminalCandidateDecision)
        .map((item) => coverageCandidateKey(item)),
      ...source.coverage.deferred.map((item) => coverageCandidateKey(item)),
    ])
      if (typeof id === "string") seen.add(id);
  }
  return { authoredResolutions, pendingDecisions };
}

/** Keep generated historical decisions aligned with the current ledger. */
export function refreshDiffCandidateHistory(
  sources: ScanDraftInput[],
  candidates: DiffCandidates,
  history?: ReturnType<typeof candidateHistory>,
): ScanDraftInput[] {
  if (candidates === undefined) return sources;
  const ledger = new Map(
    candidates.map((candidate) => [
      candidateKey(candidate.candidate_id)!,
      candidate,
    ]),
  );
  const { authoredResolutions, pendingDecisions } =
    history ?? candidateHistory(sources, ledger);
  const dispositionFor = (candidate: NonNullable<DiffCandidates>[number]) =>
    pendingDecisions.has(candidateKey(candidate.candidate_id)!)
      ? undefined
      : candidateDisposition(candidate);
  const reopened = new Map<string, DraftCoverage["deferred"][number]>();
  const refreshed = sources.map((source) => {
    const result = structuredClone(source);
    const deferred = result.coverage.deferred;
    const closed = new Set<string>();
    // Rediscovery can restore old phase values without resolving a saved proof gap.
    for (const pending of deferred) {
      const key = coverageCandidateKey(pending);
      const candidate = ledger.get(key ?? "");
      if (
        key &&
        candidate &&
        !authoredResolutions.has(key) &&
        dispositionFor(candidate) === undefined &&
        !reopened.has(key)
      )
        reopened.set(key, pending);
    }
    for (const finding of result.findings) {
      const key = findingCandidateKey(finding);
      const candidate = ledger.get(key ?? "");
      if (
        !candidate ||
        authoredResolutions.has(key!) ||
        dispositionFor(candidate) !== undefined ||
        (!changedFindingDecision(finding, candidate) && !reopened.has(key!))
      )
        continue;
      const pending = reopened.get(key!) ??
        deferred.find((item) => coverageCandidateKey(item) === key) ?? {
          candidateId: candidate.candidate_id,
          candidate,
          reason: candidateReason(candidate),
          finding,
        };
      if (!reopened.has(key!) && !deferred.includes(pending))
        deferred.push(pending);
      if (!reopened.has(key!)) reopened.set(key!, pending);
    }
    result.coverage.surfaces = result.coverage.surfaces.map((surface) => {
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
        result.coverage.surfaces,
      );
      if (!candidate || (!isGeneratedDecision(surface) && !generatedFollowUp))
        return surface;
      const disposition = dispositionFor(candidate);
      if (
        generatedFollowUp &&
        disposition === undefined &&
        surface.disposition === "needs_follow_up"
      )
        return surface;
      if (disposition === undefined && authoredResolutions.has(key))
        return surface;
      if (disposition === undefined) {
        const item = pending ??
          reopened.get(key) ?? {
            candidateId: candidate.candidate_id,
            candidate,
            reason: candidateReason(candidate),
            ...(surface.finding === undefined
              ? {}
              : { finding: surface.finding }),
          };
        if (!deferred.includes(item)) deferred.push(item);
        if (!reopened.has(key)) reopened.set(key, item);
      } else if (generatedFollowUp) {
        closed.add(key);
        const resolved = deferred.filter(
          (row) => coverageCandidateKey(row) === key,
        );
        for (const [field, archive] of [
          ["candidate", "originalCandidates"],
          ["finding", "previousFindings"],
        ] as const) {
          const values = resolved.flatMap((row) => [
            ...(row[field] === undefined ? [] : [row[field]]),
            ...(Array.isArray(row[archive]) ? row[archive] : []),
          ]);
          if (values.length > 0)
            surface[archive] = exactUnion(
              Array.isArray(surface[archive]) ? surface[archive] : [],
              values,
            );
        }
      }
      const previousCandidate = surface.candidate ?? pending?.candidate;
      const snapshot = candidateSnapshot(previousCandidate, candidate);
      if (
        previousCandidate !== undefined &&
        !isDeepStrictEqual(previousCandidate, snapshot)
      )
        surface.originalCandidates = exactUnion(
          Array.isArray(surface.originalCandidates)
            ? surface.originalCandidates
            : [],
          [previousCandidate],
        );
      return {
        ...surface,
        candidate: snapshot,
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
    });
    result.coverage.deferred = deferred.filter(
      (item) => !closed.has(coverageCandidateKey(item) ?? ""),
    );
    return result;
  });
  for (const source of refreshed) {
    source.findings = source.findings.filter((finding) => {
      const pending = reopened.get(findingCandidateKey(finding) ?? "");
      if (!pending || !isCurrentCandidateFinding(finding)) return true;
      if (object(pending.finding)) {
        if (object((pending.finding as JsonObject).provenance))
          preserveFindingDetails(pending.finding as JsonObject, finding);
        else {
          const previous = Array.isArray(pending.previousFindings)
            ? pending.previousFindings
            : [];
          if (!previous.some((item) => isDeepStrictEqual(item, finding)))
            pending.previousFindings = [...previous, structuredClone(finding)];
        }
      } else pending.finding = finding;
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
  const finding = object(pending?.finding ?? surface.finding);
  return (
    candidate !== undefined &&
    surface.label === candidate.summary &&
    ((surface.disposition === "needs_follow_up" &&
      surface.notes === (pending?.reason ?? candidateReason(candidate))) ||
      (surface.disposition === "reported" &&
        typeof finding?.summary === "string" &&
        surface.notes === finding.summary)) &&
    !deferred.some(
      (other) =>
        coverageCandidateKey(other) !== coverageCandidateKey(surface) &&
        Array.isArray(other.surfaceIds) &&
        other.surfaceIds.some(
          (id) =>
            surfaceReferenceKey(id, other, surfaces) ===
            candidateKey(
              surface.id,
              surface.sourceWorkerId ?? surface.workerId,
            ),
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
    (surface.notes === terminalReason(candidate) ||
      surface.notes === terminalReason(candidate, true))
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
  currentFindings: ScanDraftInput["findings"] = input.findings,
): ScanDraftInput {
  if (candidates === undefined) return input;
  const ledger = new Map(
    candidates.map((candidate) => [
      candidateKey(candidate.candidate_id)!,
      candidate,
    ]),
  );
  const history = candidateHistory(
    [{ ...input, findings: currentFindings }, ...previous],
    ledger,
  );
  input = {
    ...input,
    coverage: refreshDiffCandidateHistory(
      [{ ...input, findings: [] }],
      candidates,
      history,
    )[0]!.coverage,
  };
  const resolved = resolvedCandidateKeys({
    ...input,
    findings: currentFindings,
  });
  const currentFindingKeys = new Set(
    currentFindings
      .filter(isCurrentCandidateFinding)
      .map((finding) => findingCandidateKey(finding)),
  );
  const accepted = new Set(currentFindingKeys);
  accepted.delete(undefined);
  const previousDecisions = new Map<
    string,
    | { section: "surfaces"; item: DraftCoverage["surfaces"][number] }
    | {
        section: "explicitExclusions";
        item: DraftCoverage["explicitExclusions"][number];
      }
  >();
  const seen = resolvedCandidateKeys({ ...input, findings: [] });
  for (const finding of currentFindings) {
    const key = findingCandidateKey(finding);
    if (key && !isCurrentCandidateFinding(finding)) seen.add(key);
  }
  for (const source of previous) {
    for (const finding of source.findings) {
      const key = findingCandidateKey(finding);
      const candidate = ledger.get(key ?? "");
      if (
        key &&
        isCurrentCandidateFinding(finding) &&
        !seen.has(key) &&
        candidate &&
        (object(finding.provenance)?.diffCandidateDecision === undefined ||
          isDeepStrictEqual(
            object(finding.provenance)?.diffCandidateDecision,
            candidateDecision(candidate),
          ))
      )
        accepted.add(key);
      if (key) seen.add(key);
    }
    for (const decision of [
      ...source.coverage.surfaces.map((item) => ({
        section: "surfaces" as const,
        item,
      })),
      ...source.coverage.explicitExclusions.map((item) => ({
        section: "explicitExclusions" as const,
        item,
      })),
    ]) {
      if (!isTerminalCandidateDecision(decision.item)) continue;
      const key = coverageCandidateKey(decision.item)!;
      if (!seen.has(key)) previousDecisions.set(key, decision);
      seen.add(key);
    }
    for (const item of source.coverage.deferred) {
      const key = coverageCandidateKey(item);
      if (key) seen.add(key);
    }
  }
  const dismissed = new Set<string>();
  for (const item of [
    ...input.coverage.surfaces,
    ...input.coverage.explicitExclusions,
  ]) {
    if (!isTerminalCandidateDecision(item)) continue;
    const key = coverageCandidateKey(item)!;
    if (!accepted.has(key)) dismissed.add(key);
  }
  const retainDecision = (item: JsonObject) =>
    !isTerminalCandidateDecision(item) ||
    !accepted.has(coverageCandidateKey(item));
  const inputSurfaces = input.coverage.surfaces;
  const pendingReferences = new Set(
    input.coverage.deferred.flatMap((item) => {
      const key = coverageCandidateKey(item);
      return (key === undefined || !resolved.has(key)) &&
        Array.isArray(item.surfaceIds)
        ? item.surfaceIds.map((id) =>
            surfaceReferenceKey(id, item, inputSurfaces),
          )
        : [];
    }),
  );
  const surfaces: DraftCoverage["surfaces"] = inputSurfaces
    .map((item) =>
      !retainDecision(item) &&
      pendingReferences.has(
        candidateKey(item.id, item.sourceWorkerId ?? item.workerId),
      )
        ? { ...item, disposition: "reported" as const }
        : item,
    )
    .filter(retainDecision);
  const exclusions = input.coverage.explicitExclusions.filter(retainDecision);
  for (const candidate of candidates) {
    const key = candidateKey(candidate.candidate_id)!;
    const disposition = candidateDisposition(candidate);
    if (
      disposition === undefined ||
      accepted.has(key) ||
      history.pendingDecisions.has(key)
    )
      continue;
    dismissed.add(key);
    if (resolved.has(key)) continue;
    // An authored final decision keeps its rationale on later empty saves.
    const retained = previousDecisions.get(key);
    if (retained) {
      if (retained.section === "surfaces")
        surfaces.push(structuredClone(retained.item));
      else exclusions.push(structuredClone(retained.item));
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
        const { diffCandidateDecision: _previousDecision, ...provenance } =
          object(finding.provenance) ?? {};
        return {
          ...finding,
          provenance: {
            ...provenance,
            diffCandidateDecision: structuredClone(
              candidateDecision(candidate),
            ),
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
  submitted = input,
  mergedResolutions: ReadonlySet<string> = new Set(),
): ScanDraftInput {
  if (candidates === undefined) return input;
  input = structuredClone(input);
  const resolvedKeys = new Set([
    ...resolvedCandidateKeys(input),
    ...mergedResolutions,
  ]);
  const confirmed = new Map(
    input.findings
      .filter(isCurrentCandidateFinding)
      .map((finding) => [findingCandidateKey(finding), finding]),
  );
  for (const finding of input.findings.filter(isCurrentCandidateFinding))
    for (const retained of currentFindingHistory(finding)) {
      const key = findingCandidateKey(retained);
      if (key && mergedResolutions.has(key)) confirmed.set(key, finding);
    }
  const inputSurfaces = input.coverage.surfaces;
  const decisions = new Map(
    [...inputSurfaces, ...input.coverage.explicitExclusions]
      .filter(isTerminalCandidateDecision)
      .map((item) => [coverageCandidateKey(item), item]),
  );
  for (const finding of submitted.findings) {
    if (isCurrentCandidateFinding(finding)) continue;
    const decision = decisions.get(findingCandidateKey(finding));
    if (decision)
      decision.previousFindings = exactUnion(
        Array.isArray(decision.previousFindings)
          ? decision.previousFindings
          : [],
        [finding],
      );
  }
  // Resolved rows still carry submitted evidence; archive it before clearing the gap.
  for (const pending of [
    ...submitted.coverage.deferred,
    ...[
      ...submitted.coverage.surfaces,
      ...submitted.coverage.explicitExclusions,
    ].filter(
      (row) =>
        isTerminalCandidateDecision(row) &&
        confirmed.has(coverageCandidateKey(row)),
    ),
  ]) {
    const key = coverageCandidateKey(pending);
    const finding = confirmed.get(key ?? "");
    if (finding) {
      const provenance = finding.provenance as JsonObject;
      if (pending.candidate !== undefined) {
        const previous = Array.isArray(provenance.originalCandidates)
          ? provenance.originalCandidates
          : [];
        if (
          !previous.some((item) => isDeepStrictEqual(item, pending.candidate))
        )
          provenance.originalCandidates = [
            ...previous,
            structuredClone(pending.candidate),
          ];
      }
      if (object(pending.finding))
        preserveFindingDetails(finding, pending.finding as JsonObject);
      if (Array.isArray(pending.originalCandidates))
        provenance.originalCandidates = exactUnion(
          Array.isArray(provenance.originalCandidates)
            ? provenance.originalCandidates
            : [],
          pending.originalCandidates,
        );
      if (Array.isArray(pending.previousFindings))
        provenance.previousFindings = exactUnion(
          Array.isArray(provenance.previousFindings)
            ? provenance.previousFindings
            : [],
          pending.previousFindings,
        );
      continue;
    }
    const decision = decisions.get(key);
    if (!decision) continue;
    for (const [field, archive] of [
      ["candidate", "originalCandidates"],
      ["finding", "previousFindings"],
    ] as const) {
      if (pending[field] === undefined) continue;
      const previous = Array.isArray(decision[archive])
        ? (decision[archive] as unknown[])
        : [];
      if (!previous.some((item) => isDeepStrictEqual(item, pending[field])))
        decision[archive] = [...previous, structuredClone(pending[field])];
      decision[field] ??= structuredClone(pending[field]);
    }
    if (Array.isArray(pending.originalCandidates))
      decision.originalCandidates = exactUnion(
        Array.isArray(decision.originalCandidates)
          ? decision.originalCandidates
          : [],
        pending.originalCandidates,
      );
    if (Array.isArray(pending.previousFindings))
      decision.previousFindings = exactUnion(
        Array.isArray(decision.previousFindings)
          ? decision.previousFindings
          : [],
        pending.previousFindings,
      );
  }
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
  const previous = new Map<string | undefined, JsonObject[]>();
  for (const item of input.coverage.deferred) {
    const key = coverageCandidateKey(item);
    const rows = previous.get(key) ?? [];
    rows.push(item);
    previous.set(key, rows);
  }
  const deferred: DraftCoverage["deferred"] = input.coverage.deferred
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
      const snapshot = candidateSnapshot(previous, candidate);
      return {
        ...item,
        ...(Object.hasOwn(item, "candidate") &&
        !isDeepStrictEqual(item.candidate, snapshot)
          ? {
              originalCandidates: exactUnion(
                Array.isArray(item.originalCandidates)
                  ? item.originalCandidates
                  : [],
                [item.candidate],
              ),
            }
          : {}),
        candidateId: candidate.candidate_id,
        candidate: snapshot,
        reason:
          item.reason === candidateReason(previous ?? candidate)
            ? candidateReason(candidate)
            : item.reason,
      };
    });
  const receiptDecisions = new Set(
    [...submitted.coverage.surfaces, ...submitted.coverage.explicitExclusions]
      .filter(
        (surface) =>
          isTerminalCandidateDecision(surface) &&
          !confirmed.has(coverageCandidateKey(surface)) &&
          surface.receiptRefs !== undefined &&
          (!Array.isArray(surface.receiptRefs) ||
            surface.receiptRefs.length > 0),
      )
      .map((surface) => coverageCandidateKey(surface)),
  );
  // Keep submitted proof gaps until the terminal decision's receipts are verified.
  for (const item of submitted.coverage.deferred) {
    const key = coverageCandidateKey(item);
    if (
      resolvedKeys.has(key!) &&
      receiptDecisions.has(key) &&
      !deferred.some((row) => isDeepStrictEqual(row, item))
    )
      deferred.push(structuredClone(item));
  }
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
  const surfaces: DraftCoverage["surfaces"] = inputSurfaces
    .map((surface) => {
      const key = coverageCandidateKey(surface);
      const items = previous.get(key) ?? [];
      const item = items.at(-1);
      const finding = confirmed.get(key ?? "");
      const decision = decisions.get(key);
      if (
        (finding || decision) &&
        (items.length > 0
          ? items.some((item) =>
              isGeneratedFollowUp(surface, item, deferred, inputSurfaces),
            )
          : isGeneratedFollowUp(surface, undefined, deferred, inputSurfaces))
      ) {
        if (finding)
          return {
            ...surface,
            disposition: "reported" as const,
            notes: finding.summary,
          };
        const surfaceDecision = inputSurfaces.find((item) => item === decision);
        if (surfaceDecision) {
          replacedDecisions.add(decision!);
          const { notes: _generatedNotes, ...generatedSurface } = surface;
          return {
            ...generatedSurface,
            ...surfaceDecision,
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
          notes: decision!.reason as string,
        };
      }
      const candidate = pending.get(key ?? "");
      const oldCandidate = object(item?.candidate);
      if (
        !candidate ||
        !oldCandidate ||
        surface.disposition !== "needs_follow_up" ||
        input.coverage.deferred.some(
          (other) =>
            other !== item &&
            Array.isArray(other.surfaceIds) &&
            other.surfaceIds.some(
              (id) =>
                surfaceReferenceKey(id, other, input.coverage.surfaces) ===
                candidateKey(
                  surface.id,
                  surface.sourceWorkerId ?? surface.workerId,
                ),
            ),
        )
      )
        return surface;
      return {
        ...surface,
        ...(object(surface.candidate)
          ? {
              candidate: candidateSnapshot(surface.candidate, candidate),
              ...(!isDeepStrictEqual(
                surface.candidate,
                candidateSnapshot(surface.candidate, candidate),
              )
                ? {
                    originalCandidates: exactUnion(
                      Array.isArray(surface.originalCandidates)
                        ? surface.originalCandidates
                        : [],
                      [surface.candidate],
                    ),
                  }
                : {}),
            }
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
              candidateKey(
                surface.id,
                surface.sourceWorkerId ?? surface.workerId,
              ),
          ),
      )
    )
      continue;
    surfaces.push({
      candidateId: item.candidateId,
      label: candidate.summary,
      disposition: "needs_follow_up" as const,
      notes: item.reason,
    });
  }
  const coverage = {
    ...input.coverage,
    deferred,
    surfaces,
  };
  return { ...input, coverage };
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

function terminalReason(candidate: JsonObject, legacy = false): string {
  const validation = object(candidate.validation);
  const attackPath = object(candidate.attack_path);
  return (
    [
      ...((legacy || candidateDisposition(candidate) === "rejected") &&
      attackPath?.decision === "ignore"
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

function object<Value extends JsonObject>(value: Value): Value;
function object(value: unknown): JsonObject | undefined;
function object(value: unknown): JsonObject | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

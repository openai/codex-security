import {
  dependencyRecordHash,
  type DependencyAttemptStore,
} from "./dependency-attempt-store.js";
import type { DependencyEvidenceRecord } from "./dependency-evidence-sources.js";
import {
  selectedReceiptKey,
  selectedReceiptReference,
  selectedReceiptValue,
} from "./dependency-graph-evidence.js";
import type { DependencyReviewReference } from "./dependency-reachability.js";
import {
  assertReviewedPremises,
  claimInputs,
  currentApproval,
  premiseKey,
  type PremiseRef,
} from "./dependency-review-queue.js";
import {
  DependencyReviewRejection,
  reference,
  type Claim,
  type Decision,
  type VerifiedDisposition,
  type VerifiedUse,
} from "./dependency-reviewed-claims.js";

export function selectedPremises(
  store: DependencyAttemptStore,
  records: ReadonlyMap<string, DependencyEvidenceRecord>,
  refs: PremiseRef[],
  approvals = new Map<string, Decision | undefined>(),
) {
  assertReviewedPremises(store, refs, approvals);
  const result: DependencyReviewReference[] = [];
  const claims: PremiseRef[] = [];
  const visited = new Set<string>();
  function select(row: Claim) {
    const key = premiseKey(row);
    if (visited.has(key)) return;
    visited.add(key);
    claims.push(reference(row));
    const selected = new Set(
      currentApproval(store, row, approvals)!.evidenceKeys,
    );
    const {
      sources,
      sourceIds,
      wholeReceiptIds,
      selected: projections,
      dependencies,
    } = claimInputs(row);
    if (row.value.kind === "premise") {
      for (const [i, ref] of sources.entries())
        if (selected.has(sourceIds[i]!))
          result.push({
            kind: "source",
            path: ref.path,
            commit: ref.commit,
            startLine: ref.startLine,
            endLine: ref.endLine,
          });
      for (const projection of projections)
        if (selected.has(selectedReceiptKey(projection)))
          result.push(selectedReceiptReference(projection));
      for (const id of wholeReceiptIds)
        if (selected.has(id))
          result.push({
            kind: "receipt",
            receiptId: id,
            originalPayloadSha256: dependencyRecordHash(
              records.get(id)!.result,
            ),
          });
    }
    for (const dep of dependencies)
      if (selected.has(premiseKey(dep)))
        select(store.claim<Claim["value"]>(dep.id, dep.revision)!);
  }
  for (const ref of refs)
    select(store.claim<Claim["value"]>(ref.id, ref.revision)!);
  return { claims, evidence: result };
}

function publishedFindingEvidence(
  use: VerifiedUse | VerifiedDisposition,
  evidenceKeys: readonly string[],
  premiseEvidence: readonly DependencyReviewReference[],
) {
  const decidingEvidence: DependencyReviewReference[] = [
    ...use.evidence
      .filter((ref) => evidenceKeys.includes(dependencyRecordHash(ref)))
      .map(({ path, commit, startLine, endLine }) => ({
        kind: "source" as const,
        path,
        commit,
        startLine,
        endLine,
      })),
    ...use.observations
      .filter((ref) => !ref.evidenceKeys && evidenceKeys.includes(ref.sha256))
      .map((ref) => ({
        kind: "receipt" as const,
        receiptId: ref.sha256,
        originalPayloadSha256: ref.originalPayloadSha256,
      })),
    ...(use.boundReceipts ?? [])
      .filter((row) => evidenceKeys.includes(selectedReceiptKey(row)))
      .map(selectedReceiptReference),
    ...premiseEvidence,
  ];
  const evidence = use.evidence.map(
    ({ path, commit, startLine, endLine, supports }) => ({
      path,
      commit,
      startLine,
      endLine,
      supports: supports.filter(
        (s) => s === "affected_copy" || s === "affected_use",
      ),
    }),
  );
  const key = (ref: (typeof evidence)[number]) =>
    JSON.stringify([ref.path, ref.commit, ref.startLine, ref.endLine]);
  const ranges = new Set(evidence.map(key));
  for (const ref of premiseEvidence) {
    if (ref.kind !== "source") continue;
    const range = {
      path: ref.path,
      commit: ref.commit ?? use.revision,
      startLine: ref.startLine,
      endLine: ref.endLine,
      supports: [],
    };
    const rangeKey = key(range);
    if (!ranges.has(rangeKey)) {
      evidence.push(range);
      ranges.add(rangeKey);
    }
  }
  return {
    evidence,
    ...(use.trace && {
      trace: use.trace.map((frame) =>
        frame.kind === "gap"
          ? frame
          : {
              ...frame,
              site: {
                ...frame.site,
                commit: frame.site.commit ?? use.revision,
              },
            },
      ),
    }),
    observations: use.observations.map((ref) => ({
      server: ref.server,
      record: ref.quote,
      supports: ref.supports.filter(
        (s) => s === "running" || s === "access" || s === "affected_copy",
      ),
    })),
    decidingEvidence: [
      ...new Map(
        decidingEvidence.map((ref) => [dependencyRecordHash(ref), ref]),
      ).values(),
    ],
  };
}

type SelectedPremises = ReturnType<typeof selectedPremises>;

function findingDetails({
  services,
  openConditions,
  inspections,
  inputSource,
  runtimeContext,
  tags,
}: VerifiedUse | VerifiedDisposition) {
  return {
    ...(services && { services }),
    ...(openConditions && { openConditions }),
    ...(inspections && { inspections }),
    ...(inputSource && { inputSource }),
    ...(runtimeContext && { runtimeContext }),
    ...(tags && { tags }),
  };
}

function reportedDisposition(
  disposition: VerifiedDisposition,
  claim: Claim,
  evidenceKeys: readonly string[],
  selected: SelectedPremises,
) {
  const { kind, reason, location, locations, place, handoff, classification } =
    disposition;
  return {
    kind,
    reason,
    location,
    ...(locations.length && { locations }),
    ...(place && { place }),
    ...(handoff && { handoff }),
    ...(classification && { classification }),
    ...findingDetails(disposition),
    ...publishedFindingEvidence(disposition, evidenceKeys, selected.evidence),
    conclusionClaim: reference(claim),
    ...(selected.claims.length && { supportingClaims: selected.claims }),
  };
}

export function reportedUse(
  use: VerifiedUse,
  claim: Claim,
  evidenceKeys: readonly string[],
  selected: SelectedPremises = { evidence: [], claims: [] },
) {
  const runningQuotes = use.observations
    .filter((ref) => ref.supports.includes("running"))
    .map((ref) => ref.quote);
  const running = runningQuotes.length > 0;
  const configured =
    use.configured || use.place?.deploymentBasis === "configured";

  const published = publishedFindingEvidence(
    use,
    evidenceKeys,
    selected.evidence,
  );
  return {
    location: use.location,
    component: use.component,
    version: use.version,
    verdict: use.verdict,
    reason: use.reason,
    deployment: running
      ? ("confirmed" as const)
      : configured
        ? ("configured" as const)
        : ("unknown" as const),
    ...published,
    ...findingDetails(use),
    place: {
      kind: use.placeKind ?? "unknown",
      environment: null,
      artifact: null,
      observationWindow: null,
      deploymentBasis: running
        ? ("observed" as const)
        : configured
          ? ("configured" as const)
          : ("unknown" as const),
      deploymentDetail: running ? runningQuotes.join("\n") : null,
      dependencySelection: use.version,
      patch: null,
      ...use.place,
      ...(running && { deploymentBasis: "observed" as const }),
      revision: use.revision,
      unresolvedQuestions: [
        ...new Set([
          ...use.remainingQuestions,
          ...(use.place?.unresolvedQuestions ?? []),
        ]),
      ],
    },
    proof:
      use.trace?.length && use.proof.sink
        ? {
            ...use.proof,
            sink: {
              ...use.proof.sink,
              callSite: {
                ...use.proof.sink.callSite,
                commit: use.proof.sink.callSite.commit ?? use.revision,
              },
            },
          }
        : use.proof,
    conclusionClaim: reference(claim),
    ...(selected.claims.length && { supportingClaims: selected.claims }),
  };
}

// Called inside the final store read. Never reuse approvals across snapshots.
export function publishApprovedClaims(
  store: DependencyAttemptStore,
  rows: Claim[],
  {
    records,
    failures,
    contextHash,
    revision,
    subject,
  }: {
    records: ReadonlyMap<string, DependencyEvidenceRecord>;
    failures: ReadonlyMap<string, DependencyEvidenceRecord>;
    contextHash: string;
    revision: string | undefined;
    subject: string;
  },
) {
  const approvals = new Map<string, Decision | undefined>();
  const uses: ReturnType<typeof reportedUse>[] = [];
  const dispositions: ReturnType<typeof reportedDisposition>[] = [];
  const sources = new Map<
    string,
    ReturnType<typeof claimInputs>["sources"][number]
  >();
  const receipts = new Map<string, unknown>([...records, ...failures]);
  const claims = rows.map((claim) => {
    const review = currentApproval(store, claim, approvals);
    if (!review)
      throw new DependencyReviewRejection(
        "Missing current approval for " + claim.id,
      );

    const { value } = claim;
    const inputs = claimInputs(claim);
    const keys = new Set(review.evidenceKeys);
    for (const [i, source] of inputs.sources.entries())
      sources.set(inputs.sourceIds[i]!, source);
    for (const row of inputs.selected) {
      const key = selectedReceiptKey(row);
      if (keys.has(key))
        receipts.set(key, {
          ...row,
          result: selectedReceiptValue(
            records.get(row.receiptId)!,
            row.selection,
          ),
        });
    }

    let location: string | null = null;
    if (value.kind === "use" || value.kind === "disposition") {
      const selected = selectedPremises(
        store,
        records,
        inputs.dependencies.filter((ref) => keys.has(premiseKey(ref))),
        approvals,
      );
      if (value.kind === "use") {
        location = value.use.location;
        uses.push(reportedUse(value.use, claim, review.evidenceKeys, selected));
      } else {
        location = value.disposition.location;
        dispositions.push(
          reportedDisposition(
            value.disposition,
            claim,
            review.evidenceKeys,
            selected,
          ),
        );
      }
    }
    return {
      ...reference(claim),
      state: "approved" as const,
      contextHash,
      payload: value,
      scope: { revision: revision ?? null, location, subject },
      dependencies: inputs.dependencies,
      decision: {
        accepted: true as const,
        reason: review.reason,
        evidenceKeys: review.evidenceKeys,
        citedVersion: value.kind === "use" ? (value.use.version ?? null) : null,
      },
      evidence: {
        sourceIds: inputs.sourceIds,
        receiptIds: inputs.receiptKeys.filter(
          (key) => !key.startsWith("receipt:") || keys.has(key),
        ),
      },
    };
  });
  return {
    uses,
    dispositions,
    claims,
    claimEvidence: {
      sources: Object.fromEntries(sources),
      receipts: Object.fromEntries(receipts),
    },
  };
}

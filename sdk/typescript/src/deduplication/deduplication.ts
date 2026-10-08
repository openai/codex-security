import { findingGroupRoots } from "../finding-catalogue.js";
import type { Finding } from "../models.js";
import type { FindingNeighborhood } from "../finding-retrieval.js";
import {
  CodexSecurityError,
  DeduplicationReviewError,
  type DeduplicationReviewStage,
} from "../errors.js";
import {
  pairKey,
  screeningPairSlot,
  type DeduplicationReviewer,
  type ScreeningResult,
} from "./deduplication-reviewer.js";

export const DEFAULT_DEDUPE_CONCURRENCY = 8;

export function deduplicationConcurrency(
  concurrency = DEFAULT_DEDUPE_CONCURRENCY,
): number {
  if (!Number.isSafeInteger(concurrency) || concurrency < 1)
    throw new CodexSecurityError(
      "concurrency must be a positive safe integer.",
    );
  return concurrency;
}

type Job = () => Promise<void>;

async function runQueued(
  pending: Job[],
  ready: Job[],
  concurrency: number,
  signal?: AbortSignal,
): Promise<void> {
  let failure: { error: unknown } | undefined;
  await new Promise<void>((resolve) => {
    let running = 0;
    async function run(job: Job): Promise<void> {
      try {
        await job();
      } catch (error) {
        failure ??= { error };
      } finally {
        running--;
        pump();
      }
    }
    function pump(): void {
      while (
        failure === undefined &&
        !signal?.aborted &&
        running < concurrency
      ) {
        const job = ready.shift() ?? pending.shift();
        if (job === undefined) break;
        running++;
        void run(job);
      }
      // An active producer can still enqueue work. After failure, drain active
      // jobs so successful reviews can finish saving their checkpoints.
      if (running === 0) resolve();
    }
    pump();
  });
  signal?.throwIfAborted();
  if (failure !== undefined) throw failure.error;
}

export interface DeduplicationRefusal {
  decision: "NO_DECISION";
  stage: DeduplicationReviewStage;
  model: string;
  /** For screening, the first finding is the anchor and the rest are its candidates. */
  findingIds: string[];
  reason: string;
}

export interface DeduplicationResult {
  uniqueFindingIds: string[];
  duplicateGroups: string[][];
  deduplicationStatus: "completed" | "completed_with_refusals";
  /** Refused reviews are kept separate without claiming a DISTINCT verdict. */
  refusals?: DeduplicationRefusal[];
}

const severityOrder: Record<Finding["severity"]["level"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

/** @internal */
export interface ContradictionGroupingMetrics {
  candidateEvaluations: number;
  conflictNeighborChecks: number;
}

/** Greedily retain the best-supported legal merges, using input order for ties. */
/** @internal */
export function contradictionFreeSubgroups(
  findingIds: readonly string[],
  samePairs: readonly (readonly [string, string])[],
  distinctPairs: readonly (readonly [string, string])[],
  signal?: AbortSignal,
  metrics?: ContradictionGroupingMetrics,
): Set<string>[] {
  const indexes = new Map(
    findingIds.map((findingId, index) => [findingId, index]),
  );
  const clusters = new Map(
    findingIds.map((findingId, index) => [index, new Set([findingId])]),
  );
  const support = new Map<number, Map<number, number>>();
  for (const [left, right] of samePairs) {
    const leftIndex = indexes.get(left)!;
    const rightIndex = indexes.get(right)!;
    const leftSupport = support.get(leftIndex) ?? new Map<number, number>();
    const rightSupport = support.get(rightIndex) ?? new Map<number, number>();
    leftSupport.set(rightIndex, (leftSupport.get(rightIndex) ?? 0) + 1);
    rightSupport.set(leftIndex, (rightSupport.get(leftIndex) ?? 0) + 1);
    support.set(leftIndex, leftSupport);
    support.set(rightIndex, rightSupport);
  }
  const conflicts = new Map<number, Set<number>>();
  for (const [left, right] of distinctPairs) {
    const leftIndex = indexes.get(left)!;
    const rightIndex = indexes.get(right)!;
    const leftConflicts = conflicts.get(leftIndex) ?? new Set<number>();
    const rightConflicts = conflicts.get(rightIndex) ?? new Set<number>();
    leftConflicts.add(rightIndex);
    rightConflicts.add(leftIndex);
    conflicts.set(leftIndex, leftConflicts);
    conflicts.set(rightIndex, rightConflicts);
  }

  while (true) {
    signal?.throwIfAborted();
    let selected: readonly [number, number] | undefined;
    let selectedScore: readonly number[] | undefined;
    for (const leftCluster of clusters.keys()) {
      for (const [rightCluster, gain] of support.get(leftCluster) ?? []) {
        if (
          leftCluster >= rightCluster ||
          conflicts.get(leftCluster)?.has(rightCluster)
        )
          continue;
        if (metrics) metrics.candidateEvaluations++;
        let newlyBlocked = 0;
        const leftConflicts = conflicts.get(leftCluster);
        const rightConflicts = conflicts.get(rightCluster);
        for (const other of leftConflicts ?? []) {
          if (metrics) metrics.conflictNeighborChecks++;
          if (other !== rightCluster && !rightConflicts?.has(other))
            newlyBlocked += support.get(rightCluster)?.get(other) ?? 0;
        }
        for (const other of rightConflicts ?? []) {
          if (metrics) metrics.conflictNeighborChecks++;
          if (other !== leftCluster && !leftConflicts?.has(other))
            newlyBlocked += support.get(leftCluster)?.get(other) ?? 0;
        }
        const score = [
          gain - newlyBlocked,
          gain,
          -newlyBlocked,
          -leftCluster,
          -rightCluster,
        ];
        if (selectedScore !== undefined) {
          const index = score.findIndex(
            (value, position) => value !== selectedScore![position],
          );
          if (index === -1 || !(score[index]! > selectedScore[index]!)) {
            continue;
          }
        }
        selected = [leftCluster, rightCluster];
        selectedScore = score;
      }
    }
    if (selected === undefined)
      return [...clusters.values()].filter((members) => members.size > 1);
    const [leftCluster, rightCluster] = selected;
    for (const member of clusters.get(rightCluster)!)
      clusters.get(leftCluster)!.add(member);
    clusters.delete(rightCluster);

    const leftSupport = support.get(leftCluster)!;
    leftSupport.delete(rightCluster);
    for (const [neighbor, rightWeight] of support.get(rightCluster)!) {
      if (neighbor === leftCluster || neighbor === rightCluster) continue;
      const weight = (leftSupport.get(neighbor) ?? 0) + rightWeight;
      leftSupport.set(neighbor, weight);
      support.get(neighbor)!.set(leftCluster, weight).delete(rightCluster);
    }
    support.delete(rightCluster);

    const mergedConflicts = conflicts.get(leftCluster) ?? new Set<number>();
    for (const id of conflicts.get(rightCluster) ?? []) mergedConflicts.add(id);
    mergedConflicts.delete(leftCluster);
    mergedConflicts.delete(rightCluster);
    for (const neighbor of mergedConflicts) {
      conflicts.get(neighbor)!.add(leftCluster).delete(rightCluster);
    }
    conflicts.set(leftCluster, mergedConflicts);
    conflicts.delete(rightCluster);
  }
}

/** @internal */
export class FindingDeduplicator {
  constructor(
    private readonly candidates: {
      potentialDuplicates(findingId: string): Promise<FindingNeighborhood>;
    },
    private readonly reviewer: DeduplicationReviewer,
    private readonly signal?: AbortSignal,
    private readonly concurrency = DEFAULT_DEDUPE_CONCURRENCY,
  ) {}

  async run(findingIds: readonly string[]): Promise<DeduplicationResult> {
    this.signal?.throwIfAborted();
    const concurrency = deduplicationConcurrency(this.concurrency);
    const ids = [...new Set(findingIds)];
    const findings = new Map<string, Finding>();
    const refusals = new Map<string, DeduplicationRefusal>();
    const recordRefusal = (error: unknown, ids: string[]): void => {
      this.signal?.throwIfAborted();
      if (
        !(error instanceof DeduplicationReviewError) ||
        error.metadata.category !== "refusal"
      )
        throw error;
      const { stage, model, reason } = error.metadata;
      refusals.set(JSON.stringify([stage, ...ids]), {
        decision: "NO_DECISION",
        stage,
        model,
        findingIds: ids,
        reason,
      });
    };
    const neighborhoods = new Array<Finding[]>(ids.length);
    await runQueued(
      ids.map((id, index) => async () => {
        const result = await this.candidates.potentialDuplicates(id);
        this.signal?.throwIfAborted();
        neighborhoods[index] = [result.finding, ...result.potentialDuplicates];
      }),
      [],
      concurrency,
      this.signal,
    );
    const pairs = new Map<
      string,
      {
        ids: [string, string];
        remaining: number;
        rejected: boolean;
        decision?: "SAME" | "DISTINCT";
      }
    >();
    // Freeze records, insertion order, and the last nominating anchor's pair
    // orientation before reviews run, preserving grouping and checkpoint inputs.
    for (const neighborhood of neighborhoods) {
      this.signal?.throwIfAborted();
      for (const finding of neighborhood)
        findings.set(finding.findingId, finding);
      for (const neighbor of neighborhood.slice(1)) {
        const pair: [string, string] = [
          neighborhood[0]!.findingId,
          neighbor.findingId,
        ];
        const key = pairKey(pair);
        const state = pairs.get(key);
        if (state === undefined) {
          pairs.set(key, { ids: pair, remaining: 1, rejected: false });
        } else {
          state.ids = pair;
          state.remaining++;
        }
      }
    }

    const ready: Job[] = [];
    const pending = neighborhoods
      .filter((neighborhood) => neighborhood.length > 1)
      .map((neighborhood) => async () => {
        let screening: ScreeningResult | undefined;
        try {
          screening = await this.reviewer.screen(neighborhood);
        } catch (error) {
          recordRefusal(
            error,
            neighborhood.map((finding) => finding.findingId),
          );
        }
        this.signal?.throwIfAborted();
        for (let index = 0; index < neighborhood.length - 1; index++) {
          const key = pairKey([
            neighborhood[0]!.findingId,
            neighborhood[index + 1]!.findingId,
          ]);
          const state = pairs.get(key)!;
          if (
            screening === undefined ||
            screening.decisions[screeningPairSlot(index)]!.decision ===
              "DISTINCT"
          )
            state.rejected = true;
          state.remaining--;
          // Wait for every screening: a later DISTINCT verdict or refusal must
          // prevent verification, including a verification that could fail.
          if (state.remaining === 0 && !state.rejected) {
            ready.push(async () => {
              try {
                state.decision = (
                  await this.reviewer.reviewPair(
                    state.ids.map((id) => findings.get(id)!),
                  )
                ).decision;
              } catch (error) {
                recordRefusal(error, state.ids);
              }
            });
          }
        }
      });
    await runQueued(pending, ready, concurrency, this.signal);

    // Completion order must not change grouping ties.
    const supported: [string, string][] = [];
    const rejected: [string, string][] = [];
    for (const state of pairs.values()) {
      this.signal?.throwIfAborted();
      if (state.decision === "SAME") supported.push(state.ids);
      else rejected.push(state.ids);
    }

    const { parents, root } = findingGroupRoots();
    for (const [left, right] of supported) parents.set(root(right), root(left));
    // Preserve finding insertion order for contradiction-grouping ties.
    const membersByRoot = Map.groupBy(findings.keys(), (id) => {
      this.signal?.throwIfAborted();
      return parents.has(id) ? root(id) : undefined;
    });
    membersByRoot.delete(undefined);
    const components = [...membersByRoot.values()].map((members) => ({
      members,
      supported: [] as [string, string][],
      rejected: [] as [string, string][],
    }));
    const componentByFinding = new Map(
      components.flatMap((component) =>
        component.members.map((id) => [id, component] as const),
      ),
    );
    for (const pair of supported)
      componentByFinding.get(pair[0])!.supported.push(pair);
    for (const pair of rejected) {
      const component = componentByFinding.get(pair[0]);
      if (component && component === componentByFinding.get(pair[1]))
        component.rejected.push(pair);
    }

    const selected = new Set(ids);
    const duplicateGroups: string[][] = [];
    const canonical = new Map<string, string>();
    for (const component of components) {
      this.signal?.throwIfAborted();
      const groups =
        component.rejected.length === 0
          ? [new Set(component.members)]
          : contradictionFreeSubgroups(
              component.members,
              component.supported,
              component.rejected,
              this.signal,
            );
      for (const group of groups) {
        const groupMembers = [...group];
        if (!groupMembers.some((member) => selected.has(member))) continue;
        groupMembers.sort(
          (left, right) =>
            severityOrder[findings.get(left)!.severity.level] -
              severityOrder[findings.get(right)!.severity.level] ||
            (left < right ? -1 : left > right ? 1 : 0),
        );
        duplicateGroups.push(groupMembers);
        for (const member of groupMembers)
          canonical.set(member, groupMembers[0]!);
      }
    }
    return {
      uniqueFindingIds: [...new Set(ids.map((id) => canonical.get(id) ?? id))],
      duplicateGroups,
      deduplicationStatus:
        refusals.size > 0 ? "completed_with_refusals" : "completed",
      ...(refusals.size > 0
        ? {
            refusals: [...refusals.entries()]
              .sort(([left], [right]) =>
                left < right ? -1 : left > right ? 1 : 0,
              )
              .map(([, refusal]) => refusal),
          }
        : {}),
    };
  }
}

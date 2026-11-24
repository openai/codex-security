import { SCAN_SEVERITIES } from "../scan-settings.js";
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
): string[][] {
  type Cluster = {
    index: number;
    members: string[];
    support: Map<Cluster, number> | null;
    conflicts: Set<Cluster> | null;
  };
  const clusters = new Map<string, Cluster>();
  for (const [index, id] of findingIds.entries())
    clusters.set(id, { index, members: [id], support: null, conflicts: null });
  for (const [a, b] of samePairs) {
    const left = clusters.get(a)!;
    const right = clusters.get(b)!;
    const weight = (left.support?.get(right) ?? 0) + 1;
    (left.support ??= new Map()).set(right, weight);
    (right.support ??= new Map()).set(left, weight);
  }
  for (const [a, b] of distinctPairs) {
    const left = clusters.get(a)!;
    const right = clusters.get(b)!;
    (left.conflicts ??= new Set()).add(right);
    (right.conflicts ??= new Set()).add(left);
  }

  // Conflicts inherited from one side can block support on the other.
  function blocked(left: Cluster, right: Cluster): number {
    if (!left.conflicts) return 0;
    let weight = 0;
    for (const other of left.conflicts) {
      if (metrics) metrics.conflictNeighborChecks++;
      if (!right.conflicts?.has(other))
        weight += right.support!.get(other) ?? 0;
    }
    return weight;
  }
  while (true) {
    signal?.throwIfAborted();
    let best:
      { left: Cluster; right: Cluster; net: number; gain: number } | undefined;
    for (const left of clusters.values()) {
      for (const [right, gain] of left.support ?? []) {
        if (left.index >= right.index || left.conflicts?.has(right)) continue;
        if (metrics) metrics.candidateEvaluations++;
        // Equal net and gross gains imply equal blocked weight.
        const net = gain - blocked(left, right) - blocked(right, left);
        if (
          !best ||
          (net - best.net ||
            gain - best.gain ||
            best.left.index - left.index ||
            best.right.index - right.index) > 0
        )
          best = { left, right, net, gain };
      }
    }
    if (!best)
      return [...clusters.values()]
        .filter((cluster) => cluster.members.length > 1)
        .map((cluster) => cluster.members);
    const { left, right } = best;
    for (const member of right.members) left.members.push(member);
    clusters.delete(findingIds[right.index]!);

    const support = left.support!;
    support.delete(right);
    for (const [neighbor, rightWeight] of right.support!) {
      if (neighbor === left || neighbor === right) continue;
      const weight = (support.get(neighbor) ?? 0) + rightWeight;
      support.set(neighbor, weight);
      neighbor.support!.set(left, weight).delete(right);
    }
    left.conflicts?.delete(left);
    for (const neighbor of right.conflicts ?? []) {
      if (neighbor === right) continue;
      (left.conflicts ??= new Set()).add(neighbor);
      neighbor.conflicts!.add(left).delete(right);
    }
  }
}

/** @internal */
export class FindingDeduplicator<
  T extends Pick<Finding, "findingId" | "severity"> = Finding,
> {
  constructor(
    private readonly candidates: {
      potentialDuplicates(findingId: string): Promise<FindingNeighborhood<T>>;
    },
    private readonly reviewer: DeduplicationReviewer<T>,
    private readonly signal?: AbortSignal,
    private readonly concurrency = DEFAULT_DEDUPE_CONCURRENCY,
  ) {}

  async run(findingIds: readonly string[]): Promise<DeduplicationResult> {
    this.signal?.throwIfAborted();
    const concurrency = deduplicationConcurrency(this.concurrency);
    const ids = [...new Set(findingIds)];
    const findings = new Map<string, T>();
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
    const neighborhoods = new Array<T[]>(ids.length);
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
    const supportedByRoot = Map.groupBy(supported, ([left]) => root(left));
    const rejectedByRoot = Map.groupBy(
      rejected.filter(([left, right]) => root(left) === root(right)),
      ([left]) => root(left),
    );

    const selected = new Set(ids);
    const duplicateGroups: string[][] = [];
    const canonical = new Map<string, string>();
    for (const [componentRoot, members] of membersByRoot) {
      this.signal?.throwIfAborted();
      const conflicts = rejectedByRoot.get(componentRoot!);
      const groups =
        conflicts === undefined
          ? [members]
          : contradictionFreeSubgroups(
              members,
              supportedByRoot.get(componentRoot!)!,
              conflicts,
              this.signal,
            );
      for (const group of groups) {
        if (!group.some((member) => selected.has(member))) continue;
        group.sort(
          (left, right) =>
            SCAN_SEVERITIES.indexOf(findings.get(left)!.severity.level) -
              SCAN_SEVERITIES.indexOf(findings.get(right)!.severity.level) ||
            (left < right ? -1 : left > right ? 1 : 0),
        );
        duplicateGroups.push(group);
        for (const member of group) canonical.set(member, group[0]!);
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

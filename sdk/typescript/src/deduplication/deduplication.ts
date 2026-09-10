import type { Finding } from "../models.js";
import type { FindingNeighborhood } from "../finding-retrieval.js";
import { CodexSecurityError } from "../errors.js";
import {
  pairKey,
  screeningPairSlot,
  type DeduplicationReviewer,
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

export interface DeduplicationResult {
  uniqueFindingIds: string[];
  duplicateGroups: string[][];
  deduplicationStatus: "completed";
}

const severityOrder: Record<Finding["severity"]["level"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

function scoreAfter(
  left: readonly number[],
  right: readonly number[],
): boolean {
  for (let index = 0; index < left.length; index++) {
    if (left[index] !== right[index]) return left[index]! > right[index]!;
  }
  return false;
}

/** @internal */
export interface ContradictionGroupingMetrics {
  candidateEvaluations: number;
  conflictNeighborChecks: number;
}

function addSupport(
  support: Map<number, Map<number, number>>,
  left: number,
  right: number,
): void {
  const leftSupport = support.get(left) ?? new Map<number, number>();
  const rightSupport = support.get(right) ?? new Map<number, number>();
  leftSupport.set(right, (leftSupport.get(right) ?? 0) + 1);
  rightSupport.set(left, (rightSupport.get(left) ?? 0) + 1);
  support.set(left, leftSupport);
  support.set(right, rightSupport);
}

function addConflict(
  conflicts: Map<number, Set<number>>,
  left: number,
  right: number,
): void {
  const leftConflicts = conflicts.get(left) ?? new Set<number>();
  const rightConflicts = conflicts.get(right) ?? new Set<number>();
  leftConflicts.add(right);
  rightConflicts.add(left);
  conflicts.set(left, leftConflicts);
  conflicts.set(right, rightConflicts);
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
  const active = new Set(findingIds.map((_findingId, index) => index));
  const clusters = new Map(
    findingIds.map((findingId, index) => [index, new Set([findingId])]),
  );
  const support = new Map<number, Map<number, number>>();
  for (const [left, right] of samePairs)
    addSupport(support, indexes.get(left)!, indexes.get(right)!);
  const conflicts = new Map<number, Set<number>>();
  for (const [left, right] of distinctPairs)
    addConflict(conflicts, indexes.get(left)!, indexes.get(right)!);

  while (true) {
    signal?.throwIfAborted();
    let selected: readonly [number, number] | undefined;
    let selectedScore: readonly number[] | undefined;
    for (const leftCluster of active) {
      for (const [rightCluster, gain] of support.get(leftCluster) ?? []) {
        if (
          leftCluster >= rightCluster ||
          !active.has(rightCluster) ||
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
        if (selectedScore === undefined || scoreAfter(score, selectedScore)) {
          selected = [leftCluster, rightCluster];
          selectedScore = score;
        }
      }
    }
    if (selected === undefined)
      return [...active]
        .map((cluster) => clusters.get(cluster)!)
        .filter((members) => members.size > 1);
    const [leftCluster, rightCluster] = selected;
    for (const member of clusters.get(rightCluster)!)
      clusters.get(leftCluster)!.add(member);
    clusters.delete(rightCluster);
    active.delete(rightCluster);

    const leftSupport = support.get(leftCluster) ?? new Map<number, number>();
    const rightSupport = support.get(rightCluster) ?? new Map<number, number>();
    const supportNeighbors = new Set([
      ...leftSupport.keys(),
      ...rightSupport.keys(),
    ]);
    supportNeighbors.delete(leftCluster);
    supportNeighbors.delete(rightCluster);
    leftSupport.delete(rightCluster);
    for (const neighbor of supportNeighbors) {
      const weight =
        (leftSupport.get(neighbor) ?? 0) + (rightSupport.get(neighbor) ?? 0);
      leftSupport.set(neighbor, weight);
      const neighborSupport = support.get(neighbor)!;
      neighborSupport.delete(rightCluster);
      neighborSupport.set(leftCluster, weight);
    }
    support.set(leftCluster, leftSupport);
    support.delete(rightCluster);

    const mergedConflicts = new Set([
      ...(conflicts.get(leftCluster) ?? []),
      ...(conflicts.get(rightCluster) ?? []),
    ]);
    mergedConflicts.delete(leftCluster);
    mergedConflicts.delete(rightCluster);
    for (const neighbor of mergedConflicts) {
      const neighborConflicts = conflicts.get(neighbor)!;
      neighborConflicts.delete(rightCluster);
      neighborConflicts.add(leftCluster);
    }
    if (mergedConflicts.size > 0) conflicts.set(leftCluster, mergedConflicts);
    else conflicts.delete(leftCluster);
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
        const screening = await this.reviewer.screen(neighborhood);
        this.signal?.throwIfAborted();
        for (let index = 0; index < neighborhood.length - 1; index++) {
          const key = pairKey([
            neighborhood[0]!.findingId,
            neighborhood[index + 1]!.findingId,
          ]);
          const state = pairs.get(key)!;
          if (
            screening.decisions[screeningPairSlot(index)]!.decision ===
            "DISTINCT"
          )
            state.rejected = true;
          state.remaining--;
          // Wait for every screening of this pair: a later DISTINCT veto must
          // prevent verification, including a verification that could fail.
          if (state.remaining === 0 && !state.rejected) {
            ready.push(async () => {
              state.decision = (
                await this.reviewer.reviewPair(
                  state.ids.map((id) => findings.get(id)!),
                )
              ).decision;
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

    const adjacent = new Map<string, Set<string>>();
    for (const pair of supported) {
      for (const [left, right] of [pair, [pair[1], pair[0]]] as const) {
        const neighbors = adjacent.get(left) ?? new Set<string>();
        neighbors.add(right);
        adjacent.set(left, neighbors);
      }
    }

    const components: {
      members: string[];
      supported: [string, string][];
      rejected: [string, string][];
    }[] = [];
    const componentByFinding = new Map<string, (typeof components)[number]>();
    for (const id of findings.keys()) {
      this.signal?.throwIfAborted();
      if (!adjacent.has(id) || componentByFinding.has(id)) continue;
      const component: (typeof components)[number] = {
        members: [],
        supported: [],
        rejected: [],
      };
      components.push(component);
      const pending = [id];
      while (pending.length > 0) {
        const member = pending.pop()!;
        if (componentByFinding.has(member)) continue;
        componentByFinding.set(member, component);
        pending.push(...adjacent.get(member)!);
      }
    }
    // Preserve finding insertion order for contradiction-grouping ties.
    for (const id of findings.keys())
      componentByFinding.get(id)?.members.push(id);
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
      deduplicationStatus: "completed",
    };
  }
}

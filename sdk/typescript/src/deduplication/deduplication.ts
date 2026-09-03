import type { Finding } from "../models.js";
import type { FindingNeighborhood } from "../finding-retrieval.js";
import {
  pairKey,
  screeningPairSlot,
  type DeduplicationReviewer,
} from "./deduplication-reviewer.js";

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
  ) {}

  async run(findingIds: readonly string[]): Promise<DeduplicationResult> {
    this.signal?.throwIfAborted();
    const ids = [...new Set(findingIds)];
    const findings = new Map<string, Finding>();
    const nominated = new Map<string, [string, string]>();
    const rejected = new Map<string, [string, string]>();
    for (const id of ids) {
      this.signal?.throwIfAborted();
      const result = await this.candidates.potentialDuplicates(id);
      const neighborhood = [result.finding, ...result.potentialDuplicates];
      for (const finding of neighborhood)
        findings.set(finding.findingId, finding);
      if (neighborhood.length < 2) continue;
      const screening = await this.reviewer.screen(neighborhood);
      for (let index = 0; index < neighborhood.length - 1; index++) {
        const decision = screening.decisions[screeningPairSlot(index)]!;
        const pair: [string, string] = [
          neighborhood[0]!.findingId,
          neighborhood[index + 1]!.findingId,
        ];
        const key = pairKey(pair);
        if (decision.decision === "SAME") {
          if (!rejected.has(key)) nominated.set(key, pair);
        } else {
          rejected.set(key, pair);
          nominated.delete(key);
        }
      }
    }

    const supported: [string, string][] = [];
    for (const pair of nominated.values()) {
      this.signal?.throwIfAborted();
      const originals = pair.map((id) => findings.get(id)!);
      if ((await this.reviewer.reviewPair(originals)).decision === "SAME") {
        supported.push(pair);
      } else {
        rejected.set(pairKey(pair), pair);
      }
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
    for (const pair of rejected.values()) {
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

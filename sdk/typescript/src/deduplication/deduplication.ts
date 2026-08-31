import type { Finding } from "../models.js";
import type { FindingNeighborhood } from "../finding-retrieval.js";
import {
  pairKey,
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
    for (const id of ids) {
      this.signal?.throwIfAborted();
      const result = await this.candidates.potentialDuplicates(id);
      const neighborhood = [result.finding, ...result.potentialDuplicates];
      for (const finding of neighborhood)
        findings.set(finding.findingId, finding);
      if (neighborhood.length < 2) continue;
      const screening = await this.reviewer.screen(neighborhood);
      for (const decision of screening.decisions) {
        if (decision.decision === "SAME") {
          nominated.set(pairKey(decision.findingIds), decision.findingIds);
        }
      }
    }

    const adjacent = new Map<string, Set<string>>();
    for (const pair of nominated.values()) {
      this.signal?.throwIfAborted();
      const originals = pair.map((id) => findings.get(id)!);
      if ((await this.reviewer.reviewPair(originals)).decision !== "SAME")
        continue;
      for (const [left, right] of [pair, [pair[1], pair[0]]] as const) {
        const neighbors = adjacent.get(left) ?? new Set<string>();
        neighbors.add(right);
        adjacent.set(left, neighbors);
      }
    }

    const selected = new Set(ids);
    const visited = new Set<string>();
    const duplicateGroups: string[][] = [];
    const canonical = new Map<string, string>();
    for (const id of findings.keys()) {
      this.signal?.throwIfAborted();
      if (!adjacent.has(id) || visited.has(id)) continue;
      const members: string[] = [];
      const pending = [id];
      while (pending.length > 0) {
        const member = pending.pop()!;
        if (visited.has(member)) continue;
        visited.add(member);
        members.push(member);
        pending.push(...adjacent.get(member)!);
      }
      if (!members.some((member) => selected.has(member))) continue;
      members.sort(
        (left, right) =>
          severityOrder[findings.get(left)!.severity.level] -
            severityOrder[findings.get(right)!.severity.level] ||
          (left < right ? -1 : left > right ? 1 : 0),
      );
      duplicateGroups.push(members);
      for (const member of members) canonical.set(member, members[0]!);
    }
    return {
      uniqueFindingIds: [...new Set(ids.map((id) => canonical.get(id) ?? id))],
      duplicateGroups,
      deduplicationStatus: "completed",
    };
  }
}

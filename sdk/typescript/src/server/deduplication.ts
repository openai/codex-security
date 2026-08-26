import type { Finding } from "../models.js";
import { findingNeighborhoods } from "./deduplication-neighbors.js";
import {
  pairKey,
  type DeduplicationReviewer,
} from "./deduplication-reviewer.js";
import type { FindingsStore } from "./storage.js";

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

export class DeduplicationService {
  constructor(
    private readonly store: Pick<FindingsStore, "listEmbedded">,
    private readonly reviewer: DeduplicationReviewer,
  ) {}

  async run(findingIds: readonly string[]): Promise<DeduplicationResult> {
    const ids = [...new Set(findingIds)];
    if (ids.length === 0) {
      return {
        uniqueFindingIds: [],
        duplicateGroups: [],
        deduplicationStatus: "completed",
      };
    }
    const entries = await this.store.listEmbedded();
    const findings = new Map(
      entries.map(({ finding }) => [finding.findingId, finding]),
    );
    const positions = new Map(
      entries.map(({ finding }, index) => [finding.findingId, index]),
    );
    const nominated = new Map<string, [string, string]>();
    for (const neighborhood of findingNeighborhoods(entries, ids)) {
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
          positions.get(left)! - positions.get(right)!,
      );
      if (
        members.length > 2 &&
        (
          await this.reviewer.reviewGroup(
            members.map((member) => findings.get(member)!),
          )
        ).decision !== "SAME"
      )
        continue;
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

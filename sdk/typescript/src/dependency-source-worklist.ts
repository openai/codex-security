import { createHash } from "node:crypto";

interface RosterGap {
  id: string;
  description: string;
}

interface GapResolution {
  id: string;
  sourceRef: string;
}

export interface DependencySourceWorkCoverage {
  generation(): number;
  limitations(): string[];
}

interface RosterPage {
  id: string;
  owner: string;
  expectedRevision?: number;
  paths: readonly string[];
  declaredComplete: boolean;
  search: string;
  sourceRefs: readonly string[];
  gaps: readonly RosterGap[];
  resolutions?: readonly GapResolution[];
}

interface NewPartition {
  id: string;
  rosterId: string;
  owner: string;
  paths: readonly string[];
}

interface OwnedPartition {
  partitionId: string;
  owner: string;
  expectedRevision: number;
}

interface Handoff {
  recipient: string;
  newPartitionId: string;
  paths: readonly string[];
}

interface Roster {
  id: string;
  owner: string;
  revision: number;
  declaredComplete: boolean;
  paths: Set<string>;
  pathListSha256: string;
  assignments: Map<string, string>;
  gaps: Map<string, string>;
  pages: {
    search: string;
    sourceRefs: string[];
    matchedPaths: number;
    declaredComplete: boolean;
    gaps: RosterGap[];
    resolutions: GapResolution[];
  }[];
}

interface Partition {
  id: string;
  rosterId: string;
  owner: string;
  revision: number;
  paths: Set<string>;
  examined: Set<string>;
  handoff?: Handoff;
}

function checkedPaths(paths: readonly string[]): string[] {
  const unique = [...new Set(paths)].sort();
  for (const path of unique) {
    if (
      /^[a-z]:/iu.test(path) ||
      path.includes("\\") ||
      path.includes("\0") ||
      path.split("/").some((part) => !part || part === "." || part === "..")
    ) {
      throw new Error("Source work requires exact checkout-relative paths.");
    }
  }
  return unique;
}

function rosterSummary(roster: Roster) {
  return {
    id: roster.id,
    owner: roster.owner,
    revision: roster.revision,
    declaredComplete: roster.declaredComplete,
    gapCount: roster.gaps.size,
    pageCount: roster.pages.length,
    matchedFileCount: roster.paths.size,
    assignedFileCount: roster.assignments.size,
    pathListSha256: roster.pathListSha256,
  };
}

function partitionSummary(partition: Partition) {
  return {
    id: partition.id,
    rosterId: partition.rosterId,
    owner: partition.owner,
    revision: partition.revision,
    fileCount: partition.paths.size,
    remainingFileCount: partition.paths.size - partition.examined.size,
    ...(partition.handoff
      ? {
          handoff: {
            recipient: partition.handoff.recipient,
            newPartitionId: partition.handoff.newPartitionId,
            fileCount: partition.handoff.paths.length,
          },
        }
      : {}),
  };
}

/**
 * Retain the exact file roster and ownership of one investigation's source
 * searches. Completion here describes a supplied search roster or examined
 * files. Reviewed call evidence and the coordinator's plan live elsewhere.
 */
export function createDependencySourceWorklist() {
  const rosters = new Map<string, Roster>();
  const partitions = new Map<string, Partition>();
  const pendingPartitionIds = new Set<string>();
  let generation = 0;

  function getRoster(id: string): Roster {
    const roster = rosters.get(id);
    if (!roster) throw new Error("Unknown source roster.");
    return roster;
  }

  function getPartition(id: string): Partition {
    const partition = partitions.get(id);
    if (!partition) throw new Error("Unknown source partition.");
    return partition;
  }

  function requireAvailablePartition(id: string) {
    if (partitions.has(id) || pendingPartitionIds.has(id))
      throw new Error("Source partition ID is already in use.");
  }

  function requireOwner(input: OwnedPartition) {
    const partition = getPartition(input.partitionId);
    if (
      partition.owner !== input.owner ||
      partition.revision !== input.expectedRevision
    ) {
      throw new Error("Source partition owner or revision changed.");
    }
    return partition;
  }

  function partitionPaths(partition: Partition, paths: readonly string[]) {
    const unique = checkedPaths(paths);
    if (unique.some((path) => !partition.paths.has(path))) {
      throw new Error("Path is outside the source partition.");
    }
    return unique;
  }

  function requireNoHandoff(partition: Partition) {
    if (partition.handoff)
      throw new Error("Resolve the pending source handoff first.");
  }

  return {
    appendRosterPage(input: RosterPage) {
      const old = rosters.get(input.id);
      if (
        old?.revision !== input.expectedRevision ||
        (old && (old.owner !== input.owner || old.declaredComplete))
      ) {
        throw new Error(
          "Source roster is complete, or its owner or revision changed.",
        );
      }
      const gaps = new Map(old?.gaps);
      for (const { id, description } of input.gaps) {
        const current = gaps.get(id);
        if (current !== undefined && current !== description)
          throw new Error("A source roster gap ID refers to a different gap.");
        gaps.set(id, description);
      }
      for (const { id, sourceRef } of input.resolutions ?? []) {
        if (!old?.gaps.has(id) || !sourceRef.trim() || !gaps.delete(id))
          throw new Error(
            "Resolve an existing source roster gap with its source reference.",
          );
      }
      if (!input.declaredComplete && !gaps.size)
        throw new Error(
          "An incomplete source roster must identify a remaining gap.",
        );
      if (input.declaredComplete && gaps.size)
        throw new Error(
          "Resolve all recorded source roster gaps before declaring completion.",
        );
      const received = checkedPaths(input.paths);
      const paths = new Set([...(old?.paths ?? []), ...received]);
      const page = {
        search: input.search,
        sourceRefs: [...input.sourceRefs],
        matchedPaths: received.length,
        declaredComplete: input.declaredComplete,
        gaps: input.gaps.map((gap) => ({ ...gap })),
        resolutions: (input.resolutions ?? []).map((resolution) => ({
          ...resolution,
        })),
      };
      const roster = {
        id: input.id,
        owner: input.owner,
        revision: (old?.revision ?? 0) + 1,
        declaredComplete: input.declaredComplete,
        gaps,
        pages: [...(old?.pages ?? []), page],
        paths,
        pathListSha256: createHash("sha256")
          .update(JSON.stringify([...paths].sort()))
          .digest("hex"),
        assignments: old?.assignments ?? new Map<string, string>(),
      };
      rosters.set(input.id, roster);
      generation++;
      return rosterSummary(roster);
    },

    createPartition(input: NewPartition) {
      const roster = getRoster(input.rosterId);
      requireAvailablePartition(input.id);
      const paths = checkedPaths(input.paths);
      if (!paths.length || paths.some((path) => !roster.paths.has(path))) {
        throw new Error("Source partition requires paths in its roster.");
      }
      if (paths.some((path) => roster.assignments.has(path))) {
        throw new Error("Source path already has an owner in this roster.");
      }
      const partition: Partition = {
        id: input.id,
        rosterId: input.rosterId,
        owner: input.owner,
        revision: 1,
        paths: new Set(paths),
        examined: new Set(),
      };
      partitions.set(input.id, partition);
      for (const path of paths) roster.assignments.set(path, input.id);
      generation++;
      return partitionSummary(partition);
    },

    recordExamined(input: OwnedPartition & { paths: readonly string[] }) {
      const partition = requireOwner(input);
      requireNoHandoff(partition);
      const paths = partitionPaths(partition, input.paths);
      for (const path of paths) partition.examined.add(path);
      partition.revision++;
      generation++;
      return partitionSummary(partition);
    },

    offerHandoff(input: OwnedPartition & Handoff) {
      const partition = requireOwner(input);
      requireNoHandoff(partition);
      requireAvailablePartition(input.newPartitionId);
      const paths = partitionPaths(partition, input.paths);
      if (!paths.length || input.recipient === input.owner)
        throw new Error("A source handoff requires paths and a new owner.");
      partition.handoff = {
        recipient: input.recipient,
        newPartitionId: input.newPartitionId,
        paths,
      };
      pendingPartitionIds.add(input.newPartitionId);
      partition.revision++;
      generation++;
      return partitionSummary(partition);
    },

    acceptHandoff(input: {
      partitionId: string;
      recipient: string;
      expectedRevision: number;
    }) {
      const old = getPartition(input.partitionId);
      const handoff = old.handoff;
      if (
        !handoff ||
        old.revision !== input.expectedRevision ||
        handoff.recipient !== input.recipient
      ) {
        throw new Error("Source handoff recipient or revision changed.");
      }
      const roster = getRoster(old.rosterId);
      const next: Partition = {
        id: handoff.newPartitionId,
        rosterId: old.rosterId,
        owner: handoff.recipient,
        revision: 1,
        paths: new Set(handoff.paths),
        examined: new Set(
          handoff.paths.filter((path) => old.examined.has(path)),
        ),
      };
      for (const path of handoff.paths) {
        old.paths.delete(path);
        old.examined.delete(path);
        roster.assignments.set(path, next.id);
      }
      partitions.set(next.id, next);
      pendingPartitionIds.delete(next.id);
      delete old.handoff;
      old.revision++;
      generation++;
      return { from: partitionSummary(old), to: partitionSummary(next) };
    },

    cancelHandoff(input: OwnedPartition) {
      const partition = requireOwner(input);
      if (!partition.handoff) throw new Error("No pending source handoff.");
      pendingPartitionIds.delete(partition.handoff.newPartitionId);
      delete partition.handoff;
      partition.revision++;
      generation++;
      return partitionSummary(partition);
    },

    generation: () => generation,

    limitations() {
      const result: string[] = [];
      for (const roster of rosters.values()) {
        const gaps = [...roster.gaps].map(
          ([id, description]) =>
            "gap " + JSON.stringify(id) + " (" + description + ")",
        );
        const unassigned = [...roster.paths].filter(
          (path) => !roster.assignments.has(path),
        );
        if (unassigned.length)
          gaps.push("unassigned files " + JSON.stringify(unassigned.sort()));
        for (const id of new Set(roster.assignments.values())) {
          const partition = getPartition(id);
          const remaining = [...partition.paths].filter(
            (path) => !partition.examined.has(path),
          );
          const scope = "partition " + JSON.stringify(partition.id);
          if (remaining.length)
            gaps.push(
              scope +
                " has unexamined files " +
                JSON.stringify(remaining.sort()),
            );
          if (partition.handoff)
            gaps.push(
              scope +
                " awaits handoff acknowledgment for " +
                JSON.stringify(partition.handoff.paths),
            );
        }
        if (!gaps.length) continue;
        const references = [
          ...new Set(roster.pages.flatMap((page) => page.sourceRefs)),
        ];
        result.push(
          "Source work roster " +
            JSON.stringify(roster.id) +
            " remains incomplete. " +
            gaps.join(". ") +
            "." +
            (references.length
              ? " Recorded source references are " +
                JSON.stringify(references) +
                "."
              : ""),
        );
      }
      return result;
    },

    summary() {
      let remainingFileCount = 0;
      let pendingHandoffCount = 0;
      for (const partition of partitions.values()) {
        remainingFileCount += partition.paths.size - partition.examined.size;
        if (partition.handoff) pendingHandoffCount++;
      }
      const rosterSummaries = [...rosters.values()].map(rosterSummary);
      return {
        rosterCount: rosterSummaries.length,
        incompleteRosterCount: rosterSummaries.filter(
          (roster) => !roster.declaredComplete,
        ).length,
        gapCount: rosterSummaries.reduce(
          (count, roster) => count + roster.gapCount,
          0,
        ),
        unassignedFileCount: rosterSummaries.reduce(
          (count, roster) =>
            count + roster.matchedFileCount - roster.assignedFileCount,
          0,
        ),
        remainingFileCount,
        pendingHandoffCount,
      };
    },

    readRoster(id: string) {
      const roster = getRoster(id);
      const paths = [...roster.paths].sort();
      return {
        ...rosterSummary(roster),
        paths,
        gaps: [...roster.gaps].map(([id, description]) => ({
          id,
          description,
        })),
        pages: roster.pages.map((page) => ({
          ...page,
          gaps: page.gaps.map((gap) => ({ ...gap })),
          resolutions: page.resolutions.map((resolution) => ({
            ...resolution,
          })),
          sourceRefs: [...page.sourceRefs],
        })),
        partitionIds: [...new Set(roster.assignments.values())].sort(),
        unassigned: paths.filter((path) => !roster.assignments.has(path)),
      };
    },

    readPartition(id: string) {
      const partition = getPartition(id);
      const paths = [...partition.paths].sort();
      return {
        ...partitionSummary(partition),
        paths,
        remaining: paths.filter((path) => !partition.examined.has(path)),
        ...(partition.handoff
          ? { handoffPaths: [...partition.handoff.paths] }
          : {}),
      };
    },
  };
}

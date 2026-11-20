interface RosterGap {
  id: string;
  description: string;
}

interface GapResolution {
  id: string;
  sourceRef: string;
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

interface Roster {
  id: string;
  owner: string;
  revision: number;
  declaredComplete: boolean;
  paths: Set<string>;
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
        assignments: old?.assignments ?? new Map<string, string>(),
      };
      rosters.set(input.id, roster);
      generation++;
      return rosterSummary(roster);
    },

    createPartition(input: NewPartition) {
      const roster = getRoster(input.rosterId);
      if (partitions.has(input.id))
        throw new Error("Source partition ID is already in use.");
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

    recordExamined(input: { partitionId: string; paths: readonly string[] }) {
      const partition = getPartition(input.partitionId);
      const paths = checkedPaths(input.paths);
      if (paths.some((path) => !partition.paths.has(path))) {
        throw new Error("Path is outside the source partition.");
      }
      const before = partition.examined.size;
      for (const path of paths) partition.examined.add(path);
      if (partition.examined.size !== before) {
        partition.revision++;
        generation++;
      }
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
      for (const partition of partitions.values()) {
        remainingFileCount += partition.paths.size - partition.examined.size;
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
      };
    },
  };
}

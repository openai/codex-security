import { createHash } from "node:crypto";
import { z } from "zod";
import type { JsonObject, JsonValue } from "../../../config.js";
import {
  dependencySourceNoteQuerySchema,
  dependencySourceNoteSchema,
} from "../stacks/evidence.js";
import { isRecord } from "../../../record.js";

const label = z.string().trim().min(1);
const paths = z.array(z.string().min(1));
const gapSchema = z.strictObject({ id: label, description: label });
const resolutionSchema = z.strictObject({ id: label, sourceRef: label });

const sourceWorkMutationSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("append_roster_page"),
    id: label,
    owner: label,
    expectedRevision: z.number().int().positive().optional(),
    paths,
    declaredComplete: z.boolean(),
    search: label,
    sourceRefs: z.array(label),
    gaps: z.array(gapSchema),
    resolutions: z.array(resolutionSchema).optional(),
  }),
  z.strictObject({
    operation: z.literal("assign_partition"),
    id: label,
    rosterId: label,
    owner: label,
    paths: paths.min(1),
  }),
  z.strictObject({
    operation: z.literal("record_examined"),
    partitionId: label,
    paths: paths.min(1),
  }),
]);

const pageSchema = z.strictObject({
  limit: z.number().int().positive(),
  cursor: z
    .strictObject({ revision: label, offset: z.number().int().positive() })
    .optional(),
});

const sourceWorkQuerySchema = z.union([
  z.strictObject({}),
  z.strictObject({
    rosterId: label,
    page: pageSchema
      .extend({
        view: z.enum(["paths", "unassigned", "pages", "gaps", "partitionIds"]),
      })
      .optional(),
  }),
  z.strictObject({
    partitionId: label,
    page: pageSchema
      .extend({
        view: z.enum(["paths", "remaining"]),
      })
      .optional(),
  }),
]);

type Tool = {
  name: string;
  description: string;
  inputSchema: object;
  run(input: unknown): unknown;
};

const graphActions = {
  query: {
    name: "query_codex_security_graph",
    description:
      "Pass note or sourceWork as the only argument when querying shared research. Use note:{search} to find notes, note:{} to list them, or note:{id} to read pinned excerpts. Use sourceWork:{} for coverage counts, or sourceWork:{rosterId} or {partitionId} with page:{view,limit,cursor} for paths and gaps.",
    fields: {
      note: dependencySourceNoteQuerySchema,
      sourceWork: sourceWorkQuerySchema,
    },
  },
  update: {
    name: "update_codex_security_graph",
    description:
      "Pass exactly one of note or sourceWork. A note shares a question, scope and assertion with exact line ranges from the pinned checkout. Use sourceWork to record search results, resolve gaps, assign files or mark paths examined. For append_roster_page, omit expectedRevision on the first page and supply the current roster revision on later pages. Set declaredComplete to true when no gaps remain across all pages, and false when any gap remains open.",
    fields: {
      note: dependencySourceNoteSchema,
      sourceWork: sourceWorkMutationSchema,
    },
  },
};

function pageOf<T>(
  values: readonly T[],
  request: z.infer<typeof pageSchema> & { view: string },
  version: readonly unknown[],
) {
  const revision = createHash("sha256")
    .update(JSON.stringify(version))
    .digest("hex");
  const offset = request.cursor?.offset ?? 0;
  if (
    request.cursor &&
    (request.cursor.revision !== revision || offset >= values.length)
  ) {
    throw new Error(
      "Source work changed since this cursor. Start a current page.",
    );
  }
  const next = Math.min(offset + request.limit, values.length);
  return {
    view: request.view,
    total: values.length,
    items: values.slice(offset, next),
    nextCursor: next < values.length ? { revision, offset: next } : null,
  };
}

interface Roster {
  id: string;
  owner: string;
  paths: Set<string>;
  assignments: Map<string, string>;
  gaps: Map<string, string>;
  pages: {
    search: string;
    sourceRefs: string[];
    matchedPaths: number;
    declaredComplete: boolean;
    gaps: z.infer<typeof gapSchema>[];
    resolutions: z.infer<typeof resolutionSchema>[];
  }[];
}

interface Partition {
  id: string;
  rosterId: string;
  owner: string;
  revision: number;
  paths: readonly string[];
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

function unassignedPaths(roster: Roster) {
  return [...roster.paths]
    .filter((path) => !roster.assignments.has(path))
    .sort();
}

function remainingPaths(partition: Partition) {
  return partition.paths.filter((path) => !partition.examined.has(path));
}

function rosterSummary(roster: Roster) {
  return {
    id: roster.id,
    owner: roster.owner,
    revision: roster.pages.length,
    declaredComplete: roster.gaps.size === 0,
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
    fileCount: partition.paths.length,
    remainingFileCount: partition.paths.length - partition.examined.size,
  };
}

/**
 * Retain the exact file roster and ownership of one investigation's source
 * searches. Completion here describes a supplied search roster or examined
 * files. Reviewed call evidence and the coordinator's plan live elsewhere.
 */
export function createDependencySourceWorkTools() {
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

  function update(args: unknown): JsonObject {
    const input = sourceWorkMutationSchema.parse(args);
    if (input.operation === "append_roster_page") {
      const old = rosters.get(input.id);
      if (
        old?.pages.length !== input.expectedRevision ||
        (old && (old.owner !== input.owner || old.gaps.size === 0))
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
      for (const { id } of input.resolutions ?? []) {
        if (!old?.gaps.has(id) || !gaps.delete(id))
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
      const roster: Roster = old ?? {
        id: input.id,
        owner: input.owner,
        paths: new Set(),
        assignments: new Map(),
        pages: [],
        gaps,
      };
      roster.gaps = gaps;
      for (const path of received) roster.paths.add(path);
      roster.pages.push({
        search: input.search,
        sourceRefs: input.sourceRefs,
        matchedPaths: received.length,
        declaredComplete: input.declaredComplete,
        gaps: input.gaps,
        resolutions: input.resolutions ?? [],
      });
      rosters.set(input.id, roster);
      generation++;
      return rosterSummary(roster);
    }
    if (input.operation === "assign_partition") {
      const roster = getRoster(input.rosterId);
      if (partitions.has(input.id))
        throw new Error("Source partition ID is already in use.");
      const paths = checkedPaths(input.paths);
      if (paths.some((path) => !roster.paths.has(path))) {
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
        paths,
        examined: new Set(),
      };
      partitions.set(input.id, partition);
      for (const path of paths) roster.assignments.set(path, input.id);
      generation++;
      return partitionSummary(partition);
    }
    const partition = getPartition(input.partitionId);
    const paths = checkedPaths(input.paths);
    const owners = getRoster(partition.rosterId).assignments;
    if (paths.some((path) => owners.get(path) !== partition.id)) {
      throw new Error("Path is outside the source partition.");
    }
    const before = partition.examined.size;
    for (const path of paths) partition.examined.add(path);
    if (partition.examined.size !== before) {
      partition.revision++;
      generation++;
    }
    return partitionSummary(partition);
  }

  function limitations() {
    const result: string[] = [];
    for (const roster of rosters.values()) {
      const gaps = [...roster.gaps].map(
        ([id, description]) =>
          "gap " + JSON.stringify(id) + " (" + description + ")",
      );
      const unassigned = unassignedPaths(roster);
      if (unassigned.length)
        gaps.push("unassigned files " + JSON.stringify(unassigned));
      for (const id of new Set(roster.assignments.values())) {
        const partition = getPartition(id);
        const remaining = remainingPaths(partition);
        const scope = "partition " + JSON.stringify(partition.id);
        if (remaining.length)
          gaps.push(
            scope + " has unexamined files " + JSON.stringify(remaining),
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
  }

  function query(args: unknown): JsonObject {
    const input = sourceWorkQuerySchema.parse(args);
    if ("rosterId" in input) {
      const roster = getRoster(input.rosterId);
      const ids = new Set(roster.assignments.values());
      const summary = {
        ...rosterSummary(roster),
        unassignedFileCount: roster.paths.size - roster.assignments.size,
        partitionCount: ids.size,
      };
      if (!input.page) return summary;
      const partitionIds = [...ids].sort();
      const version = [
        "roster",
        input.rosterId,
        input.page.view,
        summary.revision,
        summary.assignedFileCount,
        partitionIds,
      ];
      if (input.page.view === "pages") {
        const page = pageOf(roster.pages, input.page, version);
        page.items = page.items.map((entry) => ({
          ...entry,
          sourceRefs: [...entry.sourceRefs],
          gaps: entry.gaps.map((gap) => ({ ...gap })),
          resolutions: entry.resolutions.map((resolution) => ({
            ...resolution,
          })),
        }));
        return { ...summary, page };
      }
      const entries = {
        paths: () => [...roster.paths].sort(),
        unassigned: () => unassignedPaths(roster),
        gaps: () =>
          [...roster.gaps].map(([id, description]) => ({ id, description })),
        partitionIds: () => partitionIds,
      };
      return {
        ...summary,
        page: pageOf<JsonValue>(
          entries[input.page.view](),
          input.page,
          version,
        ),
      };
    }
    if ("partitionId" in input) {
      const partition = getPartition(input.partitionId);
      const summary = partitionSummary(partition);
      if (!input.page) return summary;
      return {
        ...summary,
        page: pageOf(
          input.page.view === "paths"
            ? partition.paths
            : remainingPaths(partition),
          input.page,
          ["partition", input.partitionId, input.page.view, summary.revision],
        ),
      };
    }
    const summary = {
      rosterCount: rosters.size,
      incompleteRosterCount: 0,
      gapCount: 0,
      unassignedFileCount: 0,
      remainingFileCount: 0,
    };
    for (const roster of rosters.values()) {
      if (roster.gaps.size) summary.incompleteRosterCount++;
      summary.gapCount += roster.gaps.size;
      summary.unassignedFileCount +=
        roster.paths.size - roster.assignments.size;
    }
    for (const partition of partitions.values())
      summary.remainingFileCount +=
        partition.paths.length - partition.examined.size;
    return summary;
  }

  const sourceWork = { query, update };
  function withGraphTools(
    tools: Tool[],
    readOnly: boolean,
    notes: {
      query(input: unknown): unknown;
      update(input: unknown): unknown;
    },
  ): Tool[] {
    function graphTool(action: keyof typeof graphActions, base?: Tool): Tool {
      const { name, description, fields } = graphActions[action];
      const { properties } = z.toJSONSchema(z.strictObject(fields).partial());
      const baseSchema = base?.inputSchema as
        { properties?: object } | undefined;
      return {
        name,
        description: base ? base.description + " " + description : description,
        inputSchema: {
          type: "object",
          properties: { ...baseSchema?.properties, ...properties },
          additionalProperties: false,
          ...(!base && { minProperties: 1, maxProperties: 1 }),
        },
        run(input) {
          if (isRecord(input)) {
            const note = Object.hasOwn(input, "note");
            const work = Object.hasOwn(input, "sourceWork");
            if (!note && !work && base) return base.run(input);
            if (Object.keys(input).length === 1) {
              if (note) return notes[action](input["note"]);
              if (work)
                return { source_work: sourceWork[action](input["sourceWork"]) };
            }
          }
          throw new Error("Supply exactly one of note or sourceWork.");
        },
      };
    }

    const base = tools.find((tool) => tool.name === graphActions.query.name);
    const result = tools.filter((tool) => tool !== base);
    result.push(graphTool("query", base));
    if (!readOnly) result.push(graphTool("update"));
    return result;
  }

  return {
    coverage: { generation: () => generation, limitations },
    withGraphTools,
  };
}

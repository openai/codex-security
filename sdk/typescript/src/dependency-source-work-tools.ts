import { createHash } from "node:crypto";
import { z } from "zod";
import type { JsonObject, JsonValue } from "./config.js";
import { createDependencySourceWorklist } from "./dependency-source-worklist.js";
import {
  dependencySourceNoteQuerySchema,
  dependencySourceNoteSchema,
} from "./dependency-stack-evidence.js";
import { isRecord } from "./record.js";

const label = z.string().trim().min(1);
const paths = z.array(z.string().min(1));
const mutationSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("append_roster_page"),
    id: label,
    owner: label,
    expectedRevision: z.number().int().positive().optional(),
    paths,
    declaredComplete: z.boolean(),
    search: label,
    sourceRefs: z.array(label),
    gaps: z.array(z.strictObject({ id: label, description: label })),
    resolutions: z
      .array(z.strictObject({ id: label, sourceRef: label }))
      .optional(),
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

const page = {
  limit: z.number().int().positive(),
  cursor: z
    .strictObject({ revision: label, offset: z.number().int().positive() })
    .optional(),
};

const sourceWorkQuerySchema = z.union([
  z.strictObject({}),
  z.strictObject({
    rosterId: label,
    page: z
      .strictObject({
        ...page,
        view: z.enum(["paths", "unassigned", "pages", "gaps", "partitionIds"]),
      })
      .optional(),
  }),
  z.strictObject({
    partitionId: label,
    page: z
      .strictObject({
        ...page,
        view: z.enum(["paths", "remaining"]),
      })
      .optional(),
  }),
]);

function pageOf(
  values: readonly JsonValue[],
  request: {
    limit: number;
    view: string;
    cursor?: { revision: string; offset: number } | undefined;
  },
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

export function createDependencySourceWorkTools() {
  const work = createDependencySourceWorklist();
  return {
    coverage: { generation: work.generation, limitations: work.limitations },

    update(args: unknown): JsonObject {
      const input = mutationSchema.parse(args);
      switch (input.operation) {
        case "append_roster_page": {
          const { expectedRevision, resolutions, ...rosterPage } = input;
          return work.appendRosterPage({
            ...rosterPage,
            ...(expectedRevision === undefined ? {} : { expectedRevision }),
            ...(resolutions === undefined ? {} : { resolutions }),
          });
        }
        case "assign_partition":
          return work.createPartition(input);
        case "record_examined":
          return work.recordExamined(input);
      }
    },

    query(args: unknown): JsonObject {
      const input = sourceWorkQuerySchema.parse(args);
      if ("rosterId" in input) {
        const { paths, unassigned, pages, gaps, partitionIds, ...summary } =
          work.readRoster(input.rosterId);
        const entries = { paths, unassigned, pages, gaps, partitionIds };
        return {
          ...summary,
          unassignedFileCount: unassigned.length,
          partitionCount: partitionIds.length,
          ...(input.page && {
            page: pageOf(entries[input.page.view], input.page, [
              "roster",
              input.rosterId,
              input.page.view,
              summary.revision,
              summary.assignedFileCount,
              partitionIds,
            ]),
          }),
        };
      }
      if ("partitionId" in input) {
        const { paths, remaining, ...summary } = work.readPartition(
          input.partitionId,
        );
        const entries = { paths, remaining };
        return {
          ...summary,
          ...(input.page && {
            page: pageOf(entries[input.page.view], input.page, [
              "partition",
              input.partitionId,
              input.page.view,
              summary.revision,
            ]),
          }),
        };
      }
      return work.summary();
    },
  };
}

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
      "Use note:{search} to find shared source notes, note:{} to list them, or note:{id} to read pinned excerpts. Use sourceWork:{} for coverage counts, or sourceWork:{rosterId} or {partitionId} with page:{view,limit,cursor} for exact paths and gaps.",
    fields: {
      note: dependencySourceNoteQuerySchema,
      sourceWork: sourceWorkQuerySchema,
    },
  },
  update: {
    name: "update_codex_security_graph",
    description:
      "Use note to share a question, scope and assertion with exact line ranges from the pinned checkout. Reopen it by ID with query_codex_security_graph. Use sourceWork to append a page of search results with source references and gaps, resolve a gap by ID, assign files to a partition, or mark paths examined.",
    fields: { note: dependencySourceNoteSchema, sourceWork: mutationSchema },
  },
};

export function withInvestigationGraphTools(
  tools: Tool[],
  sourceWork: ReturnType<typeof createDependencySourceWorkTools>,
  readOnly: boolean,
  notes: {
    query(input: unknown): unknown;
    update(input: unknown): unknown;
  },
): Tool[] {
  function graphTool(action: keyof typeof graphActions, base?: Tool): Tool {
    const { name, description, fields } = graphActions[action];
    const { properties } = z.toJSONSchema(z.strictObject(fields).partial());
    const baseSchema = base?.inputSchema as { properties?: object } | undefined;
    return {
      name,
      description: base ? base.description + " " + description : description,
      inputSchema: {
        type: "object",
        properties: { ...baseSchema?.properties, ...properties },
        additionalProperties: false,
        anyOf: [
          ...(baseSchema ? [baseSchema] : []),
          { required: ["note"], maxProperties: 1 },
          { required: ["sourceWork"], maxProperties: 1 },
        ],
      },
      run(input) {
        if (isRecord(input) && Object.keys(input).length === 1) {
          if (Object.hasOwn(input, "note")) return notes[action](input["note"]);
          if (Object.hasOwn(input, "sourceWork"))
            return { source_work: sourceWork[action](input["sourceWork"]) };
        }
        if (base) return base.run(input);
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

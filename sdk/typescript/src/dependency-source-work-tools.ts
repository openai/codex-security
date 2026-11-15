import { createHash } from "node:crypto";
import { z } from "zod";
import type { JsonObject, JsonValue } from "./config.js";
import { createDependencySourceWorklist } from "./dependency-source-worklist.js";

const label = z.string().trim().min(1);
const paths = z.array(z.string().min(1));
const owned = {
  partitionId: label,
  owner: label,
  expectedRevision: z.number().int().positive(),
};
const mutationSchema = z.discriminatedUnion("operation", [
  z.strictObject({
    operation: z.literal("append_roster_page"),
    id: label,
    owner: label,
    expectedRevision: owned.expectedRevision.optional(),
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
    ...owned,
    paths: paths.min(1),
  }),
  z.strictObject({
    operation: z.literal("offer_handoff"),
    ...owned,
    recipient: label,
    newPartitionId: label,
    paths: paths.min(1),
  }),
  z.strictObject({
    operation: z.literal("accept_handoff"),
    partitionId: label,
    recipient: label,
    expectedRevision: owned.expectedRevision,
  }),
  z.strictObject({
    operation: z.literal("cancel_handoff"),
    ...owned,
  }),
]);

const toolInputSchema = z.strictObject({ work: mutationSchema });

const page = {
  limit: z.number().int().positive(),
  cursor: z
    .strictObject({ revision: label, offset: z.number().int().positive() })
    .optional(),
};

export const sourceWorkQuerySchema = z.union([
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
        view: z.enum(["paths", "remaining", "handoffPaths"]),
      })
      .optional(),
  }),
]);

export const sourceWorkTool = {
  name: "record_codex_security_source_work",
  description:
    "Retain exact already-discovered paths for the native investigation plan. Pass the operation under work. " +
    "Append each search page from stored results, with its search, source references, " +
    "remaining gap IDs and declared completion. Resolve an existing gap by ID with a source reference. Assign discovered files to primary partitions, " +
    "record examined paths, or offer and accept an exact subset handoff. Owner labels are plan " +
    "identifiers. A handoff keeps the original owner until the recipient accepts its revision. " +
    "File ownership and examination describe source work and do not establish a use verdict.",
  inputSchema: z.toJSONSchema(toolInputSchema) as JsonObject,
};

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

    mutate(args: unknown): JsonObject {
      const { work: input } = toolInputSchema.parse(args);
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
        case "offer_handoff":
          return work.offerHandoff(input);
        case "accept_handoff":
          return work.acceptHandoff(input);
        case "cancel_handoff":
          return work.cancelHandoff(input);
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
        const {
          paths,
          remaining,
          handoffPaths = [],
          ...summary
        } = work.readPartition(input.partitionId);
        const entries = { paths, remaining, handoffPaths };
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

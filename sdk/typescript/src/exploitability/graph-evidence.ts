import { z } from "zod";
import { safeRelativePath } from "../contract-values.js";
import type { DependencyEvidenceRecord } from "./evidence-sources.js";
import { dependencyRecordHash } from "./attempt-store.js";
import { isRecord } from "../record.js";

import {
  dependencyReceiptSelectionSchema,
  type DependencyReceiptSelection,
} from "./analyzers/stacks/evidence.js";
export { dependencyReceiptSelectionSchema, type DependencyReceiptSelection };
const { record: path, textBlock: block } =
  dependencyReceiptSelectionSchema.shape;
const receipt = z.object({
  receiptId: z.string().min(1),
  textBlock: block.describe(
    "Use null for structured content or the index of a returned JSON text block.",
  ),
});
const resolveServices = "resolve_codex_security_services";
const projectInput = z.strictObject({
  project: z
    .string()
    .min(1)
    .describe("Checkout-relative project directory or build file."),
});
const serviceInput = z.strictObject({
  path: z
    .string()
    .min(1)
    .describe("Checkout-relative file whose services you looked up."),
  project: projectInput.shape.project.optional(),
  lookups: z
    .array(
      receipt.extend({
        target: path.describe(
          "Field in the original tool arguments that names the file or its consuming project.",
        ),
        records: path.describe(
          "Field in the returned JSON containing the complete array of service records for this lookup.",
        ),
        name: path.describe(
          "Service name field relative to each selected record.",
        ),
        id: path.describe(
          "Stable service ID field relative to each selected record.",
        ),
      }),
    )
    .min(1),
});
const resourceInput = receipt.extend({
  document: path
    .default([])
    .describe("Select the graph evidence document within the returned JSON."),
});
export const dependencyGraphEvidenceFormat = "codex-security-graph-evidence/v1";
export const dependencyGraphEvidenceDocument = z.object({
  format: z.literal(dependencyGraphEvidenceFormat),
  frame_order: z.literal("root_first"),
  observations: z.array(
    z.object({
      id: z.string().min(1),
      kind: z.literal("sampled_stack"),
      scope: z.record(z.string(), z.json()),
      frames: z.array(
        z.object({
          kind: z.string().min(1),
          name: z.string(),
          scope: z.string().optional(),
        }),
      ),
    }),
  ),
});

type FieldPath = z.infer<typeof path>;
type Service = {
  name: string;
  scope: string;
  source: string;
  receiptSelections: DependencyReceiptSelection[];
};

export interface DependencyEvidenceGraph {
  tools: { name: string; description: string; inputSchema: object }[];
  call(
    name: string,
    args: unknown,
    signal?: AbortSignal,
  ): Promise<Record<string, unknown>>;
  recordCatalogResolution(answer: {
    path: string;
    project?: string;
    services: Service[];
    receiptSelections: DependencyReceiptSelection[];
    source: string;
  }): Record<string, unknown>;
  recordObservations(
    rows: z.infer<typeof dependencyGraphEvidenceDocument>["observations"],
    receiptId: string,
    prefix: FieldPath,
    textBlock: number | null,
  ): Record<string, unknown>;
}

export function selectDependencyEvidenceField(
  value: unknown,
  keys: FieldPath,
): unknown {
  for (const key of keys) {
    if (
      Array.isArray(value) &&
      typeof key === "number" &&
      Object.hasOwn(value, key)
    )
      value = value[key];
    else if (
      isRecord(value) &&
      typeof key === "string" &&
      Object.hasOwn(value, key)
    )
      value = value[key];
    else throw new Error("Selector does not exist in the original record.");
  }
  return value;
}

export function dependencyEvidencePayload(
  record: Pick<DependencyEvidenceRecord, "result">,
  index: number | null,
): unknown {
  const result = record.result;
  if (index === null)
    return result["structuredContent"] ?? result["structured_content"];
  const resources =
    !Array.isArray(result["content"]) && Array.isArray(result["contents"]);
  const blocks = resources ? result["contents"] : result["content"];
  const item = Array.isArray(blocks) ? blocks[index] : undefined;
  if (
    !isRecord(item) ||
    (!resources && item["type"] !== "text") ||
    typeof item["text"] !== "string"
  )
    throw new Error("Expected a JSON text block in the cited receipt.");
  return JSON.parse(item["text"]);
}

export function selectedReceiptValue(
  original: DependencyEvidenceRecord,
  selection: Omit<DependencyReceiptSelection, "receiptId">,
) {
  const value = selectDependencyEvidenceField(
    dependencyEvidencePayload(original, selection.textBlock),
    selection.record,
  );
  if (value === undefined)
    throw new Error("Selection does not identify original JSON content.");
  return value;
}

/** Bind a pointer to the captured response and origin, independently of its neighbors. */
export function bindReceiptSelections(
  selected: readonly DependencyReceiptSelection[],
  get: (id: string) => DependencyEvidenceRecord | undefined,
) {
  const bindings = selected.map(({ receiptId, textBlock, record }) => {
    const original = get(receiptId);
    if (!original) throw new Error("Unknown receipt selection: " + receiptId);
    const selection = { textBlock, record };
    selectedReceiptValue(original, selection);
    const parent =
      "linkedFrom" in original && typeof original.linkedFrom === "string"
        ? original.linkedFrom
        : undefined;
    const origin = {
      tool: original.tool,
      arguments: original.arguments,
      ...(parent && { parentReceiptId: parent }),
    };
    const originalPayloadSha256 = dependencyRecordHash(original.result);
    const key = dependencyRecordHash({
      server: original.server,
      origin,
      payloadSha256: originalPayloadSha256,
      selection,
    });
    return {
      key,
      receiptId,
      server: original.server,
      origin,
      originalPayloadSha256,
      selection,
    };
  });
  return [...new Map(bindings.map((row) => [row.key, row])).values()];
}
export type BoundReceiptSelection = ReturnType<
  typeof bindReceiptSelections
>[number];
export const selectedReceiptKey = (row: BoundReceiptSelection) =>
  "receipt:" + row.key;
export function selectedReceiptReference({
  receiptId,
  originalPayloadSha256,
  selection,
}: BoundReceiptSelection) {
  return {
    kind: "receipt" as const,
    receiptId,
    originalPayloadSha256,
    selection,
  };
}

export function partialDependencyResponse(value: unknown): boolean {
  return (
    isRecord(value) &&
    (value["truncated"] === true ||
      value["partial"] === true ||
      value["hasMore"] === true ||
      value["has_more"] === true ||
      value["complete"] === false ||
      value["coverage"] === "partial" ||
      Boolean(
        value["next_page_token"] ??
        value["nextPageToken"] ??
        value["nextCursor"] ??
        value["next_cursor"],
      ))
  );
}

function incomplete(value: unknown): boolean {
  return (
    partialDependencyResponse(value) ||
    (isRecord(value) && value["coverage"] === "unknown")
  );
}

/** The model supplies selectors; service identities and sampled frames are read from original replies. */
export function createDependencyGraphEvidenceTools(
  graph: DependencyEvidenceGraph,
  getRecord?: (id: string) => DependencyEvidenceRecord | undefined,
  signal?: AbortSignal,
) {
  const tools = graph.tools
    .filter((tool) => tool.name !== resolveServices)
    .map((tool) => ({
      ...tool,
      run: (input: unknown) => graph.call(tool.name, input, signal),
    }));
  const local = {
    name: resolveServices,
    description:
      "Pass project alone to find local configuration lines that mention its literal path. Use a path below the checkout root, such as apps/mail. For a root project, use its build file (for example, package.json) instead of '.'.",
    inputSchema: z.toJSONSchema(projectInput),
    run: (input: unknown) =>
      graph.call(resolveServices, projectInput.parse(input), signal),
  };
  if (!getRecord) return [...tools, local];

  function record(id: string) {
    const found = getRecord?.(id);
    if (!found || found.sha256 !== id)
      throw new Error("Unknown evidence receipt.");
    return found;
  }
  const catalogSchema = z.toJSONSchema(serviceInput);
  return [
    ...tools,
    {
      name: resolveServices,
      description:
        "After querying a catalog, pass path and lookups to link the file to every service in the cited replies. If you queried a verified consuming project, include project. A complete empty result covers only that lookup. " +
        local.description,
      inputSchema: {
        type: "object",
        properties: catalogSchema.properties,
        anyOf: [local.inputSchema, catalogSchema],
      },
      async run(input: unknown) {
        if (isRecord(input) && !("path" in input || "lookups" in input))
          return local.run(input);
        const args = serviceInput.parse(input);
        const file = safeRelativePath(args.path, "Service question");
        const project =
          args.project === undefined
            ? undefined
            : safeRelativePath(args.project, "Service project", true);
        const services = new Map<string, Service>();
        const selections: DependencyReceiptSelection[] = [];
        const sources = new Set<string>();
        for (const lookup of args.lookups) {
          const rec = record(lookup.receiptId);
          const target = selectDependencyEvidenceField(
            rec.arguments,
            lookup.target,
          );
          if (
            typeof target !== "string" ||
            (target !== file && target !== project)
          )
            throw new Error(
              "Catalog arguments must identify the file or its project.",
            );
          const original = dependencyEvidencePayload(rec, lookup.textBlock);
          let rows = original;
          if (incomplete(rec.result) || incomplete(rows))
            throw new Error("Catalog lookup coverage is incomplete.");
          for (const key of lookup.records) {
            rows = selectDependencyEvidenceField(rows, [key]);
            if (incomplete(rows))
              throw new Error("Catalog lookup coverage is incomplete.");
          }
          if (!Array.isArray(rows))
            throw new Error("Expected a service result array.");
          const source = rec.server + "/" + rec.tool;
          sources.add(source);
          selections.push({
            receiptId: rec.sha256,
            textBlock: lookup.textBlock,
            record: lookup.records,
          });
          for (const [index, row] of rows.entries()) {
            const name = selectDependencyEvidenceField(row, lookup.name),
              id = selectDependencyEvidenceField(row, lookup.id);
            if (
              typeof name !== "string" ||
              !name.trim() ||
              !(
                (typeof id === "string" && id.trim()) ||
                (typeof id === "number" && Number.isSafeInteger(id))
              )
            )
              throw new Error(
                "Expected a nonempty service name and stable service ID.",
              );
            const scope = rec.server + ":" + String(id);
            const service = services.get(scope) ?? {
              name,
              scope,
              source: source + "#" + String(id),
              receiptSelections: [],
            };
            if (service.name !== name)
              throw new Error(
                "Conflicting names for the same catalog service ID.",
              );
            service.receiptSelections.push({
              receiptId: rec.sha256,
              textBlock: lookup.textBlock,
              record: [...lookup.records, index],
            });
            services.set(scope, service);
          }
        }
        return graph.recordCatalogResolution({
          path: file,
          ...(project !== undefined && { project }),
          services: [...services.values()],
          source: [...sources].join(", "),
          receiptSelections: selections,
        });
      },
    },
    {
      name: "ingest_dependency_graph_evidence",
      description:
        "Load an original MCP reply or previously read linked JSON resource containing codex-security-graph-evidence/v1 with root_first sampled witnesses. Returns counts. Use query_codex_security_graph for bounded witness details; a sample alone does not establish caller access or deployment coverage.",
      inputSchema: z.toJSONSchema(resourceInput, { io: "input" }),
      run(input: unknown) {
        const args = resourceInput.parse(input),
          rec = record(args.receiptId);
        const observations = dependencyGraphEvidenceDocument.parse(
          selectDependencyEvidenceField(
            dependencyEvidencePayload(rec, args.textBlock),
            args.document,
          ),
        ).observations;
        return graph.recordObservations(
          observations,
          rec.sha256,
          [...args.document, "observations"],
          args.textBlock,
        );
      },
    },
  ];
}

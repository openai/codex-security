import { join } from "node:path";
import { pathToFileURL } from "node:url";
import {
  withEndpointTools,
  type DependencyEndpointGraph,
} from "./dependency-endpoints.js";
import { z } from "zod";
import { bundledPluginRoot } from "./runtime.js";
import { dependencyRecordHash } from "./dependency-attempt-store.js";
import type { DependencySearch } from "./dependency-reachability.js";
import type { JsonObject } from "./config.js";
import { isRecord } from "./record.js";
import { errorMessage } from "./errors.js";
import {
  investigationServer,
  type DependencyEvidenceRecord,
} from "./dependency-evidence-sources.js";
import type { LinkedDependencyEvidence } from "./dependency-linked-resources.js";
import { createDependencySourceTools } from "./dependency-source-evidence.js";
import {
  createDependencyGraphEvidenceTools,
  dependencyReceiptSelectionSchema,
  selectedReceiptValue,
  type DependencyEvidenceGraph,
} from "./dependency-graph-evidence.js";
import {
  submitPremisesSchema,
  type createPremiseQueue,
} from "./dependency-review-queue.js";

type Definition = { name: string; description: string; inputSchema: object };
type Tool = Definition & { run(input: unknown): unknown };
interface Graph extends DependencyEvidenceGraph {
  tools: Definition[];
  call(
    name: string,
    args: unknown,
    signal: AbortSignal,
  ): Promise<Record<string, unknown>>;
  boundTraceResponse(result: Record<string, unknown>): Record<string, unknown>;
  close(): Promise<void> | void;
}
type Bridge = {
  url: string;
  close(): Promise<void>;
};
interface Helpers {
  createDependencyGraphSession(
    repository: string,
    catalog: boolean,
    options: {
      productionDiscovery: boolean;
      fullTraceReply: boolean;
      excludedSourcePaths?: readonly string[];
    },
  ): Promise<Graph>;
  startDependencyToolServer(
    tools: Definition[],
    call: (name: string, args: unknown) => Promise<unknown>,
  ): Promise<Bridge>;
}

async function helpers(): Promise<Helpers> {
  return (
    await import(
      pathToFileURL(join(await bundledPluginRoot(), "mcp/helpers.mjs")).href
    )
  ).default;
}
export interface InvestigationTools {
  definitions: Definition[];
  call(name: string, args: unknown): Promise<unknown>;
}
export type InvestigationToolFactory = () => Promise<InvestigationTools>;
export async function startInvestigationTools(
  factory: InvestigationToolFactory,
) {
  const [bundle, tools] = await Promise.all([helpers(), factory()]);
  return bundle.startDependencyToolServer(tools.definitions, tools.call);
}

export { investigationServer };
const text = z.string().min(1);
const readEvidence = z.strictObject({
  id: text,
  selection: dependencyReceiptSelectionSchema
    .omit({ receiptId: true })
    .optional(),
  path: z
    .array(z.union([z.string(), z.number().int().nonnegative()]))
    .optional(),
  offset: z.number().int().nonnegative().optional(),
});
const listEvidence = z.strictObject({
  server: text.optional(),
  tool: text.optional(),
  offset: z.number().int().nonnegative().optional(),
});
const queryClaims = z.strictObject({
  ids: z.array(text).optional(),
  wait: z.boolean().optional(),
});
const pageSize = 4000;

/** Keep long original resource responses on the host; return only the requested witness page. */
export function evidencePage(
  record: DependencyEvidenceRecord,
  args: z.infer<typeof readEvidence>,
) {
  let value: unknown = args.selection
    ? selectedReceiptValue(record, args.selection)
    : record.result;
  for (const key of args.path ?? []) {
    if (!value || typeof value !== "object" || !Object.hasOwn(value, key))
      throw new Error("Unknown response selection.");
    value = Reflect.get(value, key);
  }
  const serialized = JSON.stringify(value),
    offset = args.offset ?? 0;
  return {
    ...receiptMetadata(record),
    ...(args.selection && { selection: args.selection }),
    path: args.path ?? [],
    offset,
    text: serialized.slice(offset, offset + pageSize),
    next: offset + pageSize < serialized.length ? offset + pageSize : null,
  };
}
// A result can be paged repeatedly across several review turns.
const payloadHashes = new WeakMap<DependencyEvidenceRecord, string>();
function receiptMetadata(record: DependencyEvidenceRecord) {
  let originalPayloadSha256 = payloadHashes.get(record);
  if (originalPayloadSha256 === undefined) {
    originalPayloadSha256 = dependencyRecordHash(record.result);
    payloadHashes.set(record, originalPayloadSha256);
  }
  const linked = record as Partial<LinkedDependencyEvidence>;
  return {
    id: record.sha256,
    originalPayloadSha256,
    server: record.server,
    tool: record.tool,
    ...(linked.linkedFrom && {
      linkedFrom: linked.linkedFrom,
      contentSha256: linked.contentSha256,
    }),
  };
}
export function boundedEvidence(record: DependencyEvidenceRecord) {
  const meta = receiptMetadata(record);
  if (meta.linkedFrom) return meta;
  if (JSON.stringify(record).length <= pageSize) return record;
  return {
    server: record.server,
    tool: record.tool,
    sha256: record.sha256,
    originalPayloadSha256: meta.originalPayloadSha256,
    preview: evidencePage(record, { id: record.sha256 }),
    instructions:
      "Use read_dependency_evidence for the original selected value and subsequent pages.",
  };
}

/** Initial context is bounded across the entire evidence set. Both roles can page the full ledger. */
export function evidencePreviews(
  records: Iterable<DependencyEvidenceRecord>,
  budget = 24_000,
) {
  const previews = [];
  let remaining = budget - 2;
  for (const record of records) {
    const preview = boundedEvidence(record);
    const bytes =
      Buffer.byteLength(JSON.stringify(preview)) + (previews.length ? 1 : 0);
    if (bytes > remaining) break;
    previews.push(preview);
    remaining -= bytes;
  }
  return previews;
}

function scopeFields(input: unknown) {
  if (!isRecord(input)) return [];
  return Object.entries(input).flatMap(([k, v]) => {
    if (
      typeof v === "string" ||
      typeof v === "number" ||
      typeof v === "boolean"
    )
      return [k + "=" + v];
    if (!Array.isArray(v)) return [];
    const values =
      k === "rules" ? v.filter(isRecord).map((rule) => rule["id"]) : v;
    return values.every((value) => typeof value === "string")
      ? [k + "=" + JSON.stringify(values)]
      : [];
  });
}
function auditSearch(
  tool: string,
  args: unknown,
  startedAt: string,
  response: Record<string, unknown>,
  receipt?: string,
  error?: unknown,
): DependencySearch {
  const trace = tool === "trace_codex_security_code";
  const upstream =
    tool === "fetch_dependency_source" || tool === "read_dependency_source";
  const catalog = tool === "resolve_codex_security_services";
  const source = trace
    ? "Checkout trace graph"
    : upstream
      ? "Dependency source evidence"
      : catalog
        ? "Service catalog resolution"
        : "Dependency evidence graph";
  const coverage = response[trace ? "coverage" : "service_resolution"];
  const result = isRecord(coverage) ? coverage : {};
  const scope = scopeFields(args);
  const details: string[] = [],
    evidenceReferences: string[] = receipt ? [receipt] : [];
  const strings = (x: unknown) =>
    Array.isArray(x) ? x.filter((v): v is string => typeof v === "string") : [];
  if (trace) {
    if (!scope.some((s) => /^(files|paths)=/u.test(s)))
      scope.push("Checkout search scope");
    scope.push(
      ...strings(result["searched_paths"]).map((path) => "searched=" + path),
    );
    details.push(...strings(result["limits"]));
    for (const [field, label] of [
      ["partial", "Incomplete"],
      ["frontier", "Not visited"],
      ["discovery_omissions", "Broad discovery omission"],
    ] as const) {
      const entries = result[field];
      if (Array.isArray(entries))
        for (const entry of entries.filter(isRecord))
          details.push(label + ": " + scopeFields(entry).join(" · "));
    }
    const rules = response["ruleExecutions"];
    if (Array.isArray(rules))
      for (const rule of rules)
        if (isRecord(rule) && typeof rule["id"] === "string")
          evidenceReferences.push(rule["id"]);
    if (isRecord(args) && args["source_only"] === true)
      details.push(
        "Service and runtime checks were skipped in this source-only trace.",
      );
  }
  const structural = Array.isArray(response["trace"])
    ? response["trace"].length
    : 0;
  const text = Array.isArray(response["textMatches"])
    ? response["textMatches"].length
    : 0;
  if (trace && error === undefined)
    details.push(
      structural +
        " structural trace entries and " +
        text +
        " text match groups.",
    );
  if (error !== undefined) details.push(errorMessage(error));
  if (upstream) {
    const ref = response["receiptId"] ?? response["sourceId"];
    if (typeof ref === "string") evidenceReferences.push(ref);
  }
  const complete = trace && result["complete"] === true;
  const partial = trace
    ? result["complete"] === false
    : Boolean(result["pending"] || result["unresolved"] || result["truncated"]);
  return {
    source,
    tool,
    scope,
    startedAt,
    finishedAt: new Date().toISOString(),
    result:
      error !== undefined
        ? "unknown"
        : structural + text > 0
          ? "matches"
          : complete
            ? "no_match"
            : trace
              ? "unknown"
              : "returned",
    completeness:
      error !== undefined
        ? "error"
        : complete
          ? "complete"
          : partial
            ? "partial"
            : "unknown",
    details,
    evidenceReferences,
  };
}

export function createInvestigationSession(options: {
  directory: string;
  repository: string;
  signal: AbortSignal;
  productionDiscovery: boolean;
  excludedSourcePaths?: readonly string[];
  endpoints: DependencyEndpointGraph;
  submitAssessments: Tool;
  evidenceSources: boolean;
  queue: ReturnType<typeof createPremiseQueue>;
  records: ReadonlyMap<string, DependencyEvidenceRecord>;
  failureRecords?: ReadonlyMap<string, DependencyEvidenceRecord>;
  record: (r: DependencyEvidenceRecord) => void;
  onSearch: (value: DependencySearch) => void;
  onToolStart?: (
    name: string,
    args: unknown,
  ) =>
    | ((
        outcome: "returned" | "partial" | "failed",
        searchedPaths?: unknown,
      ) => void)
    | undefined;
}) {
  const { queue, records } = options;
  let graph: Promise<Graph> | undefined;
  const remember = (
    tool: string,
    args: unknown,
    result: Record<string, unknown>,
  ) => {
    // Bundled tools return JS objects in process. Capture the same JSON an MCP
    // client can receive, before hashing or exposing the response to the ledger.
    const data: Omit<DependencyEvidenceRecord, "sha256"> = JSON.parse(
      JSON.stringify({
        server: investigationServer,
        tool,
        arguments: args,
        result,
      }),
    );
    const record = { ...data, sha256: dependencyRecordHash(data) };
    options.record(record);
    return record.sha256;
  };
  function resolveRecord(id: string) {
    const record = records.get(id) ?? options.failureRecords?.get(id);
    if (!record) throw new Error("Unknown evidence ID: " + id);
    return record;
  }
  const readers: Tool[] = [
    {
      name: "list_dependency_evidence",
      description:
        "List receipt IDs, server and tool, including the parent receipt and content hashes for linked resources. Use next as the offset for the next page.",
      inputSchema: z.toJSONSchema(listEvidence),
      run(raw) {
        const { server, tool, offset = 0 } = listEvidence.parse(raw);
        const page: ReturnType<typeof receiptMetadata>[] = [];
        const pageLength = 40;
        let count = 0;
        for (const ledger of [records, options.failureRecords]) {
          if (!ledger) continue;
          for (const r of ledger.values()) {
            if ((server && r.server !== server) || (tool && r.tool !== tool))
              continue;
            if (count++ < offset) continue;
            if (page.length === pageLength)
              return { receipts: page, next: offset + pageLength };
            page.push(receiptMetadata(r));
          }
        }
        return { receipts: page, next: null };
      },
    },
    {
      name: "read_dependency_evidence",
      description:
        "Read a page of the immutable original response by receipt ID, optionally selecting a JSON path or offset. originalPayloadSha256 identifies the complete response across pages.",
      inputSchema: z.toJSONSchema(readEvidence),
      run(raw) {
        const args = readEvidence.parse(raw);
        return evidencePage(resolveRecord(args.id), args);
      },
    },
    {
      name: "query_dependency_claims",
      description:
        "Find queued uses, candidate dispositions and premises with their exact references, evidence and review state. Check existing uses before assigning an assessment ID. A retainedUse identifies the approved finding still in effect during a withdrawal. Set wait=true to wait for outstanding reviews.",
      inputSchema: z.toJSONSchema(queryClaims),
      run: (raw) => queue.query(raw),
    },
  ];
  const sourceTools = createDependencySourceTools({
    directory: options.directory,
    repository: options.repository,
    signal: options.signal,
    fetcher: fetch,
    recordExcerpt(excerpt: JsonObject) {
      return remember(
        "read_dependency_source",
        {
          sourceId: excerpt["sourceId"] ?? null,
          startLine: excerpt["startLine"] ?? null,
          endLine: excerpt["endLine"] ?? null,
        },
        { structuredContent: excerpt },
      );
    },
  });
  return {
    async tools(readOnly: boolean): Promise<InvestigationTools> {
      const tools = readers.map((tool) =>
        readOnly && tool.name === "query_dependency_claims"
          ? {
              ...tool,
              run: (raw: unknown) =>
                queue.query({ ...queryClaims.parse(raw), wait: false }),
            }
          : tool,
      );
      if (!readOnly) {
        graph ??= helpers().then((h) =>
          h.createDependencyGraphSession(
            options.repository,
            options.evidenceSources,
            {
              productionDiscovery: options.productionDiscovery,
              fullTraceReply: true,
              excludedSourcePaths: options.excludedSourcePaths,
            },
          ),
        );
        const g = await graph;
        tools.push(
          options.submitAssessments,
          {
            name: "submit_dependency_claims",
            description:
              "Submit a batch of source- or receipt-backed premises for independent review while investigation continues. Investigators share the ledger. Use returned revision and hash when applying an approved premise to a use.",
            inputSchema: z.toJSONSchema(submitPremisesSchema),
            run: (raw) => queue.submit(raw),
          },
          ...sourceTools.map((tool) => ({
            ...tool,
            async run(input: unknown) {
              const started = new Date().toISOString();
              try {
                const result = await tool.run(input);
                options.onSearch(
                  auditSearch(tool.name, input, started, result),
                );
                return result;
              } catch (error) {
                options.onSearch(
                  auditSearch(tool.name, input, started, {}, undefined, error),
                );
                throw error;
              }
            },
          })),
          ...createDependencyGraphEvidenceTools(g, (id) => {
            const r = records.get(id);
            return r && r.server !== investigationServer ? r : undefined;
          }),
          ...g.tools.map((def) => ({
            ...def,
            async run(input: unknown) {
              const startedAt = new Date().toISOString();
              let response: Record<string, unknown>;
              try {
                response = await g.call(def.name, input, options.signal);
              } catch (error) {
                options.onSearch(
                  auditSearch(def.name, input, startedAt, {}, undefined, error),
                );
                throw error;
              }
              const receipt = remember(def.name, input, {
                structuredContent: response,
              });
              options.onSearch(
                auditSearch(def.name, input, startedAt, response, receipt),
              );
              return def.name === "trace_codex_security_code"
                ? g.boundTraceResponse(response)
                : response;
            },
          })),
        );
      }
      const exposed = withEndpointTools(tools, options.endpoints, readOnly);
      return {
        definitions: exposed.map(({ run: _, ...def }) => def),
        async call(name, args) {
          options.signal.throwIfAborted();
          const t = exposed.find((t) => t.name === name);
          if (!t) throw new Error("Unknown investigation tool: " + name);
          const finished = options.onToolStart?.(name, args);
          try {
            const response = await t.run(args);
            const coverage = isRecord(response)
              ? response["coverage"]
              : undefined;
            finished?.(
              isRecord(coverage) && coverage["complete"] === false
                ? "partial"
                : "returned",
              isRecord(coverage) ? coverage["searched_paths"] : undefined,
            );
            return response;
          } catch (error) {
            finished?.("failed");
            throw error;
          }
        },
      };
    },
    async close() {
      if (graph) {
        const g = await graph.catch(() => undefined);
        await g?.close();
      }
    },
  };
}

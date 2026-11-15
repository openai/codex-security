import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { z } from "zod";
import type { JsonObject, JsonValue } from "./config.js";
import {
  dependencyEndpointQuerySchema,
  dependencyEndpointTool,
  openDependencyEndpoints,
  type DependencyEndpointGraph,
} from "./dependency-endpoints.js";
import {
  createGraphEvidenceIngestion,
  graphEvidenceResourceSchema,
  type GraphEvidenceObservations,
  type RecordGraphInventory,
} from "./dependency-graph-evidence.js";
import {
  inventoryReceiptQuerySchema,
  type DependencyInventoryReceiptQuery,
  type DependencyInventoryRpc,
} from "./dependency-inventory.js";
import { readDependencyEvidence } from "./dependency-reachability.js";
import { createDependencySourceIdentityReader } from "./dependency-source-identity.js";
import {
  createDependencySourceWorkTools,
  sourceWorkQuerySchema,
  sourceWorkTool,
} from "./dependency-source-work-tools.js";
import type { DependencySourceWorkCoverage } from "./dependency-source-worklist.js";
import { errorMessage } from "./errors.js";
import { isRecord } from "./record.js";
import type { resolveDependencyServices } from "./dependency-service-catalog.js";

type CatalogResolver = (
  requests: Parameters<typeof resolveDependencyServices>[0]["requests"],
) => ReturnType<typeof resolveDependencyServices>;
export type DependencyCatalogAnswer = Awaited<
  ReturnType<CatalogResolver>
>[number];

export const dependencyGraphNamespace = "codex_security_dependency";

const sourceReferenceSchema = z.strictObject({
  path: z.string().trim().min(1),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
});
const sourceEvidenceSchema = z.strictObject({
  question: z.string().trim().min(1),
  scope: z.string().trim().min(1),
  claim: z.string().trim().min(1),
  evidence: z.array(sourceReferenceSchema).min(1),
});
const evidenceQuerySchema = z.strictObject({
  id: z.string().trim().min(1).optional(),
  search: z.string().trim().min(1).optional(),
});

export interface DependencyGraphTools {
  tools: { name: string; description: string; inputSchema: JsonObject }[];
  call(
    name: string,
    args: unknown,
    inventoryRpc?: DependencyInventoryRpc,
  ): Promise<JsonObject>;
  close(): Promise<void>;
  boundTraceResponse?<T extends object>(result: T): T;
  observeInventory?(
    server: string,
    result: unknown,
    receiptId: string,
    rpc: DependencyInventoryRpc,
  ): void;
  flush?(): Promise<void>;
  sourceWorkCoverage?: DependencySourceWorkCoverage;
  endpoints?: DependencyEndpointGraph;
  ingestProfileCollection?(resource: string, receiptId: string): void;
}

export async function openDependencyGraph(
  plugin: string,
  repository: string,
  resolveCatalog?: CatalogResolver,
  signal?: AbortSignal,
  onCatalogResolutions?: (
    answers: readonly DependencyCatalogAnswer[],
    inventoryRpc?: DependencyInventoryRpc,
  ) => Promise<readonly JsonObject[]>,
  recordInventory?: RecordGraphInventory,
  isReceiptCurrent?: (id: string) => boolean,
  supplemental?: {
    tools: DependencyGraphTools["tools"];
    call: DependencyGraphTools["call"];
    readInventoryReceipt?: (
      query: DependencyInventoryReceiptQuery,
    ) => JsonObject;
  },
  excludedSourcePaths?: readonly string[],
  endpointOptions?: Parameters<typeof openDependencyEndpoints>[0] & {
    productionDiscovery?: boolean;
  },
): Promise<DependencyGraphTools & { endpoints: DependencyEndpointGraph }> {
  const sourceRoot = await realpath(repository);
  const endpoints = await openDependencyEndpoints(endpointOptions);
  const readSourceIdentity = createDependencySourceIdentityReader(sourceRoot);
  const { createDependencyGraphSession } = (
    await import(pathToFileURL(join(plugin, "mcp/helpers.mjs")).href)
  ).default;
  const graph = (await createDependencyGraphSession(
    repository,
    resolveCatalog !== undefined,
    {
      fullTraceReply: true,
      excludedSourcePaths,
      productionDiscovery: endpointOptions?.productionDiscovery,
    },
  )) as Pick<DependencyGraphTools, "tools" | "close" | "boundTraceResponse"> & {
    call(
      name: string,
      args: unknown,
      signal?: AbortSignal,
    ): Promise<JsonObject & { service_resolution: JsonObject }>;
    serviceResolutionCoverage?(): JsonObject;
    includeDiscoveryFile?(path: string): void;
    pendingCatalogRequests(args?: unknown): Parameters<CatalogResolver>[0];
    recordCatalogResolutions(
      answers: Awaited<ReturnType<CatalogResolver>>,
      requests?: Parameters<CatalogResolver>[0],
    ): JsonObject;
    recordObservations(
      observations: GraphEvidenceObservations,
      receiptId: string,
    ): JsonObject;
  };
  const evidence =
    recordInventory &&
    createGraphEvidenceIngestion({
      record: recordInventory,
      ingest: (observations, receiptId) =>
        graph.recordObservations(observations, receiptId),
      signal,
    });
  const sourceWork = createDependencySourceWorkTools();
  const sourceEvidence = new Map<
    string,
    {
      id: string;
      investigator_assertion: {
        question: string;
        scope: string;
        claim: string;
      };
      excerpts: {
        path: string;
        startLine: number;
        endLine: number;
        text: string;
      }[];
    }
  >();
  const withEvidence = (result: JsonObject): JsonObject => {
    const summary = evidence?.summary();
    return {
      ...result,
      source_evidence_count: sourceEvidence.size,
      ...(summary ? { graph_evidence: summary } : {}),
    };
  };
  const readServiceCoverage = async (): Promise<JsonObject> => {
    if (graph.serviceResolutionCoverage)
      return graph.serviceResolutionCoverage();
    // Older plugin bundles only expose graph queries.
    const { service_resolution } = await graph.call(
      "query_codex_security_graph",
      {},
      signal,
    );
    const {
      paths: _paths,
      unresolved_paths: _unresolvedPaths,
      ...coverage
    } = service_resolution;
    return coverage;
  };
  const focusedReply = async (payload: JsonObject): Promise<JsonObject> => {
    const coverage = await readServiceCoverage();
    return {
      ...payload,
      source_evidence_count: sourceEvidence.size,
      service_resolution: coverage,
    };
  };
  const sourceEvidenceReply = (source_evidence: JsonValue) =>
    focusedReply({ source_evidence });
  const lookups = new Map<string, Promise<readonly JsonObject[]>>();
  const resolved = new Map<string, DependencyCatalogAnswer>();
  const lookupKey = ({
    path,
    project,
  }: Parameters<CatalogResolver>[0][number]) => JSON.stringify([path, project]);
  const reusable = (answer: DependencyCatalogAnswer) => {
    if (!isReceiptCurrent || !("services" in answer)) return false;
    const selections = answer.services.length
      ? answer.services.map((service) => service.receiptSelections)
      : [answer.receiptSelections];
    return selections.every(
      (group) =>
        !!group?.length &&
        group.every(({ receiptId }) => isReceiptCurrent(receiptId)),
    );
  };
  return {
    sourceWorkCoverage: sourceWork.coverage,
    endpoints,
    tools: [
      ...(supplemental?.tools ?? []),
      ...graph.tools.map((tool) =>
        tool.name === "query_codex_security_graph"
          ? {
              ...tool,
              description:
                tool.description +
                " Use evidence:{} to list shared source-note IDs and questions, evidence:{id} to read host-captured excerpts, or evidence:{search} to search notes. Note claims and scope associations are investigator assertions." +
                " Use endpoints:{} for a compact endpoint page, endpoints:{id} for the full record, or filter by role, origin or scope. Use page:{limit,cursor} within the endpoint selection. A supplied side is a complete boundary." +
                " Use sourceWork:{} for source-plan remainder counts, sourceWork:{rosterId} or sourceWork:{partitionId} for a summary, and page:{view,limit,cursor} within that selection for exact paths, gaps or search receipts. Follow nextCursor until null." +
                (supplemental?.readInventoryReceipt
                  ? " Use inventory:{receiptId} for original runtime receipt metadata and shape, or inventory:{receiptId,textBlock,record} for an exact value. textBlock=null selects structured content. Set original:true for an explicit whole ordinary result when necessary."
                  : ""),
              inputSchema: {
                ...tool.inputSchema,
                properties: {
                  ...(isRecord(tool.inputSchema["properties"])
                    ? tool.inputSchema["properties"]
                    : {}),
                  endpoints: z.toJSONSchema(
                    dependencyEndpointQuerySchema,
                  ) as JsonObject,
                  evidence: z.toJSONSchema(evidenceQuerySchema) as JsonObject,
                  sourceWork: z.toJSONSchema(
                    sourceWorkQuerySchema,
                  ) as JsonObject,
                  ...(supplemental?.readInventoryReceipt && {
                    inventory: z.toJSONSchema(
                      inventoryReceiptQuerySchema,
                    ) as JsonObject,
                  }),
                },
              },
            }
          : tool,
      ),
      sourceWorkTool,
      dependencyEndpointTool,
      {
        name: "record_codex_security_evidence",
        description:
          "Save source evidence for a deciding question in this investigation's shared graph. The host validates and reads the cited lines. If a range extends past the last line, the reply lists the ranges actually captured and identifies the shortened ranges. Use those exact ranges in assessments. Question, scope and claim remain investigator assertions. Returns an immutable evidence ID for other investigators and the coordinator to retrieve.",
        inputSchema: z.toJSONSchema(sourceEvidenceSchema) as JsonObject,
      },
    ],
    ...(graph.boundTraceResponse && {
      boundTraceResponse: graph.boundTraceResponse,
    }),
    async close() {
      await endpoints.flush();
      await evidence?.flush();
      await graph.close();
    },
    flush: async () => {
      await endpoints.flush();
      await evidence?.flush();
    },
    observeInventory: (server, result, receiptId, rpc) =>
      evidence?.observe(server, result, receiptId, rpc),
    ingestProfileCollection(resource, receiptId) {
      const captured = graphEvidenceResourceSchema.parse(JSON.parse(resource));
      graph.recordObservations(captured.observations, receiptId);
    },
    async call(name, args, inventoryRpc) {
      signal?.throwIfAborted();
      if (name === dependencyEndpointTool.name)
        return focusedReply({ endpoints: await endpoints.record(args) });
      if (
        name === "query_codex_security_graph" &&
        isRecord(args) &&
        args["endpoints"] !== undefined
      )
        return focusedReply({ endpoints: endpoints.query(args["endpoints"]) });
      if (name === sourceWorkTool.name)
        return focusedReply({ source_work: sourceWork.mutate(args) });
      if (
        name === "query_codex_security_graph" &&
        isRecord(args) &&
        args["sourceWork"] !== undefined
      )
        return focusedReply({
          source_work: sourceWork.query(args["sourceWork"]),
        });
      await evidence?.flush();
      signal?.throwIfAborted();
      if (supplemental?.tools.some((tool) => tool.name === name))
        return focusedReply(await supplemental.call(name, args, inventoryRpc));
      if (name === "record_codex_security_evidence") {
        const {
          question,
          scope,
          claim,
          evidence: references,
        } = sourceEvidenceSchema.parse(args);
        const excerpts: {
          path: string;
          startLine: number;
          endLine: number;
          text: string;
        }[] = [];
        const warnings: string[] = [];
        await readDependencyEvidence(
          references.map((reference) => ({ ...reference, supports: [] })),
          sourceRoot,
          signal,
          (excerpt) => excerpts.push({ ...excerpt }),
          readSourceIdentity,
          (path, startLine, requestedEnd, endLine) =>
            warnings.push(
              `Source note range ${path}:${startLine}-${requestedEnd} ended at line ${endLine}. Use the captured ranges.`,
            ),
        );
        signal?.throwIfAborted();
        const note = {
          investigator_assertion: { question, scope, claim },
          excerpts,
        };
        const id =
          "source-evidence-" +
          createHash("sha256").update(JSON.stringify(note)).digest("hex");
        const saved = { id, ...note };
        sourceEvidence.set(id, saved);
        return sourceEvidenceReply({
          id,
          ...(warnings.length && {
            ranges: excerpts.map(({ path, startLine, endLine }) => ({
              path,
              startLine,
              endLine,
            })),
            warnings,
          }),
        });
      }
      if (
        name === "query_codex_security_graph" &&
        supplemental?.readInventoryReceipt &&
        isRecord(args) &&
        args["inventory"] !== undefined
      ) {
        const query = inventoryReceiptQuerySchema.parse(args["inventory"]);
        return focusedReply({
          inventory: supplemental.readInventoryReceipt(query),
        });
      }
      if (
        name === "query_codex_security_graph" &&
        isRecord(args) &&
        args["evidence"] !== undefined
      ) {
        const { id, search } = evidenceQuerySchema.parse(args["evidence"]);
        const notes = [...sourceEvidence.values()].filter(
          (note) =>
            (id === undefined || note.id === id) &&
            (search === undefined || JSON.stringify(note).includes(search)),
        );
        return sourceEvidenceReply(
          id !== undefined
            ? (notes[0] ?? null)
            : notes.map(({ id, investigator_assertion }) => ({
                id,
                ...investigator_assertion,
              })),
        );
      }
      const result = await graph.call(name, args, signal);
      const trace = name === "trace_codex_security_code";
      if (
        !resolveCatalog ||
        (trace && isRecord(args) && args["source_only"] === true) ||
        (!trace && name !== "resolve_codex_security_services")
      )
        return withEvidence(result);
      const requests = graph.pendingCatalogRequests(trace ? undefined : args);
      if (!requests.length) return withEvidence(result);
      const batch = requests.filter(
        (request) => !lookups.has(lookupKey(request)),
      );
      if (batch.length) {
        const lookup = (async () => {
          const cached: DependencyCatalogAnswer[] = [];
          const misses = batch.filter((request) => {
            const key = lookupKey(request);
            const answer = resolved.get(key);
            if (answer && reusable(answer)) {
              cached.push(answer);
              return false;
            }
            resolved.delete(key);
            return true;
          });
          let fresh = misses.length ? await resolveCatalog(misses) : [];
          signal?.throwIfAborted();
          // A miss can refresh a receipt that supported another path in the batch.
          if (cached.some((answer) => !reusable(answer))) {
            cached.length = 0;
            fresh = await resolveCatalog(batch);
          }
          signal?.throwIfAborted();
          const requestsByPath = new Map(
            batch.map((request, index) => [request.path, { request, index }]),
          );
          const answers = cached.length
            ? [...cached, ...fresh].sort(
                (a, b) =>
                  (requestsByPath.get(a.path)?.index ?? batch.length) -
                  (requestsByPath.get(b.path)?.index ?? batch.length),
              )
            : fresh;
          graph.recordCatalogResolutions(answers, batch);
          for (const answer of answers) {
            if (
              (excludedSourcePaths?.length ||
                endpointOptions?.productionDiscovery) &&
              requestsByPath.has(answer.path) &&
              "services" in answer &&
              answer.services.length &&
              reusable(answer)
            )
              graph.includeDiscoveryFile?.(answer.path);
          }
          for (const answer of fresh) {
            const entry = requestsByPath.get(answer.path);
            if (!entry) continue;
            const key = lookupKey(entry.request);
            if (reusable(answer)) resolved.set(key, answer);
            else resolved.delete(key);
          }
          return (await onCatalogResolutions?.(answers, inventoryRpc)) ?? [];
        })().finally(() => {
          for (const request of batch) lookups.delete(lookupKey(request));
        });
        for (const request of batch) lookups.set(lookupKey(request), lookup);
      }
      const settled = await Promise.allSettled(
        new Set(requests.map((request) => lookups.get(lookupKey(request)))),
      );
      signal?.throwIfAborted();
      const outcomes = settled.flatMap((lookup) =>
        lookup.status === "fulfilled" ? (lookup.value ?? []) : [],
      );
      const failure = settled.find((lookup) => lookup.status === "rejected");
      const summary = await graph.call(
        "query_codex_security_graph",
        {},
        signal,
      );
      return withEvidence({
        ...(trace
          ? { ...result, service_resolution: summary.service_resolution }
          : summary),
        ...(outcomes.length ? { runtime_lookups: outcomes } : {}),
        ...(failure ? { catalog_error: errorMessage(failure.reason) } : {}),
      });
    },
  };
}

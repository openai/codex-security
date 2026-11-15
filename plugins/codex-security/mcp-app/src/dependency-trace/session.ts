import * as z from "zod/v4";
import { canonicalDirectory } from "../artifact-context.js";
import { safeRelativePath } from "../contract-values.js";
import {
  EvidenceGraph,
  boundGraphResponse,
  type CatalogReceiptSelection,
} from "./graph.js";
import { findProjectReferences } from "./provider.js";
import { boundTraceResponse, traceResponse } from "./response.js";
import {
  graphQuerySchema,
  serviceInputSchema,
  traceInputSchema,
} from "./schema.js";
import { createDependencyTracer } from "./trace.js";
import type { TraceObservation } from "./types.ts";

export const dependencyGraphTools = {
  trace_codex_security_code: {
    description:
      "Search source files and dependency manifests in this checkout. With source_terms, symbol and directories, the tool feeds the matching files directly into OpenGrep in batches. The graph retains cited dependency declarations, candidate calls, and same-file flows.",
    schema: traceInputSchema,
  },
  resolve_codex_security_services: {
    description:
      "Request service lookup for checkout-relative files through the configured service catalogs. A project by itself searches local configuration for source references.",
    schema: serviceInputSchema,
  },
  query_codex_security_graph: {
    description:
      "Read the graph and service lookup status. Search names or give a node ID for static paths and citations. Sampled stacks are separate witnesses: select a witness to inspect ordered frames, or node plus witness for its adjacent observed calls. Calls from different witnesses do not form an observed path; missing sampled calls do not prove absence.",
    schema: graphQuerySchema,
  },
};

interface ResolvedCatalogResolution {
  path: string;
  status?: undefined;
  services: readonly {
    name: string;
    scope: string;
    source: string;
    receiptSelections?: CatalogReceiptSelection[];
  }[];
  receiptSelections?: CatalogReceiptSelection[];
  source?: string;
  reason?: string;
}

type CatalogResolution =
  | ResolvedCatalogResolution
  | { path: string; status: "unresolved"; reason: string; source?: string };

function catalogInput(args: unknown) {
  const { paths, project } = serviceInputSchema.parse(args);
  return {
    paths: paths?.map((path) => safeRelativePath(path, "Service question")),
    project:
      project === undefined
        ? undefined
        : safeRelativePath(project, "Service project", paths !== undefined),
  };
}

export async function createDependencyGraphSession(
  checkout: string,
  catalogConfigured: boolean,
  { fullTraceReply = false }: { fullTraceReply?: boolean } = {},
) {
  const root = await canonicalDirectory(checkout, "Dependency trace checkout");
  const tracer = createDependencyTracer(root);
  const graph = new EvidenceGraph();

  function serviceResolution() {
    return {
      catalog_configured: catalogConfigured,
      ...graph.serviceResolution(),
    };
  }

  function reply(result: object): Record<string, unknown> & {
    service_resolution: ReturnType<typeof serviceResolution>;
  } {
    return {
      ...result,
      service_resolution: serviceResolution(),
    };
  }

  return {
    boundTraceResponse,
    // Used by host replies that only need counts, without querying the graph.
    serviceResolutionCoverage() {
      const {
        paths: _paths,
        unresolved_paths: _unresolvedPaths,
        ...coverage
      } = serviceResolution();
      return coverage;
    },
    tools: Object.entries(dependencyGraphTools).map(
      ([name, { description, schema }]) => ({
        name,
        description,
        inputSchema: z.toJSONSchema(schema, { io: "input" }),
      }),
    ),
    async call(name: string, args: unknown, signal?: AbortSignal) {
      switch (name) {
        case "trace_codex_security_code": {
          const request = traceInputSchema.parse(args);
          const paths = request.paths?.map((path) =>
            safeRelativePath(path, "Trace scope", true),
          );
          const files = request.files?.map((path) =>
            safeRelativePath(path, "Trace file"),
          );
          const result = await tracer.trace(
            { ...request, paths, files },
            signal,
          );
          graph.addTrace(result, catalogConfigured && !request.source_only);
          const response = reply(traceResponse(result));
          return fullTraceReply ? response : boundTraceResponse(response);
        }
        case "resolve_codex_security_services": {
          const { paths, project } = catalogInput(args);
          if (paths !== undefined) {
            if (catalogConfigured) graph.requestServices(paths, project, true);
            return boundGraphResponse(reply(graph.query()));
          }
          return reply({
            project,
            ...(await findProjectReferences(root, project!, signal)),
          });
        }
        case "query_codex_security_graph": {
          const { node, witness, search } = graphQuerySchema.parse(args);
          return boundGraphResponse(
            reply(graph.query(node, { witness, search })),
          );
        }
        default:
          throw new Error(`Unknown dependency graph tool ${name}.`);
      }
    },
    pendingCatalogRequests(args?: unknown) {
      if (!catalogConfigured) return [];
      const input = args === undefined ? undefined : catalogInput(args);
      const pending = input
        ? [...new Set(input.paths)].filter((path) =>
            graph.isServicePending(path),
          )
        : graph.pendingServicePaths();
      return pending.map((path) => {
        const project = input?.project ?? graph.serviceProject(path);
        return { path, ...(project === undefined ? {} : { project }) };
      });
    },
    // The CLI's catalog resolver owns this entry point. The model sees only call().
    recordCatalogResolutions(
      answers: readonly CatalogResolution[],
      requests?: readonly { path: string; project?: string }[],
    ) {
      if (!catalogConfigured)
        throw new Error("Service catalogs are unavailable.");
      const contexts =
        requests === undefined
          ? undefined
          : new Map(requests.map(({ path, project }) => [path, project]));
      graph.resolveServices(
        answers.map((answer) => {
          const path = safeRelativePath(answer.path, "Service question");
          if (contexts !== undefined && !contexts.has(path))
            throw new Error(`No dispatched service question for ${path}.`);
          const project =
            contexts === undefined
              ? graph.serviceProject(path)
              : contexts.get(path);
          return {
            ...answer,
            path,
            ...(project === undefined ? {} : { project }),
          };
        }),
      );
      return boundGraphResponse(reply(graph.query()));
    },
    // The host reads observation receipts off-model and owns graph ingestion.
    // This method is deliberately absent from the model-visible tool list.
    recordObservations(
      observations: readonly TraceObservation[],
      receiptId: string,
      recordPrefix: readonly (string | number)[] = ["observations"],
    ) {
      return graph.recordObservations(observations, receiptId, recordPrefix);
    },
    close: () => tracer.close(),
  };
}

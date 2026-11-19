import * as z from "zod/v4";
import { canonicalDirectory } from "../artifact-context.js";
import { safeRelativePath } from "../contract-values.js";
import { createDiscoveryScope } from "./discovery-scope.js";
import {
  EvidenceGraph,
  boundGraphResponse,
  type ServiceResolution,
} from "./graph.js";
import { findProjectReferences, localProvider } from "./provider.js";
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
  {
    fullTraceReply = false,
    excludedSourcePaths,
    productionDiscovery = false,
  }: {
    fullTraceReply?: boolean;
    excludedSourcePaths?: readonly string[];
    productionDiscovery?: boolean;
  } = {},
) {
  const root = await canonicalDirectory(checkout, "Dependency trace checkout");
  const sourceScope =
    productionDiscovery || excludedSourcePaths?.length
      ? await createDiscoveryScope(
          root,
          excludedSourcePaths ?? [],
          productionDiscovery,
        )
      : undefined;
  const tracer = createDependencyTracer(
    root,
    sourceScope ? localProvider(root, sourceScope) : undefined,
  );
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
          if (sourceScope && files)
            for (const file of files) sourceScope.includeExactFile(file);
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
    // The SDK verifies catalog receipts before passing an answer to the graph.
    recordCatalogResolution(answer: ServiceResolution) {
      if (!catalogConfigured)
        throw new Error("Service catalogs are unavailable.");
      const { paths, project } = catalogInput({
        paths: [answer.path],
        project: answer.project,
      });
      const path = paths![0]!;
      graph.requestServices([path], project, true);
      graph.resolveServices([
        { ...answer, path, ...(project !== undefined && { project }) },
      ]);
      return boundGraphResponse(reply(graph.query()));
    },
    // The host reads observation receipts off-model and owns graph ingestion.
    // This method is deliberately absent from the model-visible tool list.
    recordObservations(
      observations: readonly TraceObservation[],
      receiptId: string,
      recordPrefix: readonly (string | number)[] = ["observations"],
      textBlock: number | null = 0,
    ) {
      return graph.recordObservations(
        observations,
        receiptId,
        recordPrefix,
        textBlock,
      );
    },
    close: () => tracer.close(),
  };
}

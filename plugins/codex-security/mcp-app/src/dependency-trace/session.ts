import * as z from "zod/v4";
import { canonicalDirectory } from "../artifact-context.js";
import { safeRelativePath } from "../contract-values.js";
import { EvidenceGraph, type CatalogReceiptSelection } from "./graph.js";
import { findProjectReferences } from "./provider.js";
import { traceResponse } from "./response.js";
import {
  graphQuerySchema,
  serviceInputSchema,
  traceInputSchema,
} from "./schema.js";
import { createDependencyTracer } from "./trace.js";

export const dependencyGraphTools = {
  trace_codex_security_code: {
    description:
      "Search supported source files and dependency manifests in this checkout. Text matches locate files to inspect. The graph retains cited dependency declarations, candidate calls, and same-file flows.",
    schema: traceInputSchema,
  },
  resolve_codex_security_services: {
    description:
      "Request service lookup for checkout-relative files through the configured service catalogs. A project by itself searches local configuration for source references.",
    schema: serviceInputSchema,
  },
  query_codex_security_graph: {
    description:
      "Read the graph and service lookup status. Give a node name or ID to see its paths and citations.",
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
) {
  const root = await canonicalDirectory(checkout, "Dependency trace checkout");
  const tracer = createDependencyTracer(root);
  const graph = new EvidenceGraph();

  function reply(result: Record<string, unknown>): Record<string, unknown> & {
    service_resolution: ReturnType<EvidenceGraph["serviceResolution"]> & {
      catalog_configured: boolean;
    };
  } {
    return {
      ...result,
      service_resolution: {
        catalog_configured: catalogConfigured,
        ...graph.serviceResolution(),
      },
    };
  }

  return {
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
          const paths = request.paths.map((path) =>
            safeRelativePath(path, "Trace scope", true),
          );
          const result = await tracer.trace({ ...request, paths }, signal);
          graph.addTrace(result, catalogConfigured);
          return reply(traceResponse(result));
        }
        case "resolve_codex_security_services": {
          const { paths, project } = catalogInput(args);
          if (paths !== undefined) {
            if (catalogConfigured) graph.requestServices(paths, project, true);
            return reply(graph.query());
          }
          return reply({
            project,
            ...(await findProjectReferences(root, project!, signal)),
          });
        }
        case "query_codex_security_graph": {
          const { node } = graphQuerySchema.parse(args);
          return reply(graph.query(node));
        }
        default:
          throw new Error(`Unknown dependency graph tool ${name}.`);
      }
    },
    pendingCatalogRequests(args: unknown) {
      if (!catalogConfigured) return [];
      const { paths, project: suppliedProject } = catalogInput(args);
      return [...new Set(paths)]
        .filter((path) => graph.isServicePending(path))
        .map((path) => {
          const project = suppliedProject ?? graph.serviceProject(path);
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
      return reply(graph.query());
    },
    close: () => tracer.close(),
  };
}

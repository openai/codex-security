import { join } from "node:path";
import { pathToFileURL } from "node:url";
import type { JsonObject } from "./config.js";
import { errorMessage } from "./errors.js";
import type { resolveDependencyServices } from "./dependency-service-catalog.js";

type CatalogResolver = (
  requests: Parameters<typeof resolveDependencyServices>[0]["requests"],
) => ReturnType<typeof resolveDependencyServices>;

export const dependencyGraphNamespace = "codex_security_dependency";

export interface DependencyGraphTools {
  tools: { name: string; description: string; inputSchema: JsonObject }[];
  call(name: string, args: unknown): Promise<JsonObject>;
  close(): Promise<void>;
}

export async function openDependencyGraph(
  plugin: string,
  repository: string,
  resolveCatalog?: CatalogResolver,
  signal?: AbortSignal,
): Promise<DependencyGraphTools> {
  const { createDependencyGraphSession } = (
    await import(pathToFileURL(join(plugin, "mcp/helpers.mjs")).href)
  ).default;
  const graph = (await createDependencyGraphSession(
    repository,
    resolveCatalog !== undefined,
  )) as DependencyGraphTools & {
    call(
      name: string,
      args: unknown,
      signal?: AbortSignal,
    ): Promise<JsonObject>;
    pendingCatalogRequests(args: unknown): Parameters<CatalogResolver>[0];
    recordCatalogResolutions(
      answers: Awaited<ReturnType<CatalogResolver>>,
      requests?: Parameters<CatalogResolver>[0],
    ): JsonObject;
  };
  const lookups = new Map<string, Promise<void>>();
  const lookupKey = ({
    path,
    project,
  }: Parameters<CatalogResolver>[0][number]) => JSON.stringify([path, project]);
  return {
    tools: graph.tools,
    close: () => graph.close(),
    async call(name, args) {
      const result = await graph.call(name, args, signal);
      if (!resolveCatalog || name !== "resolve_codex_security_services")
        return result;
      const requests = graph.pendingCatalogRequests(args);
      if (!requests.length) return result;
      const batch = requests.filter(
        (request) => !lookups.has(lookupKey(request)),
      );
      if (batch.length) {
        const lookup = (async () => {
          const answers = await resolveCatalog(batch);
          signal?.throwIfAborted();
          graph.recordCatalogResolutions(answers, batch);
        })().finally(() => {
          for (const request of batch) lookups.delete(lookupKey(request));
        });
        for (const request of batch) lookups.set(lookupKey(request), lookup);
      }
      let catalogError: string | undefined;
      try {
        await Promise.all(
          new Set(requests.map((request) => lookups.get(lookupKey(request)))),
        );
      } catch (error) {
        signal?.throwIfAborted();
        catalogError = errorMessage(error);
      }
      const summary = await graph.call(
        "query_codex_security_graph",
        {},
        signal,
      );
      return catalogError === undefined
        ? summary
        : { ...summary, catalog_error: catalogError };
    },
  };
}

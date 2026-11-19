import { basename, dirname } from "node:path";
import { z } from "zod";
import type { JsonObject } from "./config.js";
import {
  evidenceKey,
  readSavedEvidence,
  saveEvidence,
} from "./dependency-evidence-store.js";
import {
  dependencyBoundarySchema as configurationSchema,
  dependencyEndpointInputSchema,
  type DependencyEndpointConfiguration,
  type DependencyRuntimeScope,
  type DependencyRuntimeSelector,
} from "./dependency-caller-scope.js";
import {
  sourceWorkQuerySchema,
  sourceWorkTool,
  type createDependencySourceWorkTools,
} from "./dependency-source-work-tools.js";
import { isRecord } from "./record.js";
import { compareTimestamps } from "./timestamps.js";

const text = z.string().min(1);
const timestamp = z.string().regex(z.regexes.datetime({ offset: true }));
const dependencyRuntimeScopeSchema = z
  .object({
    cluster: text,
    service: text,
    window: z
      .strictObject({ start: timestamp, end: timestamp })
      .refine(
        ({ start, end }) => compareTimestamps(start, end) < 0,
        "Runtime scope start must precede end.",
      ),
    container: text.optional(),
    image_name: text.optional(),
    image_tag: text.optional(),
  })
  .catchall(z.json());
const endpointId = text;
const roleSchema = z.enum(["source", "sink", "intermediate"]);
const originSchema = z.enum(["supplied", "advisory", "discovered"]);
const discoverySchema = dependencyEndpointInputSchema.extend({
  role: roleSchema,
});
const endpointSchema = discoverySchema.extend({
  id: endpointId,
  origin: originSchema,
});
const recordedEndpointSchema = z.union([
  discoverySchema.extend({ origin: z.literal("discovered").optional() }),
  discoverySchema.extend({
    origin: z.literal("advisory"),
    role: z.literal("sink"),
    evidence: z.array(text).min(1),
  }),
]);
const recordInput = z.strictObject({ endpoint: recordedEndpointSchema });

export type DependencyEndpoint = z.infer<typeof endpointSchema>;
type BoundaryRole = "source" | "sink";

export const dependencyEndpointQuerySchema = z.strictObject({
  id: endpointId.optional(),
  role: roleSchema.optional(),
  origin: originSchema.optional(),
  scope: text.optional(),
  page: z
    .strictObject({
      limit: z.number().int().positive(),
      cursor: z
        .strictObject({ revision: text, offset: z.number().int().positive() })
        .optional(),
    })
    .optional(),
});

export const dependencyEndpointTool = {
  name: "record_codex_security_endpoint",
  description:
    "Record a discovered endpoint or intermediate in the shared investigation graph. " +
    "For a proposed sink identified from an advisory or pinned affected code, set origin to advisory and cite evidence references. Advisory origin records provenance only. " +
    "A reaches relationship links an entry point to a separate vulnerable function. " +
    "A maps_to relationship, with evidence references and exact runtime selectors, " +
    "links a runtime identity to a supplied endpoint when its selectors are absent. " +
    "Advisory and discovered records never add members to a supplied source or sink boundary.",
  inputSchema: z.toJSONSchema(recordInput) as JsonObject,
};

function endpointRecord(
  { id, ...input }: z.infer<typeof discoverySchema>,
  origin: DependencyEndpoint["origin"],
): DependencyEndpoint {
  const identity = origin === "advisory" ? { ...input, origin } : input;
  return { ...input, id: id ?? `endpoint-${evidenceKey(identity)}`, origin };
}

function suppliedEndpoints(config: z.output<typeof configurationSchema>) {
  const endpoints = [
    ...(config.sources ?? []).map((endpoint) =>
      endpointRecord({ ...endpoint, role: "source" }, "supplied"),
    ),
    ...(config.sinks ?? []).map((endpoint) =>
      endpointRecord({ ...endpoint, role: "sink" }, "supplied"),
    ),
  ];
  const ids = new Set<string>();
  for (const endpoint of endpoints) {
    if (ids.has(endpoint.id))
      throw new Error(`Duplicate supplied endpoint ID: ${endpoint.id}.`);
    ids.add(endpoint.id);
  }
  return endpoints;
}

/** Validate cross-field constraints that the generated JSON Schema cannot express. */
export function validateDependencyEndpointConfiguration(
  input?: DependencyEndpointConfiguration,
) {
  suppliedEndpoints(configurationSchema.parse(input ?? {}));
}

const snapshotSchema = z.strictObject({
  configuration: configurationSchema,
  runtimeScope: dependencyRuntimeScopeSchema.optional(),
  boundary: z.strictObject({
    source: z.enum(["discover", "supplied"]),
    sink: z.enum(["discover", "supplied"]),
  }),
  endpoints: z.array(endpointSchema),
});

export type DependencyEndpointGraph = Awaited<
  ReturnType<typeof openDependencyEndpoints>
>;

export async function openDependencyEndpoints(
  options: {
    configuration?: DependencyEndpointConfiguration | undefined;
    runtimeScope?: DependencyRuntimeScope;
    snapshotPath?: string;
  } = {},
) {
  const configuration = configurationSchema.parse(options.configuration ?? {});
  const records = new Map(
    suppliedEndpoints(configuration).map((endpoint) => [endpoint.id, endpoint]),
  );
  const snapshotPath = options.snapshotPath;
  const boundary = Object.freeze({
    source: configuration.sources === undefined ? "discover" : "supplied",
    sink: configuration.sinks === undefined ? "discover" : "supplied",
  });
  const instructions = configuration.scope?.instructions;
  const runtimeScope = dependencyRuntimeScopeSchema
    .optional()
    .parse(options.runtimeScope);
  const runtimeMappings = new Map<string, DependencyRuntimeSelector[]>();
  const retainDiscovery = (record: DependencyEndpoint) => {
    records.set(record.id, record);
    for (const { kind, endpoint_id } of record.relationships ?? []) {
      if (kind !== "maps_to") continue;
      const selectors = runtimeMappings.get(endpoint_id) ?? [];
      for (const selector of record.runtime_selectors!)
        selectors.push(selector);
      runtimeMappings.set(endpoint_id, selectors);
    }
  };
  const selectorsFor = (record: DependencyEndpoint) =>
    record.runtime_selectors?.length
      ? record.runtime_selectors
      : (runtimeMappings.get(record.id) ?? []);
  const missingSelector =
    "No exact runtime selector or supported mapping is recorded.";

  const equivalent = (left: unknown, right: unknown) =>
    evidenceKey(left) === evidenceKey(right);

  const prepareRecordedEndpoint = ({
    origin = "discovered",
    ...input
  }: z.infer<typeof recordedEndpointSchema>) => {
    const record = endpointRecord(input, origin);
    const existing = records.get(record.id);
    if (existing && !equivalent(existing, record))
      throw new Error(`Endpoint ID is already in use: ${record.id}.`);
    for (const relationship of record.relationships ?? []) {
      if (relationship.kind !== "maps_to") continue;
      const target = records.get(relationship.endpoint_id);
      if (
        target?.origin !== "supplied" ||
        record.role !== target.role ||
        !record.runtime_selectors?.length ||
        !record.evidence?.length
      )
        throw new Error(
          "A runtime mapping requires a supplied endpoint of the same role, selectors and evidence references.",
        );
    }
    return { record, existing };
  };

  const persist = async (saved: Iterable<DependencyEndpoint>) => {
    if (!snapshotPath) return;
    await saveEvidence(
      dirname(snapshotPath),
      basename(snapshotPath),
      JSON.stringify(
        { configuration, runtimeScope, boundary, endpoints: [...saved] },
        null,
        2,
      ) + "\n",
    );
  };

  if (snapshotPath) {
    const saved = await readSavedEvidence(snapshotPath);
    if (saved !== undefined) {
      const snapshot = snapshotSchema.parse(JSON.parse(saved));
      if (
        !equivalent(snapshot.configuration, configuration) ||
        !equivalent(snapshot.runtimeScope ?? null, runtimeScope ?? null)
      )
        throw new Error(
          "Saved endpoint graph belongs to a different endpoint configuration.",
        );
      for (const { origin, ...endpoint } of snapshot.endpoints) {
        if (origin === "supplied") continue;
        const { record, existing } = prepareRecordedEndpoint(
          recordedEndpointSchema.parse({ ...endpoint, origin }),
        );
        if (!existing) retainDiscovery(record);
      }
    } else {
      await persist(records.values());
    }
  }

  const isBoundaryEndpoint = (id: string, role: BoundaryRole) => {
    const endpoint = records.get(id);
    return (
      endpoint?.role === role &&
      (boundary[role] === "discover" || endpoint.origin === "supplied")
    );
  };
  const get = (id: string) => structuredClone(records.get(id));
  const coverage = () => ({
    boundary,
    ...(instructions !== undefined && { scope_instructions: instructions }),
    ...(runtimeScope && { runtime_scope: structuredClone(runtimeScope) }),
  });
  let pending = Promise.resolve();

  return {
    boundary,
    get runtimeScope() {
      return structuredClone(runtimeScope);
    },
    get,
    isBoundaryEndpoint,
    flush: () => pending,
    resolveRuntimeSelectors(ids: readonly string[], role?: BoundaryRole) {
      const gaps: { endpoint_id: string; reason: string }[] = [];
      const selectors = new Map<string, DependencyRuntimeSelector>();
      for (const id of new Set(ids)) {
        const endpoint = records.get(id);
        let reason: string | undefined;
        if (!endpoint) {
          reason = "Unknown endpoint ID.";
        } else if (role && !isBoundaryEndpoint(id, role)) {
          reason = `Endpoint is outside the ${role} boundary.`;
        } else {
          const matches = selectorsFor(endpoint);
          if (!matches.length) reason = missingSelector;
          for (const selector of matches)
            selectors.set(evidenceKey(selector), selector);
        }
        if (reason) gaps.push({ endpoint_id: id, reason });
      }
      return { selectors: structuredClone([...selectors.values()]), gaps };
    },

    record(args: unknown): Promise<JsonObject> {
      const { endpoint } = recordInput.parse(args);
      const write = pending.then(async () => {
        const { record, existing } = prepareRecordedEndpoint(endpoint);
        if (!existing) {
          await persist([...records.values(), record]);
          retainDiscovery(record);
        }
        return { ...coverage(), endpoint: structuredClone(record) };
      });
      pending = write.then(
        () => undefined,
        () => undefined,
      );
      return write;
    },

    query(args: unknown): JsonObject {
      const { id, role, origin, scope, page } =
        dependencyEndpointQuerySchema.parse(args);
      const matches = (record: DependencyEndpoint) =>
        (role === undefined || role === record.role) &&
        (origin === undefined || origin === record.origin) &&
        (scope === undefined || scope === record.scope);
      if (id !== undefined) {
        const record = get(id);
        return {
          ...coverage(),
          endpoint: record && matches(record) ? record : null,
          ...(record &&
            matches(record) &&
            !selectorsFor(record).length && {
              runtime_selector_gap: missingSelector,
            }),
        };
      }
      const selection = [...records.values()].filter(matches);
      const revision = evidenceKey([
        role,
        origin,
        scope,
        selection.map((record) => record.id),
      ]);
      const offset = page?.cursor?.offset ?? 0;
      if (
        page?.cursor &&
        (page.cursor.revision !== revision || offset >= selection.length)
      )
        throw new Error(
          "Endpoint selection changed since this cursor. Start a current page.",
        );
      const next = Math.min(offset + (page?.limit ?? 25), selection.length);
      return {
        ...coverage(),
        page: {
          total: selection.length,
          items: selection.slice(offset, next).map((record) => ({
            id: record.id,
            role: record.role,
            origin: record.origin,
            function: record.function,
            ...(record.scope !== undefined && { scope: record.scope }),
            runtime_selector_count: selectorsFor(record).length,
          })),
          nextCursor:
            next < selection.length ? { revision, offset: next } : null,
        },
      };
    },
  };
}

type InvestigatorTool = {
  name: string;
  description: string;
  inputSchema: object;
  run: (input: unknown) => unknown;
};

const graphSelection = z.union([
  z.strictObject({ endpoints: dependencyEndpointQuerySchema }),
  z.strictObject({ sourceWork: sourceWorkQuerySchema }),
]);

/** Share graph queries across investigator and reviewer sessions without granting reviewers mutation tools. */
export function withInvestigationGraphTools(
  tools: InvestigatorTool[],
  endpoints: DependencyEndpointGraph,
  sourceWork: ReturnType<typeof createDependencySourceWorkTools>,
  readOnly = false,
): InvestigatorTool[] {
  const query = {
    name: "query_codex_security_graph",
    description:
      "Query endpoints with endpoints:{}. Use sourceWork:{} for source census counts, or sourceWork:{rosterId} or {partitionId} with page:{view,limit,cursor} for exact paths, gaps and handoffs.",
    inputSchema: { ...z.toJSONSchema(graphSelection), type: "object" },
    run(input: unknown) {
      const selection = graphSelection.parse(input);
      return "sourceWork" in selection
        ? { source_work: sourceWork.query(selection.sourceWork) }
        : { endpoints: endpoints.query(selection.endpoints) };
    },
  };
  const result = tools.map((tool) => {
    if (tool.name !== query.name) return tool;
    return {
      ...tool,
      description: tool.description + " " + query.description,
      inputSchema: {
        type: "object",
        anyOf: [tool.inputSchema, query.inputSchema],
      },
      run(input: unknown) {
        if (
          isRecord(input) &&
          (Object.hasOwn(input, "endpoints") ||
            Object.hasOwn(input, "sourceWork"))
        )
          return query.run(input);
        return tool.run(input);
      },
    };
  });
  if (!result.some((tool) => tool.name === query.name)) result.push(query);
  if (!readOnly)
    result.push(
      { ...dependencyEndpointTool, run: (input) => endpoints.record(input) },
      {
        ...sourceWorkTool,
        run: (input) => ({ source_work: sourceWork.mutate(input) }),
      },
    );
  return result;
}

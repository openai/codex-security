import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { JsonObject } from "./config.js";
import {
  dependencyRuntimeSelectorSchema,
  type DependencyEndpointGraph,
  type DependencyRuntimeScope,
  type DependencyRuntimeSelector,
} from "./dependency-endpoints.js";
import { canonicalJson, isRecord } from "./record.js";
import {
  evidenceDigest,
  evidenceHash,
  evidenceKey,
  readSavedEvidence,
  saveEvidence,
} from "./dependency-evidence-store.js";

const windowSchema = z
  .strictObject({
    start: z.iso.datetime({ offset: true }),
    end: z.iso.datetime({ offset: true }),
  })
  .refine(
    ({ start, end }) => Date.parse(start) < Date.parse(end),
    "Start must precede end.",
  );
const selectorSchema = z.strictObject({
  cluster: z.string().min(1),
  service: z.string().min(1),
  frames: z.array(z.string().min(1)).min(1),
  container: z.string().min(1).optional(),
  image_name: z.string().min(1).optional(),
  image_tag: z.string().min(1).optional(),
});
const pairRuleSchema = z.strictObject({
  sources: z.array(dependencyRuntimeSelectorSchema).min(1),
  sinks: z.array(dependencyRuntimeSelectorSchema).min(1),
});
const childSchema = z.strictObject({
  resource_uri: z.string().min(1),
  resource_sha256: z.string().regex(evidenceDigest),
  stack_id: z.string().min(1),
});
const frameQuerySchema = z
  .strictObject({
    kind: z.enum(["sink", "pair", "discovery", "async_parent"]).default("sink"),
    sources: z.array(dependencyRuntimeSelectorSchema).default([]),
    sinks: z.array(dependencyRuntimeSelectorSchema).default([]),
    rules: z.array(pairRuleSchema).default([]),
    child: childSchema.optional(),
    evidence: z.array(z.string().min(1)).default([]),
    taint_dependencies: z.array(z.string().min(1)).default([]),
  })
  .superRefine((query, context) => {
    const fail = (message: string) =>
      context.addIssue({ code: "custom", message });
    if (query.kind === "pair") {
      if (
        query.rules.length
          ? query.sources.length || query.sinks.length
          : !query.sources.length || !query.sinks.length
      )
        fail(
          "Use sources and sinks, or independent rules, for an ordered pair.",
        );
    } else if (
      query.rules.length ||
      query.sources.length ||
      !query.sinks.length
    ) {
      fail(
        "Sink, discovery and async_parent require sinks and no sources/rules.",
      );
    }
    if (query.kind === "async_parent") {
      if (
        !query.child ||
        !query.evidence.length ||
        !query.taint_dependencies.length ||
        query.sinks.some(
          ({ location, line }) => location === undefined || line === undefined,
        )
      )
        fail(
          "Async parent needs a child resource, creator file/line, code evidence and data dependencies.",
        );
    } else if (query.child)
      fail("Child context belongs only to an async parent query.");
  });
const querySchema = z.strictObject({
  selector: selectorSchema,
  window: windowSchema,
  limit: z.number().int().positive(),
  query: frameQuerySchema.optional(),
  cursor: z.string().min(1).optional(),
  measure: z.boolean().optional(),
});
const endpointRuleSchema = z.strictObject({
  sources: z.array(z.string().min(1)).min(1),
  sinks: z.array(z.string().min(1)).min(1),
});
const endpointSelectionSchema = z.strictObject({
  kind: z.enum(["sink", "pair", "discovery", "async_parent"]).optional(),
  sources: z.array(z.string().min(1)).default([]),
  sinks: z.array(z.string().min(1)).default([]),
  rules: z.array(endpointRuleSchema).default([]),
  child: childSchema.optional(),
  evidence: z.array(z.string().min(1)).default([]),
  taint_dependencies: z.array(z.string().min(1)).default([]),
});
const inputSchema = z
  .strictObject({
    selector: selectorSchema.partial().optional(),
    window: windowSchema.optional(),
    limit: z.number().int().positive(),
    query: frameQuerySchema.optional(),
    endpoints: endpointSelectionSchema.optional(),
    measure: z.boolean().optional(),
  })
  .refine(
    ({ endpoints, query }) => !endpoints || !query,
    "Select endpoint IDs or explicit frame selectors, not both.",
  );
const witnessRange = z.strictObject({
  collectionId: z.string().regex(evidenceDigest),
  firstRow: z.number().int().positive(),
  lastRow: z.number().int().positive(),
});
const witnessQuerySchema = witnessRange.extend({
  searchId: z.string().regex(evidenceDigest).optional(),
});
const assessmentSchema = z.strictObject({
  findings: z.array(
    z.strictObject({
      id: z.string().min(1),
      assessed: z.array(witnessRange),
    }),
  ),
});
const descriptorSchema = z.object({
  graph_evidence: z.object({
    format: z.literal("codex-security-graph-evidence/v1"),
    uri: z.string().min(1),
    sha256: z.string().regex(evidenceDigest),
  }),
});
const reportTime = z.iso.datetime({ offset: true });
const imageSchema = z.looseObject({
  name: z.string().nullable().optional(),
  tag: z.string().nullable().optional(),
});
const collectionSchema = z.looseObject({
  format: z.literal("codex-security-graph-evidence/v1"),
  frame_order: z.literal("root_first"),
  metadata: z.looseObject({
    scope: z.looseObject({
      ...selectorSchema.shape,
      container: z.string().nullish(),
      image_name: z.string().nullish(),
      image_tag: z.string().nullish(),
      start: reportTime,
      end: reportTime,
      frame_match: z.enum(["any_exact_name", "ordered_exact_selectors"]),
      query: frameQuerySchema.optional(),
    }),
    coverage: z.looseObject({
      result_complete: z.boolean(),
      returned_stack_count: z.number().int().nonnegative(),
      backend_partial: z.boolean().nullish(),
      identity_mismatch_count: z.number().int().nonnegative().optional(),
    }),
    limits: z.looseObject({
      stack_limit: z.number().int().positive(),
      truncated: z.boolean(),
    }),
    warnings: z.array(z.unknown()).optional(),
    pagination: z
      .strictObject({
        order: z.literal("stack_key_ascending"),
        cursor: z.string().nullable(),
        next_cursor: z.string().nullable(),
        snapshot_pinned: z.boolean(),
        query_exhausted: z.boolean(),
      })
      .optional(),
  }),
  observations: z.array(
    z.looseObject({
      id: z.string().min(1),
      kind: z.literal("sampled_stack"),
      scope: z.looseObject({
        cluster: z.string(),
        service: z.string(),
        container: z.string().nullable().optional(),
        observed_image: imageSchema,
        window: z.object({ start: reportTime, end: reportTime }),
      }),
      frames: z
        .array(
          z.looseObject({
            kind: z.string().min(1),
            name: z.string(),
            scope: z.string().optional(),
          }),
        )
        .min(1),
    }),
  ),
});

export type DependencyProfileQuery = z.infer<typeof querySchema>;
type FrameQuery = z.infer<typeof frameQuerySchema>;
export class DependencyProfileLookupError extends Error {
  constructor(
    message: string,
    readonly receiptId: string | undefined,
  ) {
    super(message);
  }
}
type Selector = DependencyProfileQuery["selector"];
type Window = DependencyProfileQuery["window"];
type Collection = z.infer<typeof collectionSchema>;
type CollectionRecord = {
  receiptId: string;
  collection: Collection;
  resourceUri?: string;
};
type ReturnedRange = {
  collectionId: string;
  firstRow: number;
  lastRow: number;
};
type Outcome = "found_stacks" | "no_samples" | "incomplete" | "failed";

interface ProfileOptions {
  directory: string;
  /** Host-owned identity of the provider, query contract, and authorization scope. */
  providerKey: string;
  authorize(query: DependencyProfileQuery): void;
  lookup(query: DependencyProfileQuery): Promise<unknown>;
  readResource(uri: string): Promise<string>;
  recordCollection(record: {
    query: DependencyProfileQuery;
    collectionId: string;
    resource: string;
    summary?: unknown;
  }): string;
  signal?: AbortSignal;
  endpointGraph?: () =>
    | Pick<
        DependencyEndpointGraph,
        | "runtimeScope"
        | "resolveRuntimeSelectors"
        | "isBoundaryEndpoint"
        | "boundary"
      >
    | undefined;
}

function normalizeSelector<T extends Selector>(selector: T) {
  return { ...selector, frames: [...new Set(selector.frames)].sort() };
}

function sortedSelectors(selectors: DependencyRuntimeSelector[]) {
  const distinct = new Map(
    selectors.map((value) => [canonicalJson(value)!, value]),
  );
  return [...distinct]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([, value]) => value);
}

function normalizeFrameQuery(query: FrameQuery): FrameQuery {
  return {
    ...query,
    sources: sortedSelectors(query.sources),
    sinks: sortedSelectors(query.sinks),
    rules: query.rules.map((rule) => ({
      sources: sortedSelectors(rule.sources),
      sinks: sortedSelectors(rule.sinks),
    })),
  };
}
function rulesOf(query: FrameQuery) {
  return query.rules.length
    ? query.rules
    : [{ sources: query.sources, sinks: query.sinks }];
}
function namesOf(query: FrameQuery) {
  return [
    ...new Set(
      rulesOf(query).flatMap(({ sinks }) =>
        sinks.map(({ name, observed_name }) => observed_name ?? name),
      ),
    ),
  ].sort();
}
function selectionOf(query: FrameQuery | undefined) {
  return query
    ? rulesOf(query).map(({ sources, sinks }) => ({ sources, sinks }))
    : null;
}
function inferenceOf(query: FrameQuery | undefined) {
  return query?.kind === "async_parent"
    ? {
        child: query.child,
        evidence: query.evidence,
        taint_dependencies: query.taint_dependencies,
      }
    : null;
}
function cacheKey(query: DependencyProfileQuery) {
  const key = query.query
    ? [query.selector, selectionOf(query.query), inferenceOf(query.query)]
    : [query.selector, query.limit];
  return evidenceKey(query.measure ? [...key, "workload_measurement"] : key);
}
const cacheChainSchema = z.strictObject({
  format: z.literal("profile-collection-chain/v1"),
  window: windowSchema,
  pages: z
    .array(
      z.strictObject({
        collectionId: z.string().regex(evidenceDigest),
        query: querySchema,
        uri: z.string().min(1).optional(),
      }),
    )
    .min(1),
});
function inRuntimeScope(
  query: DependencyProfileQuery,
  scope: DependencyRuntimeScope | undefined,
) {
  if (!scope) return;
  for (const field of [
    "cluster",
    "service",
    "container",
    "image_name",
    "image_tag",
  ] as const) {
    if (scope[field] !== undefined && query.selector[field] !== scope[field])
      throw new Error(
        `Profile request widens or changes configured runtime ${field}.`,
      );
  }
  if (
    Date.parse(query.window.start) < Date.parse(scope.window.start) ||
    Date.parse(query.window.end) > Date.parse(scope.window.end)
  )
    throw new Error(
      "Profile request is outside the configured runtime window.",
    );
}

function frameMatches(
  frame: Collection["observations"][number]["frames"][number],
  selector: DependencyRuntimeSelector,
) {
  if (frame.name !== (selector.observed_name ?? selector.name)) return false;
  const attributes = isRecord(frame["attributes"]) ? frame["attributes"] : {};
  const suffix = (actual: unknown, expected: string | undefined) =>
    expected === undefined ||
    (typeof actual === "string" &&
      (actual === expected ||
        actual.endsWith(`/${expected.replace(/^\/+/, "")}`)));
  const location = attributes["location"];
  return (
    (selector.frame_type === undefined ||
      attributes["language"] === selector.frame_type) &&
    suffix(
      typeof location === "string"
        ? location.replace(/:[0-9]+$/u, "")
        : location,
      selector.location,
    ) &&
    suffix(attributes["binary"], selector.binary) &&
    (selector.line === undefined ||
      (typeof location === "string" &&
        location.endsWith(`:${selector.line}`))) &&
    (selector.build_id === undefined ||
      attributes["build_id"] === selector.build_id) &&
    (selector.build_hash === undefined ||
      attributes["build_hash"] === selector.build_hash)
  );
}
function matchesQuery(
  frames: Collection["observations"][number]["frames"],
  query: FrameQuery,
) {
  return rulesOf(query).some(({ sources, sinks }) => {
    const sinkIndex = frames.findLastIndex((frame) =>
      sinks.some((selector) => frameMatches(frame, selector)),
    );
    if (sinkIndex < 0) return false;
    if (!sources.length) return true;
    const sourceIndex = frames.findIndex((frame) =>
      sources.some((selector) => frameMatches(frame, selector)),
    );
    return sourceIndex >= 0 && sourceIndex < sinkIndex;
  });
}

function sameInstant(left: string, right: string) {
  // The provider may pad a millisecond timestamp to nanoseconds. Reject a
  // genuinely different fractional instant before doing Date arithmetic.
  const fraction = /\.(\d+)/u.exec(left)?.[1];
  return (
    !fraction?.slice(3).match(/[1-9]/u) &&
    Date.parse(left) === Date.parse(right)
  );
}

function verifyScope(collection: Collection, query: DependencyProfileQuery) {
  const { selector, window } = query;
  const scope = collection.metadata.scope;
  const sameWindow = (value: Window) =>
    sameInstant(value.start, window.start) &&
    sameInstant(value.end, window.end);
  const scopeSelector = normalizeSelector({
    cluster: scope.cluster,
    service: scope.service,
    frames: scope.frames,
    ...(scope.container == null ? {} : { container: scope.container }),
    ...(scope.image_name == null ? {} : { image_name: scope.image_name }),
    ...(scope.image_tag == null ? {} : { image_tag: scope.image_tag }),
  });
  if (
    evidenceKey(scopeSelector) !== evidenceKey(selector) ||
    !sameWindow(scope) ||
    scope.frame_match !==
      (query.query ? "ordered_exact_selectors" : "any_exact_name") ||
    evidenceKey(
      selectionOf(scope.query && normalizeFrameQuery(scope.query)),
    ) !== evidenceKey(selectionOf(query.query)) ||
    (query.query?.kind === "async_parent" &&
      (scope.query?.kind !== "async_parent" ||
        evidenceKey(inferenceOf(scope.query)) !==
          evidenceKey(inferenceOf(query.query))))
  )
    throw new Error(
      "Profile collection does not match the requested selector and window.",
    );
  if (
    collection.metadata.coverage.returned_stack_count !==
      collection.observations.length ||
    collection.observations.length > query.limit ||
    collection.metadata.limits.stack_limit !== query.limit
  )
    throw new Error(
      "Profile coverage does not match the returned stack count.",
    );
  const { coverage, limits } = collection.metadata;
  const mismatch = coverage.identity_mismatch_count ?? 0;
  if (
    coverage.result_complete !==
    (coverage.backend_partial === false &&
      !limits.truncated &&
      !query.cursor &&
      mismatch === 0)
  )
    throw new Error("Profile collection reports inconsistent completeness.");
  if (query.query) {
    const pagination = collection.metadata.pagination;
    if (
      !pagination ||
      pagination.cursor !== (query.cursor ?? null) ||
      pagination.query_exhausted !==
        (coverage.backend_partial === false &&
          !limits.truncated &&
          mismatch === 0)
    )
      throw new Error(
        "Profile continuation does not match the requested page or completeness.",
      );
  }
  if (
    query.query?.kind === "async_parent" &&
    (collection.metadata["join_basis"] !==
      "inferred_from_creator_code_and_observed_build" ||
      collection.metadata["instance_correlation_verified"] !== false)
  )
    throw new Error(
      "Async profile evidence must preserve its inferred join basis.",
    );
  for (const { scope, frames } of collection.observations) {
    if (query.query?.kind === "async_parent") {
      const context = scope["async_context"];
      if (
        !isRecord(context) ||
        context["join_basis"] !==
          "inferred_from_creator_code_and_observed_build" ||
        context["instance_correlation_verified"] !== false ||
        evidenceKey(context["child"]) !== evidenceKey(query.query.child) ||
        evidenceKey(context["creator_code_evidence"]) !==
          evidenceKey(query.query.evidence) ||
        evidenceKey(context["taint_dependencies"]) !==
          evidenceKey(query.query.taint_dependencies)
      )
        throw new Error(
          "Async profile witness lost its exact child or inference caveat.",
        );
    }
    if (
      scope.cluster !== selector.cluster ||
      scope.service !== selector.service ||
      !sameWindow(scope.window) ||
      (selector.container !== undefined &&
        scope.container !== selector.container) ||
      (selector.image_name !== undefined &&
        scope.observed_image.name !== selector.image_name) ||
      (selector.image_tag !== undefined &&
        scope.observed_image.tag !== selector.image_tag) ||
      !frames.some(({ name }) => selector.frames.includes(name)) ||
      (query.query !== undefined && !matchesQuery(frames, query.query))
    )
      throw new Error(
        "Profile witness does not belong to the requested selector and window.",
      );
  }
}

function gaps(window: Window, covered: Window[]) {
  const missing: Window[] = [];
  let cursor = window.start;
  for (const slice of covered.toSorted((a, b) =>
    a.start.localeCompare(b.start),
  )) {
    if (slice.start > cursor) missing.push({ start: cursor, end: slice.start });
    if (slice.end > cursor) cursor = slice.end;
  }
  if (cursor < window.end) missing.push({ start: cursor, end: window.end });
  return missing;
}

function buildOf(witness: Collection["observations"][number]) {
  const { cluster, service, container, observed_image } = witness.scope;
  return {
    cluster,
    service,
    container: container ?? null,
    image: observed_image,
  };
}

export function createDependencyProfileEvidence(options: ProfileOptions) {
  const active = new Map<string, CollectionRecord>();
  const pending = new Map<string, Promise<unknown>>();
  const inFlight = new Map<string, ReturnType<typeof collect>>();
  // Exact successful structured receipts remain useful even when population
  // coverage is incomplete. Legacy incomplete reads remain retryable.
  const completed = new Map<string, Awaited<ReturnType<typeof collect>>>();
  const searches = new Map<
    string,
    {
      selector: Selector;
      window: Window;
      query?: FrameQuery;
      selectedRows: Map<string, number[]>;
      slices: {
        window: Window;
        outcome: Outcome;
        collectionId?: string;
        error?: string;
      }[];
    }
  >();
  const directory = join(options.directory, evidenceKey(options.providerKey));

  function resolveInput(input: unknown) {
    const value = inputSchema.parse(input);
    const graph = options.endpointGraph?.();
    const scope = graph?.runtimeScope;
    if (
      !value.endpoints &&
      graph &&
      (graph.boundary.source === "supplied" ||
        graph.boundary.sink === "supplied")
    )
      throw new Error(
        "Use registered endpoint IDs for a supplied source or sink boundary.",
      );
    const endpointGaps: {
      endpoint_id: string;
      reason: string;
      rule_index?: number;
    }[] = [];
    let frameQuery = value.query;
    if (value.endpoints) {
      if (!graph) throw new Error("No shared endpoint graph is available.");
      const selection = value.endpoints;
      const kind =
        selection.kind ??
        (selection.rules.length || selection.sources.length ? "pair" : "sink");
      if (
        selection.rules.length &&
        (selection.sources.length || selection.sinks.length)
      )
        throw new Error(
          "Use independent endpoint rules or flat source/sink IDs, not both.",
        );
      const resolve = (
        ids: string[],
        role: "source" | "sink" | undefined,
        rule_index?: number,
      ) => {
        const result = graph.resolveRuntimeSelectors(ids, role);
        endpointGaps.push(
          ...result.gaps.map((gap) => ({
            ...gap,
            ...(rule_index === undefined ? {} : { rule_index }),
          })),
        );
        return result.selectors;
      };
      const explicitResearch = kind === "discovery" || kind === "async_parent";
      const rules = selection.rules
        .map((rule, index) => ({
          sources: resolve(rule.sources, "source", index),
          sinks: resolve(rule.sinks, "sink", index),
        }))
        .filter((rule) => rule.sources.length && rule.sinks.length);
      const sources = selection.rules.length
        ? []
        : resolve(selection.sources, "source");
      const sinks = selection.rules.length
        ? []
        : resolve(selection.sinks, explicitResearch ? undefined : "sink");
      if (
        kind === "pair"
          ? selection.rules.length
            ? !rules.length
            : !sources.length || !sinks.length
          : !sinks.length
      )
        return {
          gaps: endpointGaps,
          endpoints: selection,
          unresolved: true as const,
        };
      frameQuery = frameQuerySchema.parse({
        kind,
        sources,
        sinks,
        rules,
        ...(selection.child ? { child: selection.child } : {}),
        evidence: selection.evidence,
        taint_dependencies: selection.taint_dependencies,
      });
    }
    if (frameQuery) frameQuery = normalizeFrameQuery(frameQuery);
    const { window: inheritedWindow, ...inheritedSelector } = scope ?? {
      window: undefined,
    };
    const selector = { ...inheritedSelector, ...value.selector };
    if (frameQuery) {
      const frames = namesOf(frameQuery);
      if (
        selector.frames &&
        evidenceKey([...new Set(selector.frames)].sort()) !==
          evidenceKey(frames)
      )
        throw new Error(
          "Profile frame names conflict with the selected endpoint query.",
        );
      selector.frames = frames;
    }
    const query = querySchema.parse({
      selector,
      window: value.window ?? inheritedWindow,
      limit: value.limit,
      ...(frameQuery ? { query: frameQuery } : {}),
      ...(value.measure === undefined ? {} : { measure: value.measure }),
    });
    if (query.query?.kind === "async_parent" && query.query.child) {
      const captured = active.get(query.query.child.resource_sha256);
      const child = captured?.collection.observations.find(
        ({ id }) => id === query.query!.child!.stack_id,
      );
      if (
        captured?.resourceUri &&
        captured.resourceUri !== query.query.child.resource_uri
      )
        throw new Error(
          "Async child URI does not match the captured original resource.",
        );
      if (child) {
        if (
          child.scope.cluster !== query.selector.cluster ||
          child.scope.service !== query.selector.service
        )
          throw new Error(
            "Async child belongs to a different runtime workload.",
          );
        for (const [field, label] of [
          ["image_name", "name"],
          ["image_tag", "tag"],
        ] as const) {
          const observed = child.scope.observed_image[label];
          if (
            !observed ||
            (query.selector[field] !== undefined &&
              query.selector[field] !== observed)
          )
            throw new Error(
              "Async parent image does not match its captured child observation.",
            );
          query.selector[field] = observed;
        }
      }
    }
    if (
      query.query?.kind === "async_parent" &&
      (!query.selector.image_name || !query.selector.image_tag)
    )
      throw new Error(
        "Async parent requires the observed child's image name and tag.",
      );
    for (const bound of [
      query.window.start,
      query.window.end,
      ...(scope ? [scope.window.start, scope.window.end] : []),
    ])
      if (!sameInstant(bound, bound))
        throw new Error(
          "Profile window timestamps must have millisecond precision or coarser.",
        );
    query.selector = normalizeSelector(query.selector);
    query.window = {
      start: new Date(query.window.start).toISOString(),
      end: new Date(query.window.end).toISOString(),
    };
    inRuntimeScope(query, scope);
    return {
      query,
      gaps: endpointGaps,
      ...(value.endpoints ? { endpoints: value.endpoints } : {}),
      unresolved: false as const,
    };
  }

  async function load(collectionId: string) {
    const resource = await readSavedEvidence(
      join(directory, `${collectionId}.json`),
    );
    if (resource === undefined) return;
    if (evidenceHash(resource) !== collectionId)
      throw new Error(`Saved profile collection changed: ${collectionId}`);
    return resource;
  }

  async function collect(query: DependencyProfileQuery) {
    const { selector, window } = query;
    const cachePath = join(directory, cacheKey(query));
    const covered: Window[] = [];
    const selectedRows = new Map<string, number[]>();
    const slices: {
      window: Window;
      outcome: Outcome;
      cached: boolean;
      collectionId?: string;
      stackCount?: number;
      populationStackCount?: number;
      receiptId?: string;
      error?: string;
      truncated?: boolean;
      backendPartial?: boolean | null;
      warnings?: unknown[];
      sourcePopulationReuse?: boolean;
      pageChainComplete?: boolean;
      providerStatus?: unknown;
      profileSampleCount?: unknown;
      populationProfileSampleCount?: unknown;
      populationMeasurement?: unknown;
      sourcePopulationStatus?: unknown;
      localPairStatus?: string;
      totalWorkloadProfileSampleCount?: unknown;
      measurement?: unknown;
      joinBasis?: unknown;
      instanceCorrelationVerified?: unknown;
    }[] = [];
    type Page = {
      collectionId: string;
      query: DependencyProfileQuery;
      uri?: string;
    };

    function parse(request: DependencyProfileQuery, resource: string) {
      const collection = collectionSchema.parse(JSON.parse(resource));
      verifyScope(collection, request);
      return collection;
    }

    function retain(
      request: DependencyProfileQuery,
      resource: string,
      collection: Collection,
      cached: boolean,
      sourcePopulationReuse = false,
      summary?: unknown,
    ) {
      const collectionId = evidenceHash(resource);
      let captured = active.get(collectionId);
      if (!captured) {
        const receiptId = options.recordCollection({
          query: request,
          collectionId,
          resource,
          summary,
        });
        const descriptor = descriptorSchema.safeParse(summary);
        captured = {
          receiptId,
          collection,
          ...(descriptor.success
            ? { resourceUri: descriptor.data.graph_evidence.uri }
            : {}),
        };
        active.set(collectionId, captured);
      }
      const rows = collection.observations.flatMap(({ frames }, index) =>
        !sourcePopulationReuse ||
        !query.query ||
        matchesQuery(frames, query.query)
          ? [index + 1]
          : [],
      );
      selectedRows.set(collectionId, rows);
      const sampleCounts = rows.map(
        (row) => collection.observations[row - 1]!.scope["profile_rows"],
      );
      const matchedSamples = sampleCounts.every(
        (count) =>
          typeof count === "number" &&
          Number.isSafeInteger(count) &&
          count >= 0,
      )
        ? sampleCounts.reduce<number>(
            (sum, count) => sum + (count as number),
            0,
          )
        : null;
      const slice = {
        window: request.window,
        collectionId,
        receiptId: captured.receiptId,
        stackCount: rows.length,
        cached,
        outcome: "incomplete" as Outcome,
        truncated: collection.metadata.limits.truncated,
        backendPartial: collection.metadata.coverage.backend_partial ?? null,
        warnings: collection.metadata.warnings,
        ...(!sourcePopulationReuse
          ? {
              providerStatus: collection.metadata["status"],
              measurement: collection.metadata["measurement"],
            }
          : {}),
        profileSampleCount: sourcePopulationReuse
          ? matchedSamples
          : collection.metadata.coverage["returned_profile_row_count"],
        totalWorkloadProfileSampleCount:
          collection.metadata.coverage["total_workload_profile_row_count"],
        joinBasis: collection.metadata["join_basis"],
        instanceCorrelationVerified:
          collection.metadata["instance_correlation_verified"],
        ...(sourcePopulationReuse
          ? {
              sourcePopulationReuse: true,
              populationStackCount: collection.observations.length,
              populationProfileSampleCount:
                collection.metadata.coverage["returned_profile_row_count"],
              populationMeasurement: collection.metadata["measurement"],
              sourcePopulationStatus: collection.metadata["status"],
              localPairStatus: rows.length
                ? "found_matching_pairs"
                : "no_matching_pair_in_complete_saved_population",
            }
          : {}),
      };
      slices.push(slice);
      return slice;
    }

    function checkPageProgress(
      collection: Collection,
      expectedCursor: string | undefined,
      seenIds: Set<string>,
      previousKey: string | undefined,
    ) {
      const pagination = collection.metadata.pagination;
      if (pagination && pagination.cursor !== (expectedCursor ?? null))
        throw new Error("Profile page chain skips its expected cursor.");
      let last = previousKey;
      for (const observation of collection.observations) {
        if (seenIds.has(observation.id))
          throw new Error("Profile page chain repeats a stack.");
        seenIds.add(observation.id);
        if (pagination) {
          const key = observation.scope["stack_key"];
          if (
            typeof key !== "string" ||
            !evidenceDigest.test(key) ||
            (last !== undefined && key <= last)
          )
            throw new Error(
              "Profile page chain repeats or reorders its content keys.",
            );
          last = key;
        }
      }
      if (pagination?.next_cursor && last === previousKey)
        throw new Error("Profile continuation made no progress.");
      return last;
    }

    async function restore(
      indexPath: string,
      expected: DependencyProfileQuery,
      sourcePopulationReuse: boolean,
    ) {
      const files = await readdir(indexPath).catch(
        (error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT") return [];
          throw error;
        },
      );
      const candidates: { window: Window; pages: Page[] }[] = [];
      for (const file of files) {
        const id = file.slice(0, -5);
        if (!file.endsWith(".json") || !evidenceDigest.test(id)) continue;
        const raw = await readSavedEvidence(join(indexPath, file));
        if (raw === undefined) continue;
        const value: unknown = JSON.parse(raw);
        if (
          isRecord(value) &&
          value["format"] === "profile-collection-chain/v1"
        ) {
          const chain = cacheChainSchema.parse(value);
          candidates.push(chain);
        } else {
          const slice = windowSchema.parse(value);
          candidates.push({
            window: slice,
            pages: [
              { collectionId: id, query: { ...expected, window: slice } },
            ],
          });
        }
      }
      candidates.sort(
        (a, b) =>
          a.window.start.localeCompare(b.window.start) ||
          b.window.end.localeCompare(a.window.end),
      );
      for (const candidate of candidates) {
        const slice = candidate.window;
        if (
          slice.start < window.start ||
          slice.end > window.end ||
          covered.some((old) => slice.start < old.end && slice.end > old.start)
        )
          continue;
        options.authorize({ ...query, window: slice });
        const restored: {
          page: Page;
          resource: string;
          collection: Collection;
        }[] = [];
        const seenIds = new Set<string>();
        let cursor: string | undefined;
        let lastKey: string | undefined;
        for (const page of candidate.pages) {
          if (
            cacheKey(page.query) !== cacheKey(expected) ||
            evidenceKey(page.query.window) !== evidenceKey(slice) ||
            page.query.cursor !== cursor
          )
            throw new Error(
              "Cached profile page chain does not match its requested selection.",
            );
          const resource = await load(page.collectionId);
          if (resource === undefined)
            throw new Error(
              `Cached profile page is missing: ${page.collectionId}`,
            );
          const collection = parse(page.query, resource);
          if (
            collection.metadata.coverage.backend_partial !== false ||
            (collection.metadata.coverage.identity_mismatch_count ?? 0) !== 0
          )
            throw new Error(
              `Cached profile collection is incomplete: ${page.collectionId}`,
            );
          lastKey = checkPageProgress(collection, cursor, seenIds, lastKey);
          restored.push({ page, resource, collection });
          cursor = collection.metadata.pagination?.next_cursor ?? undefined;
        }
        const final = restored.at(-1)?.collection;
        const complete =
          final &&
          (expected.query
            ? final.metadata.pagination?.query_exhausted === true &&
              cursor === undefined
            : final.metadata.coverage.result_complete);
        if (!complete)
          throw new Error("Cached profile page chain is incomplete.");
        for (const { page, resource, collection } of restored) {
          const retained = retain(
            page.query,
            resource,
            collection,
            true,
            sourcePopulationReuse,
            page.uri
              ? {
                  graph_evidence: {
                    format: "codex-security-graph-evidence/v1",
                    uri: page.uri,
                    sha256: page.collectionId,
                  },
                }
              : undefined,
          );
          retained.outcome = retained.stackCount
            ? "found_stacks"
            : "no_samples";
          Object.assign(retained, { pageChainComplete: true });
        }
        covered.push(slice);
      }
    }

    await restore(cachePath, query, false);
    // A complete source-free population can answer a new ordered pair locally.
    // A capped, partial or suffix-only population never enters this index.
    if (query.query?.kind === "pair") {
      const sinkQuery: DependencyProfileQuery = {
        ...query,
        query: frameQuerySchema.parse({
          kind: "sink",
          sinks: sortedSelectors(
            rulesOf(query.query).flatMap(({ sinks }) => sinks),
          ),
        }),
      };
      await restore(join(directory, cacheKey(sinkQuery)), sinkQuery, true);
    }

    for (const slice of gaps(window, covered)) {
      const firstSlice = slices.length;
      const pages: Page[] = [];
      const seenIds = new Set<string>();
      const cursors = new Set<string>();
      let cursor: string | undefined;
      let lastKey: string | undefined;
      let complete = false;
      let allPagesHealthy = true;
      try {
        for (;;) {
          options.signal?.throwIfAborted();
          const request = {
            ...query,
            window: slice,
            ...(cursor === undefined ? {} : { cursor }),
          };
          options.authorize(request);
          const summary = await options.lookup(request);
          const descriptor = descriptorSchema.parse(summary).graph_evidence;
          const resource = await options.readResource(descriptor.uri);
          options.signal?.throwIfAborted();
          if (evidenceHash(resource) !== descriptor.sha256)
            throw new Error(
              "Profile collection hash does not match its lookup.",
            );
          const collection = parse(request, resource);
          allPagesHealthy &&=
            collection.metadata.coverage.backend_partial === false &&
            (collection.metadata.coverage.identity_mismatch_count ?? 0) === 0;
          lastKey = checkPageProgress(collection, cursor, seenIds, lastKey);
          await saveEvidence(directory, `${descriptor.sha256}.json`, resource);
          retain(request, resource, collection, false, false, summary);
          pages.push({
            collectionId: descriptor.sha256,
            query: request,
            uri: descriptor.uri,
          });
          const pagination = collection.metadata.pagination;
          if (
            collection.metadata.coverage.backend_partial === true ||
            (collection.metadata.coverage.identity_mismatch_count ?? 0) !== 0
          )
            break;
          const next = pagination?.next_cursor;
          if (next) {
            if (cursors.has(next))
              throw new Error("Profile continuation repeats a cursor.");
            cursors.add(next);
            cursor = next;
            continue;
          }
          complete =
            allPagesHealthy &&
            (query.query
              ? pagination?.query_exhausted === true
              : collection.metadata.coverage.result_complete);
          break;
        }
        if (complete) {
          covered.push(slice);
          for (const retained of slices.slice(firstSlice)) {
            retained.outcome = retained.stackCount
              ? "found_stacks"
              : "no_samples";
            retained.pageChainComplete = true;
          }
          if (query.query) {
            const chain = {
              format: "profile-collection-chain/v1",
              window: slice,
              pages,
            };
            await saveEvidence(
              cachePath,
              `${evidenceKey(chain)}.json`,
              JSON.stringify(chain),
            );
          } else {
            await saveEvidence(
              cachePath,
              `${pages[0]!.collectionId}.json`,
              JSON.stringify(slice),
            );
          }
        }
      } catch (error) {
        options.signal?.throwIfAborted();
        slices.push({
          window: slice,
          outcome: "failed",
          cached: false,
          ...(error instanceof DependencyProfileLookupError && error.receiptId
            ? { receiptId: error.receiptId }
            : {}),
          error: String(error),
        });
      }
    }
    const searchId = evidenceKey([options.providerKey, query]);
    searches.set(searchId, {
      selector,
      window,
      ...(query.query ? { query: query.query } : {}),
      slices,
      selectedRows,
    });
    return {
      searchId,
      requestedWindow: window,
      slices: slices.toSorted((a, b) =>
        a.window.start.localeCompare(b.window.start),
      ),
      uncovered: gaps(window, covered),
    };
  }
  return {
    async collect(input: unknown) {
      options.signal?.throwIfAborted();
      const resolved = resolveInput(input);
      if (resolved.unresolved) {
        const unresolvedWindow =
          options.endpointGraph?.()?.runtimeScope?.window;
        return {
          status: "unresolved_endpoints",
          searchId: undefined,
          endpointGaps: resolved.gaps,
          endpoints: resolved.endpoints,
          slices: [],
          uncovered: unresolvedWindow ? [unresolvedWindow] : [],
        };
      }
      const { query } = resolved;
      options.authorize(query);
      // Serialize requests sharing a cache index, including overlapping backfills.
      const key = cacheKey(query);
      const exactKey = evidenceKey(query);
      const savedReceipt = query.query ? completed.get(exactKey) : undefined;
      if (savedReceipt)
        return {
          ...structuredClone(savedReceipt),
          slices: savedReceipt.slices.map((slice) => ({
            ...structuredClone(slice),
            cached: true,
            exactQueryReceiptReuse: true,
          })),
          exactQueryReceiptReuse: true,
          ...(resolved.endpoints
            ? { endpoints: resolved.endpoints, endpointGaps: resolved.gaps }
            : {}),
        };
      const existing = inFlight.get(exactKey);
      if (existing)
        return {
          ...(await existing),
          ...(resolved.endpoints
            ? { endpoints: resolved.endpoints, endpointGaps: resolved.gaps }
            : {}),
        };
      const previous = pending.get(key);
      const task = (previous?.catch(() => {}) ?? Promise.resolve()).then(() =>
        collect(query),
      );
      pending.set(key, task);
      inFlight.set(exactKey, task);
      try {
        const result = await task;
        if (
          query.query &&
          !result.slices.some(
            ({ outcome, measurement }) =>
              outcome === "failed" ||
              (isRecord(measurement) && measurement["status"] === "failed"),
          )
        )
          completed.set(exactKey, structuredClone(result));
        return {
          ...result,
          ...(resolved.endpoints
            ? { endpoints: resolved.endpoints, endpointGaps: resolved.gaps }
            : {}),
        };
      } finally {
        if (pending.get(key) === task) pending.delete(key);
        if (inFlight.get(exactKey) === task) inFlight.delete(exactKey);
      }
    },
    witnesses(input: unknown) {
      const { collectionId, firstRow, lastRow, searchId } =
        witnessQuerySchema.parse(input);
      const captured = active.get(collectionId);
      const rows = captured?.collection.observations;
      const selection = searchId
        ? searches.get(searchId)?.selectedRows.get(collectionId)
        : rows?.map((_, index) => index + 1);
      if (
        !rows ||
        !selection ||
        firstRow > lastRow ||
        lastRow > selection.length
      )
        throw new Error(
          "Requested rows are outside this investigation's profile collection.",
        );
      return selection.slice(firstRow - 1, lastRow).map((row, offset) => {
        const { id, scope, frames } = rows[row - 1]!;
        return {
          row,
          ...(searchId ? { searchId, matchOrdinal: firstRow + offset } : {}),
          id,
          ...(captured.resourceUri
            ? {
                childReference: {
                  resource_uri: captured.resourceUri,
                  resource_sha256: collectionId,
                  stack_id: id,
                },
              }
            : {}),
          scope,
          frames,
          receiptSelection: {
            receiptId: captured.receiptId,
            textBlock: 0,
            record: ["observations", row - 1],
          },
        };
      });
    },
    /** Compute deployment labels and unassessed rows from host-held witnesses. */
    assess(input: unknown) {
      const { findings: assessedFindings } = assessmentSchema.parse(input);
      const collections = new Map(
        [...active].map(([id, record]) => [id, record.collection]),
      );
      const seen = new Map<string, Set<number>>();
      const findings = assessedFindings.map(({ id, assessed: ranges }) => {
        const builds = new Map<string, ReturnType<typeof buildOf>>();
        for (const range of ranges) {
          const rows = collections.get(range.collectionId)?.observations;
          if (
            !rows ||
            range.firstRow > range.lastRow ||
            range.lastRow > rows.length
          )
            throw new Error(
              "Finding cites profile rows outside its collection.",
            );
          const assessed = seen.get(range.collectionId) ?? new Set<number>();
          seen.set(range.collectionId, assessed);
          for (let row = range.firstRow; row <= range.lastRow; row++) {
            assessed.add(row);
            const build = buildOf(rows[row - 1]!);
            builds.set(evidenceKey(build), build);
          }
        }
        return { id, observedImages: [...builds.values()] };
      });
      const unassessed: ReturnedRange[] = [];
      const requestedRows = new Map<string, Set<number>>();
      for (const search of searches.values())
        for (const [id, rows] of search.selectedRows) {
          const requested = requestedRows.get(id) ?? new Set<number>();
          for (const row of rows) requested.add(row);
          requestedRows.set(id, requested);
        }
      for (const [collectionId, { observations }] of collections) {
        const assessed = seen.get(collectionId);
        let first: number | undefined;
        for (let row = 1; row <= observations.length + 1; row++) {
          if (
            row <= observations.length &&
            requestedRows.get(collectionId)?.has(row) &&
            !assessed?.has(row)
          ) {
            first ??= row;
          } else if (first !== undefined) {
            unassessed.push({
              collectionId,
              firstRow: first,
              lastRow: row - 1,
            });
            first = undefined;
          }
        }
      }
      return {
        findings,
        unassessed,
        searches: [...searches.values()].map(
          ({ selector, window, slices, query }) => ({
            selector,
            window,
            ...(query ? { query } : {}),
            slices,
            uncovered: gaps(
              window,
              slices
                .filter(
                  ({ outcome }) =>
                    outcome === "found_stacks" || outcome === "no_samples",
                )
                .map(({ window }) => window),
            ),
          }),
        ),
      };
    },
  };
}

export const dependencyProfileToolSchema = z.toJSONSchema(
  inputSchema,
) as JsonObject;
export const dependencyProfileWitnessesSchema = z.toJSONSchema(
  witnessQuerySchema,
) as JsonObject;
export const dependencyProfileAssessmentSchema = z.toJSONSchema(
  assessmentSchema,
) as JsonObject;

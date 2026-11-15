import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import type { JsonObject } from "./config.js";
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
const querySchema = z.strictObject({
  selector: selectorSchema,
  window: windowSchema,
  limit: z.number().int().positive(),
});
const witnessRange = z.strictObject({
  collectionId: z.string().regex(evidenceDigest),
  firstRow: z.number().int().positive(),
  lastRow: z.number().int().positive(),
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
      frame_match: z.literal("any_exact_name"),
    }),
    coverage: z.looseObject({
      result_complete: z.boolean(),
      returned_stack_count: z.number().int().nonnegative(),
      backend_partial: z.boolean().nullish(),
    }),
    limits: z.looseObject({
      stack_limit: z.number().int().positive(),
      truncated: z.boolean(),
    }),
    warnings: z.array(z.unknown()).optional(),
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
type Selector = DependencyProfileQuery["selector"];
type Window = DependencyProfileQuery["window"];
type Collection = z.infer<typeof collectionSchema>;
type CollectionRecord = { receiptId: string; collection: Collection };
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
}

function normalizeSelector<T extends Selector>(selector: T) {
  return { ...selector, frames: [...new Set(selector.frames)].sort() };
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
    !sameWindow(scope)
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
  if (
    coverage.result_complete !==
    (coverage.backend_partial === false && !limits.truncated)
  )
    throw new Error("Profile collection reports inconsistent completeness.");
  for (const { scope, frames } of collection.observations) {
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
      !frames.some(({ name }) => selector.frames.includes(name))
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
  const searches = new Map<
    string,
    {
      selector: Selector;
      window: Window;
      slices: {
        window: Window;
        outcome: Outcome;
        collectionId?: string;
        error?: string;
      }[];
    }
  >();
  const directory = join(options.directory, evidenceKey(options.providerKey));

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
    const { selector, window, limit } = query;
    const queryKey = evidenceKey([selector, limit]);
    const cachePath = join(directory, queryKey);
    const covered: Window[] = [];
    const slices: {
      window: Window;
      outcome: Outcome;
      cached: boolean;
      collectionId?: string;
      stackCount?: number;
      receiptId?: string;
      error?: string;
      truncated?: boolean;
      backendPartial?: boolean | null;
      warnings?: unknown[];
    }[] = [];

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
        captured = { receiptId, collection };
        active.set(collectionId, captured);
      }
      const stackCount = collection.observations.length;
      const complete = collection.metadata.coverage.result_complete;
      slices.push({
        window: request.window,
        collectionId,
        receiptId: captured.receiptId,
        stackCount,
        cached,
        outcome: complete
          ? stackCount
            ? "found_stacks"
            : "no_samples"
          : "incomplete",
        truncated: collection.metadata.limits.truncated,
        backendPartial: collection.metadata.coverage.backend_partial ?? null,
        warnings: collection.metadata.warnings,
      });
      if (complete) covered.push(request.window);
    }

    // Aggregated stacks cannot be clipped to a smaller time interval.
    const files = await readdir(cachePath).catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return [];
        throw error;
      },
    );
    const candidates: [string, Window][] = [];
    for (const file of files) {
      const id = file.slice(0, -5);
      if (!file.endsWith(".json") || !evidenceDigest.test(id)) continue;
      const entry = await readSavedEvidence(join(cachePath, file));
      if (entry !== undefined)
        candidates.push([id, windowSchema.parse(JSON.parse(entry))]);
    }
    candidates.sort(
      ([, a], [, b]) =>
        a.start.localeCompare(b.start) || b.end.localeCompare(a.end),
    );
    for (const [id, slice] of candidates) {
      if (
        slice.start < window.start ||
        slice.end > window.end ||
        covered.some(
          (existing) =>
            slice.start < existing.end && slice.end > existing.start,
        )
      )
        continue;
      const resource = await load(id);
      if (resource !== undefined) {
        const request = { ...query, window: slice };
        options.authorize(request);
        const cached = parse(request, resource);
        if (!cached.metadata.coverage.result_complete)
          throw new Error(`Cached profile collection is incomplete: ${id}`);
        retain(request, resource, cached, true);
      }
    }

    for (const slice of gaps(window, covered)) {
      options.signal?.throwIfAborted();
      const request = { ...query, window: slice };
      let summary: unknown;
      let resource: string;
      let collection: Collection;
      try {
        options.authorize(request);
        summary = await options.lookup(request);
        const descriptor = descriptorSchema.parse(summary).graph_evidence;
        resource = await options.readResource(descriptor.uri);
        options.signal?.throwIfAborted();
        if (evidenceHash(resource) !== descriptor.sha256)
          throw new Error("Profile collection hash does not match its lookup.");
        collection = parse(request, resource);
      } catch (error) {
        options.signal?.throwIfAborted();
        slices.push({
          window: slice,
          outcome: "failed",
          cached: false,
          error: String(error),
        });
        continue;
      }
      const file = `${evidenceHash(resource)}.json`;
      await saveEvidence(directory, file, resource);
      retain(request, resource, collection, false, summary);
      if (collection.metadata.coverage.result_complete)
        await saveEvidence(cachePath, file, JSON.stringify(slice));
    }
    searches.set(evidenceKey(query), { selector, window, slices });
    return {
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
      const { selector, window, limit } = querySchema.parse(input);
      for (const bound of [window.start, window.end]) {
        if (!sameInstant(bound, bound))
          throw new Error(
            "Profile window timestamps must have millisecond precision or coarser.",
          );
      }
      const query = {
        selector: normalizeSelector(selector),
        window: {
          start: new Date(window.start).toISOString(),
          end: new Date(window.end).toISOString(),
        },
        limit,
      };
      options.authorize(query);
      // Serialize requests sharing a cache index, including overlapping backfills.
      const key = evidenceKey([query.selector, limit]);
      const previous = pending.get(key);
      const task = (previous?.catch(() => {}) ?? Promise.resolve()).then(() =>
        collect(query),
      );
      pending.set(key, task);
      try {
        return await task;
      } finally {
        if (pending.get(key) === task) pending.delete(key);
      }
    },
    witnesses(input: unknown) {
      const { collectionId, firstRow, lastRow } = witnessRange.parse(input);
      const captured = active.get(collectionId);
      const rows = captured?.collection.observations;
      if (!rows || firstRow > lastRow || lastRow > rows.length)
        throw new Error(
          "Requested rows are outside this investigation's profile collection.",
        );
      return rows
        .slice(firstRow - 1, lastRow)
        .map(({ id, scope, frames }, offset) => ({
          row: firstRow + offset,
          id,
          scope,
          frames,
          receiptSelection: {
            receiptId: captured.receiptId,
            textBlock: 0,
            record: ["observations", firstRow + offset - 1],
          },
        }));
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
      for (const [collectionId, { observations }] of collections) {
        const assessed = seen.get(collectionId);
        let first: number | undefined;
        for (let row = 1; row <= observations.length + 1; row++) {
          if (row <= observations.length && !assessed?.has(row)) {
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
          ({ selector, window, slices }) => ({
            selector,
            window,
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
  querySchema,
) as JsonObject;
export const dependencyProfileWitnessesSchema = z.toJSONSchema(
  witnessRange,
) as JsonObject;
export const dependencyProfileAssessmentSchema = z.toJSONSchema(
  assessmentSchema,
) as JsonObject;

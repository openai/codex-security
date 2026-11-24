import { randomUUID } from "node:crypto";
import { realpath } from "node:fs/promises";
import { z } from "zod";
import {
  DependencyAttemptStore,
  dependencyRecordHash,
} from "./dependency-attempt-store.js";
import {
  queryWorkItems,
  sampledStacksSchema,
  stackPacketWorkItems,
  stackSinkMatches,
  stackSinksSchema,
  stackSourcesSchema,
  type StackPacket,
  type StackWorkItem,
} from "./dependency-stack-packet.js";
import { CodexSecurityError } from "./errors.js";
import { canonicalJson } from "./record.js";
import { readRuntimeStackQueries } from "./dependency-stack-runtime-receipts.js";
import { repositoryRevision } from "./targets.js";
import { VERSION } from "./version.js";

const text = z.string().min(1);
const querySchema = sampledStacksSchema.shape.queries.element;
type Query = z.infer<typeof querySchema>;
type Origin = z.infer<typeof sampledStacksSchema.shape.origin>;
type Sink = StackPacket["sinks"]["sinks"][number];

export const liveInitInputSchema = z.strictObject({
  cve: stackSinksSchema.shape.cve.optional(),
  advisory: stackSinksSchema.shape.advisory.optional(),
  sources: stackSourcesSchema.shape.sources.optional(),
  sinks: stackSinksSchema.shape.sinks.element.array().optional(),
  repository: text.optional(),
  toolRevision: text.optional(),
  runId: text.optional(),
  attemptId: text.optional(),
});

export const recordObservationsInputSchema = z
  .strictObject({
    queries: z.array(querySchema).min(1).optional(),
    origin: sampledStacksSchema.shape.origin.optional(),
    receiptId: text.optional(),
  })
  .refine(
    (input) => input.queries !== undefined || input.receiptId !== undefined,
    "Provide captured queries or a runtime receipt.",
  );

export interface LiveRun {
  format: "codex-security.live-investigation/v1";
  repo: string;
  target: StackPacket["manifest"]["target"];
  logicalRepository?: string;
  runId: string;
  attemptId: string;
  toolRevision: string;
  inputDigest: string;
  cve?: string;
  advisory?: StackPacket["manifest"]["advisory"];
  sources: StackPacket["sources"]["sources"];
  sinks: Sink[];
}

type SupplementalQuery = SupplementalReceipt & { query: Query };

interface SupplementalReceipt {
  sha256: string;
  receiptId?: string;
  origin?: Origin;
}

function fail(message: string): never {
  throw new CodexSecurityError(message);
}

export function getLiveRun(store: DependencyAttemptStore): LiveRun | undefined {
  return store.get<LiveRun>("live-run", "active");
}

function mergeEndpoints<T extends { id: string }>(
  kind: string,
  existing: readonly T[] = [],
  incoming: readonly T[] = [],
): T[] {
  const result = [...existing];
  const byId = new Map(existing.map((value) => [value.id, value]));
  for (const value of incoming) {
    const prior = byId.get(value.id);
    if (prior) {
      if (canonicalJson(prior) !== canonicalJson(value))
        fail(
          `The ${kind} endpoint ${value.id} is already recorded differently.`,
        );
      continue;
    }
    result.push(value);
    byId.set(value.id, value);
  }
  return result;
}

function immutable<T>(
  existing: T | undefined,
  incoming: T | undefined,
  name: string,
): T | undefined {
  if (
    existing !== undefined &&
    incoming !== undefined &&
    canonicalJson(existing) !== canonicalJson(incoming)
  )
    fail(`The investigation ${name} is already recorded differently.`);
  return incoming ?? existing;
}

export async function initializeLive(
  store: DependencyAttemptStore,
  repo: string,
  input?: unknown,
  signal?: AbortSignal,
): Promise<LiveRun> {
  const update = liveInitInputSchema.parse(input ?? {});
  const checkout = await realpath(repo);
  const sha = await repositoryRevision(checkout, signal);
  if (!sha)
    fail(
      "The interactive investigation requires a Git checkout with a local HEAD.",
    );
  const existing = getLiveRun(store);
  if (store.get("manifest", "active"))
    fail("This database belongs to a prepared stack packet.");
  if (existing && (existing.repo !== checkout || existing.target.sha !== sha))
    fail("The interactive investigation target checkout or revision changed.");
  const logicalRepository = immutable(
    existing?.logicalRepository,
    update.repository,
    "repository",
  );
  const target = { repository: logicalRepository ?? checkout, sha };
  function checkRepositoryChange() {
    if (
      existing &&
      existing.target.repository !== target.repository &&
      (store.claims().length > 0 || store.size("stack-assessment") > 0)
    )
      fail(
        "Set the logical repository before recording claims or assessments.",
      );
  }
  checkRepositoryChange();
  const runId =
    immutable(existing?.runId, update.runId, "run ID") ?? randomUUID();
  const attemptId =
    immutable(existing?.attemptId, update.attemptId, "attempt ID") ??
    randomUUID();
  const toolRevision =
    immutable(existing?.toolRevision, update.toolRevision, "tool revision") ??
    `@openai/codex-security@${VERSION}`;
  const identity = {
    format: "codex-security.live-investigation/v1" as const,
    checkout: { repository: checkout, sha },
    runId,
    attemptId,
    toolRevision,
  };
  const sources = mergeEndpoints("source", existing?.sources, update.sources);
  const sinks = mergeEndpoints("sink", existing?.sinks, update.sinks);
  const sourceIds = new Set(sources.map((value) => value.id));
  for (const sink of sinks)
    if (sourceIds.has(sink.id)) fail(`Duplicate endpoint ID: ${sink.id}.`);
  const cve = immutable(existing?.cve, update.cve, "CVE");
  const advisory = immutable(existing?.advisory, update.advisory, "advisory");
  const next: LiveRun = {
    format: identity.format,
    target,
    runId,
    attemptId,
    toolRevision,
    repo: checkout,
    inputDigest: existing?.inputDigest ?? dependencyRecordHash(identity),
    sources,
    sinks,
    ...(cve && { cve }),
    ...(advisory && { advisory }),
    ...(logicalRepository && { logicalRepository }),
  };
  return store.transaction(() => {
    if (canonicalJson(getLiveRun(store)) !== canonicalJson(existing))
      fail(
        "The interactive investigation changed during initialization. Retry init.",
      );
    if (
      store.get("report", "final") &&
      canonicalJson(existing) !== canonicalJson(next)
    )
      fail("This investigation has been finalized.");
    checkRepositoryChange();
    store.bindIdentity(identity);
    store.set("live-run", "active", next);
    if (!existing) store.set("stack-protocol", "capture-origin", "next");
    return next;
  });
}

function advisoryGaps(run: LiveRun) {
  const gaps: string[] = [];
  if (!run.cve) gaps.push("Supply the CVE identifier.");
  if (!run.advisory) gaps.push("Supply the advisory URL and summary.");
  return gaps;
}

export function liveMetadataGaps(store: DependencyAttemptStore): string[] {
  const run = getLiveRun(store);
  if (!run) return ["Initialize the interactive investigation first."];
  const gaps = advisoryGaps(run);
  if (!run.sinks.length)
    gaps.push("Identify and register the vulnerable sink.");
  if (!store.size("supplemental-query"))
    gaps.push("Collect a runtime query or record a concrete coverage gap.");
  return gaps;
}

function fileIdentity(value: unknown) {
  return {
    byteLength: Buffer.byteLength(canonicalJson(value) ?? "null"),
    sha256: dependencyRecordHash(value),
  };
}

export function livePacket(store: DependencyAttemptStore): StackPacket {
  const run = getLiveRun(store);
  if (!run) fail("Initialize the interactive investigation first.");
  const gaps = advisoryGaps(run);
  if (gaps.length)
    fail(`Interactive investigation metadata is incomplete. ${gaps.join(" ")}`);
  const sources: StackPacket["sources"] = {
    format: "codex-security.stack-sources/v1",
    sources: run.sources,
  };
  const sinks: StackPacket["sinks"] = {
    format: "codex-security.stack-sinks/v1",
    cve: run.cve!,
    advisory: run.advisory!,
    sinks: run.sinks,
  };
  const stacks: StackPacket["stacks"] = {
    format: "codex-security.sampled-stacks/v1",
    target: run.target,
    origin: { source: "interactive-run", revision: run.inputDigest },
    frameOrder: "leaf_first",
    queries: [],
  };
  return {
    manifest: {
      format: "codex-security.stack-manifest/v1",
      cve: run.cve!,
      advisory: run.advisory!,
      target: run.target,
      toolRevision: run.toolRevision,
      inputDigest: run.inputDigest,
      runId: run.runId,
      attemptId: run.attemptId,
      files: {
        sources: fileIdentity(sources),
        sinks: fileIdentity(sinks),
        stacks: fileIdentity(stacks),
      },
    },
    sources,
    sinks,
    stacks,
  };
}

function mergeQuery(queries: Query[], incoming: Query): Query[] {
  const index = queries.findIndex((query) => query.id === incoming.id);
  if (index < 0) return [...queries, incoming];
  const old = queries[index]!;
  const { groups: oldGroups, ...oldFields } = old;
  const { groups: newGroups, ...newFields } = incoming;
  if (canonicalJson(oldFields) !== canonicalJson(newFields))
    fail(
      `Query ${incoming.id} was already recorded with different scope or selectors.`,
    );
  const groups = [...oldGroups];
  for (const group of newGroups) {
    const groupIndex = groups.findIndex((entry) => entry.id === group.id);
    if (groupIndex < 0) {
      groups.push(group);
      continue;
    }
    const previous = groups[groupIndex]!;
    const { observations: priorRows, ...priorFields } = previous;
    const { observations: newRows, ...groupFields } = group;
    if (
      canonicalJson(priorFields) !== canonicalJson(groupFields) ||
      previous.status !== "observed" ||
      !newRows.length
    )
      fail(
        `Group ${group.id} in query ${incoming.id} is already recorded differently.`,
      );
    const ids = new Set(priorRows.map((row) => row.id));
    for (const row of newRows) {
      if (ids.has(row.id))
        fail(
          `Observation ${row.id} in query ${incoming.id} is already recorded.`,
        );
      ids.add(row.id);
    }
    groups[groupIndex] = {
      ...previous,
      observations: [...priorRows, ...newRows],
    };
  }
  return queries.map((query, i) => (i === index ? { ...old, groups } : query));
}

function validateAddedQuery(query: Query, sinkIds: Set<string>) {
  const groups = new Set<string>();
  for (const group of query.groups) {
    if (groups.has(group.id))
      fail(`Duplicate group ID in query ${query.id}: ${group.id}.`);
    groups.add(group.id);
    const observations = new Set<string>();
    for (const row of group.observations) {
      if (observations.has(row.id))
        fail(`Duplicate observation ID in query ${query.id}: ${row.id}.`);
      observations.add(row.id);
      for (const match of stackSinkMatches(row))
        if (!sinkIds.has(match.sinkId))
          fail(
            `Unknown catalog sink on observation ${row.id}: ${match.sinkId}.`,
          );
    }
    if (group.status !== "no_coverage" && !sinkIds.size)
      fail(
        "Identify and register the vulnerable sink before recording observed or no-match query data.",
      );
  }
}

function queryReceipt(
  query: Query,
  { origin, receiptId }: Omit<SupplementalReceipt, "sha256">,
): SupplementalReceipt {
  const provenance = {
    ...(origin && { origin }),
    ...(receiptId && { receiptId }),
  };
  return {
    sha256: dependencyRecordHash({ query, ...provenance }),
    ...provenance,
  };
}

function replayQueries(store: DependencyAttemptStore, base: Query[] = []) {
  const entries = store.values<SupplementalQuery>("supplemental-query");
  for (const entry of entries)
    if (queryReceipt(entry.query, entry).sha256 !== entry.sha256)
      fail("Recorded supplemental observation evidence changed.");
  return entries.reduce(
    (queries, entry) => mergeQuery(queries, entry.query),
    base,
  );
}

export function overlayPacket(
  store: DependencyAttemptStore,
  base?: StackPacket,
): StackPacket {
  const packet = base ?? livePacket(store);
  const queries = replayQueries(store, packet.stacks.queries);
  if (queries === packet.stacks.queries) return packet;
  const sinkIds = new Set(packet.sinks.sinks.map((sink) => sink.id));
  for (const query of queries) validateAddedQuery(query, sinkIds);
  return { ...packet, stacks: { ...packet.stacks, queries } };
}

export function investigationVersion(store: DependencyAttemptStore) {
  return dependencyRecordHash({
    reviewRound: store.get<number>("review", "round") ?? 0,
    live: getLiveRun(store) ?? null,
    queries: store.keys("supplemental-query"),
    runtime: store.keys("runtime-receipt"),
    sources: store.keys("source-note"),
  });
}

export function packetSnapshot(
  store: DependencyAttemptStore,
  base?: StackPacket,
) {
  const snapshot = store.read(() => ({
    packet: overlayPacket(store, base),
    version: investigationVersion(store),
  }));
  return { ...snapshot, items: stackPacketWorkItems(snapshot.packet) };
}

export function effectiveInputDigest(
  store: DependencyAttemptStore,
  packet: StackPacket,
) {
  if (
    !getLiveRun(store) &&
    !store.size("supplemental-query") &&
    !store.size("runtime-receipt")
  )
    return undefined;
  const { manifest, sources, sinks, stacks } = packet;
  return dependencyRecordHash({
    format: "codex-security.stack-effective-input/v1",
    inputDigest: manifest.inputDigest,
    target: manifest.target,
    sources,
    sinks,
    stacks,
    runtimeReceiptIds: store.keys("runtime-receipt").sort(),
  });
}

export function recordObservations(
  store: DependencyAttemptStore,
  input: unknown,
  base?: StackPacket,
): { workItemIds: string[] } {
  const parsed = recordObservationsInputSchema.parse(input);
  const live = getLiveRun(store);
  if (!base && !live)
    fail("Initialize the investigation before recording observations.");
  const allSinks = base?.sinks.sinks ?? live?.sinks ?? [];
  const sinkIds = new Set(allSinks.map((sink) => sink.id));
  const originalQueries = parsed.receiptId
    ? readRuntimeStackQueries(store, parsed.receiptId, allSinks)
    : undefined;
  const requested = parsed.queries ?? originalQueries ?? [];
  if (!requested.length)
    fail("No captured queries were available in the runtime receipt.");
  if (originalQueries && parsed.queries) {
    const originals = new Set(originalQueries.map(canonicalJson));
    for (const query of requested)
      if (!originals.has(canonicalJson(query)))
        fail("The supplied query does not match the original runtime receipt.");
  } else if (!originalQueries) {
    for (const query of requested)
      if (query.groups.some((group) => group.status !== "no_coverage"))
        fail(
          "Observed stacks and no-match results require an original runtime receipt.",
        );
  }
  let queries = replayQueries(store, base?.stacks.queries);
  const added = requested.map((query) => {
    validateAddedQuery(query, sinkIds);
    queries = mergeQuery(queries, query);
    return { query, receipt: queryReceipt(query, parsed) };
  });
  const workItemIds: string[] = [];
  for (const { query, receipt } of added) {
    store.set("supplemental-query", randomUUID(), { query, ...receipt });
    for (const { id } of queryWorkItems(query)) {
      store.set("supplemental-receipt", id, receipt);
      workItemIds.push(id);
    }
  }
  return { workItemIds };
}

export function supplementalReceipt(
  store: DependencyAttemptStore,
  item: Pick<StackWorkItem, "id">,
) {
  return store.get<SupplementalReceipt>("supplemental-receipt", item.id);
}

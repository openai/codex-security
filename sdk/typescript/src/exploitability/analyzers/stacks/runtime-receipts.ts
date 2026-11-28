import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { z } from "zod";
import type { JsonValue } from "../../../config.js";
import {
  dependencyRecordHash,
  type DependencyAttemptStore,
} from "../../attempt-store.js";
import {
  dependencyEvidencePayload,
  dependencyGraphEvidenceFormat,
} from "../../graph-evidence.js";
import {
  inventoryJsonField,
  stackJsonValue,
  type BoundDependencyInventoryReceipt,
  type DependencyInventoryReceiptSelection,
} from "./evidence.js";
import { sampledStacksSchema, type StackPacket } from "./packet.js";
import { CodexSecurityError } from "../../../errors.js";
import { readRegularInputFileBytes } from "../../../prompt-files.js";
import { asRecord, canonicalJson, isRecord } from "../../../record.js";

const text = z.string().trim().min(1);
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const runtimeImportServer = "runtime-import";
const captureServers = new Set([
  "stack-packet",
  "stack-observation",
  runtimeImportServer,
]);

export const runtimeEvidenceInputSchema = z
  .strictObject({
    kind: z.literal("runtime"),
    server: text.refine(
      (name) => !captureServers.has(name),
      "A runtime receipt cannot use a host capture server name.",
    ),
    tool: text,
    arguments: stackJsonValue.optional(),
    scope: stackJsonValue.optional(),
    result: stackJsonValue.optional(),
    resource: z.strictObject({ path: text, sha256: digest }).optional(),
  })
  .refine(
    (input) => (input.result !== undefined) !== (input.resource !== undefined),
    "Provide exactly one runtime result or resource.",
  );

interface RuntimeReceiptRecord {
  server: string;
  tool: string;
  arguments?: JsonValue;
  scope?: JsonValue;
  result: JsonValue;
  resourceSha256?: string;
}

export interface PreparedRuntimeEvidence {
  receiptId: string;
  sha256: string;
  record: RuntimeReceiptRecord;
}

/** Capture the supplied original before opening the short state transaction. */
export async function prepareRuntimeEvidence(
  raw: unknown,
  repository: string,
  signal?: AbortSignal,
): Promise<PreparedRuntimeEvidence> {
  const input = runtimeEvidenceInputSchema.parse(raw);
  signal?.throwIfAborted();
  let result = input.result;
  if (input.resource) {
    const bytes = await readRegularInputFileBytes(
      resolve(input.resource.path),
      repository,
    );
    signal?.throwIfAborted();
    if (
      createHash("sha256").update(bytes).digest("hex") !== input.resource.sha256
    )
      throw new CodexSecurityError(
        "Runtime resource SHA-256 does not match its original bytes.",
      );
    try {
      result = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
    } catch (error) {
      throw new CodexSecurityError(
        `Runtime resource is not UTF-8 JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    result = stackJsonValue.parse(result);
  }
  const record: RuntimeReceiptRecord = {
    server: input.server,
    tool: input.tool,
    ...(input.arguments !== undefined && { arguments: input.arguments }),
    ...(input.scope !== undefined && { scope: input.scope }),
    result: result as JsonValue,
    ...(input.resource && { resourceSha256: input.resource.sha256 }),
  };
  const sha256 = dependencyRecordHash(record);
  return { receiptId: "runtime-" + sha256, sha256, record };
}

export function saveRuntimeEvidence(
  store: DependencyAttemptStore,
  prepared: PreparedRuntimeEvidence,
): { receiptId: string; sha256: string } {
  const { receiptId, sha256, record } = prepared;
  if (
    sha256 !== dependencyRecordHash(record) ||
    receiptId !== "runtime-" + sha256
  )
    throw new CodexSecurityError(
      "Runtime receipt identity does not match its original record.",
    );
  const existing = store.get<RuntimeReceiptRecord>(
    "runtime-receipt",
    receiptId,
  );
  if (existing && dependencyRecordHash(existing) !== sha256)
    throw new CodexSecurityError(
      "A runtime receipt cannot replace its original record.",
    );
  if (!existing) store.set("runtime-receipt", receiptId, record);
  return { receiptId, sha256 };
}

function structuredResult(result: unknown) {
  return isRecord(result)
    ? (dependencyEvidencePayload({ result }, null) ?? result)
    : result;
}

/** Reopen and verify the host-saved original before binding any projection. */
export function selectRuntimeReceipt(
  store: DependencyAttemptStore,
  receiptId: string,
  selection?: DependencyInventoryReceiptSelection,
): BoundDependencyInventoryReceipt {
  const record = store.get<RuntimeReceiptRecord>("runtime-receipt", receiptId);
  if (!record)
    throw new CodexSecurityError("Unknown runtime receipt: " + receiptId);
  const sha256 = dependencyRecordHash(record);
  if (receiptId !== "runtime-" + sha256 || captureServers.has(record.server))
    throw new CodexSecurityError(
      "Runtime receipt no longer matches its original record.",
    );
  if (selection && selection.receiptId !== receiptId)
    throw new CodexSecurityError(
      "Runtime receipt selection identifies a different receipt.",
    );
  let result: unknown = record.result;
  if (selection) {
    if (selection.textBlock !== null) {
      if (!isRecord(record.result))
        throw new CodexSecurityError(
          "A runtime text block requires an original MCP response.",
        );
      result = dependencyEvidencePayload(
        { result: record.result },
        selection.textBlock,
      );
    } else result = structuredResult(result);
    result = inventoryJsonField(result, selection.record);
    if (result === undefined)
      throw new CodexSecurityError(
        "The selected runtime receipt record does not exist.",
      );
  }
  const origin = {
    tool: "record-evidence",
    arguments: {
      kind: "runtime",
      provenance: "caller_imported",
      verification: "unverified",
      declaredServer: record.server,
      declaredTool: record.tool,
      receiptId,
      sha256,
      ...(record.arguments !== undefined && { arguments: record.arguments }),
      ...(record.scope !== undefined && { scope: record.scope }),
      ...(record.resourceSha256 && { resourceSha256: record.resourceSha256 }),
    },
  };
  const originalPayloadSha256 =
    record.resourceSha256 ?? dependencyRecordHash(record.result);
  const projection = selection && {
    textBlock: selection.textBlock,
    record: selection.record,
  };
  return {
    receiptId,
    key: dependencyRecordHash({
      server: runtimeImportServer,
      origin,
      originalPayloadSha256,
      selection: projection ?? null,
    }),
    server: runtimeImportServer,
    originalPayloadSha256,
    origin,
    ...(projection && { selection: projection }),
    result,
  };
}

/** The import receipt protects immutable bytes, not the claimed provider identity. */
export function isRuntimeReceipt(
  receipt: BoundDependencyInventoryReceipt,
): boolean {
  const args = receipt.origin.arguments;
  return (
    receipt.server === runtimeImportServer &&
    receipt.origin.tool === "record-evidence" &&
    args["kind"] === "runtime" &&
    args["provenance"] === "caller_imported" &&
    args["verification"] === "unverified" &&
    typeof args["declaredServer"] === "string" &&
    !captureServers.has(args["declaredServer"]) &&
    typeof args["declaredTool"] === "string" &&
    args["receiptId"] === receipt.receiptId &&
    typeof args["sha256"] === "string" &&
    /^[a-f0-9]{64}$/u.test(args["sha256"]) &&
    receipt.receiptId === "runtime-" + args["sha256"] &&
    /^[a-f0-9]{64}$/u.test(receipt.originalPayloadSha256)
  );
}

const querySchema = sampledStacksSchema.shape.queries.element;
type Query = z.infer<typeof querySchema>;
type Sink = StackPacket["sinks"]["sinks"][number];

function fail(message: string): never {
  throw new CodexSecurityError(message);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function arrayOrEmpty(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function graphFrame(value: unknown) {
  if (
    !isRecord(value) ||
    value["kind"] !== "function" ||
    !isRecord(value["attributes"])
  )
    fail("Graph observation contains an invalid function frame.");
  const attributes = value["attributes"];
  const name =
    typeof attributes["name"] === "string" ? attributes["name"] : value["name"];
  const type = attributes["language"];
  if (
    typeof name !== "string" ||
    typeof type !== "string" ||
    (value["name"] !== undefined && value["name"] !== name)
  )
    fail(
      "Graph observation frame name or language is missing or inconsistent.",
    );
  const sampledLocation =
    typeof attributes["location"] === "string"
      ? attributes["location"]
      : undefined;
  const sampledLine = sampledLocation?.match(/:(\d+)$/u)?.[1];
  const line =
    Number.isSafeInteger(attributes["line"]) && Number(attributes["line"]) > 0
      ? Number(attributes["line"])
      : sampledLine &&
          Number.isSafeInteger(Number(sampledLine)) &&
          Number(sampledLine) > 0
        ? Number(sampledLine)
        : undefined;
  return {
    name,
    type,
    ...(sampledLocation !== undefined && { location: sampledLocation }),
    ...(line !== undefined && { line }),
    ...(typeof attributes["binary"] === "string" && {
      binary: attributes["binary"],
    }),
    ...(typeof attributes["build_id"] === "string" && {
      buildId: attributes["build_id"],
    }),
    ...(typeof attributes["build_hash"] === "string" && {
      buildHash: attributes["build_hash"],
    }),
    ...(((typeof attributes["offset"] === "string" &&
      /^\d+$/u.test(attributes["offset"])) ||
      (typeof attributes["offset"] === "number" &&
        Number.isSafeInteger(attributes["offset"]) &&
        attributes["offset"] >= 0)) && {
      offset: attributes["offset"],
    }),
  };
}

type GraphFrame = ReturnType<typeof graphFrame>;

function graphSelectorMatches(selector: unknown, frame: GraphFrame): boolean {
  if (!isRecord(selector)) return selector === frame.name;
  const observed =
    typeof selector["observed_name"] === "string"
      ? selector["observed_name"]
      : selector["name"];
  if (observed !== frame.name) return false;
  const suffix = (value: string | undefined, expected: unknown) =>
    typeof expected !== "string" ||
    (value !== undefined &&
      (value === expected ||
        value.endsWith("/" + expected.replace(/^\/+/, ""))));
  const location = frame.location?.replace(/:\d+$/u, "");
  return (
    (selector["frame_type"] === undefined ||
      selector["frame_type"] === frame.type) &&
    suffix(location, selector["location"]) &&
    suffix(frame.binary, selector["binary"]) &&
    (selector["line"] === undefined || selector["line"] === frame.line) &&
    (selector["build_id"] === undefined ||
      selector["build_id"] === frame.buildId) &&
    (selector["build_hash"] === undefined ||
      selector["build_hash"] === frame.buildHash)
  );
}

function graphWorkload(scope: Record<string, unknown>) {
  const image = asRecord(scope["observed_image"]);
  for (const [field, observed] of [
    ["image_name", image?.["name"]],
    ["image_tag", image?.["tag"]],
  ] as const)
    if (
      typeof scope[field] === "string" &&
      typeof observed === "string" &&
      scope[field] !== observed
    )
      fail(`Graph workload ${field} conflicts with its observed image.`);
  const tags = scope["image_tags"];
  if (
    tags !== undefined &&
    (!Array.isArray(tags) || !tags.every((tag) => typeof tag === "string"))
  )
    fail("Graph workload has an invalid image tag selection.");
  return {
    ...Object.fromEntries(
      [
        "environment",
        "cluster",
        "service",
        "container",
        "image_name",
        "image_tag",
        "image_digest",
      ].flatMap((key) => (stringValue(scope[key]) ? [[key, scope[key]]] : [])),
    ),
    ...(image && stringValue(image["name"]) && { image_name: image["name"] }),
    ...(image && stringValue(image["tag"]) && { image_tag: image["tag"] }),
    ...(tags !== undefined && { image_tags: tags as string[] }),
  };
}

function graphQuery(
  value: Record<string, unknown>,
  sinks: readonly Sink[],
): Query {
  if (
    value["frame_order"] !== "root_first" ||
    !Array.isArray(value["observations"]) ||
    !isRecord(value["metadata"])
  )
    fail(
      "Graph evidence is missing root-first observations or query metadata.",
    );
  const metadata = value["metadata"];
  if (!isRecord(metadata["scope"]))
    fail("Graph evidence is missing the requested query scope.");
  const scope = metadata["scope"];
  const id =
    stringValue(metadata["clickhouse_query_id"]) ??
    stringValue(metadata["request_id"]);
  const start = stringValue(scope["start"]),
    end = stringValue(scope["end"]);
  if (!id || !start || !end)
    fail("Graph evidence requires an original query ID and sampling window.");
  const structured = asRecord(scope["query"]);
  const rules = arrayOrEmpty(structured?.["rules"]);
  const ruleInputs = rules.length
    ? rules.map(
        (rule) =>
          asRecord(rule) ?? fail("Graph evidence has invalid query rules."),
      )
    : [
        {
          sources: structured?.["sources"],
          sinks: structured?.["sinks"] ?? scope["frames"],
        },
      ];
  const querySelectors = (side: "sources" | "sinks") =>
    ruleInputs.flatMap((rule, ruleIndex) => {
      const selectors = arrayOrEmpty(rule[side]);
      if (!rules.length) return selectors;
      return selectors.map((selector) => ({
        ...(asRecord(selector) ?? { name: selector }),
        rule_index: ruleIndex,
      }));
    });
  const querySources = querySelectors("sources");
  const querySinks = querySelectors("sinks");
  const inferred =
    structured?.["kind"] === "async_parent" ||
    metadata["instance_correlation_verified"] === false ||
    typeof metadata["join_basis"] === "string";
  if (!querySinks.length)
    fail("Graph evidence does not identify the queried sink selectors.");
  const observations = value["observations"].map((raw) => {
    if (
      !isRecord(raw) ||
      raw["kind"] !== "sampled_stack" ||
      !stringValue(raw["id"]) ||
      !isRecord(raw["scope"]) ||
      !Array.isArray(raw["frames"])
    )
      fail("Graph evidence contains an invalid sampled stack.");
    const rowScope = raw["scope"];
    if (canonicalJson(rowScope["window"]) !== canonicalJson({ start, end }))
      fail("Graph observation window differs from the query window.");
    // Stack citations count from the leaf. Graph match indices count from the root.
    const frames = raw["frames"].map(graphFrame).reverse();
    const matches = asRecord(rowScope["matches"]);
    if (structured && !matches)
      fail("A structured graph query requires captured match indices.");
    if (matches && matches["frame_order"] !== "root_first")
      fail("Graph match indices must declare root-first frame order.");
    if (matches && matches["matched"] !== true)
      fail("Graph observation is not a match for the requested query.");
    const matchedSinks: { sinkId: string; rawIndex: number }[] = [];
    let sinkIndex: number | null = null,
      sourceIndex: number | undefined;
    for (const rawRule of arrayOrEmpty(matches?.["rules"])) {
      if (!isRecord(rawRule) || !Number.isInteger(rawRule["rule_index"]))
        fail("Graph evidence contains an invalid match rule.");
      if (rawRule["matched"] !== true) continue;
      const input = ruleInputs[Number(rawRule["rule_index"])];
      if (!input) fail("Graph evidence references an unknown query rule.");
      const selectors = arrayOrEmpty(input["sinks"]);
      const pairs = arrayOrEmpty(rawRule["ordered_pairs"]);
      for (const rawMatch of arrayOrEmpty(rawRule["sinks"])) {
        if (
          !isRecord(rawMatch) ||
          !Number.isInteger(rawMatch["frame_index"]) ||
          !Number.isInteger(rawMatch["selector_index"])
        )
          fail("Graph evidence contains an invalid sink match.");
        const index = frames.length - 1 - Number(rawMatch["frame_index"]);
        if (index < 0 || index >= frames.length)
          fail("Graph sink match index is outside its captured frames.");
        const selector = selectors[Number(rawMatch["selector_index"])];
        if (!selector || !graphSelectorMatches(selector, frames[index]!))
          fail("Graph sink selector does not match its captured frame.");
        let matchedSource: number | undefined;
        if (structured?.["kind"] === "pair") {
          const pair = pairs.find(
            (candidate) =>
              isRecord(candidate) &&
              isRecord(candidate["sink"]) &&
              candidate["sink"]["frame_index"] === rawMatch["frame_index"] &&
              candidate["sink"]["selector_index"] ===
                rawMatch["selector_index"],
          );
          // A rule can contain additional sink hits without an allowed source ancestor.
          if (!isRecord(pair) || !Array.isArray(pair["source_ancestors"]))
            continue;
          const sources = arrayOrEmpty(input["sources"]);
          for (const ancestor of pair["source_ancestors"]) {
            if (
              !isRecord(ancestor) ||
              !Number.isInteger(ancestor["frame_index"]) ||
              !Number.isInteger(ancestor["selector_index"])
            )
              fail("Graph evidence contains an invalid source ancestor.");
            const source = frames.length - 1 - Number(ancestor["frame_index"]);
            const sourceSelector = sources[Number(ancestor["selector_index"])];
            if (
              source <= index ||
              source >= frames.length ||
              !sourceSelector ||
              !graphSelectorMatches(sourceSelector, frames[source]!)
            )
              fail(
                "Graph source ancestor does not match its captured selector or sink.",
              );
            matchedSource ??= source;
          }
          if (matchedSource === undefined)
            fail("An ordered graph sink has no captured source ancestor.");
        }
        sinkIndex ??= index;
        if (sinkIndex === index && matchedSource !== undefined)
          sourceIndex ??= matchedSource;
        for (const sink of inferred ? [] : sinks)
          if (sink.function === frames[index]!.name)
            matchedSinks.push({ sinkId: sink.id, rawIndex: index });
      }
    }
    if (!matches) {
      for (const selector of querySinks) {
        for (const [index, frame] of frames.entries()) {
          if (!graphSelectorMatches(selector, frame)) continue;
          sinkIndex ??= index;
          for (const sink of inferred ? [] : sinks)
            if (sink.function === frame.name)
              matchedSinks.push({ sinkId: sink.id, rawIndex: index });
        }
      }
    }
    if (structured && sinkIndex === null)
      fail("Graph observation has no sink matched by the requested query.");
    // A query can select a wrapper while catalog sinks occur elsewhere on
    // this same sampled call path. An alias requested by the caller does not
    // establish that the sampled function is the catalog implementation.
    if (sinkIndex !== null && !inferred)
      for (const [index, frame] of frames.entries()) {
        for (const sink of sinks)
          if (
            sink.function === frame.name &&
            !matchedSinks.some(
              (match) => match.sinkId === sink.id && match.rawIndex === index,
            )
          )
            matchedSinks.push({ sinkId: sink.id, rawIndex: index });
      }
    return {
      id: String(raw["id"]),
      stackHash: stringValue(rowScope["stack_key"]) ?? String(raw["id"]),
      sinkIndex,
      ...(sourceIndex !== undefined && { sourceIndex }),
      ...(matchedSinks.length && { sinkMatches: matchedSinks }),
      framesTruncated: false,
      frames,
      scope: graphWorkload(rowScope),
    };
  });
  const coverage = asRecord(metadata["coverage"]) ?? {};
  const limits = asRecord(metadata["limits"]) ?? {};
  const truncated =
    limits["truncated"] === true || coverage["result_complete"] === false
      ? true
      : limits["truncated"] === false && coverage["result_complete"] === true
        ? false
        : null;
  const status = observations.length
    ? "observed"
    : truncated === false && metadata["status"] === "empty_matches"
      ? "no_match"
      : "no_coverage";
  return querySchema.parse({
    id,
    scope: { ...graphWorkload(scope), window: { start, end } },
    ...(inferred && {
      provenance: {
        source:
          stringValue(metadata["join_basis"]) ?? "inferred_async_creator_link",
      },
    }),
    selectors: { sources: querySources, sinks: querySinks },
    groups: [{ id: "capture", status, truncated, observations }],
  });
}

export function readRuntimeStackQueries(
  store: DependencyAttemptStore,
  receiptId: string,
  sinks: readonly Sink[],
): Query[] {
  const value = structuredResult(selectRuntimeReceipt(store, receiptId).result);
  if (isRecord(value) && value["format"] === dependencyGraphEvidenceFormat)
    return [graphQuery(value, sinks)];
  if (isRecord(value) && Array.isArray(value["queries"]))
    return z.array(querySchema).min(1).parse(value["queries"]);
  const single = querySchema.safeParse(value);
  if (single.success) return [single.data];
  fail(
    "Runtime receipt does not contain a verifiable stack query or graph evidence.",
  );
}

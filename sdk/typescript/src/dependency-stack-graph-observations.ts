import { z } from "zod";
import { dependencyGraphEvidenceFormat } from "./dependency-graph-evidence.js";
import {
  sampledStacksSchema,
  type StackPacket,
} from "./dependency-stack-packet.js";
import { CodexSecurityError } from "./errors.js";
import { canonicalJson, isRecord } from "./record.js";

const querySchema = sampledStacksSchema.shape.queries.element;
type Query = z.infer<typeof querySchema>;
type Sink = StackPacket["sinks"]["sinks"][number];

function fail(message: string): never {
  throw new CodexSecurityError(message);
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
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
  const type =
    typeof attributes["language"] === "string"
      ? attributes["language"]
      : undefined;
  if (
    typeof name !== "string" ||
    type === undefined ||
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

function graphSelectorName(selector: unknown): unknown {
  return typeof selector === "string"
    ? selector
    : isRecord(selector)
      ? selector["name"]
      : undefined;
}

function graphSelectorMatches(selector: unknown, frame: GraphFrame): boolean {
  const requested = graphSelectorName(selector);
  const observed =
    isRecord(selector) && typeof selector["observed_name"] === "string"
      ? selector["observed_name"]
      : requested;
  if (observed !== frame.name) return false;
  if (!isRecord(selector)) return true;
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
  const image = isRecord(scope["observed_image"])
    ? scope["observed_image"]
    : undefined;
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

function graphQueries(
  value: Record<string, unknown>,
  sinks: readonly Sink[],
): Query[] {
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
  const structured = isRecord(scope["query"]) ? scope["query"] : undefined;
  const ruleInputs =
    structured &&
    Array.isArray(structured["rules"]) &&
    structured["rules"].length
      ? structured["rules"].map((rule) =>
          isRecord(rule)
            ? rule
            : fail("Graph evidence has invalid query rules."),
        )
      : [
          {
            sources: structured?.["sources"] ?? [],
            sinks: structured?.["sinks"] ?? scope["frames"] ?? [],
          },
        ];
  const sourceSelectors = ruleInputs.flatMap((rule) =>
    Array.isArray(rule["sources"]) ? rule["sources"] : [],
  );
  const sinkSelectors = ruleInputs.flatMap((rule) =>
    Array.isArray(rule["sinks"]) ? rule["sinks"] : [],
  );
  const annotateRules = (side: "sources" | "sinks", fallback: unknown[]) =>
    structured &&
    Array.isArray(structured["rules"]) &&
    structured["rules"].length
      ? ruleInputs.flatMap((rule, ruleIndex) =>
          (Array.isArray(rule[side]) ? rule[side] : []).map((selector) =>
            isRecord(selector)
              ? { ...selector, rule_index: ruleIndex }
              : { name: selector, rule_index: ruleIndex },
          ),
        )
      : fallback;
  const querySources = annotateRules("sources", sourceSelectors);
  const querySinks = annotateRules("sinks", sinkSelectors);
  const inferred =
    structured?.["kind"] === "async_parent" ||
    metadata["instance_correlation_verified"] === false ||
    typeof metadata["join_basis"] === "string";
  if (!sinkSelectors.length)
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
    const frames = raw["frames"].map(graphFrame).reverse();
    const matches = isRecord(rowScope["matches"])
      ? rowScope["matches"]
      : undefined;
    if (structured && !matches)
      fail("A structured graph query requires captured match indices.");
    if (matches && matches["frame_order"] !== "root_first")
      fail("Graph match indices must declare root-first frame order.");
    if (matches && matches["matched"] !== true)
      fail("Graph observation is not a match for the requested query.");
    const matchedSinks: { sinkId: string; rawIndex: number }[] = [];
    let sinkIndex: number | null = null,
      sourceIndex: number | undefined;
    const rules =
      matches && Array.isArray(matches["rules"]) ? matches["rules"] : [];
    for (const rawRule of rules) {
      if (!isRecord(rawRule) || !Number.isInteger(rawRule["rule_index"]))
        fail("Graph evidence contains an invalid match rule.");
      if (rawRule["matched"] !== true) continue;
      const input = ruleInputs[Number(rawRule["rule_index"])];
      if (!input) fail("Graph evidence references an unknown query rule.");
      const selectors =
        input && Array.isArray(input["sinks"]) ? input["sinks"] : [];
      const pairs = Array.isArray(rawRule["ordered_pairs"])
        ? rawRule["ordered_pairs"]
        : [];
      for (const rawMatch of Array.isArray(rawRule["sinks"])
        ? rawRule["sinks"]
        : []) {
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
          const sources = Array.isArray(input["sources"])
            ? input["sources"]
            : [];
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
    if (
      !matches &&
      (!structured ||
        structured["kind"] === "sink" ||
        structured["kind"] === "discovery")
    ) {
      for (const selector of sinkSelectors) {
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
  const coverage = isRecord(metadata["coverage"]) ? metadata["coverage"] : {};
  const limits = isRecord(metadata["limits"]) ? metadata["limits"] : {};
  const truncated =
    limits["truncated"] === true || coverage["result_complete"] === false
      ? true
      : limits["truncated"] === false && coverage["result_complete"] === true
        ? false
        : null;
  let status: "observed" | "no_match" | "no_coverage" = observations.length
    ? "observed"
    : "no_coverage";
  if (
    !observations.length &&
    coverage["result_complete"] === true &&
    truncated === false &&
    metadata["status"] === "empty_matches"
  )
    status = "no_match";
  return [
    querySchema.parse({
      id,
      scope: { ...graphWorkload(scope), window: { start, end } },
      ...(inferred && {
        provenance: {
          source:
            stringValue(metadata["join_basis"]) ??
            "inferred_async_creator_link",
        },
      }),
      selectors: { sources: querySources, sinks: querySinks },
      groups: [{ id: "capture", status, truncated, observations }],
    }),
  ];
}

export function normalizeRuntimeObservationData(
  original: unknown,
  sinks: readonly Sink[],
): Query[] {
  const value = isRecord(original)
    ? (original["structuredContent"] ??
      original["structured_content"] ??
      original)
    : original;
  if (isRecord(value) && value["format"] === dependencyGraphEvidenceFormat)
    return graphQueries(value, sinks);
  if (isRecord(value) && Array.isArray(value["queries"]))
    return z.array(querySchema).min(1).parse(value["queries"]);
  const single = querySchema.safeParse(value);
  if (single.success) return [single.data];
  fail(
    "Runtime receipt does not contain a verifiable stack query or graph evidence.",
  );
}

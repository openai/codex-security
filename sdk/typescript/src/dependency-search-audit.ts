import { createHash } from "node:crypto";
import {
  inventoryResultPayload,
  type DependencyInventoryReceiptMetadata,
} from "./dependency-inventory.js";
import type { DependencySearch } from "./dependency-reachability.js";
import { canonicalJson, isRecord } from "./record.js";

// Publish search selectors, not RPC argument objects, credentials or response bodies.
const selectorFields = [
  "paths",
  "files",
  "path",
  "project",
  "package",
  "version",
  "symbol",
  "source_symbol",
  "source_terms",
  "source_only",
  "max_hops",
  "time_budget_ms",
  "service",
  "service_name",
  "environment",
  "cluster",
  "namespace",
  "workload",
  "revision",
  "digest",
  "image",
  "image_ref",
  "artifact",
  "run_id",
  "runId",
  "job",
  "start",
  "end",
  "from",
  "until",
  "sourceId",
  "startLine",
  "endLine",
  "collectionId",
  "frames",
  "name",
  "limit",
  "owner",
  "repo",
  "repository",
  "commit",
  "advisoryId",
] as const;

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function selectors(input: unknown): string[] {
  if (!isRecord(input)) return [];
  const scope = selectorFields.flatMap((key) => {
    const value = input[key];
    if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    )
      return [`${key}=${value}`];
    const values = strings(value);
    return values.length ? [`${key}=${JSON.stringify(values)}`] : [];
  });
  if (Array.isArray(input["rules"])) {
    const rules = input["rules"].flatMap((rule) =>
      isRecord(rule) && typeof rule["id"] === "string" ? [rule["id"]] : [],
    );
    if (rules.length) scope.push(`rules=${JSON.stringify(rules)}`);
  }
  for (const key of ["query", "selector", "window"]) {
    if (isRecord(input[key])) scope.push(...selectors(input[key]));
  }
  return scope;
}

function podQuerySelectors(query: unknown): string[] {
  if (typeof query !== "string") return [];
  const [table, filter, ...stages] = query.trim().split(/\r?\n/u);
  if (table !== "pods" || !filter?.startsWith("| where ")) return [];
  const terms = filter.slice("| where ".length).split(/\s+and\s+/u);
  const parsed = new Map<string, string>();
  for (const term of terms) {
    const match =
      /^(cluster|namespace|servicename) (?:in \(("[\w.-]+"(?:,\s*"[\w.-]+")*)\)|== ("[\w.-]+"))$/u.exec(
        term,
      );
    if (!match || parsed.has(match[1]!)) return [];
    const field = {
      cluster: "cluster",
      namespace: "namespace",
      servicename: "service",
    }[match[1]!]!;
    const value = match[2]
      ? JSON.stringify(JSON.parse(`[${match[2]}]`))
      : JSON.parse(match[3]!);
    parsed.set(match[1]!, `${field}=${value}`);
  }
  const take = stages.at(-1)?.match(/^\| take ([1-9]\d*)$/u);
  return [
    "resource=pods",
    ...parsed.values(),
    ...(take ? [`limit=${take[1]}`] : []),
  ];
}

function isoTime(value: unknown) {
  return typeof value === "string" &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/u.test(
      value,
    ) &&
    Number.isFinite(Date.parse(value))
    ? value
    : undefined;
}

function completePodCoverage(text: string): unknown[] | undefined {
  // An archived table can have a damaged rows array while its preceding
  // coverage array is intact. Recover only that bounded, complete section.
  const header =
    /^\{\s*"columns"\s*:\s*\[[\s\S]*?\]\s*,\s*"coverage"\s*:\s*(\[[\s\S]*?\])\s*,\s*"rows"\s*:\s*\[/u.exec(
      text.slice(0, 16_384),
    );
  if (!header) return undefined;
  try {
    const coverage: unknown = JSON.parse(header[1]!);
    if (
      Array.isArray(coverage) &&
      coverage.length &&
      coverage.every(
        (entry) =>
          isRecord(entry) &&
          entry["resource"] === "pods" &&
          typeof entry["cluster"] === "string" &&
          /^[\w.-]+$/u.test(entry["cluster"]) &&
          isoTime(entry["snapshotAt"]) !== undefined,
      )
    )
      return coverage;
  } catch {
    // A damaged header cannot establish a snapshot timestamp.
  }
  return undefined;
}

function inventoryRecords(
  result: unknown,
  podTable: boolean,
): Record<string, unknown>[] {
  if (!isRecord(result)) return [];
  const records = [result];
  // Some clients retain the original MCP result alongside a structured or
  // text projection. Preserve explicit coverage even when one copy is neutral.
  for (const value of records) {
    const content = value["content"];
    const next = [
      value["data"],
      value["coverage"],
      value["metadata"],
      inventoryResultPayload(value, null),
    ];
    if (Array.isArray(content)) {
      for (const [index, block] of content.entries()) {
        const parsed = inventoryResultPayload(value, index);
        next.push(parsed);
        // The transport can omit bytes while leaving parseable JSON.
        if (
          isRecord(block) &&
          block["type"] === "text" &&
          typeof block["text"] === "string" &&
          /…[1-9]\d* chars truncated…/u.test(block["text"])
        ) {
          next.push({
            truncated: true,
            coverage:
              podTable && parsed === undefined
                ? completePodCoverage(block["text"])
                : undefined,
          });
        }
      }
    }
    for (const item of next)
      if (isRecord(item) && !records.includes(item)) records.push(item);
  }
  return records;
}

function reportedOmissions(truncation: unknown): boolean {
  if (!isRecord(truncation)) return false;
  const omittedByKey = truncation["omitted_by_key"];
  const positive = (value: unknown) => typeof value === "number" && value > 0;
  return (
    positive(truncation["omitted_top_level"]) ||
    (isRecord(omittedByKey) && Object.values(omittedByKey).some(positive))
  );
}

export function inventoryOutcome(
  result: unknown,
  metadata: DependencyInventoryReceiptMetadata,
): Pick<DependencySearch, "result" | "completeness" | "details"> {
  const { outcome, tool, arguments: args } = metadata;
  if (outcome === "unavailable")
    return {
      result: "not_run",
      completeness: "unavailable",
      details: ["The configured provider could not start."],
    };
  if (outcome === "failed")
    return {
      result: "unknown",
      completeness: "error",
      details: ["The provider returned a tool error. See the cited receipt."],
    };
  if (outcome === "empty")
    return {
      result: "unknown",
      completeness: "unknown",
      details: [
        "The tool returned no payload; lookup coverage could not be established.",
      ],
    };
  const isPodTable =
    tool === "kube-lens-query" &&
    isRecord(args) &&
    typeof args["query"] === "string" &&
    args["query"].trim().split(/\r?\n/u)[0] === "pods";
  const requestedPartial =
    tool === "kube-lens-query" && isRecord(args) && args["mode"] === "partial";
  const records = inventoryRecords(result, isPodTable);
  const completeness =
    requestedPartial ||
    records.some(
      (record) =>
        record["partial"] === true ||
        record["truncated"] === true ||
        reportedOmissions(record["truncation"]) ||
        (isPodTable &&
          isRecord(record["stats"]) &&
          record["stats"]["truncated"] === true) ||
        record["complete"] === false ||
        record["result_complete"] === false ||
        record["backend_partial"] === true ||
        record["has_more"] === true ||
        record["hasMore"] === true,
    )
      ? "partial"
      : records.some(
            (record) =>
              record["complete"] === true || record["result_complete"] === true,
          )
        ? "complete"
        : "unknown";
  const details = new Set<string>();
  if (requestedPartial)
    details.add("The inventory query requested partial coverage.");
  if (isPodTable || tool === "images.provenance") {
    const clocks = new Map<string, Set<string>>();
    function keepClock(label: string, value: unknown) {
      const time = isoTime(value);
      if (!time) return;
      const sameClock = clocks.get(label) ?? new Set<string>();
      sameClock.add(time);
      clocks.set(label, sameClock);
    }
    for (const record of records) {
      const provenance = record["_meta"];
      if (isRecord(provenance) && isRecord(provenance["offlineReplay"])) {
        keepClock(
          "Archived response originally recorded at",
          provenance["offlineReplay"]["original_recorded_at"],
        );
      }
      if (
        tool === "images.provenance" &&
        record["status"] === "verified" &&
        isRecord(args) &&
        typeof args["image_ref"] === "string" &&
        record["image"] === args["image_ref"] &&
        record["environment"] === args["environment"]
      ) {
        keepClock("Image provenance observed at", record["observed_at"]);
      }
      if (!isPodTable || !Array.isArray(record["coverage"])) continue;
      for (const snapshot of record["coverage"]) {
        if (
          !isRecord(snapshot) ||
          snapshot["resource"] !== "pods" ||
          typeof snapshot["cluster"] !== "string" ||
          !/^[\w.-]+$/u.test(snapshot["cluster"])
        )
          continue;
        keepClock(
          `Pod inventory snapshot for ${snapshot["cluster"]} at`,
          snapshot["snapshotAt"],
        );
      }
    }
    for (const [label, values] of clocks) {
      if (values.size === 1) details.add(`${label} ${[...values][0]}.`);
      else details.add(`${label}: conflicting captured timestamps.`);
    }
  }
  let noMatch = false;
  let matched = false;
  for (const record of records) {
    const state = String(record["outcome"] ?? record["status"]);
    noMatch ||= ["no_match", "not_found", "no_samples"].includes(state);
    matched ||= ["matched", "found", "found_stacks"].includes(state);
    const footprints = record["footprints"];
    if (
      Array.isArray(footprints) &&
      typeof record["serviceName"] === "string"
    ) {
      noMatch ||= footprints.length === 0;
      matched ||= footprints.length > 0;
      details.add(
        `${footprints.length} footprints returned for ${record["serviceName"]}.`,
      );
    }
    if (typeof record["clusters_queried"] === "number")
      details.add(`${record["clusters_queried"]} clusters queried.`);
    const unavailable = strings(record["unavailableClusters"]);
    if (unavailable.length)
      details.add(`Unavailable clusters: ${unavailable.join(", ")}.`);
  }
  if (noMatch && !matched)
    details.add("No match was observed within this lookup's reported scope.");
  return {
    result: matched ? "matches" : noMatch ? "no_match" : "returned",
    completeness,
    details: [...details],
  };
}

export class DependencySearchAudit {
  private searches: DependencySearch[] = [];
  private graphCalls = new Map<string, string>();

  observeGraph(
    phase: "item/started" | "item/completed",
    item: Record<string, unknown>,
  ) {
    const { tool, id, arguments: args } = item;
    if (
      typeof id !== "string" ||
      typeof tool !== "string" ||
      ![
        "trace_codex_security_code",
        "resolve_codex_security_services",
        "collect_dependency_profiles",
        "fetch_dependency_source",
        "read_dependency_source",
      ].includes(tool)
    )
      return;
    const now = new Date().toISOString();
    if (phase === "item/started") {
      this.graphCalls.set(id, now);
      return;
    }
    const startedAt = this.graphCalls.get(id) ?? null;
    this.graphCalls.delete(id);
    const result = isRecord(item["result"])
      ? item["result"]["structuredContent"]
      : undefined;
    const response = isRecord(result) ? result : {};
    const sourceTrace = tool === "trace_codex_security_code";
    const failed = item["status"] !== "completed";
    const scope = selectors(args);
    if (
      tool === "collect_dependency_profiles" &&
      Array.isArray(response["slices"])
    ) {
      for (const slice of response["slices"].filter(isRecord)) {
        const outcome = slice["outcome"];
        const details =
          typeof slice["error"] === "string" ? [slice["error"]] : [];
        if (slice["cached"] === true)
          details.push("Reused a complete captured window.");
        if (outcome === "no_samples")
          details.push(
            "Zero matching samples in this window. Reachability remains unverified by this query.",
          );
        this.searches.push({
          source: "Sampled profile evidence",
          tool,
          scope: [
            ...scope,
            ...selectors({ window: slice["window"] }).map(
              (value) => `slice ${value}`,
            ),
          ],
          startedAt,
          finishedAt: now,
          result:
            outcome === "found_stacks"
              ? "matches"
              : outcome === "no_samples"
                ? "no_match"
                : "unknown",
          completeness:
            outcome === "failed"
              ? "error"
              : outcome === "incomplete"
                ? "partial"
                : "complete",
          details,
          evidenceReferences:
            typeof slice["receiptId"] === "string" ? [slice["receiptId"]] : [],
        });
      }
      return;
    }
    if (
      tool === "collect_dependency_profiles" ||
      tool === "fetch_dependency_source" ||
      tool === "read_dependency_source"
    ) {
      this.searches.push({
        source:
          tool === "collect_dependency_profiles"
            ? "Sampled profile evidence"
            : "Dependency source evidence",
        tool,
        scope,
        startedAt,
        finishedAt: now,
        result: failed ? "unknown" : "returned",
        completeness: failed ? "error" : "unknown",
        details:
          failed && typeof item["error"] === "string" ? [item["error"]] : [],
        evidenceReferences:
          typeof response["receiptId"] === "string"
            ? [response["receiptId"]]
            : typeof response["sourceId"] === "string"
              ? [response["sourceId"]]
              : [],
      });
      return;
    }
    const coverage = response[sourceTrace ? "coverage" : "service_resolution"];
    const reported = isRecord(coverage) ? coverage : {};
    const matched = [response["trace"], response["textMatches"]].some(
      (value) => Array.isArray(value) && value.length > 0,
    );
    const complete = sourceTrace && reported["complete"] === true;
    const partial = sourceTrace
      ? reported["complete"] === false
      : Boolean(
          reported["pending"] ||
          reported["unresolved"] ||
          reported["truncated"],
        );
    if (!scope.some((field) => /^(paths|files|project)=/u.test(field)))
      scope.push("Checkout search scope");
    scope.push(
      ...strings(reported["searched_paths"]).map((path) => `searched=${path}`),
    );
    const details = strings(reported["limits"]);
    if (sourceTrace && Array.isArray(reported["discovery_omissions"])) {
      for (const entry of reported["discovery_omissions"].filter(isRecord)) {
        if (
          typeof entry["path"] === "string" &&
          typeof entry["excludedBy"] === "string"
        )
          details.push(
            `Broad discovery omitted ${JSON.stringify(entry["path"])} under operator exclusion ${JSON.stringify(entry["excludedBy"])}.`,
          );
      }
    }
    for (const [key, label] of [
      ["partial", "Incomplete"],
      ["frontier", "Not visited"],
    ] as const) {
      const entries = reported[key];
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        if (!isRecord(entry)) continue;
        const description = selectors(entry);
        if (typeof entry["reason"] === "string")
          description.push(entry["reason"]);
        details.push(`${label}: ${description.join(" · ")}`);
      }
    }
    if (isRecord(args) && args["source_only"] === true)
      details.push(
        "Service and runtime checks were skipped in this source-only trace.",
      );
    if (sourceTrace && !failed) {
      const structural = Array.isArray(response["trace"])
        ? response["trace"].length
        : 0;
      const text = Array.isArray(response["textMatches"])
        ? response["textMatches"].length
        : 0;
      details.push(
        `${structural} structural trace entries and ${text} text match groups.`,
      );
    }
    if (failed && typeof item["error"] === "string")
      details.push(item["error"]);
    const execution = response["ruleExecutions"];
    const refs = Array.isArray(execution)
      ? execution.flatMap((entry) =>
          isRecord(entry) && typeof entry["id"] === "string"
            ? [entry["id"]]
            : [],
        )
      : [];
    this.searches.push({
      source: sourceTrace
        ? "Checkout trace graph"
        : "Service catalog resolution",
      tool,
      scope,
      startedAt,
      finishedAt: now,
      result: matched
        ? "matches"
        : complete
          ? "no_match"
          : failed || sourceTrace
            ? "unknown"
            : "returned",
      completeness: failed
        ? "error"
        : complete
          ? "complete"
          : partial
            ? "partial"
            : "unknown",
      details,
      evidenceReferences: refs,
    });
  }

  recordInventory(
    receiptId: string,
    server: string,
    result: unknown,
    metadata: DependencyInventoryReceiptMetadata = {},
  ) {
    const finishedAt = metadata.finishedAt ?? new Date().toISOString();
    const scope = selectors(metadata.arguments);
    if (metadata.tool === "kube-lens-query" && isRecord(metadata.arguments)) {
      const mode = metadata.arguments["mode"];
      if (mode === "partial" || mode === "strict") scope.push(`mode=${mode}`);
      scope.push(...podQuerySelectors(metadata.arguments["query"]));
    }
    if (metadata.arguments !== undefined && !metadata.parentReceiptId)
      scope.push(
        `Request SHA-256 ${createHash("sha256")
          .update(canonicalJson(metadata.arguments) ?? "null")
          .digest("hex")}`,
      );
    this.searches.push({
      source: server,
      tool: metadata.tool ?? "MCP startup",
      scope,
      startedAt: metadata.startedAt ?? null,
      finishedAt,
      ...inventoryOutcome(result, metadata),
      evidenceReferences: [receiptId],
    });
  }

  snapshot(configuredServers: readonly string[]): DependencySearch[] {
    const now = new Date().toISOString();
    const used = new Set(this.searches.map(({ source }) => source));
    return [
      ...this.searches,
      ...configuredServers
        .filter((server) => !used.has(server))
        .map((server): DependencySearch => ({
          source: server,
          tool: "MCP inventory",
          scope: [],
          startedAt: null,
          finishedAt: now,
          result: "not_run",
          completeness: "skipped",
          details: [
            "No captured lookup used this configured provider for this advisory.",
          ],
          evidenceReferences: [],
        })),
    ];
  }
}

import { dependencyRecordHash } from "./dependency-attempt-store.js";
import {
  dependencyEvidencePayload,
  partialDependencyResponse,
} from "./dependency-graph-evidence.js";
import type { DependencyEvidenceRecord } from "./dependency-evidence-sources.js";
import type { DependencySearch } from "./dependency-reachability.js";
import { isRecord } from "./record.js";
import { formatSecurityPolicyText } from "./security-policy.js";

// Only selectors belong in the summary. The receipt retains the complete request.
const selectors = new Set([
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
]);

export function dependencyLookupScope(args: unknown): string[] {
  const fields = new Set<string>();
  const scopes = [args];
  // Keep the human-readable summary within one evidence preview page.
  let remaining = 4000;
  for (const scope of scopes) {
    if (!isRecord(scope)) continue;
    for (const [key, value] of Object.entries(scope)) {
      if (["selector", "window", "query"].includes(key) && isRecord(value)) {
        scopes.push(value);
        continue;
      }
      if (!selectors.has(key) && key !== "rules") continue;
      const v =
        key === "rules" && Array.isArray(value)
          ? value.filter(isRecord).map((rule) => rule["id"])
          : value;
      const displayed =
        typeof v === "string" || typeof v === "number" || typeof v === "boolean"
          ? String(v)
          : Array.isArray(v) && v.every((s) => typeof s === "string")
            ? JSON.stringify(v)
            : undefined;
      if (displayed === undefined || displayed.length > remaining) continue;
      const entry = key + "=" + formatSecurityPolicyText(displayed);
      if (entry.length > remaining || fields.has(entry)) continue;
      remaining -= entry.length;
      fields.add(entry);
    }
  }
  return [...fields, "Request SHA-256 " + dependencyRecordHash(args)];
}

function omitted(value: unknown) {
  if (!isRecord(value)) return false;
  const positive = (count: unknown) => typeof count === "number" && count > 0;
  return (
    positive(value["omitted_top_level"]) ||
    (isRecord(value["omitted_by_key"]) &&
      Object.values(value["omitted_by_key"]).some(positive))
  );
}

export function dependencyLookupSearch(
  record: DependencyEvidenceRecord,
): DependencySearch {
  const values = new Set([record.result]);
  let matched = false,
    noMatch = false,
    partial = false,
    complete = false,
    hasPayload = false;
  // Inspect response metadata and MCP envelopes, keeping individual result rows out of lookup-wide coverage.
  for (const value of values) {
    const envelope = { result: value };
    const structured = dependencyEvidencePayload(envelope, null);
    if (structured != null) hasPayload = true;
    const next = [
      structured,
      value["data"],
      value["coverage"],
      value["metadata"],
      value["_meta"],
    ];
    const blocks = value["content"];
    const resources = value["contents"];
    hasPayload ||= Array.isArray(resources) && resources.length > 0;
    if (Array.isArray(blocks)) {
      hasPayload ||= blocks.length > 0;
      for (const [index, block] of blocks.entries()) {
        if (
          isRecord(block) &&
          block["type"] === "text" &&
          typeof block["text"] === "string"
        ) {
          partial ||= /…[1-9]\d* chars truncated…/u.test(block["text"]);
          try {
            next.push(dependencyEvidencePayload(envelope, index));
          } catch {
            // A plain-text result does not assert structured lookup coverage.
          }
        }
      }
    }
    for (const item of next) if (isRecord(item)) values.add(item);
    const status = value["outcome"] ?? value["status"];
    matched ||=
      status === "matched" || status === "found" || status === "found_stacks";
    noMatch ||=
      status === "no_match" ||
      status === "not_found" ||
      status === "no_samples";
    partial ||=
      partialDependencyResponse(value) ||
      value["backend_partial"] === true ||
      value["result_complete"] === false ||
      omitted(value["truncation"]);
    complete ||=
      value["complete"] === true || value["result_complete"] === true;
  }
  return {
    source: record.server,
    tool: record.tool,
    scope: dependencyLookupScope(record.arguments),
    startedAt: null,
    finishedAt: new Date().toISOString(),
    result: matched
      ? "matches"
      : noMatch
        ? "no_match"
        : hasPayload
          ? "returned"
          : "unknown",
    completeness: partial ? "partial" : complete ? "complete" : "unknown",
    details: !hasPayload
      ? ["The server returned no payload."]
      : noMatch && !matched
        ? ["No match was observed within this lookup's reported scope."]
        : [],
    evidenceReferences: [record.sha256],
  };
}

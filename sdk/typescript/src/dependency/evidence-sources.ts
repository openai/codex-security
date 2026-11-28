import {
  dependencyEvidencePayload,
  partialDependencyResponse,
} from "./graph-evidence.js";
import type { DependencySearch } from "./reachability.js";
import { formatSecurityPolicyText } from "../security-policy.js";
import type { JsonObject, JsonValue } from "../config.js";
import { dependencyRecordHash } from "./attempt-store.js";
import { ConfigurationError } from "../errors.js";
import { isRecord } from "../record.js";

export const investigationServer = "dependency_investigation";

export interface DependencyEvidenceSource {
  server: string;
  instructions: string;
}

export interface DependencyEvidenceRecord {
  server: string;
  tool: string;
  arguments: unknown;
  result: Record<string, unknown>;
  sha256: string;
}

/** Use the selected servers with their native Codex connection and tool settings. */
export function selectDependencyEvidenceServers(
  sources: readonly DependencyEvidenceSource[],
  configured: JsonValue | undefined,
): JsonObject {
  const selected = new Map<string, JsonObject>();
  for (const { server } of sources) {
    const settings =
      isRecord(configured) && Object.hasOwn(configured, server)
        ? configured[server]
        : undefined;
    if (!isRecord(settings) || settings["enabled"] === false)
      throw new ConfigurationError(
        `Evidence source ${JSON.stringify(server)} needs an enabled server in codex.mcp_servers.`,
      );
    if (selected.has(server))
      throw new ConfigurationError(
        `Duplicate evidence source ${JSON.stringify(server)}.`,
      );
    selected.set(server, settings);
  }
  return Object.fromEntries(selected);
}

export type DependencyEvidenceFailure = Pick<
  DependencyEvidenceRecord,
  "server" | "tool" | "arguments"
>;

/** Remember linked resources only for the lifetime of this investigator run. */
export function createDependencyEvidenceCapture(
  servers: JsonObject,
  onFailure?: (
    call: DependencyEvidenceFailure,
    result: Record<string, unknown>,
  ) => void,
) {
  const links = new Map(
    Object.keys(servers).map((server) => [server, new Set<string>()]),
  );
  return (event: unknown): DependencyEvidenceRecord | undefined => {
    if (!isRecord(event)) return;
    const item =
      event["type"] === "item.completed"
        ? event["item"]
        : event["method"] === "item/completed" && isRecord(event["params"])
          ? event["params"]["item"]
          : undefined;
    if (
      !isRecord(item) ||
      (item["type"] !== "mcp_tool_call" && item["type"] !== "mcpToolCall") ||
      (item["status"] !== "completed" && item["status"] !== "failed")
    )
      return;
    const { server, tool, result } = item;
    if (
      typeof server !== "string" ||
      typeof tool !== "string" ||
      !Object.hasOwn(item, "arguments")
    )
      return;

    const linked = links.get(server);
    const settings = servers[server];
    if (!linked || !isRecord(settings) || settings["enabled"] === false) return;
    const allow = settings["enabled_tools"];
    const deny = settings["disabled_tools"];
    if (Array.isArray(deny) && deny.includes(tool)) return;
    const args = item["arguments"];
    if (tool === "read_mcp_resource") {
      // Codex reads linked resources using its own tool, outside enabled_tools.
      if (
        !isRecord(args) ||
        args["server"] !== server ||
        typeof args["uri"] !== "string" ||
        !linked.has(args["uri"])
      )
        return;
    } else if (Array.isArray(allow) && !allow.includes(tool)) return;
    if (
      item["status"] === "failed" ||
      item["error"] != null ||
      (isRecord(result) &&
        (result["isError"] === true || result["is_error"] === true))
    ) {
      onFailure?.(
        { server, tool, arguments: args },
        isRecord(result)
          ? result
          : {
              structuredContent: {
                status: "failed",
                error: item["error"] ?? null,
              },
            },
      );
      return;
    }
    if (!isRecord(result)) return;
    if (tool !== "read_mcp_resource") {
      if (Array.isArray(result["content"]))
        for (const block of result["content"]) {
          if (
            isRecord(block) &&
            block["type"] === "resource_link" &&
            typeof block["uri"] === "string"
          )
            linked.add(block["uri"]);
        }
    }
    const record = { server, tool, arguments: args, result };
    return { ...record, sha256: dependencyRecordHash(record) };
  };
}

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

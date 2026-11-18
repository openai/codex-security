import type { JsonObject, JsonValue } from "./config.js";
import { dependencyRecordHash } from "./dependency-attempt-store.js";
import { ConfigurationError } from "./errors.js";
import { isRecord } from "./record.js";

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
  onFailure?: (call: DependencyEvidenceFailure) => void,
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
      onFailure?.({ server, tool, arguments: args });
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

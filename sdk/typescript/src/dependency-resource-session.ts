import { isDeepStrictEqual } from "node:util";
import type { JsonObject } from "./config.js";
import { isRecord } from "./record.js";
import { tokenUsage, type ScanTokenUsage } from "./cost-model.js";

export interface DependencyResourceEvents {
  item(
    event: Readonly<Record<string, unknown>>,
    read: (server: string, uri: string) => Promise<unknown>,
    invocation: { threadId: string; callId: string },
  ): Promise<void>;
  usage?(value: ScanTokenUsage): void;
}

/** A lower-priority permission table can add filesystem rules to the named profile. */
export function dependencyResourcePermissionsMatch(
  config: JsonObject,
  layers: unknown[],
) {
  const flags = layers.find(
    (layer) =>
      isRecord(layer) &&
      isRecord(layer["name"]) &&
      layer["name"]["type"] === "sessionFlags",
  );
  const settings = isRecord(flags) ? flags["config"] : undefined;
  const expectedTable = isRecord(settings)
    ? settings["permissions"]
    : undefined;
  const expected = isRecord(expectedTable)
    ? expectedTable["dependency_investigation"]
    : undefined;
  const table = config["permissions"];
  const actual = isRecord(table)
    ? table["dependency_investigation"]
    : undefined;
  if (
    !isRecord(expected) ||
    !isRecord(actual) ||
    config["default_permissions"] !== "dependency_investigation"
  )
    return false;
  // Native config/read fills unset optional fields with null.
  return isDeepStrictEqual(
    JSON.parse(
      JSON.stringify(actual, (_key, value: unknown) =>
        value === null ? undefined : value,
      ),
    ),
    expected,
  );
}

/** Use the connection and thread which produced each resource link. */
export function createDependencyResourceSession(
  events: DependencyResourceEvents,
  send: (request: JsonObject) => void,
) {
  const parents = new Map<string, string>();
  let root: string | undefined;
  let closed = false;
  let next = 0;
  const requests = new Map<
    string,
    {
      resolve(value: unknown): void;
      reject(): void;
    }
  >();
  const work = new Set<Promise<void>>();
  const usage = new Map<string, ScanTokenUsage>();
  let failure: unknown;

  function owns(id: string) {
    const seen = new Set<string>();
    let parent: string | undefined = id;
    while (parent !== undefined && !seen.has(parent)) {
      if (parent === root) return true;
      seen.add(parent);
      parent = parents.get(parent);
    }
    return false;
  }

  function read(
    threadId: string,
    originCallId: string,
    server: string,
    uri: string,
  ) {
    return new Promise<unknown>((resolve, reject) => {
      if (closed) {
        reject(new Error("The evidence connection is closed."));
        return;
      }
      const id = "dependency-resource-" + next++;
      const end = () => {
        clearTimeout(timer);
        requests.delete(id);
      };
      const fail = () => {
        end();
        reject(new Error("The linked resource is unavailable."));
      };
      const timer = setTimeout(fail, 30_000);
      timer.unref();
      requests.set(id, {
        resolve(value) {
          end();
          resolve(value);
        },
        reject: fail,
      });
      send({
        id,
        method: "mcpServer/resource/read",
        params: { threadId, server, uri, originCallId },
      });
    });
  }

  return {
    permissionsMatch: dependencyResourcePermissionsMatch,
    register(id: string) {
      root = id;
    },
    receive(event: Readonly<Record<string, unknown>>): boolean {
      if (
        typeof event["id"] === "string" &&
        event["id"].startsWith("dependency-resource-") &&
        !event["method"]
      ) {
        const pending = requests.get(event["id"]);
        if (event["error"] !== undefined) pending?.reject();
        else pending?.resolve(event["result"]);
        return true;
      }
      const params = event["params"];
      if (!isRecord(params)) return false;
      const thread = params["thread"];
      if (
        event["method"] === "thread/started" &&
        isRecord(thread) &&
        typeof thread["id"] === "string" &&
        typeof thread["parentThreadId"] === "string"
      )
        parents.set(thread["id"], thread["parentThreadId"]);
      const threadId = params["threadId"];
      if (typeof threadId !== "string" || !owns(threadId)) return false;
      const item = params["item"];
      if (event["method"] === "item/completed" && isRecord(item)) {
        if (
          item["type"] === "subAgentActivity" &&
          item["kind"] === "started" &&
          typeof item["agentThreadId"] === "string"
        )
          parents.set(item["agentThreadId"], threadId);
        if (
          item["type"] === "mcpToolCall" &&
          typeof item["id"] === "string" &&
          !closed
        ) {
          const callId = item["id"];
          const task = events
            .item(event, (server, uri) => read(threadId, callId, server, uri), {
              threadId,
              callId,
            })
            .catch((error: unknown) => {
              failure ??= error;
            })
            .finally(() => work.delete(task));
          work.add(task);
        }
      }
      if (
        event["method"] === "thread/tokenUsage/updated" &&
        isRecord(params["tokenUsage"]) &&
        isRecord(params["tokenUsage"]["total"])
      ) {
        const total = params["tokenUsage"]["total"];
        const value = tokenUsage({
          input_tokens: total["inputTokens"],
          cached_input_tokens: total["cachedInputTokens"],
          cache_write_input_tokens: total["cacheWriteInputTokens"],
          output_tokens: total["outputTokens"],
          reasoning_output_tokens: total["reasoningOutputTokens"],
        });
        if (value) usage.set(threadId, value);
      }
      return false;
    },
    async drain() {
      await Promise.all(work);
      if (failure !== undefined) throw failure;
    },
    close() {
      closed = true;
      for (const pending of requests.values()) pending.reject();
      for (const value of usage.values()) events.usage?.(value);
      usage.clear();
    },
  };
}

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
  startup?(
    name: string,
    status: import("./dependency-blocked-evidence.js").DependencyStartupStatus,
    error: unknown,
  ): void;
  abort?: {
    name: string;
    description: string;
    inputSchema: object;
    call(args: unknown, thread: string): unknown;
  };
}

/** Checkpoint for one replacement native process. The CLI-owned MCP session stays alive. */
export interface DependencyCoordinatorRecovery {
  threadId?: string;
  turnId?: string;
  sent: boolean;
  terminalError: boolean;
  pendingCorrection?: { afterTurn: string; prompt: string };
  parents: Map<string, string>;
  pendingWrites: Set<string>;
  usage: Map<string, ScanTokenUsage>;
}

function mayChangeState(item: Record<string, unknown>) {
  switch (item["type"]) {
    case "mcpToolCall":
      return item["readOnlyHint"] !== true;
    case "dynamicToolCall":
    case "collabAgentToolCall":
    case "commandExecution":
    case "fileChange":
      return true;
    default:
      return false;
  }
}

export const continueDependencyInvestigation = [
  "The native connection closed. Continue this investigation on its original thread.",
  "Read the shared claims and saved evidence before doing further work. Retain completed source checks, the plan, reviewed premises and submitted assessments. Reconcile available results before assigning work.",
  "Do not repeat previous tool calls or resubmit a recorded mutation. Use the retained receipts and report any result you cannot verify.",
].join(" ");

export function recoveredDependencyTurn(
  thread: Record<string, unknown>,
  recovery: DependencyCoordinatorRecovery,
) {
  const turns = thread["turns"];
  if (!Array.isArray(turns))
    throw new Error("Codex did not return the saved investigation turns.");
  const turn = recovery.turnId
    ? turns.find((value) => isRecord(value) && value["id"] === recovery.turnId)
    : turns.at(-1);
  if (!isRecord(turn)) {
    if (recovery.sent)
      throw new Error(
        "Codex could not verify the interrupted investigation turn.",
      );
    return { kind: "initial" } as const;
  }
  const status = turn["status"];
  if (status === "failed")
    throw new Error("The saved investigation turn failed.");
  const items = turn["items"];
  if (!Array.isArray(items))
    throw new Error("Codex did not return the saved investigation items.");
  if (status === "completed") {
    const answer = items.findLast(
      (item) =>
        isRecord(item) &&
        item["type"] === "agentMessage" &&
        item["phase"] !== "commentary",
    );
    if (!isRecord(answer) || typeof answer["text"] !== "string")
      throw new Error("The saved investigation turn has no final answer.");
    if (typeof turn["id"] !== "string")
      throw new Error(
        "Codex returned an invalid completed investigation turn.",
      );
    return {
      kind: "completed",
      id: turn["id"],
      message: answer["text"],
    } as const;
  }
  if (
    (status !== "interrupted" && status !== "inProgress") ||
    items.some(
      (item) =>
        isRecord(item) &&
        mayChangeState(item) &&
        item["status"] === "inProgress",
    )
  )
    throw new Error(
      "The interrupted investigation has an unresolved tool outcome.",
    );
  const id = turn["id"];
  if (typeof id !== "string")
    throw new Error("Codex returned an invalid investigation turn.");
  if (
    isRecord(thread["status"]) &&
    thread["status"]["type"] === "active" &&
    status === "inProgress"
  )
    return { kind: "active", id } as const;
  return { kind: "continue" } as const;
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
  recovery?: DependencyCoordinatorRecovery,
) {
  const parents = recovery?.parents ?? new Map<string, string>();
  let root: string | undefined;
  let closed = false;
  let finishedTurn: string | undefined;
  let next = 0;
  const requests = new Map<
    string,
    {
      resolve(value: unknown): void;
      reject(): void;
    }
  >();
  const work = new Set<Promise<void>>();
  const usage = recovery?.usage ?? new Map<string, ScanTokenUsage>();
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
    abortTool: events.abort && {
      type: "namespace",
      name: "codex_security_reports",
      description: "Coordinator investigation outcomes.",
      tools: [
        {
          type: "function",
          name: events.abort.name,
          description: events.abort.description,
          inputSchema: events.abort.inputSchema,
        },
      ],
    },
    abortCall(
      event: Readonly<Record<string, unknown>>,
      activeTurn: string | undefined,
    ) {
      if (
        !events.abort ||
        event["method"] !== "item/tool/call" ||
        (typeof event["id"] !== "string" && typeof event["id"] !== "number")
      )
        return false;
      const params = event["params"];
      if (!isRecord(params) || params["tool"] !== events.abort.name)
        return false;
      let result;
      try {
        if (
          closed ||
          !root ||
          !activeTurn ||
          activeTurn === finishedTurn ||
          params["threadId"] !== root ||
          params["turnId"] !== activeTurn ||
          params["namespace"] !== "codex_security_reports"
        )
          throw new Error(
            "Only the active coordinator turn can end this investigation.",
          );
        const outcome = events.abort.call(params["arguments"], root);
        result = {
          success: true,
          contentItems: [{ type: "inputText", text: JSON.stringify(outcome) }],
        };
      } catch (error) {
        result = {
          success: false,
          contentItems: [
            {
              type: "inputText",
              text: error instanceof Error ? error.message : String(error),
            },
          ],
        };
      }
      send({ id: event["id"], result });
      return true;
    },
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
      if (
        event["method"] === "turn/completed" &&
        root &&
        params["threadId"] === root &&
        isRecord(params["turn"]) &&
        typeof params["turn"]["id"] === "string"
      )
        finishedTurn = params["turn"]["id"];
      if (event["method"] === "mcpServer/startupStatus/updated" && !closed) {
        const thread = params["threadId"],
          status = params["status"];
        if (
          (thread == null || thread === root) &&
          typeof params["name"] === "string" &&
          (status === "starting" ||
            status === "ready" ||
            status === "failed" ||
            status === "cancelled")
        )
          events.startup?.(params["name"], status, params["error"]);
        return false;
      }
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
      if (recovery) {
        if (event["method"] === "error") recovery.terminalError = true;
        if (isRecord(item) && typeof item["id"] === "string") {
          const key = JSON.stringify([threadId, item["id"]]);
          if (event["method"] === "item/started" && mayChangeState(item))
            recovery.pendingWrites.add(key);
          if (event["method"] === "item/completed") {
            recovery.pendingWrites.delete(key);
            if (item["type"] === "mcpToolCall" && item["status"] === "failed")
              recovery.terminalError = true;
          }
        }
      }
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
        if (value) {
          const previous = usage.get(threadId);
          // Resumed native threads replay cumulative totals. Emit new usage
          // before the host builds a report from the completed turn.
          if (recovery) {
            const delta = previous
              ? tokenUsage({
                  input_tokens: value.input_tokens - previous.input_tokens,
                  cached_input_tokens:
                    value.cached_input_tokens - previous.cached_input_tokens,
                  cache_write_input_tokens:
                    value.cache_write_input_tokens -
                    previous.cache_write_input_tokens,
                  cache_write_input_tokens_reported:
                    value.cache_write_input_tokens_reported,
                  output_tokens: value.output_tokens - previous.output_tokens,
                  reasoning_output_tokens:
                    value.reasoning_output_tokens -
                    previous.reasoning_output_tokens,
                })
              : value;
            if (delta && delta.total_tokens > 0) events.usage?.(delta);
          }
          usage.set(threadId, value);
        }
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
      if (!recovery) {
        for (const value of usage.values()) events.usage?.(value);
        usage.clear();
      }
    },
  };
}

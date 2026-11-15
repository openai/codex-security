import { asRecord as record } from "./record.js";

/** Routes native subagent calls using app-server thread metadata. */
export function createDependencyNativeSession() {
  let rootId: string | undefined;
  // Native edges can arrive child-first; check ownership when routing calls.
  const parents = new Map<string, string | null>();
  // A null turn means native activity reports work before exposing its turn ID.
  const turns = new Map<string, string | null>();

  function registerThread(value: unknown) {
    const thread = record(value);
    if (!thread || typeof thread["id"] !== "string") return;
    const parent = thread["parentThreadId"];
    if (parent === null || typeof parent === "string")
      parents.set(thread["id"], parent);
    const status = record(thread["status"]);
    if (status?.["type"] === "active" && !turns.has(thread["id"]))
      turns.set(thread["id"], null);
    else if (
      status?.["type"] === "idle" ||
      status?.["type"] === "notLoaded" ||
      status?.["type"] === "systemError"
    )
      turns.delete(thread["id"]);
  }

  function ownsThread(threadId: unknown): boolean {
    if (typeof threadId !== "string" || rootId === undefined) return false;
    const visited = new Set<string>();
    let current: string | null | undefined = threadId;
    while (current !== undefined && current !== null && !visited.has(current)) {
      if (current === rootId) return true;
      visited.add(current);
      current = parents.get(current);
    }
    return false;
  }

  return {
    registerRoot(threadId: string) {
      if (rootId !== undefined && rootId !== threadId)
        throw new Error("The native investigation already has a root thread.");
      rootId = threadId;
      parents.set(threadId, null);
    },
    registerThread,
    resetTurns() {
      turns.clear();
    },
    setTurn(threadId: string, turnId: string) {
      turns.set(threadId, turnId);
    },
    observe(event: Record<string, unknown>) {
      const params = record(event["params"]);
      if (!params) return;
      if (event["method"] === "thread/started") {
        registerThread(params["thread"]);
        return;
      }
      const threadId = params["threadId"];
      if (
        event["method"] === "thread/status/changed" &&
        typeof threadId === "string"
      ) {
        registerThread({ id: threadId, status: params["status"] });
        return;
      }
      const item = record(params["item"]);
      if (
        event["method"] === "item/completed" &&
        item?.["type"] === "subAgentActivity" &&
        typeof threadId === "string" &&
        typeof item["agentThreadId"] === "string"
      ) {
        const child = item["agentThreadId"];
        if (item["kind"] === "started" && !parents.has(child))
          parents.set(child, threadId);
        if (child === rootId) return;
        if (item["kind"] === "started" && !turns.has(child))
          turns.set(child, null);
        else if (item["kind"] === "completed" || item["kind"] === "interrupted")
          turns.delete(child);
        return;
      }
      if (
        event["method"] === "item/tool/call" &&
        typeof threadId === "string" &&
        typeof params["turnId"] === "string" &&
        turns.get(threadId) === null &&
        ownsThread(threadId)
      )
        turns.set(threadId, params["turnId"]);
      const turn = record(params["turn"]);
      if (typeof threadId !== "string" || typeof turn?.["id"] !== "string")
        return;
      if (event["method"] === "turn/started") turns.set(threadId, turn["id"]);
      if (
        event["method"] === "turn/completed" &&
        turns.get(threadId) === turn["id"]
      )
        turns.delete(threadId);
    },
    ownsThread,
    investigatorIds() {
      return [...parents.keys()].filter(
        (threadId) => threadId !== rootId && ownsThread(threadId),
      );
    },
    knowsThread(threadId: unknown) {
      return typeof threadId === "string" && parents.has(threadId);
    },
    hasActiveInvestigators() {
      for (const threadId of turns.keys())
        if (threadId !== rootId && ownsThread(threadId)) return true;
      return false;
    },
    isRoot(threadId: unknown) {
      return rootId !== undefined && threadId === rootId;
    },
    isCurrentTurn(value: unknown) {
      const params = record(value);
      return (
        typeof params?.["threadId"] === "string" &&
        typeof params["turnId"] === "string" &&
        ownsThread(params["threadId"]) &&
        (turns.get(params["threadId"]) === params["turnId"] ||
          (params["threadId"] !== rootId &&
            turns.get(params["threadId"]) === null))
      );
    },
  };
}

/** Reduce a single stream; callers retain error, retry and acceptance policy. */
export async function readCodexSessionTurn(options) {
  let threadId = options.thread.id;
  let status = "in_progress";
  let finalResponse = "";
  let usage = null;
  let lastStreamError = null;
  for await (const event of eventsWithOptionalUsage(options.events)) {
    await options.onEvent(event);
    if (
      event.type === "thread.started" &&
      typeof event["thread_id"] === "string"
    ) {
      threadId = event["thread_id"];
    } else if (
      event.type === "item.completed" &&
      isRecord(event["item"]) &&
      event["item"]["type"] === "agent_message" &&
      typeof event["item"]["text"] === "string"
    ) {
      finalResponse = event["item"]["text"];
    } else if (event.type === "turn.completed") {
      status = "completed";
      usage = event["usage"] ?? null;
      if (options.stopOnCompletion) break;
    } else if (event.type === "error" && typeof event["message"] === "string") {
      lastStreamError = event["message"];
    }
  }
  return { threadId, status, finalResponse, usage, lastStreamError };
}

async function* eventsWithOptionalUsage(events) {
  try {
    yield* events;
  } catch (error) {
    // The pinned SDK accesses this field before yielding a completion with
    // absent usage. Preserve completion without inventing a zero-token receipt.
    if (
      error instanceof TypeError &&
      /\b(?:null|undefined)\b/u.test(error.message) &&
      /\bcache_write_input_tokens\b/u.test(error.message)
    ) {
      yield { type: "turn.completed", usage: null };
      return;
    }
    throw error;
  }
}

function isRecord(value) {
  return typeof value === "object" && value !== null;
}

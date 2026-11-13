import { randomUUID } from "node:crypto";
import { isRecord } from "./record.js";

/** Map the text/function subset used by the scanner to HF's chat endpoint. */
export function huggingFaceChatRequest(request: Record<string, unknown>) {
  if (
    request["previous_response_id"] != null ||
    request["conversation"] != null
  )
    throw new Error(
      "HF chat needs the full conversation history in the input.",
    );
  const messages: Record<string, unknown>[] = [];
  if (request["instructions"])
    messages.push({ role: "system", content: request["instructions"] });
  messages.push({
    role: "system",
    content:
      "This transport uses Chat Completions and has no separate commentary channel. An assistant response without tool calls ends your turn. While work remains, include the next tool call in the same response as any progress update. Return a text-only response only when the task is complete or cannot proceed.",
  });
  const input =
    typeof request["input"] === "string"
      ? [{ role: "user", content: request["input"] }]
      : request["input"];
  if (!Array.isArray(input)) throw new Error("Invalid HF conversation input.");
  for (const item of input) {
    if (!isRecord(item)) throw new Error("Invalid HF conversation item.");
    if (item["type"] === "reasoning") continue;
    if (item["type"] === "function_call") {
      const call = {
        id: item["call_id"],
        type: "function",
        function: { name: item["name"], arguments: item["arguments"] },
      };
      const previous = messages.at(-1);
      if (previous?.["role"] === "assistant") {
        previous["tool_calls"] = [
          ...(Array.isArray(previous["tool_calls"])
            ? previous["tool_calls"]
            : []),
          call,
        ];
      } else
        messages.push({ role: "assistant", content: null, tool_calls: [call] });
    } else if (item["type"] === "function_call_output") {
      const output = item["output"];
      messages.push({
        role: "tool",
        tool_call_id: item["call_id"],
        content: typeof output === "string" ? output : content(output),
      });
    } else if (typeof item["role"] === "string") {
      messages.push({
        role: item["role"] === "developer" ? "system" : item["role"],
        content: content(item["content"]),
      });
    } else
      throw new Error(`HF does not support conversation item ${item["type"]}.`);
  }
  const format = isRecord(request["text"])
    ? request["text"]["format"]
    : undefined;
  let responseFormat;
  if (isRecord(format) && format["type"] === "json_schema") {
    const { type, ...json_schema } = format;
    responseFormat = { type, json_schema };
  } else if (isRecord(format) && format["type"] === "json_object") {
    responseFormat = { type: "json_object" };
  } else if (
    format != null &&
    (!isRecord(format) || format["type"] !== "text")
  ) {
    throw new Error("Unsupported HF response format.");
  }
  const reasoning = request["reasoning"];
  return {
    model: request["model"],
    messages,
    tools: (Array.isArray(request["tools"]) ? request["tools"] : []).map(
      (tool) => {
        if (!isRecord(tool) || tool["type"] !== "function")
          throw new Error(
            "HF scans require local function tools; remote MCP tools are not supported.",
          );
        const { type: _type, ...definition } = tool;
        return { type: "function", function: definition };
      },
    ),
    ...(request["tool_choice"] === undefined
      ? {}
      : { tool_choice: request["tool_choice"] }),
    ...(request["parallel_tool_calls"] === undefined
      ? {}
      : { parallel_tool_calls: request["parallel_tool_calls"] }),
    ...(request["max_output_tokens"] === undefined
      ? {}
      : { max_tokens: request["max_output_tokens"] }),
    ...(request["temperature"] === undefined
      ? {}
      : { temperature: request["temperature"] }),
    ...(request["top_p"] === undefined ? {} : { top_p: request["top_p"] }),
    ...(isRecord(reasoning) && reasoning["effort"] !== undefined
      ? { reasoning_effort: reasoning["effort"] }
      : {}),
    ...(responseFormat === undefined
      ? {}
      : { response_format: responseFormat }),
    stream: true,
    stream_options: { include_usage: true },
  };
}

function content(value: unknown): unknown {
  if (typeof value === "string" || value === null) return value;
  if (!Array.isArray(value)) throw new Error("Invalid HF message content.");
  return value.map((part) => {
    if (!isRecord(part)) throw new Error("Invalid HF content part.");
    if (part["type"] === "input_text" || part["type"] === "output_text")
      return { type: "text", text: part["text"] };
    if (part["type"] === "input_image")
      return {
        type: "image_url",
        image_url: {
          url: part["image_url"],
          ...(part["detail"] === undefined ? {} : { detail: part["detail"] }),
        },
      };
    throw new Error(`HF does not support content part ${part["type"]}.`);
  });
}

/** Retain usage and finish status; never turn a truncated generation into success. */
export function huggingFaceChatResponse() {
  let text = "";
  let refusal = "";
  let usage: Record<string, unknown> | undefined;
  let finish: unknown;
  const calls = new Map<
    number,
    { id: string; name: string; arguments: string }
  >();
  return {
    add(chunk: Record<string, unknown>) {
      if (chunk["error"]) throw new Error(JSON.stringify(chunk["error"]));
      if (isRecord(chunk["usage"])) usage = chunk["usage"];
      for (const choice of Array.isArray(chunk["choices"])
        ? chunk["choices"]
        : []) {
        if (!isRecord(choice) || choice["index"] !== 0) continue;
        if (choice["finish_reason"] != null) finish = choice["finish_reason"];
        const delta = choice["delta"];
        if (!isRecord(delta)) continue;
        if (typeof delta["refusal"] === "string") refusal += delta["refusal"];
        if (typeof delta["content"] === "string") text += delta["content"];
        for (const fragment of Array.isArray(delta["tool_calls"])
          ? delta["tool_calls"]
          : []) {
          if (!isRecord(fragment) || typeof fragment["index"] !== "number")
            throw new Error("Invalid HF tool-call fragment.");
          const call = calls.get(fragment["index"]) ?? {
            id: "",
            name: "",
            arguments: "",
          };
          if (typeof fragment["id"] === "string") call.id = fragment["id"];
          const fn = fragment["function"];
          if (isRecord(fn)) {
            if (typeof fn["name"] === "string") call.name += fn["name"];
            if (typeof fn["arguments"] === "string")
              call.arguments += fn["arguments"];
          }
          calls.set(fragment["index"], call);
        }
      }
    },
    finish() {
      if (refusal) throw new Error(`HF refused the request: ${refusal}`);
      if (finish !== "stop" && finish !== "tool_calls")
        throw new Error(
          `HF generation did not complete (finish_reason=${String(finish)}).`,
        );
      if (finish === "tool_calls" && !calls.size)
        throw new Error(
          "HF finished with tool_calls but returned no tool calls.",
        );
      const output: Record<string, unknown>[] = [];
      if (text)
        output.push({
          type: "message",
          id: `msg_${randomUUID()}`,
          role: "assistant",
          status: "completed",
          content: [{ type: "output_text", text, annotations: [] }],
        });
      for (const [, call] of [...calls].sort(([a], [b]) => a - b)) {
        if (!call.id || !call.name) throw new Error("Incomplete HF tool call.");
        output.push({
          type: "function_call",
          id: `fc_${randomUUID()}`,
          call_id: call.id,
          name: call.name,
          arguments: call.arguments,
          status: "completed",
        });
      }
      if (output.length === 0)
        throw new Error(
          "HF generation ended without assistant content or tool calls.",
        );
      const promptDetails = isRecord(usage?.["prompt_tokens_details"])
        ? usage["prompt_tokens_details"]
        : {};
      const completionDetails = isRecord(usage?.["completion_tokens_details"])
        ? usage["completion_tokens_details"]
        : {};
      return {
        id: `resp_${randomUUID()}`,
        object: "response",
        status: "completed",
        output,
        ...(usage === undefined
          ? {}
          : {
              usage: {
                input_tokens: usage["prompt_tokens"],
                output_tokens: usage["completion_tokens"],
                total_tokens: usage["total_tokens"],
                input_tokens_details: {
                  cached_tokens: promptDetails["cached_tokens"] ?? 0,
                },
                output_tokens_details: {
                  reasoning_tokens: completionDetails["reasoning_tokens"] ?? 0,
                },
              },
            }),
      };
    },
  };
}

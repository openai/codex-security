import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import { json } from "node:stream/consumers";
import { pipeline } from "node:stream/promises";
import { asRecord, isRecord } from "./record.js";
import { errorMessage } from "./errors.js";

type Item = Record<string, unknown>;

// Declarations, tool choices and historical calls must use the same spelling,
// even when a tool is no longer offered on the current turn.
function identity({ name, type, namespace }: Item) {
  if (
    typeof name !== "string" ||
    (namespace != null && typeof namespace !== "string")
  )
    throw new Error("Invalid xAI tool identity.");
  const custom = type === "custom" || type === "custom_tool_call";
  const key = JSON.stringify([namespace ?? "", name, custom]);
  let alias = name;
  if (custom || namespace != null) {
    // Keep names readable, unique and under the 64-character limit.
    const prefix = (namespace ? `${namespace}__${name}` : name)
      .replace(/[^a-zA-Z0-9_-]/g, "_")
      .slice(0, 48);
    const suffix = createHash("sha256").update(key).digest("hex").slice(0, 12);
    alias = `${prefix}_${suffix}`;
  }
  const message =
    namespace === "collaboration" &&
    ["spawn_agent", "send_message", "followup_task"].includes(name);
  return { name, namespace, custom, message, alias, key };
}

function requirePlaintext(args: unknown) {
  if (args != null && !(Array.isArray(args) && args.length === 0)) {
    throw new Error("xAI supports only plaintext collaboration messages.");
  }
}

function replayInput(raw: unknown): unknown {
  if (!isRecord(raw)) return raw;
  const value = { ...raw };
  delete value["internal_chat_message_metadata_passthrough"];
  const { type } = value;
  if (type === "function_call" || type === "custom_tool_call") {
    const tool = identity(value);
    if (tool.message) {
      requirePlaintext(value["encrypted_function_args"]);
      delete value["encrypted_function_args"];
    }
    if (tool.custom) {
      value["type"] = "function_call";
      value["arguments"] = JSON.stringify({ input: value["input"] });
      delete value["input"];
    }
    delete value["namespace"];
    value["name"] = tool.alias;
  }
  if (type === "custom_tool_call_output")
    value["type"] = "function_call_output";
  if (type === "agent_message") {
    const { author, recipient, content } = value;
    if (
      typeof author !== "string" ||
      typeof recipient !== "string" ||
      !Array.isArray(content)
    )
      throw new Error("Invalid agent message in xAI replay.");
    const blocks = content.map((part: unknown) => {
      const { type, text } = asRecord(part) ?? {};
      if (type !== "input_text" || typeof text !== "string")
        throw new Error("xAI replay supports only plaintext agent messages.");
      return text;
    });
    return {
      type: "message",
      role: "assistant",
      ...(typeof value["id"] === "string" ? { id: value["id"] } : {}),
      content: `Agent message from ${JSON.stringify(author)} to ${JSON.stringify(recipient)}\n${blocks.join("\n")}`,
    };
  }
  if (type === "reasoning" && value["content"] === null)
    delete value["content"];
  return value;
}

/** Translate xAI tools and keep their identities local to the request. */
export function responsesCompatRequest(request: Item) {
  const identities = new Map<string, ReturnType<typeof identity>>();
  function tools(values: unknown[], namespace?: string): Item[] {
    return values.flatMap<Item>((value) => {
      if (!isRecord(value)) throw new Error("Invalid xAI tool declaration.");
      const { type, format } = value;
      if (type === "namespace" && Array.isArray(value["tools"]))
        return tools(value["tools"], String(value["name"]));
      if (type !== "custom" && type !== "function") return value;
      const tool = identity({ ...value, namespace });
      const name = tool.alias;
      const previous = identities.get(name);
      if (previous && previous.key !== tool.key)
        throw new Error(`Tool alias ${name} collides with another tool.`);
      identities.set(name, tool);
      if (!tool.custom && namespace === undefined) return value;
      const description = `${namespace ? namespace + "." : ""}${tool.name}: ${value["description"] ?? ""}`;
      if (tool.message) {
        const parameters = structuredClone(value["parameters"]);
        const fields = asRecord(parameters)?.["properties"];
        if (isRecord(fields) && isRecord(fields["message"]))
          delete fields["message"]["encrypted"];
        return { ...value, name, description, parameters };
      }
      if (!tool.custom) return { ...value, name, description };
      const input = {
        type: "string",
        description:
          isRecord(format) && format["type"] === "grammar"
            ? `The complete freeform tool input, matching this ${format["syntax"]} grammar:\n${format["definition"]}`
            : "The complete freeform tool input.",
      };
      return {
        type: "function",
        name,
        description,
        strict: true,
        parameters: {
          type: "object",
          properties: { input },
          required: ["input"],
          additionalProperties: false,
        },
      };
    });
  }
  const { tools: declared, input, tool_choice: choice } = request;
  const flattened = tools(Array.isArray(declared) ? declared : []);
  const body: Item = { ...request, tools: flattened };
  if (Array.isArray(input)) body["input"] = input.map(replayInput);
  if (
    isRecord(choice) &&
    (choice["type"] === "function" || choice["type"] === "custom")
  ) {
    const tool = identity(choice);
    if (tool.custom || tool.namespace != null)
      body["tool_choice"] = { type: "function", name: tool.alias };
  }
  if (flattened.length === 0) delete body["tool_choice"];
  function output(value: Item, done = true): Item | undefined {
    const { type, namespace, name } = value;
    if (type !== "function_call" && type !== "custom_tool_call") return value;
    // Codex dispatches done items even when the call is marked incomplete.
    if (type === "function_call" && done && unfinished(value)) return;
    if (type !== "function_call" || namespace != null)
      throw new Error("Expected a flattened function call from xAI.");
    const tool = typeof name === "string" ? identities.get(name) : undefined;
    if (!tool) throw new Error(`xAI returned an unknown tool: ${name}`);
    if (!tool.custom && tool.namespace == null) return value;
    const restored: Item = { ...value, name: tool.name };
    if (tool.namespace != null) restored["namespace"] = tool.namespace;
    // Codex treats an absent list as an encrypted collaboration message.
    // xAI returned plain JSON, so mark the arguments explicitly as plaintext.
    if (tool.message) {
      requirePlaintext(value["encrypted_function_args"]);
      restored["encrypted_function_args"] = [];
    }
    if (tool.custom) {
      // Added events have no input yet. Decode only completed calls.
      const args = value["arguments"];
      const input = done
        ? typeof args === "string" && asRecord(JSON.parse(args))?.["input"]
        : "";
      if (typeof input !== "string")
        throw new Error(`Invalid xAI input for custom tool ${tool.name}.`);
      delete restored["arguments"];
      restored["type"] = "custom_tool_call";
      restored["input"] = input;
    }
    return restored;
  }
  return { body, output };
}

/** Read complete SSE frames, including CR, LF, or CRLF split across chunks. */
async function* compatFrames(body: ReadableStream<Uint8Array>) {
  let buffer = "";
  const decoder = new TextDecoder();
  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    let boundary: RegExpExecArray | null;
    // A CRLF is one line ending, even when its bytes arrive separately.
    while ((boundary = /(?:\r\n|\r(?!\n)|\n){2}/.exec(buffer)) !== null) {
      const frame = buffer.slice(0, boundary.index);
      buffer = buffer.slice(boundary.index + boundary[0].length);
      const data = frame
        .split(/\r\n|\r|\n/)
        .filter((line) => line === "data" || line.startsWith("data:"))
        .map((line) => line.slice(5).replace(/^ /, ""))
        .join("\n");
      if (data) yield data;
    }
  }
  if ((buffer + decoder.decode()).trim())
    throw new Error("Incomplete xAI stream.");
}

type RestoreTool = ReturnType<typeof responsesCompatRequest>["output"];

function unfinished({ status }: Item) {
  return status != null && status !== "completed";
}

function restoreOutput(response: unknown, restore: RestoreTool) {
  if (!isRecord(response)) throw new Error("Invalid xAI response.");
  // An unfinished response can contain truncated JSON in a tool's arguments.
  // Keep that evidence and the provider's failure or interruption reason.
  if (!unfinished(response) && Array.isArray(response["output"])) {
    response["output"] = response["output"].flatMap((item: unknown) =>
      isRecord(item) ? (restore(item) ?? []) : [item],
    );
  }
  return response;
}

async function* translateEvents(
  body: ReadableStream<Uint8Array>,
  restore: RestoreTool,
) {
  try {
    for await (const data of compatFrames(body)) {
      if (data === "[DONE]") return;
      const event: unknown = JSON.parse(data);
      if (!isRecord(event)) throw new Error("Invalid xAI event.");
      const { type, item } = event;
      if (isRecord(item)) {
        event["item"] = restore(item, type === "response.output_item.done");
        if (!event["item"]) continue;
      }
      if (type === "response.completed")
        restoreOutput(event["response"], restore);
      yield `data: ${JSON.stringify(event)}\n\n`;
    }
  } catch (error) {
    const response = {
      status: "failed",
      error: { message: errorMessage(error) },
    };
    yield `data: ${JSON.stringify({ type: "response.failed", response })}\n\n`;
  }
}

const connectionHeaders = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  // Fetch calculates these for the translated request or decoded response body.
  "host",
  "content-length",
  "content-encoding",
  "accept-encoding",
];

function forwardedHeaders(source: Headers): Headers {
  const result = new Headers(source);
  for (const name of (source.get("connection") ?? "").split(","))
    if (name.trim()) result.delete(name.trim());
  for (const name of connectionHeaders) result.delete(name);
  return result;
}

/** Rewrite only the selected private provider for the lifetime of its profile. */
export async function routeXaiProvider(definition: unknown) {
  if (!isRecord(definition)) return;
  const { base_url, wire_api, supports_websockets } = definition;
  const upstream = "https://api.x.ai/v1";
  if (
    (base_url !== upstream && base_url !== upstream + "/") ||
    (wire_api ?? "responses") !== "responses" ||
    supports_websockets === true
  )
    return;
  const proxy = await startResponsesCompatProxy(upstream);
  definition["base_url"] = proxy.baseUrl;
  return proxy;
}

export async function startResponsesCompatProxy(upstream: string) {
  const upstreamUrl = new URL(upstream);
  upstreamUrl.pathname = upstreamUrl.pathname.replace(/\/$/, "") + "/responses";
  const path = `/${randomUUID()}/v1`;
  const server = createServer(async (request, response) => {
    const controller = new AbortController();
    response.on("close", () => controller.abort());
    let errorStatus = 400;
    try {
      const url = new URL(request.url ?? "/", "http://localhost");
      if (request.method !== "POST" || url.pathname !== path + "/responses") {
        response.writeHead(404).end();
        return;
      }
      const parsed = await json(request);
      if (!isRecord(parsed))
        throw new Error("Expected a JSON Responses request.");
      const { body, output } = responsesCompatRequest(parsed);
      const headers = new Headers();
      for (const [name, value] of Object.entries(request.headers))
        if (value !== undefined)
          headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      const target = new URL(upstreamUrl.href);
      for (const [name, value] of url.searchParams)
        target.searchParams.append(name, value);
      errorStatus = 502;
      const result = await fetch(target, {
        method: "POST",
        headers: forwardedHeaders(headers),
        body: JSON.stringify(body),
        signal: controller.signal,
        // A redirect can otherwise replay scan prompts and provider credentials.
        redirect: "error",
      });
      const forwarded = Object.fromEntries(forwardedHeaders(result.headers));
      if (!result.ok) {
        response.writeHead(result.status, forwarded).end(await result.text());
      } else if (
        result.body &&
        /^text\/event-stream(?:\s*;|$)/i.test(forwarded["content-type"] ?? "")
      ) {
        response.writeHead(result.status, forwarded);
        await pipeline(translateEvents(result.body, output), response);
      } else {
        const payload = restoreOutput(await result.json(), output);
        forwarded["content-type"] = "application/json";
        response
          .writeHead(result.status, forwarded)
          .end(JSON.stringify(payload));
      }
    } catch (error) {
      if (response.destroyed) return;
      if (response.headersSent) response.destroy();
      else
        response
          .writeHead(errorStatus, { "content-type": "application/json" })
          .end(JSON.stringify({ error: { message: errorMessage(error) } }));
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("Responses compat proxy did not bind a TCP port.");
  let closing: Promise<void> | undefined;
  return {
    baseUrl: `http://127.0.0.1:${address.port}${path}`,
    close() {
      closing ??= server[Symbol.asyncDispose]();
      server.closeAllConnections();
      return closing;
    },
  };
}

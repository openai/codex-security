import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import { json } from "node:stream/consumers";
import { pipeline } from "node:stream/promises";
import { isRecord } from "./record.js";
import { errorMessage } from "./errors.js";

interface CompatToolIdentity {
  name: string;
  namespace?: string;
  custom: boolean;
}

function collaborationMessage(tool: CompatToolIdentity): boolean {
  return (
    tool.namespace === "collaboration" &&
    ["spawn_agent", "send_message", "followup_task"].includes(tool.name)
  );
}

function requirePlaintext(args: unknown) {
  if (args != null && !(Array.isArray(args) && args.length === 0)) {
    throw new Error("xAI supports only plaintext collaboration messages.");
  }
}

/** Translate xAI tools and keep their identities local to the request. */
export function responsesCompatRequest(request: Record<string, unknown>) {
  const identities = new Map<string, CompatToolIdentity>();
  const declared = Array.isArray(request["tools"]) ? request["tools"] : [];
  const plainNames = new Set(
    declared.flatMap((tool) =>
      isRecord(tool) && tool["type"] === "function" ? [tool["name"]] : [],
    ),
  );
  function alias(identity: CompatToolIdentity): string {
    // Function names are limited to 64 characters. Keep names readable without
    // letting truncation or namespace separators merge distinct tool identities.
    const label = [identity.namespace, identity.name]
      .filter(Boolean)
      .join("__")
      .replace(/[^a-zA-Z0-9_-]/g, "_")
      .slice(0, 48);
    return `${label}_${createHash("sha256")
      .update(
        JSON.stringify([
          identity.namespace ?? "",
          identity.name,
          identity.custom,
        ]),
      )
      .digest("hex")
      .slice(0, 12)}`;
  }
  function identity(
    tool: Record<string, unknown>,
    namespace?: string,
  ): CompatToolIdentity {
    if (typeof tool["name"] !== "string")
      throw new Error("Responses compat proxy tool has no name.");
    return {
      name: tool["name"],
      ...(namespace === undefined ? {} : { namespace }),
      custom: tool["type"] === "custom" || tool["type"] === "custom_tool_call",
    };
  }
  function register(tool: CompatToolIdentity): string {
    const name = alias(tool);
    const existing = identities.get(name);
    if (
      plainNames.has(name) ||
      (existing && JSON.stringify(existing) !== JSON.stringify(tool))
    ) {
      throw new Error(`Tool alias ${name} collides with another tool.`);
    }
    identities.set(name, tool);
    return name;
  }
  function tools(values: unknown[], namespace?: string): unknown[] {
    return values.flatMap((value) => {
      if (!isRecord(value))
        throw new Error("Invalid Responses compat proxy tool declaration.");
      if (value["type"] === "namespace" && Array.isArray(value["tools"])) {
        return tools(value["tools"], String(value["name"]));
      }
      if (
        value["type"] !== "custom" &&
        (value["type"] !== "function" || namespace === undefined)
      )
        return [value];
      const tool = identity(value, namespace);
      const name = register(tool);
      const description = `${namespace ? namespace + "." : ""}${tool.name}: ${value["description"] ?? ""}`;
      if (collaborationMessage(tool)) {
        const parameters = structuredClone(value["parameters"]);
        const fields = isRecord(parameters)
          ? parameters["properties"]
          : undefined;
        if (isRecord(fields) && isRecord(fields["message"]))
          delete fields["message"]["encrypted"];
        return [{ ...value, name, description, parameters }];
      }
      if (!tool.custom) return [{ ...value, name, description }];
      const format = value["format"];
      return [
        {
          type: "function",
          name,
          description,
          parameters: {
            type: "object",
            properties: {
              input: {
                type: "string",
                description:
                  isRecord(format) && format["type"] === "grammar"
                    ? `The complete freeform tool input, matching this ${format["syntax"]} grammar:\n${format["definition"]}`
                    : "The complete freeform tool input.",
              },
            },
            required: ["input"],
            additionalProperties: false,
          },
          strict: true,
        },
      ];
    });
  }
  function input(raw: unknown): unknown {
    if (!isRecord(raw)) return raw;
    const { internal_chat_message_metadata_passthrough: _metadata, ...value } =
      raw;
    if (
      value["type"] === "function_call" ||
      value["type"] === "custom_tool_call"
    ) {
      const tool = identity(
        value,
        typeof value["namespace"] === "string" ? value["namespace"] : undefined,
      );
      const { namespace: _namespace, input: freeform, ...rest } = value;
      if (collaborationMessage(tool)) {
        requirePlaintext(rest["encrypted_function_args"]);
        delete rest["encrypted_function_args"];
      }
      if (!tool.custom && tool.namespace === undefined) return value;
      return {
        ...rest,
        type: "function_call",
        name: alias(tool),
        arguments: tool.custom
          ? JSON.stringify({ input: freeform })
          : value["arguments"],
      };
    }
    if (value["type"] === "custom_tool_call_output")
      return { ...value, type: "function_call_output" };
    if (value["type"] === "agent_message") {
      const { author, recipient, content } = value;
      if (
        typeof author !== "string" ||
        typeof recipient !== "string" ||
        !Array.isArray(content)
      )
        throw new Error("Invalid agent message in xAI replay.");
      const blocks = content.map((part: unknown) => {
        if (
          !isRecord(part) ||
          part["type"] !== "input_text" ||
          typeof part["text"] !== "string"
        )
          throw new Error("xAI replay supports only plaintext agent messages.");
        return part["text"];
      });
      return {
        type: "message",
        role: "assistant",
        ...(typeof value["id"] === "string" ? { id: value["id"] } : {}),
        content: `Agent message from ${JSON.stringify(author)} to ${JSON.stringify(recipient)}\n${blocks.join("\n")}`,
      };
    }
    if (value["type"] === "reasoning" && value["content"] === null) {
      const { content: _content, ...rest } = value;
      return rest;
    }
    return value;
  }
  const flattenedTools = tools(declared);
  const body: Record<string, unknown> = {
    ...request,
    tools: flattenedTools,
    input: Array.isArray(request["input"])
      ? request["input"].map(input)
      : request["input"],
  };
  const choice = request["tool_choice"];
  if (
    isRecord(choice) &&
    (choice["type"] === "function" || choice["type"] === "custom")
  ) {
    const tool = identity(
      choice,
      typeof choice["namespace"] === "string" ? choice["namespace"] : undefined,
    );
    body["tool_choice"] =
      tool.namespace !== undefined || tool.custom
        ? { type: "function", name: alias(tool) }
        : choice;
  }
  if (flattenedTools.length === 0) delete body["tool_choice"];
  function output(
    value: Record<string, unknown>,
    parseArguments = true,
  ): Record<string, unknown> {
    if (
      value["type"] !== "function_call" &&
      value["type"] !== "custom_tool_call"
    )
      return value;
    if (value["type"] !== "function_call" || value["namespace"] != null)
      throw new Error("Expected a flattened function call from xAI.");
    const tool = identities.get(String(value["name"]));
    if (tool === undefined) {
      if (plainNames.has(value["name"])) return value;
      throw new Error(
        `Responses compat proxy returned an unknown tool: ${value["name"]}`,
      );
    }
    const { arguments: args, ...rest } = value;
    // Codex treats an absent list as an encrypted collaboration message.
    // xAI returned plain JSON, so mark the arguments explicitly as plaintext.
    if (collaborationMessage(tool)) {
      requirePlaintext(rest["encrypted_function_args"]);
      rest["encrypted_function_args"] = [];
    }
    const restored = {
      ...rest,
      name: tool.name,
      ...(tool.namespace === undefined ? {} : { namespace: tool.namespace }),
    };
    if (!tool.custom) return { ...restored, arguments: args };
    // A stream's added event carries empty arguments; restore the identity
    // there and parse the input at output_item.done instead.
    if (!parseArguments)
      return { ...restored, type: "custom_tool_call", input: "" };
    const parsed = JSON.parse(String(args)) as unknown;
    const freeform = isRecord(parsed) ? parsed["input"] : undefined;
    if (typeof freeform !== "string")
      throw new Error(
        `Responses compat proxy returned invalid input for custom tool ${tool.name}.`,
      );
    return { ...restored, type: "custom_tool_call", input: freeform };
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
    throw new Error("Incomplete Responses compat proxy stream.");
}

type RestoreTool = ReturnType<typeof responsesCompatRequest>["output"];

function restoreOutput(response: unknown, restore: RestoreTool) {
  if (!isRecord(response)) throw new Error("Invalid xAI response.");
  if (Array.isArray(response["output"])) {
    response["output"] = response["output"].map((item: unknown) =>
      isRecord(item) ? restore(item) : item,
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
      if (isRecord(event["item"])) {
        event["item"] = restore(
          event["item"],
          event["type"] !== "response.output_item.added",
        );
      }
      if (isRecord(event["response"]))
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

const connectionHeaders = new Set([
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
]);

function forwardedHeaders(source: Headers): Headers {
  const result = new Headers(source);
  for (const name of (source.get("connection") ?? "").split(","))
    if (name.trim()) result.delete(name.trim());
  for (const name of connectionHeaders) result.delete(name);
  return result;
}

/**
 * Translate one Responses provider through a loopback proxy. Scoped to a
 * private native provider profile; the profile cleanup closes the server.
 * Headers (including authorization) are forwarded as-is and never logged.
 */
export async function startResponsesCompatProxy(upstream: string) {
  const upstreamUrl = new URL(upstream);
  upstreamUrl.pathname = upstreamUrl.pathname.replace(/\/$/, "") + "/responses";
  const route = `/${randomUUID()}/v1/responses`;
  const server = createServer((request, response) => {
    const controller = new AbortController();
    response.on("close", () => controller.abort());
    void (async () => {
      const requestedUrl = new URL(request.url ?? "/", "http://localhost");
      if (request.method !== "POST" || requestedUrl.pathname !== route) {
        response.writeHead(404).end();
        return;
      }
      let translation: ReturnType<typeof responsesCompatRequest>;
      try {
        const parsed = await json(request);
        if (!isRecord(parsed))
          throw new Error(
            "Responses compat proxy requires a JSON Responses request.",
          );
        translation = responsesCompatRequest(parsed);
      } catch (error) {
        response
          .writeHead(400, { "content-type": "application/json" })
          .end(JSON.stringify({ error: { message: errorMessage(error) } }));
        return;
      }
      const headers = new Headers();
      for (const [name, value] of Object.entries(request.headers))
        if (value !== undefined)
          headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      const target = new URL(upstreamUrl.href);
      for (const [name, value] of requestedUrl.searchParams)
        target.searchParams.append(name, value);
      const result = await fetch(target, {
        method: "POST",
        headers: forwardedHeaders(headers),
        body: JSON.stringify(translation.body),
        signal: controller.signal,
        // A redirect can otherwise replay scan prompts and provider credentials.
        redirect: "error",
      });
      const forwarded = Object.fromEntries(forwardedHeaders(result.headers));
      const type = result.headers
        .get("content-type")
        ?.split(";")[0]
        ?.trim()
        .toLowerCase();
      if (!result.ok) {
        response.writeHead(result.status, forwarded).end(await result.text());
      } else if (type === "text/event-stream" && result.body) {
        response.writeHead(result.status, forwarded);
        await pipeline(
          translateEvents(result.body, translation.output),
          response,
        );
      } else {
        const payload = restoreOutput(await result.json(), translation.output);
        response
          .writeHead(result.status, {
            ...forwarded,
            "content-type": "application/json",
          })
          .end(JSON.stringify(payload));
      }
    })().catch((error: unknown) => {
      if (response.destroyed) return;
      if (response.headersSent)
        response.destroy(
          error instanceof Error ? error : new Error(String(error)),
        );
      else
        response
          .writeHead(502, { "content-type": "application/json" })
          .end(JSON.stringify({ error: { message: errorMessage(error) } }));
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("Responses compat proxy did not bind a TCP port.");
  let closing: Promise<void> | undefined;
  return {
    baseUrl: `http://127.0.0.1:${address.port}${route.slice(0, -"/responses".length)}`,
    close() {
      return (closing ??= new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      }));
    },
  };
}

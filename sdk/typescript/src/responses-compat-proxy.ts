import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { isRecord } from "./record.js";
import { errorMessage } from "./errors.js";

interface CompatToolIdentity {
  name: string;
  namespace?: string;
  custom: boolean;
}

/**
 * The xAI Responses endpoint rejects the
 * `namespace` tool type and the `custom` tool type, so Codex scans through a
 * custom provider fail with a 422 before the first turn. Flatten namespaced
 * and custom tools to plain `function` tools on the way out and restore the
 * original calls on the way back, for JSON and streaming responses.
 */
export function responsesCompatRequest(request: Record<string, unknown>) {
  const identities = new Map<string, CompatToolIdentity>();
  const plainNames = new Set<string>();
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
    if (plainNames.has(name))
      throw new Error(
        `Responses compat proxy tool alias ${name} collides with a plain tool name.`,
      );
    const existing = identities.get(name);
    if (
      existing !== undefined &&
      JSON.stringify(existing) !== JSON.stringify(tool)
    )
      throw new Error(
        `Responses compat proxy tool alias ${name} collides with another tool.`,
      );
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
      if (value["type"] === "function") {
        if (typeof value["name"] !== "string")
          throw new Error("Responses compat proxy tool has no name.");
        if (namespace === undefined) return [value];
        const tool = identity(value, namespace);
        return [
          {
            type: "function",
            name: register(tool),
            description: `${namespace}.${tool.name}: ${value["description"] ?? ""}`,
            parameters: value["parameters"],
            strict: value["strict"],
          },
        ];
      }
      if (value["type"] !== "custom") {
        // Tool types the proxy does not translate (for example web_search)
        // pass through unchanged; the upstream rejects what it cannot serve.
        return [value];
      }
      const tool = identity(value, namespace);
      const format = value["format"];
      return [
        {
          type: "function",
          name: register(tool),
          description: `${namespace ? namespace + "." : ""}${tool.name}: ${value["description"] ?? ""}`,
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
  // Plain names must be known before aliases are checked for collisions.
  const declaredTools = Array.isArray(request["tools"]) ? request["tools"] : [];
  for (const value of declaredTools) {
    if (
      isRecord(value) &&
      value["type"] === "function" &&
      typeof value["name"] === "string"
    )
      plainNames.add(value["name"]);
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
      const aliased = tool.namespace !== undefined || tool.custom;
      return {
        ...rest,
        type: "function_call",
        name: aliased ? alias(tool) : tool.name,
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
  const flattenedTools = tools(declaredTools);
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
        ? { type: "function", name: register(tool) }
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
    const tool = identities.get(String(value["name"]));
    if (tool === undefined) {
      if (
        value["type"] === "function_call" &&
        plainNames.has(String(value["name"]))
      )
        return value;
      throw new Error(
        `Responses compat proxy returned an unknown tool: ${value["name"]}`,
      );
    }
    const { arguments: args, ...rest } = value;
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
  let upstreamUrl: URL;
  try {
    upstreamUrl = new URL(upstream);
  } catch {
    throw new Error(
      `Responses compat proxy upstream is not a valid URL: ${upstream}`,
    );
  }
  if (upstreamUrl.protocol !== "http:" && upstreamUrl.protocol !== "https:")
    throw new Error(
      `Responses compat proxy upstream must use http or https: ${upstream}`,
    );
  if (!upstreamUrl.hostname)
    throw new Error(`Responses compat proxy upstream has no host: ${upstream}`);
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
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      let translation: ReturnType<typeof responsesCompatRequest>;
      try {
        const parsed: unknown = JSON.parse(
          Buffer.concat(chunks).toString("utf8"),
        );
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
      target.pathname = `${target.pathname.replace(/\/$/, "")}/responses`;
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
      const contentType = result.headers.get("content-type") ?? "";
      if (!result.ok) {
        const responseHeaders = Object.fromEntries(
          forwardedHeaders(result.headers),
        );
        response
          .writeHead(result.status, responseHeaders)
          .end(await result.text());
      } else if (
        contentType.split(";")[0]?.trim().toLowerCase() ===
          "text/event-stream" &&
        result.body
      ) {
        response.writeHead(result.status, { "content-type": contentType });
        async function* events() {
          try {
            for await (const data of compatFrames(result.body!)) {
              if (data === "[DONE]") break;
              const event: unknown = JSON.parse(data);
              if (!isRecord(event))
                throw new Error("Invalid Responses compat proxy stream event.");
              if (
                (event["type"] === "response.output_item.added" ||
                  event["type"] === "response.output_item.done") &&
                isRecord(event["item"])
              ) {
                const item = translation.output(
                  event["item"],
                  event["type"] !== "response.output_item.added",
                );
                yield `data: ${JSON.stringify({ ...event, item })}\n\n`;
              } else if (
                event["type"] === "response.completed" &&
                isRecord(event["response"]) &&
                Array.isArray(event["response"]["output"])
              ) {
                const restored = {
                  ...event["response"],
                  output: event["response"]["output"].map((item: unknown) =>
                    isRecord(item) ? translation.output(item) : item,
                  ),
                };
                yield `data: ${JSON.stringify({ ...event, response: restored })}\n\n`;
              } else {
                yield `data: ${data}\n\n`;
              }
            }
          } catch (error) {
            yield `data: ${JSON.stringify({ type: "response.failed", response: { status: "failed", error: { message: errorMessage(error) } } })}\n\n`;
          }
        }
        await pipeline(Readable.from(events()), response);
      } else {
        const payload: unknown = JSON.parse(await result.text());
        if (!isRecord(payload))
          throw new Error("Invalid Responses compat proxy response.");
        const output = Array.isArray(payload["output"])
          ? payload["output"].map((item: unknown) =>
              isRecord(item) ? translation.output(item) : item,
            )
          : payload["output"];
        response
          .writeHead(result.status, { "content-type": "application/json" })
          .end(JSON.stringify({ ...payload, output }));
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

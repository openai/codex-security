import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { isRecord } from "./record.js";
import {
  huggingFaceChatRequest,
  huggingFaceChatResponse,
} from "./huggingface-chat.js";

interface ToolIdentity {
  name: string;
  namespace?: string;
  custom: boolean;
}

/** HF chat accepts flat function tools; Codex uses namespaces and freeform tools. */
export function huggingFaceRequest(request: Record<string, unknown>) {
  const identities = new Map<string, ToolIdentity>();
  const customItems = new Set<string>();
  function alias(identity: ToolIdentity): string {
    // Chat tool names are limited to 64 characters. Keep names readable without
    // letting truncation or namespace separators merge distinct tool identities.
    const label = [identity.namespace, identity.name]
      .filter(Boolean)
      .join("__")
      .replace(/[^a-zA-Z0-9_-]/g, "_")
      .slice(0, 48);
    const name = `${label}_${createHash("sha256").update(JSON.stringify(identity)).digest("hex").slice(0, 12)}`;
    identities.set(name, identity);
    return name;
  }
  function identity(
    tool: Record<string, unknown>,
    namespace?: string,
  ): ToolIdentity {
    if (typeof tool["name"] !== "string")
      throw new Error("HF tool has no name.");
    return {
      name: tool["name"],
      ...(namespace === undefined ? {} : { namespace }),
      custom: tool["type"] === "custom" || tool["type"] === "custom_tool_call",
    };
  }
  function tools(values: unknown[], namespace?: string): unknown[] {
    return values.flatMap((value) => {
      if (!isRecord(value)) throw new Error("Invalid HF tool declaration.");
      if (value["type"] === "namespace" && Array.isArray(value["tools"])) {
        return tools(value["tools"], String(value["name"]));
      }
      if (value["type"] !== "function" && value["type"] !== "custom") {
        throw new Error(
          `Hugging Face does not support the ${value["type"]} tool. Disable hosted web search with web_search="disabled".`,
        );
      }
      const tool = identity(value, namespace);
      return [
        {
          type: "function",
          name: alias(tool),
          description: `${namespace ? namespace + "." : ""}${tool.name}: ${value["description"] ?? ""}`,
          parameters: tool.custom
            ? {
                type: "object",
                properties: {
                  input: {
                    type: "string",
                    description: "The complete freeform tool input.",
                  },
                },
                required: ["input"],
                additionalProperties: false,
              }
            : value["parameters"],
          strict: tool.custom ? true : value["strict"],
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
    return value;
  }
  const body = {
    ...request,
    stream: request["stream"],
    tool_choice: request["tool_choice"],
    tools: tools(Array.isArray(request["tools"]) ? request["tools"] : []),
    input: Array.isArray(request["input"])
      ? request["input"].map(input)
      : request["input"],
  };
  const choice = request["tool_choice"];
  if (isRecord(choice)) {
    if (choice["type"] !== "function" && choice["type"] !== "custom") {
      throw new Error(`HF does not support tool choice ${choice["type"]}.`);
    }
    body["tool_choice"] = {
      type: "function",
      function: {
        name: alias(
          identity(
            choice,
            typeof choice["namespace"] === "string"
              ? choice["namespace"]
              : undefined,
          ),
        ),
      },
    };
  }
  function output(value: unknown, partial = false): unknown {
    if (!isRecord(value) || value["type"] !== "function_call") return value;
    const tool = identities.get(String(value["name"]));
    if (tool === undefined)
      throw new Error(`HF returned an unknown tool: ${value["name"]}`);
    const { arguments: args, ...rest } = value;
    if (tool.custom && typeof value["id"] === "string")
      customItems.add(value["id"]);
    return {
      ...rest,
      name: tool["name"],
      ...(tool.namespace === undefined ? {} : { namespace: tool.namespace }),
      ...(tool.custom
        ? {
            type: "custom_tool_call",
            input: partial ? "" : JSON.parse(String(args)).input,
          }
        : { arguments: args }),
    };
  }
  function response(value: unknown): unknown {
    if (!isRecord(value)) return value;
    return {
      ...value,
      ...(Array.isArray(value["output"])
        ? { output: value["output"].map((item) => output(item)) }
        : {}),
    };
  }
  function event(value: Record<string, unknown>): unknown | null {
    if (
      typeof value["type"] === "string" &&
      value["type"].startsWith("response.function_call_arguments.") &&
      customItems.has(String(value["item_id"]))
    )
      return null;
    return {
      ...value,
      ...(value["item"] === undefined
        ? {}
        : {
            item: output(
              value["item"],
              value["type"] === "response.output_item.added",
            ),
          }),
      ...(value["response"] === undefined
        ? {}
        : { response: response(value["response"]) }),
    };
  }
  return { body, response, event };
}

/** Scoped to a private native provider profile, shared by its discovery workers. */
export async function startHuggingFaceResponsesAdapter(upstream: string) {
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
      const translation = huggingFaceRequest(
        JSON.parse(Buffer.concat(chunks).toString("utf8")),
      );
      if (translation.body["stream"] !== true) {
        response.writeHead(400, { "content-type": "application/json" }).end(
          JSON.stringify({
            error: {
              message:
                "The HF scan adapter requires a streaming Responses request.",
            },
          }),
        );
        return;
      }
      const headers = new Headers();
      for (const [name, value] of Object.entries(request.headers)) {
        if (
          value !== undefined &&
          ![
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
            "accept-encoding",
          ].includes(name)
        )
          headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      }
      const upstreamUrl = new URL(
        `${upstream.replace(/\/$/, "")}/chat/completions`,
      );
      upstreamUrl.search = requestedUrl.search;
      const result = await fetch(upstreamUrl, {
        method: "POST",
        headers,
        body: JSON.stringify(huggingFaceChatRequest(translation.body)),
        signal: controller.signal,
      });
      const contentType =
        result.headers.get("content-type") ?? "application/json";
      response.writeHead(result.status, { "content-type": contentType });
      if (!result.ok) {
        response.end(await result.text());
      } else if (contentType.includes("text/event-stream") && result.body) {
        async function* events() {
          let pending = "";
          const decoder = new TextDecoder();
          const completion = huggingFaceChatResponse();
          for await (const chunk of result.body!) {
            pending += decoder.decode(chunk, { stream: true });
            let boundary: RegExpExecArray | null;
            while ((boundary = /\r?\n\r?\n/.exec(pending)) !== null) {
              const frame = pending.slice(0, boundary.index);
              pending = pending.slice(boundary.index + boundary[0].length);
              const data = frame
                .split(/\r?\n/)
                .filter((line) => line.startsWith("data:"))
                .map((line) => line.slice(5).trimStart())
                .join("\n");
              if (!data || data === "[DONE]") continue;
              completion.add(JSON.parse(data));
              yield ": upstream\n\n";
            }
          }
          if (pending.trim())
            throw new Error("Incomplete Hugging Face response stream.");
          const completed = completion.finish();
          yield `data: ${JSON.stringify({ type: "response.created", response: { ...completed, status: "in_progress", output: [] } })}\n\n`;
          for (const [output_index, item] of completed.output.entries()) {
            for (const type of [
              "response.output_item.added",
              "response.output_item.done",
            ]) {
              yield `data: ${JSON.stringify(translation.event({ type, output_index, item }))}\n\n`;
            }
          }
          yield `data: ${JSON.stringify({ type: "response.completed", response: translation.response(completed) })}\n\n`;
        }
        async function* protocolEvents() {
          try {
            yield* events();
          } catch (error) {
            yield `data: ${JSON.stringify({ type: "response.failed", response: { status: "failed", error: { message: error instanceof Error ? error.message : String(error) } } })}\n\n`;
          }
        }
        await pipeline(Readable.from(protocolEvents()), response);
      } else {
        throw new Error("Expected a streaming HF Chat Completions response.");
      }
    })().catch((error: unknown) => {
      if (response.destroyed) return;
      if (response.headersSent)
        response.destroy(
          error instanceof Error ? error : new Error(String(error)),
        );
      else
        response.writeHead(502, { "content-type": "application/json" }).end(
          JSON.stringify({
            error: {
              message: error instanceof Error ? error.message : String(error),
            },
          }),
        );
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("HF adapter did not bind a TCP port.");
  return {
    baseUrl: `http://127.0.0.1:${address.port}${route.slice(0, -"/responses".length)}`,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

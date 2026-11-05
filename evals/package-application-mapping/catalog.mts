import { readFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { isRecord } from "../../sdk/typescript/src/record.ts";
import { catalogServer, catalogTool, type CatalogService } from "./cases.mts";

const records = JSON.parse(await readFile(process.argv[2]!, "utf8")) as Record<
  string,
  CatalogService[]
>;

for await (const line of createInterface({ input: process.stdin })) {
  const request: unknown = JSON.parse(line);
  if (!isRecord(request) || request.id === undefined) continue;
  const params = isRecord(request.params) ? request.params : {};
  let result: unknown;
  if (request.method === "initialize") {
    result = {
      protocolVersion: params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: catalogServer, version: "1" },
    };
  } else if (request.method === "tools/list") {
    result = {
      tools: [
        {
          name: catalogTool,
          description:
            "Look up catalog service names and IDs by a checkout-relative consumer project directory, build file, entrypoint, or launch file.",
          inputSchema: {
            type: "object",
            properties: { target: { type: "string" } },
            required: ["target"],
            additionalProperties: false,
          },
          annotations: { readOnlyHint: true },
        },
      ],
    };
  } else if (request.method === "tools/call" && params.name === catalogTool) {
    const args = params.arguments;
    const target = isRecord(args) ? args.target : undefined;
    if (typeof target === "string" && Object.hasOwn(records, target)) {
      const structuredContent = { services: records[target] };
      result = {
        content: [{ type: "text", text: JSON.stringify(structuredContent) }],
        structuredContent,
      };
    } else {
      result = {
        isError: true,
        content: [
          {
            type: "text",
            text: "This target could not be resolved. Use the checkout-relative consumer project directory, build file, entrypoint, or launch file.",
          },
        ],
      };
    }
  } else {
    process.stdout.write(
      `${JSON.stringify({ jsonrpc: "2.0", id: request.id, error: { code: -32601, message: "Method not found" } })}\n`,
    );
    continue;
  }
  process.stdout.write(
    `${JSON.stringify({ jsonrpc: "2.0", id: request.id, result })}\n`,
  );
}

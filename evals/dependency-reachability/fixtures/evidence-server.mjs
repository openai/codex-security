// Synthetic deployment inventory for the mixed-services fixture. Each process
// writes its actual replies to the external grader's transcript.
import { randomUUID } from "node:crypto";
import { appendFile, readFile } from "node:fs/promises";
import { createInterface } from "node:readline";

const [recordsFile, transcript] = process.argv.slice(2);
const records = JSON.parse(await readFile(recordsFile, "utf8"));
const tools = [
  [
    "release_record",
    "Find the running source revision and loaded package for one service.",
  ],
  ["request_record", "Find an observed client request to one service."],
].map(([name, description]) => ({
  name,
  description,
  inputSchema: {
    type: "object",
    properties: { service: { type: "string", enum: ["notes", "reviews"] } },
    required: ["service"],
    additionalProperties: false,
  },
  annotations: { readOnlyHint: true },
}));

async function dispatch({ method, params }) {
  if (method === "initialize")
    return {
      protocolVersion: params.protocolVersion,
      serverInfo: { name: "service-records", version: "1.0.0" },
      capabilities: { tools: {} },
    };
  if (method === "ping") return {};
  if (method === "tools/list") return { tools };
  if (method !== "tools/call")
    throw { code: -32601, message: "Method not found" };
  const { name: tool, arguments: args } = params;
  if (
    !tools.some(({ name }) => name === tool) ||
    !["notes", "reviews"].includes(args?.service)
  )
    throw { code: -32602, message: "Unknown tool or service" };
  const observation =
    records[args.service]?.[tool] ?? `No observation for ${args.service}.`;
  const text = `Record ${randomUUID()}: ${observation}`;
  const result = { content: [{ type: "text", text }] };
  await appendFile(
    transcript,
    JSON.stringify({ tool, arguments: args, result }) + "\n",
    { mode: 0o600 },
  );
  return result;
}

for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (request.id === undefined) continue;
  const reply = { jsonrpc: "2.0", id: request.id };
  try {
    reply.result = await dispatch(request);
  } catch (error) {
    if (typeof error.code !== "number") throw error;
    reply.error = error;
  }
  process.stdout.write(JSON.stringify(reply) + "\n");
}

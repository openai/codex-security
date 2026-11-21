import { createInterface } from "node:readline";

export async function serveRecordTools(tools, lookup) {
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
    return lookup(params);
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
}

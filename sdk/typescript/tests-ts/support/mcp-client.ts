import type { ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { capture } from "../cli-fixtures.js";

type JsonObject = Record<string, unknown>;

export async function initializeMcpClient(
  child: ChildProcessWithoutNullStreams,
  clientName: string,
  splitRequestWrites: boolean,
) {
  const messages = createInterface({ input: child.stdout })[
    Symbol.asyncIterator
  ]();
  const stderr = capture();
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", stderr.stream.write);
  let nextId = 0;

  async function request(
    method: string,
    params: JsonObject,
  ): Promise<JsonObject> {
    const id = ++nextId;
    if (splitRequestWrites) {
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }));
      child.stdin.write("\n");
    } else {
      child.stdin.write(
        `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`,
      );
    }
    while (true) {
      const message = await messages.next();
      if (message.done) {
        throw new Error(`MCP server exited before replying: ${stderr.text()}`);
      }
      const response = JSON.parse(message.value) as JsonObject;
      if (response["id"] !== id) continue;
      if (response["error"] !== undefined) {
        throw new Error(JSON.stringify(response["error"]));
      }
      return response["result"] as JsonObject;
    }
  }

  await request("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: clientName, version: "1.0.0" },
  });
  child.stdin.write(
    `${JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/initialized",
      params: {},
    })}\n`,
  );

  return {
    request,
    async close(): Promise<void> {
      child.stdin.end();
      await new Promise<void>((resolve) => {
        child.once("close", () => resolve());
      });
    },
  };
}

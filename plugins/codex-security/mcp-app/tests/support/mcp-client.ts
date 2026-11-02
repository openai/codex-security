import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  StdioClientTransport,
  type StdioServerParameters,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import { ResultSchema } from "@modelcontextprotocol/sdk/types.js";

export async function startMcpClient(
  parameters: StdioServerParameters,
  name: string,
) {
  const client = new Client({ name, version: "1.0.0" });
  try {
    await client.connect(new StdioClientTransport(parameters));
  } catch (error) {
    await client.close();
    throw error;
  }
  return {
    request(method: string, params: Record<string, unknown>) {
      return client.request({ method, params }, ResultSchema);
    },
    close: () => client.close(),
  };
}

// Deliberately vulnerable local fixture. Do not deploy this application.
import { once } from "node:events";
import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { pathToFileURL } from "node:url";

// These identities, tokens, and records are synthetic demo data.
const tokens = new Map([
  ["demo-alice", "alice"],
  ["demo-bob", "bob"],
]);
type Invoice = { id: string; owner: string; amount: number };
const invoices = new Map<string, Invoice>([
  ["1001", { id: "1001", owner: "alice", amount: 25 }],
  ["1002", { id: "1002", owner: "bob", amount: 80 }],
]);

export async function createServer(): Promise<Server> {
  const server = createHttpServer((request, response) => {
    function reply(status: number, body: Invoice | { error: string }): void {
      const encoded = JSON.stringify(body);
      response.writeHead(status, {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(encoded),
      });
      response.end(encoded);
    }

    if (request.method !== "GET") {
      response.writeHead(501).end();
      return;
    }
    const authorization = request.headers.authorization ?? "";
    const token = authorization.startsWith("Bearer ")
      ? authorization.slice("Bearer ".length)
      : authorization;
    const user = tokens.get(token);
    if (user === undefined) return reply(401, { error: "unauthorized" });
    const path = request.url ?? "";
    if (!path.startsWith("/invoices/"))
      return reply(404, { error: "not found" });
    const invoice = invoices.get(path.slice("/invoices/".length));
    if (invoice === undefined) return reply(404, { error: "not found" });
    // BUG: authentication does not establish ownership of this invoice.
    reply(200, invoice);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return server;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const server = await createServer();
  console.log(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
}

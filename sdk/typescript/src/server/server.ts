import { once } from "node:events";
import { createServer, type Server } from "node:http";
import { handleFindingsRequest } from "./routes.js";
import type { FindingsStore } from "./storage.js";

export async function startFindingsServer(options: {
  store: FindingsStore;
  host: string;
  port: number;
}): Promise<Server> {
  await options.store.initialize();
  const server = createServer(handleFindingsRequest);
  server.listen(options.port, options.host);
  await once(server, "listening");
  return server;
}

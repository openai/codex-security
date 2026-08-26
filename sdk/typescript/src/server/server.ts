import { once } from "node:events";
import { createServer, type Server } from "node:http";
import { DeduplicationService } from "./deduplication.js";
import type { FindingEmbedder } from "./embeddings.js";
import { FindingsService } from "./findings-service.js";
import { handleFindingsRequest } from "./routes.js";
import type { FindingsStore } from "./storage.js";
import { findingsRequestValidator } from "./validation.js";

export async function startFindingsServer(options: {
  store: FindingsStore;
  embeddings: FindingEmbedder;
  deduplication?: DeduplicationService;
  host: string;
  port: number;
}): Promise<Server> {
  await options.store.initialize();
  const validate = await findingsRequestValidator();
  const service = new FindingsService(
    options.store,
    options.embeddings,
    options.deduplication ?? new DeduplicationService(),
  );
  const server = createServer((request, response) => {
    void handleFindingsRequest(request, response, service, validate);
  });
  server.listen(options.port, options.host);
  await once(server, "listening");
  return server;
}

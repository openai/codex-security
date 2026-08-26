import { startFindingsServer } from "./server.js";
import { SqliteFindingsStore } from "./sqlite-store.js";
import { OpenAiFindingEmbedder } from "./embeddings.js";

async function main(): Promise<void> {
  const host = process.env["HOST"] ?? "127.0.0.1";
  const port = Number(process.env["PORT"] ?? 3000);
  const server = await startFindingsServer({
    store: new SqliteFindingsStore(),
    embeddings: new OpenAiFindingEmbedder(
      process.env["OPENAI_API_KEY"] ?? process.env["CODEX_API_KEY"],
    ),
    host,
    port,
  });
  const address = server.address();
  if (address !== null && typeof address !== "string") {
    console.log(
      `Findings service listening on ${address.address}:${address.port}`,
    );
  }

  const shutdown = () => {
    server.close((error) => {
      if (error !== undefined) {
        console.error(error);
        process.exitCode = 1;
      }
    });
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});

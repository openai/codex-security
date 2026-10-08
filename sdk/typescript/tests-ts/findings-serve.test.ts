import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { expect, test } from "bun:test";

test("findings service uses a nonempty API key with CODEX_API_KEY fallback", () => {
  const source = `
    import { mock } from 'bun:test';
    const keys = [];
    mock.module(${JSON.stringify(resolve(import.meta.dir, "../src/server/embeddings.ts"))}, () => ({OpenAiFindingEmbedder: class {constructor(key) { keys.push(key ?? null); }}}));
    mock.module(${JSON.stringify(resolve(import.meta.dir, "../src/server/sqlite-store.ts"))}, () => ({SqliteFindingsStore: class {}}));
    mock.module(${JSON.stringify(resolve(import.meta.dir, "../src/server/server.ts"))}, () => ({startFindingsServer: async () => ({address: () => null})}));
    const { serveFindings } = await import(${JSON.stringify(resolve(import.meta.dir, "../src/server/serve.ts"))});
    await serveFindings({OPENAI_API_KEY:'', CODEX_API_KEY:'synthetic-codex-key'});
    await serveFindings({OPENAI_API_KEY:'synthetic-openai-key', CODEX_API_KEY:'synthetic-codex-key'});
    await serveFindings({});
    console.log(JSON.stringify(keys));
  `;
  const result = spawnSync(process.execPath, ["--eval", source], {
    encoding: "utf8",
  });
  expect(result.status).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual([
    "synthetic-codex-key",
    "synthetic-openai-key",
    null,
  ]);
});

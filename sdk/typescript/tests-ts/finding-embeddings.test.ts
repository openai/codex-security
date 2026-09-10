import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { Tiktoken } from "js-tiktoken/lite";
import cl100kBase from "js-tiktoken/ranks/cl100k_base";
import type { Finding, FindingsDocument } from "../src/models.js";
import {
  EMBEDDING_DIMENSIONS,
  EMBEDDING_MODEL,
  OpenAiFindingEmbedder,
} from "../src/server/embeddings.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { SqliteFindingsStore } from "../src/server/sqlite-store.js";

const example = (
  JSON.parse(
    await readFile(
      join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
      "utf8",
    ),
  ) as FindingsDocument
).findings[0]!;
const encoding = new Tiktoken(cl100kBase);

function vector(axis = 0): number[] {
  const values = Array<number>(EMBEDDING_DIMENSIONS).fill(0);
  values[axis] = 1;
  return values;
}

test("resumes paid embedding batches from SQLite after a later batch fails", async () => {
  const root = await mkdtemp(join(tmpdir(), "embedding-checkpoints-"));
  const environment = {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  try {
    const firstStore = new SqliteFindingsStore(environment);
    await firstStore.initialize();
    const findings = Array.from({ length: 40 }, (_, index) => ({
      ...example,
      title: `Finding ${index}`,
      summary: " evidence".repeat(8000),
    }));
    let calls = 0;
    const provider = async (_url: string, init: RequestInit) => {
      const input: number[][] = JSON.parse(String(init.body)).input;
      if (++calls === 2) return new Response("Unavailable", { status: 503 });
      return Response.json({
        model: EMBEDDING_MODEL,
        data: input.map((_, index) => ({ index, embedding: vector() })),
      });
    };
    await expect(
      new OpenAiFindingEmbedder(
        "synthetic",
        provider,
        undefined,
        firstStore,
      ).embed(findings),
    ).rejects.toThrow("HTTP 503");
    expect(
      (await firstStore.list({ limit: 100, offset: 0 })).findings,
    ).toHaveLength(0);
    const nextStore = new SqliteFindingsStore(environment);
    const result = await new OpenAiFindingEmbedder(
      "synthetic",
      provider,
      undefined,
      nextStore,
    ).embed(findings);
    expect(result).toHaveLength(40);
    expect(calls).toBe(3);
    expect(result.every((item) => item.vector[0] === 1)).toBe(true);
    await new OpenAiFindingEmbedder(
      "synthetic",
      provider,
      undefined,
      nextStore,
    ).embed(findings);
    expect(calls).toBe(3);
    await new OpenAiFindingEmbedder(
      "synthetic",
      provider,
      "http://other-provider.test/embeddings",
      nextStore,
    ).embed([example]);
    expect(calls).toBe(4);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("does not checkpoint part of an invalid provider response", async () => {
  const root = await mkdtemp(join(tmpdir(), "embedding-invalid-checkpoint-"));
  const environment = {
    ...process.env,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const findings = [example, { ...example, title: "Another finding" }];
  let valid = false;
  const requests: number[] = [];
  const provider = async (_url: string, init: RequestInit) => {
    const input: number[][] = JSON.parse(String(init.body)).input;
    requests.push(input.length);
    return Response.json({
      model: EMBEDDING_MODEL,
      data: input.map((_, index) => ({
        index,
        embedding:
          valid || index === 0 ? vector() : Array(EMBEDDING_DIMENSIONS).fill(0),
      })),
    });
  };
  try {
    await expect(
      new OpenAiFindingEmbedder(
        "synthetic",
        provider,
        undefined,
        new SqliteFindingsStore(environment),
      ).embed(findings),
    ).rejects.toThrow("invalid vectors");
    valid = true;
    expect(
      await new OpenAiFindingEmbedder(
        "synthetic",
        provider,
        undefined,
        new SqliteFindingsStore(environment),
      ).embed(findings),
    ).toHaveLength(2);
    expect(requests).toEqual([2, 2]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("uses the configured embedding model and preserves response indexes", async () => {
  const findings = [
    example,
    { ...example, title: "Different full report <|endoftext|> ✓" },
  ];
  const embedder = new OpenAiFindingEmbedder(
    "synthetic-key",
    async (url, init) => {
      expect(url).toBe("https://api.openai.com/v1/embeddings");
      expect(init.headers).toMatchObject({
        Authorization: "Bearer synthetic-key",
      });
      const request = JSON.parse(String(init.body));
      expect(request).toMatchObject({
        model: EMBEDDING_MODEL,
        dimensions: EMBEDDING_DIMENSIONS,
        encoding_format: "float",
      });
      expect(
        request.input.map((tokens: number[]) => encoding.decode(tokens)),
      ).toEqual(findings.map((finding) => JSON.stringify(finding)));
      return Response.json({
        model: EMBEDDING_MODEL,
        data: [
          { index: 1, embedding: vector(1) },
          { index: 0, embedding: vector(0) },
        ],
      });
    },
  );
  expect(await embedder.embed(findings)).toEqual([
    { model: EMBEDDING_MODEL, vector: vector(0) },
    { model: EMBEDDING_MODEL, vector: vector(1) },
  ]);
});

test("chunks long findings losslessly and pools vectors by token count", async () => {
  const finding = { ...example, summary: " evidence".repeat(9000) };
  const chunks: number[][] = [];
  const embedder = new OpenAiFindingEmbedder(
    "synthetic-key",
    async (_url, init) => {
      const input: number[][] = JSON.parse(String(init.body)).input;
      chunks.push(...input);
      return Response.json({
        model: EMBEDDING_MODEL,
        data: input.map((_, index) => ({ index, embedding: vector(index) })),
      });
    },
  );
  const result = (await embedder.embed([finding]))[0]!;
  expect(chunks).toHaveLength(2);
  expect(chunks[0]).toHaveLength(8192);
  expect(encoding.decode(chunks.flat())).toBe(JSON.stringify(finding));
  const weights = chunks.map((chunk) => chunk.length);
  const norm = Math.hypot(...weights);
  expect(result.vector[0]).toBeCloseTo(weights[0]! / norm, 10);
  expect(result.vector[1]).toBeCloseTo(weights[1]! / norm, 10);
  expect(Math.hypot(...result.vector)).toBeCloseTo(1, 10);
});

test("splits bulk requests at the provider token budget and renews credentials per batch", async () => {
  const finding: Finding = { ...example, summary: " evidence".repeat(8000) };
  const requests: number[][][] = [];
  let credentials = 0;
  const embedder = new OpenAiFindingEmbedder(
    async () => `synthetic-key-${++credentials}`,
    async (_url, init) => {
      expect(credentials).toBe(requests.length + 1);
      expect(init.headers).toMatchObject({
        Authorization: `Bearer synthetic-key-${credentials}`,
      });
      const input: number[][] = JSON.parse(String(init.body)).input;
      requests.push(input);
      expect(
        input.reduce((sum, tokens) => sum + tokens.length, 0),
      ).toBeLessThanOrEqual(300_000);
      expect(input.every((tokens) => tokens.length <= 8192)).toBe(true);
      return Response.json({
        model: EMBEDDING_MODEL,
        data: input.map((_, index) => ({ index, embedding: vector() })),
      });
    },
  );
  const result = await embedder.embed(
    Array.from({ length: 40 }, () => finding),
  );
  expect(requests).toHaveLength(2);
  expect(credentials).toBe(2);
  expect(result).toHaveLength(40);
  expect(result.every((embedding) => embedding.vector[0] === 1)).toBe(true);
});

test("does not resolve credentials for empty input or reuse a key after renewal fails", async () => {
  for (const failure of ["throw", "empty"]) {
    let credentials = 0;
    let requests = 0;
    const embedder = new OpenAiFindingEmbedder(
      () => {
        if (++credentials === 1) return "synthetic-key";
        if (failure === "throw") throw new Error("synthetic-private-token");
        return "";
      },
      async () => {
        requests++;
        return Response.json({
          model: EMBEDDING_MODEL,
          data: [{ index: 0, embedding: vector() }],
        });
      },
    );
    expect(await embedder.embed([])).toEqual([]);
    expect(credentials).toBe(0);
    await embedder.embed([example]);
    await expect(embedder.embed([example])).rejects.toMatchObject({
      code: "embedding_failed",
      message: "Could not reach the embedding provider.",
    });
    expect(credentials).toBe(2);
    expect(requests).toBe(1);
  }
});

test("does not call the provider for empty input or missing credentials", async () => {
  let calls = 0;
  const embedder = new OpenAiFindingEmbedder(undefined, async () => {
    calls++;
    throw new Error("Must not call");
  });
  expect(await embedder.embed([])).toEqual([]);
  await expect(embedder.embed([example])).rejects.toMatchObject({
    code: "embedding_unavailable",
  });
  expect(calls).toBe(0);
});

test("reports provider failures without echoing response bodies or credentials", async () => {
  const embedder = new OpenAiFindingEmbedder(
    "synthetic-key",
    async () => new Response("synthetic private body", { status: 429 }),
  );
  await expect(embedder.embed([example])).rejects.toMatchObject({
    code: "embedding_failed",
    message: "Embedding provider returned HTTP 429.",
  });
});

test("rejects malformed vectors instead of misaligning stored findings", async () => {
  for (const data of [
    [],
    [
      { index: 0, embedding: [1] },
      { index: 1, embedding: vector() },
    ],
    [
      { index: 0, embedding: vector() },
      { index: 0, embedding: vector() },
    ],
    [
      { index: 0, embedding: vector() },
      { index: 2, embedding: vector() },
    ],
    [
      { index: 0, embedding: vector() },
      { index: 1, embedding: Array(EMBEDDING_DIMENSIONS).fill(0) },
    ],
  ]) {
    const embedder = new OpenAiFindingEmbedder("synthetic-key", async () =>
      Response.json({ model: EMBEDDING_MODEL, data }),
    );
    await expect(embedder.embed([example, example])).rejects.toMatchObject({
      code: "embedding_failed",
    });
  }
});

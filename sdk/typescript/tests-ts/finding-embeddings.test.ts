import { readFile } from "node:fs/promises";
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

test("splits bulk requests at the provider token budget", async () => {
  const finding: Finding = { ...example, summary: " evidence".repeat(8000) };
  const requests: number[][][] = [];
  const embedder = new OpenAiFindingEmbedder(
    "synthetic-key",
    async (_url, init) => {
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
  expect(result).toHaveLength(40);
  expect(result.every((embedding) => embedding.vector[0] === 1)).toBe(true);
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

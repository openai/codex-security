import { rejecting } from "./support/errors.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test, mock } from "bun:test";
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

test.each(["headers", "body"])(
  "preserves cancellation during embedding response %s",
  async (stage) => {
    const controller = new AbortController();
    const canceled = new Error("Synthetic cancellation");
    const embedder = new OpenAiFindingEmbedder(
      "synthetic-key",
      async (_url, init) => {
        expect(init.signal).toBe(controller.signal);
        if (stage === "body") {
          const response = new Response();
          response.json = async () => {
            controller.abort(canceled);
            throw new TypeError("Canceled body read");
          };
          return response;
        }
        controller.abort(canceled);
        throw new TypeError("Canceled transport");
      },
      undefined,
      controller.signal,
    );
    await expect(embedder.embed([example])).rejects.toBe(canceled);
  },
);

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
    const observeRequests = mock(async () => {
      return Response.json({
        model: EMBEDDING_MODEL,
        data: [{ index: 0, embedding: vector() }],
      });
    });
    const embedder = new OpenAiFindingEmbedder(() => {
      if (++credentials === 1) return "synthetic-key";
      if (failure === "throw") throw new Error("synthetic-private-token");
      return "";
    }, observeRequests);
    expect(await embedder.embed([])).toEqual([]);
    expect(credentials).toBe(0);
    await embedder.embed([example]);
    await expect(embedder.embed([example])).rejects.toMatchObject({
      code: "embedding_failed",
      message: "Could not reach the embedding provider.",
    });
    expect(credentials).toBe(2);
    expect(observeRequests).toHaveBeenCalledTimes(1);
  }
});

test("does not call the provider for empty input or missing credentials", async () => {
  const observeCalls = mock(rejecting("Must not call"));
  const embedder = new OpenAiFindingEmbedder(undefined, observeCalls);
  expect(await embedder.embed([])).toEqual([]);
  await expect(embedder.embed([example])).rejects.toMatchObject({
    code: "embedding_unavailable",
  });
  expect(observeCalls).toHaveBeenCalledTimes(0);
});

test.each(["synthetic private body", null])(
  "preserves the HTTP error with response body %p",
  async (body) => {
    const embedder = new OpenAiFindingEmbedder(
      "synthetic-key",
      async () => new Response(body, { status: 429 }),
    );
    await expect(embedder.embed([example])).rejects.toMatchObject({
      code: "embedding_failed",
      message: "Embedding provider returned HTTP 429.",
    });
  },
);

test.each(["complete", "reject", "pending"])(
  "cancels a rejected embedding response without replacing its HTTP error (%s)",
  async (cleanup) => {
    let cancelled = false;
    const body = new ReadableStream({
      cancel() {
        cancelled = true;
        if (cleanup === "reject")
          return Promise.reject(new Error("cleanup failed"));
        if (cleanup === "pending") return new Promise<void>(() => {});
      },
    });
    const embedder = new OpenAiFindingEmbedder(
      "synthetic-key",
      async () => new Response(body, { status: 503 }),
    );
    await expect(embedder.embed([example])).rejects.toMatchObject({
      code: "embedding_failed",
      message: "Embedding provider returned HTTP 503.",
    });
    expect(cancelled).toBe(true);
  },
);

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

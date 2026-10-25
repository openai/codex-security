import { readJson } from "./support/json.js";
import { rejecting } from "./support/errors.js";
import { join } from "node:path";
import { setImmediate as nextTurn } from "node:timers/promises";
import { expect, test, mock } from "bun:test";
import { Tiktoken } from "js-tiktoken/lite";
import cl100kBase from "js-tiktoken/ranks/cl100k_base";
import type { Finding, FindingsDocument } from "../src/models.js";
import {
  EMBEDDING_DIMENSIONS,
  EMBEDDING_MODEL,
  OpenAiFindingEmbedder,
  type EmbeddingUsageObservation,
} from "../src/server/embeddings.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { VERSION } from "../src/version.js";

const example = (
  await readJson<FindingsDocument>(
    join(PLUGIN_ROOT, "examples/completed-scan/findings.json"),
  )
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
    const observations: EmbeddingUsageObservation[] = [];
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
      (observation) => observations.push(observation),
    );
    await expect(embedder.embed([example])).rejects.toBe(canceled);
    expect(observations).toEqual([
      {
        model: EMBEDDING_MODEL,
        inputCount: 1,
        inputTokens: null,
        outcome: "canceled",
        durationMs: expect.any(Number),
      },
    ]);
  },
);

test.each(["before", "callback", "pending"] as const)(
  "does not admit embedding work after cancellation at %s key acquisition",
  async (stage) => {
    const controller = new AbortController();
    const canceled = new Error("Synthetic acquisition cancellation");
    const entered = Promise.withResolvers<void>();
    const key = Promise.withResolvers<string>();
    const acquire = mock(() => {
      if (stage === "callback") controller.abort(canceled);
      if (stage === "pending") {
        entered.resolve();
        return key.promise;
      }
      return "synthetic-key";
    });
    const request = mock(async (_url: string, init: RequestInit) => {
      init.signal?.throwIfAborted();
      return Response.json({
        model: EMBEDDING_MODEL,
        data: [{ index: 0, embedding: vector() }],
      });
    });
    const embedder = new OpenAiFindingEmbedder(
      acquire,
      request,
      undefined,
      controller.signal,
    );
    if (stage === "before") controller.abort(canceled);
    const result = embedder.embed([example]);
    const settled = result.then(
      () => "resolved",
      (error: unknown) => error,
    );
    try {
      if (stage === "pending") {
        await entered.promise;
        controller.abort(canceled);
        const pending = Symbol("pending");
        expect(
          await Promise.race([settled, nextTurn().then(() => pending)]),
        ).toBe(pending);
        key.resolve("synthetic-key");
      }
      await expect(result).rejects.toBe(canceled);
      expect(acquire).toHaveBeenCalledTimes(stage === "before" ? 0 : 1);
      expect(request).not.toHaveBeenCalled();
    } finally {
      key.resolve("synthetic-key");
      await settled;
    }
  },
);

test("preserves empty input and missing static key precedence when canceled", async () => {
  const controller = new AbortController();
  controller.abort(new Error("Synthetic cancellation"));
  const acquire = mock(() => "synthetic-key");
  const request = mock(rejecting("Must not call"));
  expect(
    await new OpenAiFindingEmbedder(
      acquire,
      request,
      undefined,
      controller.signal,
    ).embed([]),
  ).toEqual([]);
  expect(acquire).not.toHaveBeenCalled();
  for (const key of [undefined, ""]) {
    await expect(
      new OpenAiFindingEmbedder(
        key,
        request,
        undefined,
        controller.signal,
      ).embed([example]),
    ).rejects.toMatchObject({ code: "embedding_unavailable" });
  }
  expect(request).not.toHaveBeenCalled();
});

test.each(["empty", "throw"])(
  "preserves cancellation when key acquisition returns %s",
  async (failure) => {
    const controller = new AbortController();
    const canceled = new Error("Synthetic acquisition cancellation");
    const request = mock(rejecting("Must not call"));
    const embedder = new OpenAiFindingEmbedder(
      () => {
        controller.abort(canceled);
        if (failure === "throw") throw new Error("Synthetic callback failure");
        return "";
      },
      request,
      undefined,
      controller.signal,
    );
    await expect(embedder.embed([example])).rejects.toBe(canceled);
    expect(request).not.toHaveBeenCalled();
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
        "User-Agent": `codex-security/${VERSION}`,
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
  const observations: EmbeddingUsageObservation[] = [];
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
        usage: {
          prompt_tokens: input.reduce((sum, tokens) => sum + tokens.length, 0),
        },
      });
    },
    undefined,
    undefined,
    (observation) => observations.push(observation),
  );
  const result = await embedder.embed(
    Array.from({ length: 40 }, () => finding),
  );
  expect(requests).toHaveLength(2);
  expect(credentials).toBe(2);
  expect(result).toHaveLength(40);
  expect(result.every((embedding) => embedding.vector[0] === 1)).toBe(true);
  expect(observations).toEqual(
    requests.map((input) => ({
      model: EMBEDDING_MODEL,
      inputCount: input.length,
      inputTokens: input.reduce((sum, tokens) => sum + tokens.length, 0),
      outcome: "completed",
      durationMs: expect.any(Number),
    })),
  );
});

test.each([
  { usage: { prompt_tokens: 17 }, inputTokens: 17 },
  { usage: { prompt_tokens: 0 }, inputTokens: 0 },
  { usage: undefined, inputTokens: null },
  { usage: { prompt_tokens: -1 }, inputTokens: null },
])(
  "reports provider token usage and missingness (%j)",
  async ({ usage, inputTokens }) => {
    const observations: EmbeddingUsageObservation[] = [];
    const embedder = new OpenAiFindingEmbedder(
      "synthetic-key",
      async () =>
        Response.json({
          model: EMBEDDING_MODEL,
          data: [{ index: 0, embedding: vector() }],
          usage,
        }),
      undefined,
      undefined,
      (observation) => observations.push(observation),
    );
    await embedder.embed([example]);
    expect(observations).toEqual([
      {
        model: EMBEDDING_MODEL,
        inputCount: 1,
        inputTokens,
        outcome: "completed",
        durationMs: expect.any(Number),
      },
    ]);
    expect(observations[0]!.durationMs).toBeGreaterThanOrEqual(0);
  },
);

test.each(["throw", "reject", "pending"] as const)(
  "embedding usage observer failures do not affect results (%s)",
  async (failure) => {
    const observer = mock(() => {
      if (failure === "throw") throw new Error("Synthetic observer failure");
      if (failure === "reject")
        return Promise.reject(new Error("Synthetic observer rejection"));
      return new Promise<void>(() => {});
    });
    const embedder = new OpenAiFindingEmbedder(
      "synthetic-key",
      async () =>
        Response.json({
          model: EMBEDDING_MODEL,
          data: [{ index: 0, embedding: vector() }],
        }),
      undefined,
      undefined,
      observer,
    );
    expect(await embedder.embed([example])).toHaveLength(1);
    await nextTurn();
    expect(observer).toHaveBeenCalledTimes(1);
  },
);

test.each(["transport", "http", "vectors"] as const)(
  "reports failed embedding batches without discarding reported usage (%s)",
  async (failure) => {
    const observations: EmbeddingUsageObservation[] = [];
    const embedder = new OpenAiFindingEmbedder(
      "synthetic-key",
      async () => {
        if (failure === "transport")
          throw new Error("Synthetic transport failure");
        if (failure === "http") return new Response(null, { status: 503 });
        return Response.json({
          model: EMBEDDING_MODEL,
          data: [],
          usage: { prompt_tokens: 23 },
        });
      },
      undefined,
      undefined,
      (observation) => observations.push(observation),
    );
    await expect(embedder.embed([example])).rejects.toMatchObject({
      code: "embedding_failed",
    });
    expect(observations).toEqual([
      {
        model: EMBEDDING_MODEL,
        inputCount: 1,
        inputTokens: failure === "vectors" ? 23 : null,
        outcome: "failed",
        durationMs: expect.any(Number),
      },
    ]);
  },
);

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
      if (failure === "throw")
        throw new Error("Credential source unavailable: synthetic fixture");
      return "";
    }, observeRequests);
    expect(await embedder.embed([])).toEqual([]);
    expect(credentials).toBe(0);
    await embedder.embed([example]);
    await expect(embedder.embed([example])).rejects.toMatchObject({
      code: "embedding_failed",
      message: `Could not request finding embeddings: ${failure === "throw" ? "Credential source unavailable: synthetic fixture" : "Missing embedding credentials"}`,
    });
    expect(credentials).toBe(2);
    expect(observeRequests).toHaveBeenCalledTimes(1);
  }
});

test("preserves fetch failure diagnostics", async () => {
  const embedder = new OpenAiFindingEmbedder(
    "synthetic-key",
    rejecting("ECONNREFUSED: synthetic endpoint"),
  );
  await expect(embedder.embed([example])).rejects.toMatchObject({
    code: "embedding_failed",
    message:
      "Could not request finding embeddings: ECONNREFUSED: synthetic endpoint",
  });
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

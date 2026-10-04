import { expect, test } from "bun:test";
import type { Finding } from "../src/models.js";
import {
  EMBEDDING_DIMENSIONS,
  EMBEDDING_MODEL,
  OpenAiFindingEmbedder,
} from "../src/server/embeddings.js";

const example: Finding = {
  findingId: "csf_111111111111111111111111",
  occurrenceId: "occ_222222222222222222222222",
  ruleId: "synthetic-rule",
  identity: {
    anchor: "synthetic-anchor",
  },
  fingerprints: {
    algorithm: "codex-security/v1",
    primary:
      "codex-security/v1:sha256:3333333333333333333333333333333333333333333333333333333333333333",
  },
  title: "Synthetic report",
  summary: "Synthetic text for response cleanup tests.",
  severity: {
    level: "low",
  },
  confidence: {
    level: "low",
    rationale: "Synthetic fixture.",
  },
  taxonomy: {
    category: "synthetic",
    cwe: [],
  },
  locations: [
    {
      path: "synthetic.ts",
      startLine: 1,
    },
  ],
  remediation: "Synthetic text.",
  provenance: {
    source: "local_plugin",
  },
  extensions: {},
};

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

test("keeps the HTTP error when the response has no body", async () => {
  const embedder = new OpenAiFindingEmbedder(
    "synthetic-key",
    async () => new Response(null, { status: 429 }),
  );
  await expect(embedder.embed([example])).rejects.toMatchObject({
    code: "embedding_failed",
    message: "Embedding provider returned HTTP 429.",
  });
});

test("consumes successful embedding responses without cancelling them", async () => {
  const vector = Array<number>(EMBEDDING_DIMENSIONS).fill(0);
  vector[0] = 1;
  let cancelled = false;
  const payload = JSON.stringify({
    model: EMBEDDING_MODEL,
    data: [{ index: 0, embedding: vector }],
  });
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(payload));
      controller.close();
    },
    cancel() {
      cancelled = true;
    },
  });
  const embedder = new OpenAiFindingEmbedder(
    "synthetic-key",
    async () => new Response(body),
  );
  expect(await embedder.embed([example])).toEqual([
    { model: EMBEDDING_MODEL, vector },
  ]);
  expect(cancelled).toBe(false);
});

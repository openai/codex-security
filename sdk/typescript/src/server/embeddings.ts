import { createHash } from "node:crypto";
import { Tiktoken } from "js-tiktoken/lite";
import cl100kBase from "js-tiktoken/ranks/cl100k_base";
import type { Finding } from "../models.js";
import { FindingsError } from "./errors.js";
import type { FindingEmbedding } from "./storage.js";

export const EMBEDDING_MODEL = "text-embedding-3-large";
export const EMBEDDING_DIMENSIONS = 1536;
const MAX_INPUT_TOKENS = 8192;
const MAX_REQUEST_TOKENS = 300_000;
const MAX_REQUEST_INPUTS = 2048;

export interface FindingEmbedder {
  embed(findings: readonly Finding[]): Promise<FindingEmbedding[]>;
}

export interface EmbeddingCheckpointStore {
  getEmbeddingChunks(keys: readonly string[]): Promise<(number[] | null)[]>;
  saveEmbeddingChunks(
    entries: readonly { key: string; vector: number[] }[],
  ): Promise<void>;
}

interface Chunk {
  findingIndex: number;
  tokens: number[];
}

export class OpenAiFindingEmbedder implements FindingEmbedder {
  private readonly encoding = new Tiktoken(cl100kBase);

  constructor(
    private readonly apiKey:
      | string
      | (() => string | Promise<string>)
      | undefined,
    private readonly request: (
      url: string,
      init: RequestInit,
    ) => Promise<Response> = fetch,
    private readonly url: string = "https://api.openai.com/v1/embeddings",
    private readonly checkpoints?: EmbeddingCheckpointStore,
  ) {}

  async embed(findings: readonly Finding[]): Promise<FindingEmbedding[]> {
    if (findings.length === 0) return [];
    if (!this.apiKey) {
      throw new FindingsError(
        "embedding_unavailable",
        "Set OPENAI_API_KEY or CODEX_API_KEY to generate embeddings.",
      );
    }

    const vectors = findings.map(() =>
      Array<number>(EMBEDDING_DIMENSIONS).fill(0),
    );
    let chunks: Chunk[] = [];
    let requestTokens = 0;
    for (const [findingIndex, finding] of findings.entries()) {
      const tokens = this.encoding.encode(JSON.stringify(finding), [], []);
      for (let start = 0; start < tokens.length; start += MAX_INPUT_TOKENS) {
        const chunk = tokens.slice(start, start + MAX_INPUT_TOKENS);
        if (
          chunks.length === MAX_REQUEST_INPUTS ||
          requestTokens + chunk.length > MAX_REQUEST_TOKENS
        ) {
          await this.embedChunks(chunks, vectors);
          chunks = [];
          requestTokens = 0;
        }
        chunks.push({ findingIndex, tokens: chunk });
        requestTokens += chunk.length;
      }
    }
    if (chunks.length > 0) await this.embedChunks(chunks, vectors);

    return vectors.map((vector) => {
      const norm = Math.hypot(...vector);
      if (norm === 0 || !Number.isFinite(norm))
        throw invalidEmbeddingResponse();
      return {
        model: EMBEDDING_MODEL,
        vector: vector.map((value) => value / norm),
      };
    });
  }

  private async embedChunks(
    chunks: Chunk[],
    vectors: number[][],
  ): Promise<void> {
    const keys = chunks.map(({ tokens }) =>
      createHash("sha256")
        .update(
          JSON.stringify({
            version: 1,
            url: this.url,
            model: EMBEDDING_MODEL,
            dimensions: EMBEDDING_DIMENSIONS,
            tokens,
          }),
        )
        .digest("hex"),
    );
    const cached = await this.checkpoints?.getEmbeddingChunks(keys);
    const pending: Chunk[] = [];
    const pendingKeys: string[] = [];
    for (const [index, chunk] of chunks.entries()) {
      const vector = cached?.[index];
      if (vector != null) this.accumulate(chunk, vector, vectors);
      else {
        pending.push(chunk);
        pendingKeys.push(keys[index]!);
      }
    }
    if (pending.length === 0) return;
    chunks = pending;
    let response: Response;
    try {
      const apiKey =
        typeof this.apiKey === "function" ? await this.apiKey() : this.apiKey;
      if (!apiKey) throw new Error("Missing embedding credentials");
      response = await this.request(this.url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: EMBEDDING_MODEL,
          dimensions: EMBEDDING_DIMENSIONS,
          encoding_format: "float",
          input: chunks.map(({ tokens }) => tokens),
        }),
      });
    } catch {
      throw new FindingsError(
        "embedding_failed",
        "Could not reach the embedding provider.",
      );
    }
    if (!response.ok) {
      throw new FindingsError(
        "embedding_failed",
        `Embedding provider returned HTTP ${response.status}.`,
      );
    }

    let payload: { model?: unknown; data?: unknown } | null;
    try {
      payload = (await response.json()) as typeof payload;
    } catch {
      throw invalidEmbeddingResponse();
    }
    if (
      payload?.model !== EMBEDDING_MODEL ||
      !Array.isArray(payload.data) ||
      payload.data.length !== chunks.length
    ) {
      throw invalidEmbeddingResponse();
    }
    const seen = new Set<number>();
    const entries: { key: string; vector: number[] }[] = [];
    for (const item of payload.data) {
      const index: unknown = item?.index;
      const embedding: unknown = item?.embedding;
      if (
        typeof index !== "number" ||
        !Number.isInteger(index) ||
        index < 0 ||
        index >= chunks.length ||
        seen.has(index) ||
        !Array.isArray(embedding) ||
        embedding.length !== EMBEDDING_DIMENSIONS ||
        !embedding.every(
          (value: unknown) =>
            typeof value === "number" && Number.isFinite(value),
        )
      ) {
        throw invalidEmbeddingResponse();
      }
      const norm = Math.hypot(...embedding);
      if (norm === 0 || !Number.isFinite(norm))
        throw invalidEmbeddingResponse();
      seen.add(index);
      entries.push({ key: pendingKeys[index]!, vector: embedding as number[] });
    }
    // Commit only a fully validated provider response, before another paid batch.
    await this.checkpoints?.saveEmbeddingChunks(entries);
    for (const item of payload.data)
      this.accumulate(chunks[item.index]!, item.embedding, vectors);
  }

  private accumulate(
    chunk: Chunk,
    embedding: number[],
    vectors: number[][],
  ): void {
    const vector = vectors[chunk.findingIndex]!;
    for (let dimension = 0; dimension < vector.length; dimension++) {
      vector[dimension] =
        vector[dimension]! + embedding[dimension]! * chunk.tokens.length;
    }
  }
}

function invalidEmbeddingResponse(): FindingsError {
  return new FindingsError(
    "embedding_failed",
    "Embedding provider returned invalid vectors.",
  );
}

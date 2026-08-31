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

interface Chunk {
  findingIndex: number;
  tokens: number[];
}

export class OpenAiFindingEmbedder implements FindingEmbedder {
  private readonly encoding = new Tiktoken(cl100kBase);

  constructor(
    private readonly apiKey: string | undefined,
    private readonly request: (
      url: string,
      init: RequestInit,
    ) => Promise<Response> = fetch,
    private readonly url: string = "https://api.openai.com/v1/embeddings",
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
    let response: Response;
    try {
      response = await this.request(this.url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
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
      seen.add(index);
      const chunk = chunks[index]!;
      const vector = vectors[chunk.findingIndex]!;
      for (let dimension = 0; dimension < vector.length; dimension++) {
        vector[dimension] =
          vector[dimension]! + embedding[dimension]! * chunk.tokens.length;
      }
    }
  }
}

function invalidEmbeddingResponse(): FindingsError {
  return new FindingsError(
    "embedding_failed",
    "Embedding provider returned invalid vectors.",
  );
}

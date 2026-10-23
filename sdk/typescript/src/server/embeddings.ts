import { Tiktoken } from "js-tiktoken/lite";
import cl100kBase from "js-tiktoken/ranks/cl100k_base";
import { errorMessage } from "../errors.js";
import type { Finding } from "../models.js";
import { VERSION } from "../version.js";
import { FindingsError } from "./errors.js";
import type { FindingEmbedding } from "./storage.js";

export const EMBEDDING_MODEL = "text-embedding-3-large";
export const EMBEDDING_DIMENSIONS = 1536;
export const EMBEDDINGS_URL = "https://api.openai.com/v1/embeddings";
const MAX_INPUT_TOKENS = 8192;
const MAX_REQUEST_TOKENS = 300_000;
const MAX_REQUEST_INPUTS = 2048;

export interface FindingEmbedder {
  embed(findings: readonly Finding[]): Promise<FindingEmbedding[]>;
}

/** One embedding batch, separate from scan model-token accounting. */
export interface EmbeddingUsageObservation {
  model: string;
  /** Number of tokenized inputs in this batch, including chunks of long findings. */
  inputCount: number;
  /** Provider-reported input tokens; null means the response did not supply them. */
  inputTokens: number | null;
  /** Batch request and decoding outcome; final vector pooling belongs to embed(). */
  outcome: "completed" | "failed" | "canceled";
  durationMs: number;
}

export type EmbeddingUsageObserver = (
  observation: Readonly<EmbeddingUsageObservation>,
) => void;

interface Chunk {
  findingIndex: number;
  tokens: number[];
}

export class OpenAiFindingEmbedder implements FindingEmbedder {
  private readonly encoding = new Tiktoken(cl100kBase);

  constructor(
    private readonly apiKey:
      string | (() => string | Promise<string>) | undefined,
    private readonly request: (
      url: string,
      init: RequestInit,
    ) => Promise<Response> = fetch,
    private readonly url: string = EMBEDDINGS_URL,
    private readonly signal?: AbortSignal,
    private readonly onUsage?: EmbeddingUsageObserver,
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
    const started = performance.now();
    let inputTokens: number | null = null;
    let outcome: EmbeddingUsageObservation["outcome"] = "failed";
    try {
      await this.requestChunks(chunks, vectors, (tokens) => {
        inputTokens = tokens;
      });
      outcome = "completed";
    } finally {
      const observation = Object.freeze({
        model: EMBEDDING_MODEL,
        inputCount: chunks.length,
        inputTokens,
        outcome: this.signal?.aborted ? ("canceled" as const) : outcome,
        durationMs: Math.max(0, performance.now() - started),
      });
      // Optional observers must neither reject nor delay embedding work.
      void Promise.resolve()
        .then(() => this.onUsage?.(observation))
        .catch(() => {});
    }
  }

  private async requestChunks(
    chunks: Chunk[],
    vectors: number[][],
    onUsage: (inputTokens: number) => void,
  ): Promise<void> {
    let response: Response;
    try {
      this.signal?.throwIfAborted();
      const apiKey =
        typeof this.apiKey === "function" ? await this.apiKey() : this.apiKey;
      this.signal?.throwIfAborted();
      if (!apiKey) throw new Error("Missing embedding credentials");
      response = await this.request(this.url, {
        method: "POST",
        ...(this.signal === undefined ? {} : { signal: this.signal }),
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": `codex-security/${VERSION}`,
        },
        body: JSON.stringify({
          model: EMBEDDING_MODEL,
          dimensions: EMBEDDING_DIMENSIONS,
          encoding_format: "float",
          input: chunks.map(({ tokens }) => tokens),
        }),
      });
    } catch (error) {
      this.signal?.throwIfAborted();
      throw new FindingsError(
        "embedding_failed",
        `Could not request finding embeddings: ${errorMessage(error)}`,
      );
    }
    if (!response.ok) {
      void response.body?.cancel().catch(() => undefined);
      throw new FindingsError(
        "embedding_failed",
        `Embedding provider returned HTTP ${response.status}.`,
      );
    }

    let payload: {
      model?: unknown;
      data?: unknown;
      usage?: { prompt_tokens?: unknown };
    } | null;
    try {
      payload = (await response.json()) as typeof payload;
    } catch {
      this.signal?.throwIfAborted();
      throw invalidEmbeddingResponse();
    }
    const inputTokens = payload?.usage?.prompt_tokens;
    if (
      typeof inputTokens === "number" &&
      Number.isSafeInteger(inputTokens) &&
      inputTokens >= 0
    )
      onUsage(inputTokens);
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

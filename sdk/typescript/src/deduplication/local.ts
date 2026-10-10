import { environmentEntry } from "../auth.js";
import { gitProtectionRoots } from "../targets.js";
import type { Finding } from "../models.js";
import type {
  FindingNeighborhood,
  FindingSearchScope,
} from "../finding-retrieval.js";
import { CodexSecurityError } from "../errors.js";
import { workflowDigest } from "../finding-workflow.js";
import {
  resolveWorkbenchRuntime,
  workbenchEnvironment,
  runWorkbench,
  type WorkbenchCommandOptions,
} from "../runtime.js";
import {
  OpenAiFindingEmbedder,
  EMBEDDING_MODEL,
  EMBEDDING_DIMENSIONS,
  EMBEDDINGS_URL,
  type FindingEmbedder,
} from "../server/embeddings.js";
import { retryDelay, waitForRetry } from "./retry.js";

// Checkpoint bounded batches so a retry keeps completed work without one process per finding.
const EMBEDDING_BATCH_SIZE = 64;

/** One vector space and the adapter that produces its embeddings. */
export interface FindingEmbeddingBinding {
  readonly embedder: FindingEmbedder;
  readonly model: string;
  readonly dimensions: number;
  /** Identifies the provider/vector space and preprocessing version; exclude credentials. */
  readonly cacheNamespace: string;
}

/** Direct workbench adapter. Importing it starts no HTTP or MCP server. */
export class LocalDeduplication {
  private options?: Promise<WorkbenchCommandOptions>;
  private cacheKeys: Record<string, string> = {};
  private readonly space: string;
  private readonly embedding: FindingEmbeddingBinding;

  constructor(
    private readonly environment: NodeJS.ProcessEnv,
    private readonly scope: FindingSearchScope,
    private readonly repositoryPath: string,
    private readonly signal?: AbortSignal,
    private readonly workbench: typeof runWorkbench = runWorkbench,
    embedding?: FindingEmbeddingBinding,
  ) {
    const endpoint =
      environmentEntry(environment, "CODEX_SECURITY_EMBEDDINGS_URL") ||
      EMBEDDINGS_URL;
    this.embedding = embedding ?? {
      model: EMBEDDING_MODEL,
      dimensions: EMBEDDING_DIMENSIONS,
      cacheNamespace: endpoint,
      embedder: new OpenAiFindingEmbedder(
        [
          environmentEntry(environment, "OPENAI_API_KEY"),
          environmentEntry(environment, "CODEX_API_KEY"),
        ].find((value) => value?.trim()),
        embeddingRequest,
        endpoint,
        signal,
      ),
    };
    // The digest keeps endpoint/namespace details out of persisted cache keys.
    this.space = workflowDigest({
      version: 1,
      model: this.embedding.model,
      dimensions: this.embedding.dimensions,
      namespace: this.embedding.cacheNamespace,
    });
  }

  get inputDigest(): string {
    return workflowDigest(this.cacheKeys);
  }

  async prepare(
    findings: readonly Finding[],
    repositoryId: string,
  ): Promise<void> {
    const result = await this.command({
      action: "prepare",
      findings,
      anchorRepositoryId: repositoryId,
      repositoryPath: this.repositoryPath,
    });
    this.cacheKeys = result["cacheKeys"] as Record<string, string>;
    const findingsToEmbed = result["findingsToEmbed"] as unknown as Finding[];
    for (
      let offset = 0;
      offset < findingsToEmbed.length;
      offset += EMBEDDING_BATCH_SIZE
    ) {
      this.signal?.throwIfAborted();
      const batch = findingsToEmbed.slice(
        offset,
        offset + EMBEDDING_BATCH_SIZE,
      );
      const embeddings = await this.embedding.embedder.embed(batch);
      this.signal?.throwIfAborted();
      if (embeddings.length !== batch.length)
        throw new CodexSecurityError(
          "Embedding provider returned an invalid number of vectors.",
        );
      await this.command({
        action: "embed",
        entries: batch.map((finding, index) => ({
          findingId: finding.findingId,
          cacheKey: this.cacheKeys[finding.findingId],
          embedding: embeddings[index],
        })),
      });
    }
  }

  async potentialDuplicates(findingId: string): Promise<FindingNeighborhood> {
    return (await this.command({
      action: "neighbors",
      findingId,
      cacheKeys: this.cacheKeys,
    })) as unknown as FindingNeighborhood;
  }

  async storeDedupeGroups(groups: readonly string[][]): Promise<void> {
    await this.command({ action: "commit", groups, cacheKeys: this.cacheKeys });
  }

  private async command(payload: { action: string; [key: string]: unknown }) {
    this.signal?.throwIfAborted();
    this.options ??= (async () => {
      const environment = workbenchEnvironment(this.environment);
      const [python, pluginRoot] = await resolveWorkbenchRuntime({
        environment,
        protectedRoot: this.repositoryPath,
        signal: this.signal,
      });
      return {
        python,
        pluginRoot,
        environment,
        signal: this.signal,
        protectedRoot: [
          this.repositoryPath,
          ...(await gitProtectionRoots(this.repositoryPath, this.signal)),
          ...(await gitProtectionRoots(process.cwd(), this.signal)),
        ],
        failureMessage: "Could not access local deduplication state",
      };
    })();
    const result = await this.workbench(
      await this.options,
      [
        payload.action === "neighbors"
          ? "find-potential-duplicates"
          : payload.action === "commit"
            ? "store-dedupe-groups"
            : "local-dedupe",
      ],
      JSON.stringify({
        ...payload,
        scope: this.scope,
        space: this.space,
        model: this.embedding.model,
        dimensions: this.embedding.dimensions,
        ...(this.scope.allRepositories
          ? {}
          : { repositoryId: this.scope.repositoryId }),
      }),
    );
    this.signal?.throwIfAborted();
    const code = result["error"];
    if (code !== undefined) {
      const message =
        code === "finding_changed"
          ? "Findings changed during local deduplication. Retry with a new workflow ID if resuming."
          : code === "target_mismatch"
            ? "The scan target does not match the approved local checkout. Use its original checkout or an explicitly configured findings service."
            : code === "finding_not_indexed"
              ? "A local finding has no complete document. Reimport its scan before deduplicating."
              : `Local deduplication failed: ${String(code)}.`;
      throw new CodexSecurityError(message);
    }
    return result;
  }
}

async function embeddingRequest(
  url: string,
  init: RequestInit,
): Promise<Response> {
  for (let attempt = 1; ; attempt++) {
    init.signal?.throwIfAborted();
    let delay = retryDelay(attempt);
    try {
      const response = await fetch(url, init);
      if (
        attempt === 3 ||
        ![408, 429, 500, 502, 503, 504].includes(response.status)
      )
        return response;
      const retryAfter = response.headers.get("Retry-After");
      if (retryAfter !== null) {
        const seconds = Number(retryAfter);
        const retryAt = Number.isFinite(seconds)
          ? seconds * 1000
          : Date.parse(retryAfter) - Date.now();
        if (Number.isFinite(retryAt)) delay = Math.max(delay, retryAt);
      }
      await response.body?.cancel().catch(() => undefined);
    } catch (error) {
      init.signal?.throwIfAborted();
      if (attempt === 3 || !(error instanceof TypeError)) throw error;
    }
    await waitForRetry(delay, init.signal ?? undefined);
  }
}

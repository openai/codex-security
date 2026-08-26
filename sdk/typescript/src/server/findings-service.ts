import type { Finding } from "../models.js";
import type {
  DeduplicationService,
  DeduplicationResult,
} from "./deduplication/deduplication.js";
import type { FindingEmbedder } from "./embeddings.js";
import type { FindingsPage, FindingsStore } from "./storage.js";

export class FindingsService {
  constructor(
    private readonly store: FindingsStore,
    private readonly embeddings: FindingEmbedder,
    private readonly deduplication: Pick<DeduplicationService, "run">,
  ) {}

  async insert(findings: readonly Finding[]): Promise<string[]> {
    const embeddings = await this.embeddings.embed(findings);
    return await this.store.insert(
      findings.map((finding, index) => ({
        finding,
        embedding: embeddings[index]!,
      })),
    );
  }

  async insertAndDeduplicate(
    findings: readonly Finding[],
  ): Promise<DeduplicationResult> {
    const ids = await this.insert(findings);
    return await this.deduplication.run(ids);
  }

  async list(page: { limit: number; offset: number }): Promise<FindingsPage> {
    return await this.store.list(page);
  }
}

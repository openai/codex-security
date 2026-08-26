import type { Finding } from "../models.js";
import { potentialDuplicates } from "./potential-duplicates.js";
import type { FindingEmbedder } from "./embeddings.js";
import type { FindingsPage, FindingsStore } from "./storage.js";

export class FindingsService {
  constructor(
    private readonly store: FindingsStore,
    private readonly embeddings: FindingEmbedder,
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

  async potentialDuplicates(findingId: string) {
    return potentialDuplicates(await this.store.listEmbedded(), findingId);
  }

  async list(page: { limit: number; offset: number }): Promise<FindingsPage> {
    return await this.store.list(page);
  }
}

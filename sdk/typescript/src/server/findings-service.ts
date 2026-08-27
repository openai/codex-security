import type { Finding } from "../models.js";
import type { DashboardQuery } from "./dashboard-types.js";
import type { FindingSearchScope } from "../finding-retrieval.js";
import type { FindingEmbedder } from "./embeddings.js";
import type { FindingsPage, FindingsStore } from "./storage.js";

export class FindingsService {
  constructor(
    private readonly store: FindingsStore,
    private readonly embeddings: FindingEmbedder,
  ) {}

  async insert(
    findings: readonly Finding[],
    repositoryId?: string,
  ): Promise<string[]> {
    const embeddings = await this.embeddings.embed(findings);
    return await this.store.insert(
      findings.map((finding, index) => ({
        finding,
        embedding: embeddings[index]!,
      })),
      repositoryId,
    );
  }

  async potentialDuplicates(findingId: string, scope: FindingSearchScope) {
    return await this.store.findPotentialDuplicates(findingId, scope);
  }

  async storeDedupeGroups(groups: readonly string[][]) {
    return await this.store.storeDedupeGroups(groups);
  }

  async listDedupeGroups(findingId: string) {
    return await this.store.listDedupeGroups(findingId);
  }

  async list(page: { limit: number; offset: number }): Promise<FindingsPage> {
    return await this.store.list(page);
  }

  async dashboard(query: DashboardQuery) {
    return await this.store.dashboard(query);
  }
}

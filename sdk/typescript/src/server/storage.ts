import type { Finding } from "../models.js";
import type { DashboardQuery, DashboardSnapshot } from "./dashboard-types.js";
import type { FindingDedupeGroup } from "../finding-dedupe-groups.js";
import type {
  FindingNeighborhood,
  FindingSearchScope,
} from "../finding-retrieval.js";

export interface FindingEmbedding {
  model: string;
  vector: number[];
}

export interface EmbeddedFinding {
  finding: Finding;
  embedding: FindingEmbedding;
}

export interface FindingsPage {
  findings: Finding[];
  limit: number;
  offset: number;
  total: number;
  nextOffset: number | null;
}

export interface FindingsStore {
  initialize(): Promise<void>;
  dashboard(query: DashboardQuery): Promise<DashboardSnapshot>;
  insert(
    entries: readonly EmbeddedFinding[],
    repositoryId?: string,
  ): Promise<string[]>;
  list(page: { limit: number; offset: number }): Promise<FindingsPage>;
  storeDedupeGroups(groups: readonly string[][]): Promise<FindingDedupeGroup[]>;
  listDedupeGroups(findingId: string): Promise<FindingDedupeGroup[]>;
  findPotentialDuplicates(
    findingId: string,
    scope: FindingSearchScope,
  ): Promise<FindingNeighborhood>;
}

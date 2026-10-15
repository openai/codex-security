import type { Finding } from "./models.js";

export type FindingSearchScope =
  | { repositoryId: string; allRepositories?: never }
  | { allRepositories: true; repositoryId?: never };

export interface FindingSourceSnapshot {
  repositoryId: string | null;
  revision: string;
  snapshotDigest: string | null;
}

export interface FindingNeighborhood {
  finding: Finding;
  potentialDuplicates: Finding[];
  /** Saved storage associations, separate from model-authored finding content. */
  repositoryIds?: Record<string, string[]>;
  /** Present only when the current body matches its persisted scan occurrence. */
  sourceSnapshots?: Record<string, FindingSourceSnapshot>;
}

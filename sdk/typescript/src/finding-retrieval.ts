import type { Finding } from "./models.js";

export type FindingSearchScope =
  | { repositoryId: string; allRepositories?: never }
  | { allRepositories: true; repositoryId?: never };

export interface FindingNeighborhood {
  finding: Finding;
  potentialDuplicates: Finding[];
}

import type { Finding } from "../models.js";

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
  insert(entries: readonly EmbeddedFinding[]): Promise<string[]>;
  list(page: { limit: number; offset: number }): Promise<FindingsPage>;
  listEmbedded(): Promise<EmbeddedFinding[]>;
}

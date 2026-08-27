import type { Finding } from "../models.js";
import type { FindingDedupeGroup } from "../finding-dedupe-groups.js";

export type DashboardView = "findings" | "groups";

export interface DashboardQuery {
  view: DashboardView;
  limit: number;
  offset: number;
  query: string;
  repository: string;
  sort: "activity" | "newest";
  id?: string;
}

/** Stored finding or duplicate group list projection. */
export interface DashboardItem {
  id: string;
  title: string;
  repositoryIds: string[];
  createdAt: string;
  updatedAt: string;
  memberCount?: number;
  severity?: Finding["severity"]["level"];
}

export interface DashboardDetail {
  item: DashboardItem;
  finding?: Finding;
  group?: FindingDedupeGroup;
  groups?: FindingDedupeGroup[];
}

export interface DashboardSnapshot {
  overview: {
    findings: number;
    groups: number;
  };
  repositories: { id: string; label: string }[];
  items: DashboardItem[];
  total: number;
  limit: number;
  offset: number;
  nextOffset: number | null;
  detail: DashboardDetail | null;
}

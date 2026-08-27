import type { Finding } from "../models.js";
import type { WorkflowState } from "../finding-workflow.js";
import type { FindingDedupeGroup } from "../finding-dedupe-groups.js";

export type DashboardView = "scans" | "workflows" | "findings" | "groups";

export interface DashboardQuery {
  view: DashboardView;
  limit: number;
  offset: number;
  query: string;
  repository: string;
  status: string;
  stage: string;
  sort: "activity" | "newest";
  id?: string;
}

/** A list projection; absent counts are unknown, not zero. */
export interface DashboardItem {
  id: string;
  title: string;
  repositoryIds: string[];
  createdAt: string;
  updatedAt: string;
  repositoryPath?: string | null;
  status?: string;
  stage?: string;
  scanId?: string | null;
  mode?: string | null;
  findingCount?: number | null;
  publishedCount?: number | null;
  uniqueCount?: number | null;
  memberCount?: number;
  severity?: Finding["severity"]["level"];
}

export interface DashboardScan {
  scanId: string;
  repositoryPath: string;
  repositoryId: string | null;
  revision: string;
  scope: string;
  mode: string;
  status: string;
  phase: string;
  startedAt: string;
  completedAt: string | null;
  updatedAt: string;
  scanDir: string;
  error: string | null;
  progress: {
    reviewed: number | null;
    total: number | null;
    reportable: number | null;
    deepPass: number | null;
  };
  findingIds: string[];
  workflowIds: string[];
}

export interface DashboardDetail {
  item: DashboardItem;
  scan?: DashboardScan;
  workflow?: WorkflowState;
  finding?: Finding;
  group?: FindingDedupeGroup;
  groups?: FindingDedupeGroup[];
  scanIds?: string[];
}

export interface DashboardSnapshot {
  overview: {
    scans: Record<string, number>;
    workflows: Record<string, number>;
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

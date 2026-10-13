import type { ScanCost } from "./cost.js";

/** Saved workbench status differs from canonical manifest scan.status. */
export type SavedScanStatus = "running" | "complete" | "failed" | "canceled";

export interface SavedScanRecord {
  scanId: string;
  scanDir: string;
  parentScanId?: string | null;
  parentScanRole?: "deep_pass" | null;
  targetPath: string;
  completedAt?: string | null;
  continuationThreadId?: string | null;
  progress: { status: SavedScanStatus; [extension: string]: unknown };
  cost?: ScanCost | null;
  [extension: string]: unknown;
}

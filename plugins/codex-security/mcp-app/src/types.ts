export type Mode = "diff" | "standard" | "deep";
export type DiffTargetKind = "working_tree" | "commit" | "range";
export type JsonObject = Record<string, unknown>;

export interface DiffTarget {
  baseRevision?: string;
  contentDigest?: string;
  headRevision?: string;
  kind: DiffTargetKind;
}

export interface ScanArtifacts {
  coverage?: string;
  findings?: string;
  manifest?: string;
  markdownReport?: string;
  sarifReport?: string;
}

export interface ScanResults {
  artifacts: ScanArtifacts;
  canceledAt?: string;
  diffTarget?: DiffTarget;
  findingCount: number;
  findings: JsonObject[];
  findingsTruncated?: boolean;
  failureMessage?: string;
  handoffClaimedAt?: string;
  handoffClaimToken?: string;
  handoffStatus: "delivered" | "pending";
  mode: Mode;
  progress?: JsonObject;
  remediationAvailable?: boolean;
  remediationUnavailableReason?: string;
  scanDir: string;
  scanId: string;
  scope?: string;
  severityCounts?: Record<string, number>;
  targetPath: string;
  targetRevision?: string;
  targetSummary?: string | null;
  updatedAt?: string;
  userContext?: string;
}

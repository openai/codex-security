/* Generated from cloud-import-v1.schema.json. Run node scripts/generate-cloud-import-models.cjs. */

export type ProtocolVersion = 1;
export type EnvironmentId = string;
export type RepositoryId = string;
export type ConnectorId = string | null;
export type SourceScanId = string;
export type RepositoryRemote = string;
export type RepositoryPath = ".";
export type TargetKind = "git_revision" | "git_worktree";
export type CoverageMode = "full_repository";
export type BaseCommit = string;
export type SnapshotDigest = string | null;
export type ScanStartedAt = string;
export type ScanCompletedAt = string;
export type Name =
  "findings.json" | "scan-manifest.json" | "coverage.json" | "report.md";
export type Sha256 = string;
export type SizeBytes = number;
/**
 * @minItems 3
 * @maxItems 4
 */
export type Artifacts = ImportArtifactDeclaration[];
export type ProtocolVersion1 = 1;
export type ImportedScanId = string;
export type Source = "cli";
export type SourceScanId1 = string;
export type EnvironmentId1 = string;
export type RepositoryId1 = string;
export type RepositoryFullName = string;
export type BaseCommit1 = string;
export type SnapshotDigest1 = string | null;
export type TargetKind1 = "git_revision" | "git_worktree";
export type ConnectorId1 = string | null;
export type RepositoryRemote1 = string;
export type UploadStatus = "uploading" | "finalizing" | "accepted" | "expired";
export type MaterializationStatus =
  "pending" | "processing" | "completed" | "failed";
export type DedupeStatus = "pending" | "processing" | "completed" | "failed";
export type Name1 =
  "findings.json" | "scan-manifest.json" | "coverage.json" | "report.md";
export type Sha2561 = string;
export type SizeBytes1 = number;
export type Uploaded = boolean;
export type DownloadUrl = string | null;
export type Artifacts1 = ImportedArtifactStatus[];
export type CreatedAt = string;
export type ScanStartedAt1 = string;
export type ScanCompletedAt1 = string;
export type FinalizationStartedAt = string | null;
export type FinalizedAt = string | null;
export type MaterializationCompletedAt = string | null;
export type FindingCount = number | null;
export type FailureCode = string | null;
export type StatusUrl = string;
export type ProtocolVersion2 = 1;
export type EnvironmentId2 = string;
export type EnvironmentName = string;
export type RepositoryId2 = string;
export type RepositoryFullName1 = string;
export type RepositoryRemote2 = string;
export type ConnectorId2 = string | null;
export type Destinations = ImportDestination[];

export interface CloudImportProtocolV1 {
  CreateImportedScan?: CreateImportedScan;
  ImportedScanReceipt?: ImportedScanReceipt;
  ImportDestinations?: ImportDestinations;
}
export interface CreateImportedScan {
  protocol_version: ProtocolVersion;
  environment_id: EnvironmentId;
  repository_id: RepositoryId;
  connector_id: ConnectorId;
  source_scan_id: SourceScanId;
  repository_remote: RepositoryRemote;
  repository_path: RepositoryPath;
  target_kind: TargetKind;
  coverage_mode: CoverageMode;
  base_commit: BaseCommit;
  snapshot_digest?: SnapshotDigest;
  scan_started_at: ScanStartedAt;
  scan_completed_at: ScanCompletedAt;
  artifacts: Artifacts;
}
export interface ImportArtifactDeclaration {
  name: Name;
  sha256: Sha256;
  size_bytes: SizeBytes;
}
export interface ImportedScanReceipt {
  protocol_version?: ProtocolVersion1;
  imported_scan_id: ImportedScanId;
  source?: Source;
  source_scan_id: SourceScanId1;
  environment_id: EnvironmentId1;
  repository_id: RepositoryId1;
  repository_full_name: RepositoryFullName;
  base_commit: BaseCommit1;
  snapshot_digest: SnapshotDigest1;
  target_kind: TargetKind1;
  connector_id: ConnectorId1;
  repository_remote: RepositoryRemote1;
  upload_status: UploadStatus;
  materialization_status: MaterializationStatus;
  dedupe_status: DedupeStatus;
  artifacts: Artifacts1;
  created_at: CreatedAt;
  scan_started_at: ScanStartedAt1;
  scan_completed_at: ScanCompletedAt1;
  finalization_started_at?: FinalizationStartedAt;
  finalized_at: FinalizedAt;
  materialization_completed_at: MaterializationCompletedAt;
  finding_count: FindingCount;
  failure_code: FailureCode;
  status_url: StatusUrl;
}
export interface ImportedArtifactStatus {
  name: Name1;
  sha256: Sha2561;
  size_bytes: SizeBytes1;
  uploaded: Uploaded;
  download_url?: DownloadUrl;
}
export interface ImportDestinations {
  protocol_version?: ProtocolVersion2;
  destinations: Destinations;
}
export interface ImportDestination {
  environment_id: EnvironmentId2;
  environment_name: EnvironmentName;
  repository_id: RepositoryId2;
  repository_full_name: RepositoryFullName1;
  repository_remote: RepositoryRemote2;
  connector_id: ConnectorId2;
}

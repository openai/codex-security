/* Generated from schemas/external-findings.schema.json. Run pnpm generate:external-import-models. */

export type RequestId = string;
export type Id = string;
export type RepoConnectorId = string;
export type EnvironmentId = string;
export type ResetMarker = string;
export type Provider = "wiz" | "endor" | "snyk";
export type SourceKey = string;
export type ClientId = string;
export type SourceFindingId = string;
export type ExpectedVersion = number;
export type Title = string;
export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Description = string | null;
export type Url = string | null;
/**
 * @maxItems 100
 */
export type AdvisoryIds = string[];
export type Name = string;
export type Ecosystem = string | null;
export type InstalledVersion = string | null;
export type ManifestPath = string | null;
/**
 * @maxItems 100
 */
export type FixedVersions = string[];
/**
 * @maxItems 100
 */
export type Packages = ImportedPackage[];
export type Path = string;
export type Line = number | null;
/**
 * @maxItems 100
 */
export type Locations = ImportedLocation[];
export type Branch = string | null;
export type CodeRevision = string | null;
export type SourceScanId = string | null;
/**
 * @maxItems 100
 */
export type ImageDigests = string[];
export type SourceUpdatedAt = number | null;
/**
 * @minItems 1
 * @maxItems 100
 */
export type Items = FindingImportItem[];
export type Id1 = string;
export type Object = "security.finding_import";
export type Actor = string;
export type CreatedAt = number;
export type ItemCount = number;
export type Created = number;
export type Updated = number;
export type Unchanged = number;
export type Error = number;
export type ClientId1 = string;
export type Outcome = "created" | "updated" | "unchanged" | "error";
export type SourceReportId = string | null;
export type ObservationId = string | null;
export type CanonicalFindingId = string | null;
export type Version = number | null;
export type Code =
  "version_conflict" | "scope_conflict" | "stale_source_snapshot";
export type Message = string;
export type Results = FindingImportResult[];
export type Object1 = "page";
export type Id2 = string;
export type Object2 = "security.repository";
export type RepoConnectorId1 = string;
export type Url1 = string;
export type DefaultBranch = string | null;
export type ResetMarker1 = string;
export type ImportEnvironmentId = string | null;
export type Data = ImportRepository[];
export type HasMore = boolean;
export type Next = string | null;
export type Id3 = string;
export type Object3 = "security.source_report";
export type Origin = "imported";
export type RepoId = string;
export type RepoConnectorId2 = string;
export type EnvironmentId1 = string;
export type CanonicalFindingId1 = string;
export type SourceFindingId1 = string;
export type ObservationId1 = string;
export type Version1 = number;
export type State = "not_assessed";
export type Id4 = string;
export type Actor1 = string;
export type CreatedAt1 = number;
export type CreatedAt2 = number;
export type UpdatedAt = number;
export type Object4 = "page";
export type Id5 = string;
export type Object5 = "security.source_report_summary";
export type Origin1 = "imported";
export type RepoId1 = string;
export type RepoConnectorId3 = string;
export type EnvironmentId2 = string;
export type CanonicalFindingId2 = string;
export type SourceFindingId2 = string;
export type ObservationId2 = string;
export type Version2 = number;
export type Title1 = string;
export type Severity1 =
  "critical" | "high" | "medium" | "low" | "informational";
export type SourceUpdatedAt1 = number | null;
export type CreatedAt3 = number;
export type UpdatedAt1 = number;
export type Data1 = SourceReportSummary[];
export type HasMore1 = boolean;
export type Next1 = string | null;

/**
 * Schema export root; transport endpoints return the individual models.
 */
export interface ExternalFindingContracts {
  request: FindingImportRequest;
  receipt: FindingImportReceipt;
  repositories: ImportRepositoryPage;
  source_report: SourceReport;
  source_reports: SourceReportPage;
}
export interface FindingImportRequest {
  request_id: RequestId;
  repository: ImportDestination;
  source: ImportSource;
  items: Items;
}
export interface ImportDestination {
  id: Id;
  repo_connector_id: RepoConnectorId;
  environment_id: EnvironmentId;
  reset_marker: ResetMarker;
}
export interface ImportSource {
  provider: Provider;
  source_key: SourceKey;
}
export interface FindingImportItem {
  client_id: ClientId;
  source_finding_id: SourceFindingId;
  expected_version: ExpectedVersion;
  evidence: ImportedFindingEvidence;
}
export interface ImportedFindingEvidence {
  title: Title;
  severity: Severity;
  description?: Description;
  url?: Url;
  advisory_ids?: AdvisoryIds;
  packages?: Packages;
  locations?: Locations;
  branch?: Branch;
  code_revision?: CodeRevision;
  source_scan_id?: SourceScanId;
  image_digests?: ImageDigests;
  source_updated_at?: SourceUpdatedAt;
  source_data?: SourceData;
}
export interface ImportedPackage {
  name: Name;
  ecosystem?: Ecosystem;
  installed_version?: InstalledVersion;
  manifest_path?: ManifestPath;
  fixed_versions?: FixedVersions;
}
export interface ImportedLocation {
  path: Path;
  line?: Line;
}
export interface SourceData {
  [k: string]: unknown;
}
export interface FindingImportReceipt {
  id: Id1;
  object?: Object;
  repository: ImportDestination;
  source: ImportSource;
  actor: Actor;
  created_at: CreatedAt;
  item_count: ItemCount;
  counts: ImportCounts;
  results: Results;
}
export interface ImportCounts {
  created?: Created;
  updated?: Updated;
  unchanged?: Unchanged;
  error?: Error;
}
export interface FindingImportResult {
  client_id: ClientId1;
  outcome: Outcome;
  source_report_id?: SourceReportId;
  observation_id?: ObservationId;
  canonical_finding_id?: CanonicalFindingId;
  version?: Version;
  error?: ImportItemError | null;
}
export interface ImportItemError {
  code: Code;
  message: Message;
}
export interface ImportRepositoryPage {
  object?: Object1;
  data: Data;
  has_more: HasMore;
  next: Next;
}
export interface ImportRepository {
  id: Id2;
  object?: Object2;
  repo_connector_id: RepoConnectorId1;
  url: Url1;
  default_branch?: DefaultBranch;
  reset_marker: ResetMarker1;
  import_environment_id?: ImportEnvironmentId;
}
export interface SourceReport {
  id: Id3;
  object?: Object3;
  origin?: Origin;
  repo_id: RepoId;
  repo_connector_id: RepoConnectorId2;
  environment_id: EnvironmentId1;
  canonical_finding_id: CanonicalFindingId1;
  source: ImportSource;
  source_finding_id: SourceFindingId1;
  observation_id: ObservationId1;
  version: Version1;
  evidence: ImportedFindingEvidence;
  assessment?: ImportedAssessment;
  last_import?: LastImport | null;
  created_at: CreatedAt2;
  updated_at: UpdatedAt;
}
export interface ImportedAssessment {
  state?: State;
}
export interface LastImport {
  id: Id4;
  actor: Actor1;
  created_at: CreatedAt1;
}
export interface SourceReportPage {
  object?: Object4;
  data: Data1;
  has_more: HasMore1;
  next: Next1;
}
export interface SourceReportSummary {
  id: Id5;
  object?: Object5;
  origin?: Origin1;
  repo_id: RepoId1;
  repo_connector_id: RepoConnectorId3;
  environment_id: EnvironmentId2;
  canonical_finding_id: CanonicalFindingId2;
  source: ImportSource;
  source_finding_id: SourceFindingId2;
  observation_id: ObservationId2;
  version: Version2;
  title: Title1;
  severity: Severity1;
  source_updated_at: SourceUpdatedAt1;
  assessment?: ImportedAssessment;
  created_at: CreatedAt3;
  updated_at: UpdatedAt1;
}

export type ExternalFindingEvidence = ImportedFindingEvidence;

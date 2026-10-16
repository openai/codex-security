/* Generated from schemas/external-findings.schema.json. Run pnpm generate:external-import-models. */

export type Actor = string;
export type Created = number;
export type Error = number;
export type Unchanged = number;
export type Updated = number;
export type CreatedAt = number;
export type Id = string;
export type ItemCount = number;
export type Object = "security.finding_import";
export type EnvironmentId = string;
export type Id1 = string;
export type RepoConnectorId = string;
export type ResetMarker = string;
export type CanonicalFindingId = string | null;
export type ClientId = string;
export type Code =
  "version_conflict" | "scope_conflict" | "stale_source_snapshot";
export type Message = string;
export type ObservationId = string | null;
export type Outcome = "created" | "updated" | "unchanged" | "error";
export type SourceReportId = string | null;
export type Version = number | null;
export type Results = FindingImportResult[];
export type Provider = "wiz" | "endor" | "snyk" | "github" | "semgrep";
export type SourceKey = string;
export type DefaultBranch = string | null;
export type Id2 = string;
export type ImportEnvironmentId = string | null;
export type Object1 = "security.repository";
export type RepoConnectorId1 = string;
export type ResetMarker1 = string;
export type Url = string;
export type Data = ImportRepository[];
export type HasMore = boolean;
export type Next = string | null;
export type Object2 = "page";
export type ClientId1 = string;
/**
 * @maxItems 100
 */
export type AdvisoryIds = string[];
export type Branch = string | null;
export type CodeRevision = string | null;
export type Description = string | null;
export type Source = "repository" | "global";
export type EndLine = number | null;
export type Snippet = string | null;
export type Actual = string | null;
export type CloudPlatform = string | null;
export type Expected = string | null;
export type Platform = string | null;
export type FileUrl = string | null;
export type Kind = "sast" | "secret" | "iac" | "advisory";
export type RemediationInstructions = string | null;
export type Id3 = string | null;
export type Name = string | null;
export type Url1 = string;
export type Id4 = string | null;
export type Name1 = string | null;
export type ShortId = string | null;
export type ScannerOrigin = string | null;
export type ScannerVerdict = string | null;
export type ImportedSecretConfidence = string;
export type IntroducedCommit = string | null;
export type IsEncrypted = boolean | null;
export type IsManaged = boolean | null;
export type Type = string | null;
export type ValidationStatus = string | null;
export type SourceStatus = string | null;
/**
 * @maxItems 100
 */
export type WeaknessIds = string[];
/**
 * @maxItems 100
 */
export type ImageDigests = string[];
export type Line = number | null;
export type Path = string;
/**
 * @maxItems 100
 */
export type Locations = ImportedLocation[];
export type Ecosystem = string | null;
/**
 * @maxItems 100
 */
export type FixedVersions = string[];
export type InstalledVersion = string | null;
export type ManifestPath = string | null;
export type Name2 = string;
export type VulnerableVersionRange = string | null;
/**
 * @maxItems 100
 */
export type Packages = ImportedPackage[];
export type Severity =
  "critical" | "high" | "medium" | "low" | "informational" | "unknown";
export type SourceScanId = string | null;
export type SourceUpdatedAt = number | null;
export type Title = string;
export type Url2 = string | null;
export type ExpectedVersion = number;
export type SourceFindingId = string;
/**
 * @minItems 1
 * @maxItems 100
 */
export type Items = FindingImportItem[];
export type RequestId = string;
export type State = "not_assessed";
export type CanonicalFindingId1 = string;
export type CreatedAt1 = number;
export type EnvironmentId1 = string;
export type Id5 = string;
export type Actor1 = string;
export type CreatedAt2 = number;
export type Id6 = string;
export type Object3 = "security.source_report";
export type ObservationId1 = string;
export type Origin = "imported";
export type RepoConnectorId2 = string;
export type RepoId = string;
export type SourceFindingId1 = string;
export type UpdatedAt = number;
export type Version1 = number;
export type CanonicalFindingId2 = string;
export type CreatedAt3 = number;
export type EnvironmentId2 = string;
export type Id7 = string;
export type Object4 = "security.source_report_summary";
export type ObservationId2 = string;
export type Origin1 = "imported";
export type RepoConnectorId3 = string;
export type RepoId1 = string;
export type Severity1 =
  "critical" | "high" | "medium" | "low" | "informational" | "unknown";
export type SourceFindingId2 = string;
export type SourceUpdatedAt1 = number | null;
export type Title1 = string;
export type UpdatedAt1 = number;
export type Version2 = number;
export type Data1 = SourceReportSummary[];
export type HasMore1 = boolean;
export type Next1 = string | null;
export type Object5 = "page";

/**
 * Schema export root; transport endpoints return the individual models.
 */
export interface ExternalFindingContracts {
  receipt: FindingImportReceipt;
  repositories: ImportRepositoryPage;
  request: FindingImportRequest;
  source_report: SourceReport;
  source_reports: SourceReportPage;
}
export interface FindingImportReceipt {
  actor: Actor;
  counts: ImportCounts;
  created_at: CreatedAt;
  id: Id;
  item_count: ItemCount;
  object?: Object;
  repository: ImportDestination;
  results: Results;
  source: ImportSource;
}
export interface ImportCounts {
  created?: Created;
  error?: Error;
  unchanged?: Unchanged;
  updated?: Updated;
}
export interface ImportDestination {
  environment_id: EnvironmentId;
  id: Id1;
  repo_connector_id: RepoConnectorId;
  reset_marker: ResetMarker;
}
export interface FindingImportResult {
  canonical_finding_id?: CanonicalFindingId;
  client_id: ClientId;
  error?: ImportItemError | null;
  observation_id?: ObservationId;
  outcome: Outcome;
  source_report_id?: SourceReportId;
  version?: Version;
}
export interface ImportItemError {
  code: Code;
  message: Message;
}
export interface ImportSource {
  provider: Provider;
  source_key: SourceKey;
}
export interface ImportRepositoryPage {
  data: Data;
  has_more: HasMore;
  next: Next;
  object?: Object2;
}
export interface ImportRepository {
  default_branch?: DefaultBranch;
  id: Id2;
  import_environment_id?: ImportEnvironmentId;
  object?: Object1;
  repo_connector_id: RepoConnectorId1;
  reset_marker: ResetMarker1;
  url: Url;
}
export interface FindingImportRequest {
  items: Items;
  repository: ImportDestination;
  request_id: RequestId;
  source: ImportSource;
}
export interface FindingImportItem {
  client_id: ClientId1;
  evidence: ImportedFindingEvidence;
  expected_version: ExpectedVersion;
  source_finding_id: SourceFindingId;
}
export interface ImportedFindingEvidence {
  advisory_ids?: AdvisoryIds;
  branch?: Branch;
  code_revision?: CodeRevision;
  description?: Description;
  details?: ImportedFindingDetails | null;
  image_digests?: ImageDigests;
  locations?: Locations;
  packages?: Packages;
  severity: Severity;
  source_data?: SourceData;
  source_scan_id?: SourceScanId;
  source_updated_at?: SourceUpdatedAt;
  title: Title;
  url?: Url2;
}
/**
 * Typed repository evidence; vendor state is not a Codex assessment.
 */
export interface ImportedFindingDetails {
  advisory?: ImportedAdvisoryContext | null;
  code?: ImportedCodeContext | null;
  configuration?: ImportedConfigurationDetails | null;
  file_url?: FileUrl;
  kind: Kind;
  remediation_instructions?: RemediationInstructions;
  repository?: ImportedRepositoryReference | null;
  rule?: ImportedFindingRule | null;
  scanner_origin?: ScannerOrigin;
  scanner_verdict?: ScannerVerdict;
  secret?: ImportedSecretDetails | null;
  source_status?: SourceStatus;
  weakness_ids?: WeaknessIds;
}
/**
 * Where the advisory was read; applicability is assessed separately.
 */
export interface ImportedAdvisoryContext {
  source: Source;
}
/**
 * Optional range and snippet for the evidence's first source location.
 */
export interface ImportedCodeContext {
  end_line?: EndLine;
  snippet?: Snippet;
}
export interface ImportedConfigurationDetails {
  actual?: Actual;
  cloud_platform?: CloudPlatform;
  expected?: Expected;
  platform?: Platform;
}
/**
 * Vendor repository identity, resolved to the full source-control URL.
 */
export interface ImportedRepositoryReference {
  id?: Id3;
  name?: Name;
  url: Url1;
}
export interface ImportedFindingRule {
  id?: Id4;
  name?: Name1;
  short_id?: ShortId;
}
export interface ImportedSecretDetails {
  confidence?: ImportedSecretConfidence | null;
  introduced_commit?: IntroducedCommit;
  is_encrypted?: IsEncrypted;
  is_managed?: IsManaged;
  type?: Type;
  validation_status?: ValidationStatus;
}
export interface ImportedLocation {
  line?: Line;
  path: Path;
}
export interface ImportedPackage {
  ecosystem?: Ecosystem;
  fixed_versions?: FixedVersions;
  installed_version?: InstalledVersion;
  manifest_path?: ManifestPath;
  name: Name2;
  vulnerable_version_range?: VulnerableVersionRange;
}
export interface SourceData {
  [k: string]: unknown;
}
export interface SourceReport {
  assessment?: ImportedAssessment;
  canonical_finding_id: CanonicalFindingId1;
  created_at: CreatedAt1;
  environment_id: EnvironmentId1;
  evidence: ImportedFindingEvidence;
  id: Id5;
  last_import?: LastImport | null;
  object?: Object3;
  observation_id: ObservationId1;
  origin?: Origin;
  repo_connector_id: RepoConnectorId2;
  repo_id: RepoId;
  source: ImportSource;
  source_finding_id: SourceFindingId1;
  updated_at: UpdatedAt;
  version: Version1;
}
export interface ImportedAssessment {
  state?: State;
}
export interface LastImport {
  actor: Actor1;
  created_at: CreatedAt2;
  id: Id6;
}
export interface SourceReportPage {
  data: Data1;
  has_more: HasMore1;
  next: Next1;
  object?: Object5;
}
export interface SourceReportSummary {
  assessment?: ImportedAssessment;
  canonical_finding_id: CanonicalFindingId2;
  created_at: CreatedAt3;
  environment_id: EnvironmentId2;
  id: Id7;
  object?: Object4;
  observation_id: ObservationId2;
  origin?: Origin1;
  repo_connector_id: RepoConnectorId3;
  repo_id: RepoId1;
  severity: Severity1;
  source: ImportSource;
  source_finding_id: SourceFindingId2;
  source_updated_at: SourceUpdatedAt1;
  title: Title1;
  updated_at: UpdatedAt1;
  version: Version2;
}

export type ExternalFindingEvidence = ImportedFindingEvidence;

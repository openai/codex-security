export interface ContractObject {
  [key: string]: unknown;
}

export type TargetKind =
  | "git_revision"
  | "git_worktree"
  | "git_diff"
  | "directory_snapshot";

export interface ScanTargetRecord extends ContractObject {
  kind: TargetKind;
  targetId: string;
  displayName: string;
  remote?: string;
  revision?: string;
  baseRevision?: string;
  headRevision?: string;
  snapshotDigest?: string;
}

export interface ScanScope extends ContractObject {
  includePaths: string[];
  excludePaths: string[];
  summary?: string;
  artifactsReviewed?: string[];
  runtimeStatus?: string;
  validationMode?: string;
  context?: string;
  limitations?: string[];
}

export interface ThreatModel extends ContractObject {
  summary: string;
  assets?: string[];
  trustBoundaries?: string[];
  attackerCapabilities?: string[];
  securityObjectives?: string[];
  assumptions?: string[];
}

export interface ScanHardening extends ContractObject {
  portfolioPath: "hardening/hardening.md";
}

export interface ScanArtifact extends ContractObject {
  path: string;
  sha256: string;
  mediaType: string;
}

export interface ScanProducer extends ContractObject {
  name: string;
  version: string;
}

export interface ScanRecord extends ContractObject {
  id: string;
  producer: ScanProducer;
  status: "completed";
  startedAt: string;
  completedAt: string;
  sealedAt: string;
  target: ScanTargetRecord;
  scope: ScanScope;
  threatModel?: ThreatModel;
  hardening?: ScanHardening;
  coverageRef: "coverage.json";
  findingsRef: "findings.json";
  artifacts: ScanArtifact[];
}

export interface ScanManifest extends ContractObject {
  documentType: "codex-security.scan-manifest";
  schemaVersion: "1.0";
  scan: ScanRecord;
}

export interface FindingIdentity extends ContractObject {
  anchor: string;
  instance?: string;
}

export interface FindingFingerprints extends ContractObject {
  algorithm: "codex-security/v1";
  primary: string;
}

export type SeverityLevel =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

export interface FindingSeverity extends ContractObject {
  level: SeverityLevel;
  score?: number;
  scoringSystem?: string;
  vector?: string;
  rationale?: string;
  changeConditions?: string;
}

export type ConfidenceLevel = "high" | "medium" | "low";

export interface FindingConfidence extends ContractObject {
  level: ConfidenceLevel;
  rationale: string;
}

export interface FindingTaxonomy extends ContractObject {
  category: string;
  cwe: string[];
}

export interface FindingLocation extends ContractObject {
  path: string;
  startLine: number;
  endLine?: number;
  role?: string;
}

export interface FindingValidation extends ContractObject {
  summary?: string | null;
  method?: string | null;
  evidence?: string | string[] | null;
  counterEvidence?: string | string[] | null;
}

export interface AttackPathDataflow extends ContractObject {
  summary: string;
  source?: string | null;
  transformations?: string[] | null;
  sink?: string | null;
  outcome?: string | null;
}

export interface AttackPathReachability extends ContractObject {
  summary: string;
  attacker?: string | null;
  entrypoint?: string | null;
  preconditions?: string[] | null;
  outcome?: string | null;
}

export interface FindingAttackPath extends ContractObject {
  dataflow?: string | AttackPathDataflow | null;
  reachability?: string | AttackPathReachability | null;
}

export interface FindingProvenance extends ContractObject {
  source: string;
}

export interface FindingWriteup extends ContractObject {
  reportPath: string;
}

export interface FindingCodeEvidence extends ContractObject {
  id: string;
  label: string;
  path: string;
  startLine: number;
  endLine?: number;
  language?: string;
  role?: string;
  code: string;
  explanation: string;
}

export interface FindingRootCause extends ContractObject {
  summary: string;
  evidenceRefs?: string[];
  code?: string;
  language?: string;
}

export interface Finding extends ContractObject {
  findingId: string;
  occurrenceId: string;
  ruleId: string;
  identity: FindingIdentity;
  fingerprints: FindingFingerprints;
  title: string;
  summary: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  taxonomy: FindingTaxonomy;
  locations: FindingLocation[];
  remediation: string;
  writeup?: FindingWriteup;
  codeEvidence?: FindingCodeEvidence[];
  rootCause?: string | FindingRootCause;
  validation?: FindingValidation | null;
  attackPath?: FindingAttackPath | null;
  remediationTests?: string[];
  preventiveControls?: string[];
  provenance: FindingProvenance;
  extensions?: Record<string, unknown>;
}

export interface FindingsDocument extends ContractObject {
  documentType: "codex-security.findings";
  schemaVersion: "1.0";
  scanId: string;
  findings: Finding[];
}

export type CoverageMode =
  | "repository"
  | "scoped_path"
  | "diff"
  | "commit"
  | "branch_diff"
  | "working_tree"
  | "deep_repository";
export type CoverageCompleteness = "complete" | "partial" | "unknown";
export type InventoryStrategy =
  | "repository"
  | "scoped_path"
  | "diff"
  | "directory"
  | "custom";
export type SurfaceDisposition =
  | "reported"
  | "no_issue_found"
  | "rejected"
  | "not_applicable"
  | "needs_follow_up";

export interface CoverageSurface extends ContractObject {
  id: string;
  label: string;
  disposition: SurfaceDisposition;
  receiptRefs: string[];
  riskArea?: string;
  notes?: string;
}

export interface ExplicitExclusion extends ContractObject {
  pattern: string;
  reason: string;
}

export interface DeferredCoverage extends ContractObject {
  id: string;
  reason: string;
  paths?: string[];
  surfaceIds?: string[];
}

export interface CoverageOpenQuestion extends ContractObject {
  question: string;
  followUpPrompt?: string;
}

export interface CoverageDocument extends ContractObject {
  documentType: "codex-security.coverage";
  schemaVersion: "1.0";
  scanId: string;
  mode: CoverageMode;
  completeness: CoverageCompleteness;
  inventoryStrategy: InventoryStrategy;
  includePaths: string[];
  excludePaths: string[];
  surfaces: CoverageSurface[];
  explicitExclusions: ExplicitExclusion[];
  deferred: DeferredCoverage[];
  openQuestions?: CoverageOpenQuestion[];
}

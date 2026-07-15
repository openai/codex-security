from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ContractModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")


class TargetKind(str, Enum):
    git_revision = "git_revision"
    git_worktree = "git_worktree"
    git_diff = "git_diff"
    directory_snapshot = "directory_snapshot"


class ScanTargetRecord(ContractModel):
    kind: TargetKind
    target_id: str = Field(alias="targetId")
    display_name: str = Field(alias="displayName")
    remote: str | None = None
    revision: str | None = None
    base_revision: str | None = Field(default=None, alias="baseRevision")
    head_revision: str | None = Field(default=None, alias="headRevision")
    snapshot_digest: str | None = Field(default=None, alias="snapshotDigest")


class ScanScope(ContractModel):
    include_paths: list[str] = Field(alias="includePaths")
    exclude_paths: list[str] = Field(alias="excludePaths")
    summary: str | None = None
    artifacts_reviewed: list[str] | None = Field(default=None, alias="artifactsReviewed")
    runtime_status: str | None = Field(default=None, alias="runtimeStatus")
    validation_mode: str | None = Field(default=None, alias="validationMode")
    context: str | None = None
    limitations: list[str] | None = None


class ThreatModel(ContractModel):
    summary: str
    assets: list[str] | None = None
    trust_boundaries: list[str] | None = Field(default=None, alias="trustBoundaries")
    attacker_capabilities: list[str] | None = Field(default=None, alias="attackerCapabilities")
    security_objectives: list[str] | None = Field(default=None, alias="securityObjectives")
    assumptions: list[str] | None = None


class ScanArtifact(ContractModel):
    path: str
    sha256: str
    media_type: str = Field(alias="mediaType")


class ScanProducer(ContractModel):
    name: str
    version: str


class ScanRecord(ContractModel):
    id: str
    producer: ScanProducer
    status: Literal["completed"]
    started_at: datetime = Field(alias="startedAt")
    completed_at: datetime = Field(alias="completedAt")
    sealed_at: datetime = Field(alias="sealedAt")
    target: ScanTargetRecord
    scope: ScanScope
    threat_model: ThreatModel | None = Field(default=None, alias="threatModel")
    coverage_ref: Literal["coverage.json"] = Field(alias="coverageRef")
    findings_ref: Literal["findings.json"] = Field(alias="findingsRef")
    artifacts: list[ScanArtifact]


class ScanManifest(ContractModel):
    document_type: Literal["codex-security.scan-manifest"] = Field(alias="documentType")
    schema_version: Literal["1.0"] = Field(alias="schemaVersion")
    scan: ScanRecord


class FindingIdentity(ContractModel):
    anchor: str
    instance: str | None = None


class FindingFingerprints(ContractModel):
    algorithm: Literal["codex-security/v1"]
    primary: str


class SeverityLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class FindingSeverity(ContractModel):
    level: SeverityLevel
    score: float | None = None
    scoring_system: str | None = Field(default=None, alias="scoringSystem")
    vector: str | None = None
    rationale: str | None = None
    change_conditions: str | None = Field(default=None, alias="changeConditions")


class ConfidenceLevel(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


class FindingConfidence(ContractModel):
    level: ConfidenceLevel
    rationale: str


class FindingTaxonomy(ContractModel):
    category: str
    cwe: list[str]


class FindingLocation(ContractModel):
    path: str
    start_line: int = Field(alias="startLine")
    end_line: int | None = Field(default=None, alias="endLine")
    role: str | None = None


class FindingValidation(ContractModel):
    summary: str | None = None
    method: str | None = None
    evidence: str | list[str] | None = None
    counter_evidence: str | list[str] | None = Field(default=None, alias="counterEvidence")


class AttackPathDataflow(ContractModel):
    summary: str
    source: str | None = None
    transformations: list[str] | None = None
    sink: str | None = None
    outcome: str | None = None


class AttackPathReachability(ContractModel):
    summary: str
    attacker: str | None = None
    entrypoint: str | None = None
    preconditions: list[str] | None = None
    outcome: str | None = None


class FindingAttackPath(ContractModel):
    dataflow: str | AttackPathDataflow | None = None
    reachability: str | AttackPathReachability | None = None


class FindingProvenance(ContractModel):
    source: str


class Finding(ContractModel):
    finding_id: str = Field(alias="findingId")
    occurrence_id: str = Field(alias="occurrenceId")
    rule_id: str = Field(alias="ruleId")
    identity: FindingIdentity
    fingerprints: FindingFingerprints
    title: str
    summary: str
    severity: FindingSeverity
    confidence: FindingConfidence
    taxonomy: FindingTaxonomy
    locations: list[FindingLocation]
    remediation: str
    validation: FindingValidation | None = None
    attack_path: FindingAttackPath | None = Field(default=None, alias="attackPath")
    remediation_tests: list[str] | None = Field(default=None, alias="remediationTests")
    preventive_controls: list[str] | None = Field(default=None, alias="preventiveControls")
    provenance: FindingProvenance
    extensions: dict[str, Any] | None = None


class FindingsDocument(ContractModel):
    document_type: Literal["codex-security.findings"] = Field(alias="documentType")
    schema_version: Literal["1.0"] = Field(alias="schemaVersion")
    scan_id: str = Field(alias="scanId")
    findings: list[Finding]


class CoverageMode(str, Enum):
    repository = "repository"
    scoped_path = "scoped_path"
    diff = "diff"
    commit = "commit"
    branch_diff = "branch_diff"
    working_tree = "working_tree"
    deep_repository = "deep_repository"


class CoverageCompleteness(str, Enum):
    complete = "complete"
    partial = "partial"
    unknown = "unknown"


class InventoryStrategy(str, Enum):
    repository = "repository"
    scoped_path = "scoped_path"
    diff = "diff"
    directory = "directory"
    custom = "custom"


class SurfaceDisposition(str, Enum):
    reported = "reported"
    no_issue_found = "no_issue_found"
    rejected = "rejected"
    not_applicable = "not_applicable"
    needs_follow_up = "needs_follow_up"


class CoverageSurface(ContractModel):
    id: str
    label: str
    disposition: SurfaceDisposition
    receipt_refs: list[str] = Field(alias="receiptRefs")
    risk_area: str | None = Field(default=None, alias="riskArea")
    notes: str | None = None


class ExplicitExclusion(ContractModel):
    pattern: str
    reason: str


class DeferredCoverage(ContractModel):
    id: str
    reason: str
    paths: list[str] | None = None
    surface_ids: list[str] | None = Field(default=None, alias="surfaceIds")


class CoverageOpenQuestion(ContractModel):
    question: str
    follow_up_prompt: str | None = Field(default=None, alias="followUpPrompt")


class CoverageDocument(ContractModel):
    document_type: Literal["codex-security.coverage"] = Field(alias="documentType")
    schema_version: Literal["1.0"] = Field(alias="schemaVersion")
    scan_id: str = Field(alias="scanId")
    mode: CoverageMode
    completeness: CoverageCompleteness
    inventory_strategy: InventoryStrategy = Field(alias="inventoryStrategy")
    include_paths: list[str] = Field(alias="includePaths")
    exclude_paths: list[str] = Field(alias="excludePaths")
    surfaces: list[CoverageSurface]
    explicit_exclusions: list[ExplicitExclusion] = Field(alias="explicitExclusions")
    deferred: list[DeferredCoverage]
    open_questions: list[CoverageOpenQuestion] | None = Field(default=None, alias="openQuestions")

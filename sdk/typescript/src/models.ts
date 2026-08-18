/* Generated from the plugin JSON Schemas. Run `pnpm generate:models`. */

export interface ScanManifest {
  documentType: "codex-security.scan-manifest";
  schemaVersion: "1.0";
  scan: {
    id: string;
    producer: {
      name: string;
      version: string;
      [k: string]: unknown;
    };
    status: "completed";
    startedAt: string;
    completedAt: string;
    sealedAt: string;
    target: {
      kind: "git_revision" | "git_worktree" | "git_diff" | "directory_snapshot";
      targetId: string;
      displayName: string;
      remote?: string;
      revision?: string;
      baseRevision?: string;
      headRevision?: string;
      snapshotDigest?: string;
      [k: string]: unknown;
    };
    scope: {
      includePaths: string[];
      excludePaths: string[];
      summary?: string;
      artifactsReviewed?: string[];
      runtimeStatus?: string;
      validationMode?: string;
      context?: string;
      limitations?: string[];
      [k: string]: unknown;
    };
    threatModel?: {
      summary: string;
      assets?: string[];
      trustBoundaries?: string[];
      attackerCapabilities?: string[];
      securityObjectives?: string[];
      assumptions?: string[];
      [k: string]: unknown;
    };
    hardening?: {
      portfolioPath: "hardening/hardening.md";
      [k: string]: unknown;
    };
    coverageRef: "coverage.json";
    findingsRef: "findings.json";
    /**
     * @minItems 1
     */
    artifacts: {
      path: string;
      sha256: string;
      mediaType: string;
      [k: string]: unknown;
    }[];
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

export interface FindingsDocument {
  documentType: "codex-security.findings";
  schemaVersion: "1.0";
  scanId: string;
  findings: {
    findingId: string;
    occurrenceId: string;
    ruleId: string;
    identity: {
      anchor: string;
      instance?: string;
      [k: string]: unknown;
    };
    fingerprints: {
      algorithm: "codex-security/v1";
      primary: string;
      [k: string]: unknown;
    };
    title: string;
    summary: string;
    severity: {
      level: "critical" | "high" | "medium" | "low" | "informational";
      score?: number;
      scoringSystem?: string;
      vector?: string;
      rationale?: string;
      changeConditions?: string;
      [k: string]: unknown;
    };
    confidence: {
      level: "high" | "medium" | "low";
      rationale: string;
      [k: string]: unknown;
    };
    taxonomy: {
      category: string;
      cwe: string[];
      [k: string]: unknown;
    };
    /**
     * @minItems 1
     */
    locations: {
      path: string;
      startLine: number;
      endLine?: number;
      role?: string;
      [k: string]: unknown;
    }[];
    writeup?: {
      reportPath: string;
      [k: string]: unknown;
    };
    codeEvidence?: {
      id: string;
      label: string;
      path: string;
      startLine: number;
      endLine?: number;
      language?: string;
      role?: string;
      code: string;
      explanation: string;
      [k: string]: unknown;
    }[];
    code_evidence?:
      | {
          id: string;
          code: string;
          [k: string]: unknown;
        }[]
      | null;
    rootCause?:
      | {
          summary: string;
          evidenceRefs?: string[];
          code?: string;
          language?: string;
          [k: string]: unknown;
        }
      | string;
    root_cause?:
      | {
          summary?: string;
          evidenceRefs?: string[];
          evidence_refs?: string[];
          code?: string;
          language?: string;
          [k: string]: unknown;
        }
      | string
      | null;
    remediation: string;
    validation?: {
      assertions?: string[];
      counterEvidence?: string[];
      evidence?: string | string[];
      evidenceRefs?: string[];
      evidence_refs?: string[];
      limitations?: string[];
      method?: string;
      status?: string | null;
      summary?: string;
      disposition?: string | null;
      result?: string | null;
      [k: string]: unknown;
    } | null;
    attackPath?: {
      assumptions?: string[];
      blindspots?: string[];
      controls?: string[];
      dataFlow?:
        | string
        | {
            summary?: string;
            source?: string;
            sink?: string;
            outcome?: string;
            transformations?: string[];
            evidenceRefs?: string[];
            evidence_refs?: string[];
            [k: string]: unknown;
          };
      data_flow?:
        | string
        | {
            summary?: string;
            source?: string;
            sink?: string;
            outcome?: string;
            transformations?: string[];
            evidenceRefs?: string[];
            evidence_refs?: string[];
            [k: string]: unknown;
          };
      dataflow?:
        | string
        | {
            summary?: string;
            source?: string;
            sink?: string;
            outcome?: string;
            transformations?: string[];
            evidenceRefs?: string[];
            evidence_refs?: string[];
            [k: string]: unknown;
          };
      evidenceRefs?: string[];
      evidence_refs?: string[];
      impact?:
        | string
        | {
            level?: string;
            rationale?: string;
            why?: string;
            [k: string]: unknown;
          }
        | null;
      likelihood?:
        | string
        | {
            level?: string;
            rationale?: string;
            why?: string;
            [k: string]: unknown;
          }
        | null;
      limitations?: string[];
      preconditions?: string[];
      reachability?:
        | string
        | {
            summary?: string;
            attacker?: string;
            entrypoint?: string;
            source?: string;
            sink?: string;
            outcome?: string;
            preconditions?: string[];
            evidenceRefs?: string[];
            evidence_refs?: string[];
            [k: string]: unknown;
          };
      steps?: string[];
      summary?: string;
      [k: string]: unknown;
    } | null;
    remediationTests?: string[];
    preventiveControls?: string[];
    provenance: {
      source: string;
      [k: string]: unknown;
    };
    extensions?: {
      candidateId?: string;
      ledgerRowId?: string;
      reportId?: string;
      [k: string]: unknown;
    };
    [k: string]: unknown;
  }[];
  [k: string]: unknown;
}

export interface CoverageDocument {
  documentType: "codex-security.coverage";
  schemaVersion: "1.0";
  scanId: string;
  mode:
    | "repository"
    | "scoped_path"
    | "diff"
    | "commit"
    | "branch_diff"
    | "working_tree"
    | "deep_repository";
  completeness: "complete" | "partial" | "unknown";
  inventoryStrategy:
    | "repository"
    | "scoped_path"
    | "diff"
    | "directory"
    | "custom";
  includePaths: string[];
  excludePaths: string[];
  surfaces: {
    id: string;
    label: string;
    disposition:
      | "reported"
      | "no_issue_found"
      | "rejected"
      | "not_applicable"
      | "needs_follow_up";
    receiptRefs: string[];
    riskArea?: string;
    notes?: string;
    [k: string]: unknown;
  }[];
  explicitExclusions: {
    pattern: string;
    reason: string;
    [k: string]: unknown;
  }[];
  deferred: {
    id: string;
    reason: string;
    paths?: string[];
    surfaceIds?: string[];
    [k: string]: unknown;
  }[];
  openQuestions?: {
    question: string;
    followUpPrompt?: string;
    [k: string]: unknown;
  }[];
  [k: string]: unknown;
}

export type ContractObject = Record<string, unknown>;

export type ScanRecord = ScanManifest["scan"];

export type ScanProducer = ScanRecord["producer"];

export type ScanTargetRecord = ScanRecord["target"];

export type TargetKind = ScanTargetRecord["kind"];

export type ScanScope = ScanRecord["scope"];

export type ThreatModel = NonNullable<ScanRecord["threatModel"]>;

export type ScanHardening = NonNullable<ScanRecord["hardening"]>;

export type ScanArtifact = ScanRecord["artifacts"][number];

export type Finding = FindingsDocument["findings"][number];

export type FindingIdentity = Finding["identity"];

export type FindingFingerprints = Finding["fingerprints"];

export type FindingSeverity = Finding["severity"];

export type SeverityLevel = FindingSeverity["level"];

export type FindingConfidence = Finding["confidence"];

export type ConfidenceLevel = FindingConfidence["level"];

export type FindingTaxonomy = Finding["taxonomy"];

export type FindingLocation = Finding["locations"][number];

export type FindingWriteup = NonNullable<Finding["writeup"]>;

export type FindingCodeEvidence = NonNullable<Finding["codeEvidence"]>[number];

export type FindingRootCause = Extract<Finding["rootCause"], object>;

export type FindingValidation = NonNullable<Finding["validation"]>;

export type FindingAttackPath = NonNullable<Finding["attackPath"]>;

export type AttackPathDataflow = Extract<
  NonNullable<FindingAttackPath["dataFlow"]>,
  object
>;

export type AttackPathReachability = Extract<
  NonNullable<FindingAttackPath["reachability"]>,
  object
>;

export type FindingProvenance = Finding["provenance"];

export type CoverageMode = CoverageDocument["mode"];

export type CoverageCompleteness = CoverageDocument["completeness"];

export type InventoryStrategy = CoverageDocument["inventoryStrategy"];

export type CoverageSurface = CoverageDocument["surfaces"][number];

export type SurfaceDisposition = CoverageSurface["disposition"];

export type ExplicitExclusion = CoverageDocument["explicitExclusions"][number];

export type DeferredCoverage = CoverageDocument["deferred"][number];

export type CoverageOpenQuestion = NonNullable<
  CoverageDocument["openQuestions"]
>[number];

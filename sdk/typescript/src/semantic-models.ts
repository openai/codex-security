/* Generated from the plugin semantic draft schema. Run `pnpm generate:models`. */

export type ScanId = string;
export type HandoffClaimToken = string;
export type Text = string;
export type TextList = Text[];
/**
 * Copy the reviewed candidate's exact cwe_ids array. Use an empty array when no CWE is established; do not invent one.
 */
export type TextList1 = Text[];
export type RepositoryPath = string;
export type TextOrSummary =
  | Text
  | {
      summary?: Text;
      source?: Text;
      sink?: Text;
      outcome?: Text;
      transformations?: TextList;
      evidenceRefs?: TextList;
      evidence_refs?: TextList;
      [k: string]: unknown;
    };
export type FindingAssessment =
  | Text
  | {
      level?: Text;
      rationale?: Text;
      why?: Text;
      [k: string]: unknown;
    };
export type FindingReachability =
  | Text
  | {
      summary?: Text;
      attacker?: Text;
      entrypoint?: Text;
      source?: Text;
      sink?: Text;
      outcome?: Text;
      preconditions?: TextList;
      evidenceRefs?: TextList;
      evidence_refs?: TextList;
      [k: string]: unknown;
    };

export interface SemanticScan {
  /**
   * Set false to save progress without declaring this worker or parent audit finished. Omit or set true only for the terminal result. Put provisional candidates in coverage.deferred, not findings.
   */
  complete?: boolean;
  scanId: ScanId;
  handoffClaimToken?: HandoffClaimToken;
  scope?: Scope;
  threatModel?: ThreatModel;
  findings: Finding[];
  coverage: Coverage;
}
export interface Scope {
  includePaths?: never;
  excludePaths?: never;
  summary?: Text;
  artifactsReviewed?: TextList;
  runtimeStatus?: Text;
  validationMode?: Text;
  context?: Text;
  limitations?: TextList;
  [k: string]: unknown;
}
export interface ThreatModel {
  summary: Text;
  assets?: TextList;
  trustBoundaries?: TextList;
  attackerCapabilities?: TextList;
  securityObjectives?: TextList;
  assumptions?: TextList;
  [k: string]: unknown;
}
export interface Finding {
  findingId?: never;
  occurrenceId?: never;
  fingerprints?: never;
  /**
   * A stable lowercase vulnerability-family slug, such as prototype-pollution.json-patch; a CWE is taxonomy, not a rule ID.
   */
  ruleId: string;
  identity?: Identity;
  title: Text;
  summary: Text;
  severity: Severity;
  confidence: Confidence;
  taxonomy: Taxonomy;
  /**
   * @minItems 1
   */
  locations: Location[];
  writeup?: {
    reportPath: string;
    [k: string]: unknown;
  };
  codeEvidence?: CodeEvidence[];
  code_evidence?: LegacyCodeEvidence[];
  rootCause?:
    | Text
    | {
        summary: Text;
        code?: Text;
        language?: Text;
        evidenceRefs?: TextList;
        [k: string]: unknown;
      };
  root_cause?:
    | Text
    | {
        summary?: Text;
        code?: Text;
        language?: Text;
        evidenceRefs?: TextList;
        evidence_refs?: TextList;
        [k: string]: unknown;
      };
  remediation: Text;
  validation?: FindingValidation | null;
  attackPath?: FindingAttackPath | null;
  remediationTests?: TextList;
  preventiveControls?: TextList;
  provenance: {
    /**
     * Host-provided source finding references represented by this Deep reduction. Preserve every assigned reference exactly once.
     */
    sourceFindingIds?: Text[];
    /**
     * Original source payloads retained by the host for lossless semantic merges.
     */
    sourceFindings?: {
      id: Text;
      finding: {
        [k: string]: unknown;
      };
    }[];
    /**
     * The actual finding producer. Use local_plugin only for a finding discovered by this plugin.
     */
    source: string;
    [k: string]: unknown;
  };
  extensions?: {
    [k: string]: unknown;
  };
  [k: string]: unknown;
}
export interface Identity {
  anchor: string;
  instance?: string;
  [k: string]: unknown;
}
export interface Severity {
  level: "critical" | "high" | "medium" | "low" | "informational";
  score?: number;
  scoringSystem?: Text;
  vector?: Text;
  rationale?: Text;
  changeConditions?: Text;
  [k: string]: unknown;
}
export interface Confidence {
  level: "high" | "medium" | "low";
  rationale: Text;
  [k: string]: unknown;
}
export interface Taxonomy {
  /**
   * The actual primary broken security control, not a CWE identifier.
   */
  category: string;
  cwe: TextList1;
  [k: string]: unknown;
}
export interface Location {
  path: RepositoryPath;
  startLine: number;
  endLine?: number;
  role?: Text;
  [k: string]: unknown;
}
export interface CodeEvidence {
  id: string;
  label: Text;
  path: RepositoryPath;
  startLine: number;
  endLine?: number;
  language?: Text;
  role?: Text;
  /**
   * The genuine, nonempty source snippet at this evidence location.
   */
  code: string;
  explanation: Text;
  [k: string]: unknown;
}
export interface LegacyCodeEvidence {
  id: Text;
  code: Text;
  [k: string]: unknown;
}
export interface FindingValidation {
  assertions?: TextList;
  counterEvidence?: TextList;
  evidence?: Text | TextList;
  evidenceRefs?: TextList;
  evidence_refs?: TextList;
  limitations?: TextList;
  method?: Text;
  status?: Text | null;
  summary?: Text;
  disposition?: Text | null;
  result?: Text | null;
  [k: string]: unknown;
}
export interface FindingAttackPath {
  assumptions?: TextList;
  blindspots?: TextList;
  controls?: TextList;
  dataFlow?: TextOrSummary;
  data_flow?: TextOrSummary;
  dataflow?: TextOrSummary;
  evidenceRefs?: TextList;
  evidence_refs?: TextList;
  impact?: FindingAssessment | null;
  likelihood?: FindingAssessment | null;
  limitations?: TextList;
  preconditions?: TextList;
  reachability?: FindingReachability;
  steps?: TextList;
  summary?: Text;
  [k: string]: unknown;
}
export interface Coverage {
  documentType?: never;
  schemaVersion?: never;
  scanId?: never;
  mode?: never;
  includePaths?: never;
  excludePaths?: never;
  receiptRefs?: never;
  /**
   * Use partial if any work is deferred or any surface needs follow-up; use complete only when no such work remains.
   */
  completeness: "complete" | "partial" | "unknown";
  inventoryStrategy?: never;
  surfaces: Surface[];
  explicitExclusions: {
    pattern: Text;
    reason: Text;
    [k: string]: unknown;
  }[];
  deferred: {
    id?: Text;
    candidateId?: string;
    reason: Text;
    paths?: TextList;
    surfaceIds?: TextList;
    [k: string]: unknown;
  }[];
  openQuestions?: (
    | Text
    | {
        question: Text;
        followUpPrompt?: Text;
        [k: string]: unknown;
      }
  )[];
  [k: string]: unknown;
}
export interface Surface {
  id?: string;
  /**
   * The meaningful name of the reviewed security surface.
   */
  label: string;
  /**
   * The evidence-supported review result for this surface.
   */
  disposition:
    | "reported"
    | "no_issue_found"
    | "rejected"
    | "not_applicable"
    | "needs_follow_up";
  receiptRefs?: string[];
  riskArea?: Text;
  notes?: Text;
  [k: string]: unknown;
}

export type SemanticFinding = SemanticScan["findings"][number];

export type SemanticCoverage = SemanticScan["coverage"];

export type SemanticScope = NonNullable<SemanticScan["scope"]>;

export type SemanticThreatModel = NonNullable<SemanticScan["threatModel"]>;

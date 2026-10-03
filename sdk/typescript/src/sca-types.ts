/* Generated from the plugin JSON Schemas. Run `pnpm generate:models`. */

export interface ScaResult {
  schemaVersion: "sca/v0";
  status: "completed" | "partial" | "failed";
  startedAt: string;
  completedAt: string;
  repository: {
    path: string;
    revision: string | null;
    dirty: boolean | null;
  };
  scanner: ScaScanner;
  coverage: ScaCoverage;
  components: ScaComponent[];
  matches: ScaMatch[];
  assessments: ScaAssessment[];
  diagnostics: string[];
  model: {
    model: string | null;
    skillDigest: string | null;
    threadId: string | null;
    costUsd: number | null;
  };
  outputDir: string;
}
export interface ScaScanner {
  name: string;
  version: string | null;
  argv: string[];
  startedAt: string;
  completedAt: string;
  exitCode: number | null;
  rawOutputPath: string;
  stderrPath: string;
  advisoryMode: "online" | "offline" | "unknown";
  advisorySnapshotId: string | null;
  /**
   * Actual sequential OSV calls. argv retains the first call for compatibility; rawOutputPath aggregates source records when there is more than one invocation.
   */
  invocations?: {
    argv: string[];
    exitCode: number | null;
    rawOutputPath: string;
    stderrPath: string;
  }[];
}
export interface ScaCoverage {
  status: "complete" | "partial" | "failed";
  inputs: ScaInput[];
  configFiles: ScaFile[];
  limitations: string[];
  unresolvedPackages: number;
}
export interface ScaInput {
  path: string;
  sha256: string;
  format:
    | "npm"
    | "pnpm"
    | "uv"
    | "poetry"
    | "pipenv"
    | "requirements"
    | "go"
    | "cargo"
    | "gradle"
    | "maven"
    | "bundler"
    | "composer"
    | "nuget";
  status: "scanned" | "excluded" | "unsupported" | "failed";
  reason: string | null;
}
export interface ScaFile {
  path: string;
  sha256: string;
}
export interface ScaComponent {
  id: string;
  name: string;
  version: string | null;
  ecosystem: string | null;
  sourcePath: string;
  dependencyGroups: string[];
}
export interface ScaMatch {
  id: string;
  componentId: string;
  advisoryIds: string[];
  aliases: string[];
  sourceAdvisories: {
    [k: string]: unknown;
  }[];
  severity: string | null;
  fixedVersions: string[];
  advisoryModifiedAt: string[];
}
export interface ScaAssessment {
  matchId: string;
  status: "not_started" | "completed" | "failed" | "cancelled";
  verdict: "confirmed" | "not_actionable" | "needs_review" | null;
  triage: TriageFinding | null;
  error: string | null;
}
export interface TriageFinding {
  triage_item_id: string;
  input_id: string;
  source_type:
    | "sarif"
    | "cve"
    | "advisory"
    | "scanner_ticket"
    | "bug_bounty"
    | "codex_security_finding"
    | "freeform"
    | "unknown";
  title: string;
  normalized_input: {
    vulnerable_component: string;
    claimed_source: string;
    claimed_sink: string;
    claimed_control: string;
    affected_version_or_path: string;
    preconditions: string[];
    impact: string;
    references: string[];
  };
  verdict: "confirmed" | "not_actionable" | "needs_review";
  confidence: "high" | "medium" | "low";
  affected_locations: {
    label: string;
    path: string;
    lines: string;
    detail: string;
  }[];
  reachable_path: string[];
  boundary_assessment: {
    product_surface: string;
    source_trust:
      | "untrusted"
      | "trusted_operator"
      | "trusted_developer_config"
      | "local_only"
      | "unknown";
    boundary_crossed: boolean | null;
    policy_basis: string;
  };
  exploitability_stack_rank: {
    rank_queue: "confirmed" | "needs_review" | null;
    rank: number | null;
    rationale: string;
    drivers: string[];
  };
  evidence: string[];
  counterevidence: string[];
  proof_gaps: string[];
  recommended_next_step: string;
  fix_finding_handoff: string | null;
}

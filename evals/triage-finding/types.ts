export interface AssertionContext {
  vars: Record<string, unknown>;
  test?: PromptfooTest;
}

export interface PromptfooTest {
  metadata?: Record<string, unknown>;
}

export interface PromptfooRow {
  vars: Record<string, unknown>;
  latencyMs?: number;
  cost?: number;
  response?: {
    output?: unknown;
    error?: unknown;
    tokenUsage?: { total?: number; [key: string]: unknown };
    sessionId?: string;
  };
  tokenUsage?: { total?: number; [key: string]: unknown };
  error?: unknown;
  failureReason?: unknown;
  namedScores?: Record<string, number>;
  metadata?: Record<string, unknown>;
}

export interface TriageFinding {
  input_id: string;
  source_type: string;
  verdict: string;
  exploitability_stack_rank?: {
    rank: number | null;
    rank_queue: string | null;
  };
  fix_finding_handoff?: string | null;
  [key: string]: unknown;
}

export interface TriageResult {
  schema_version: string;
  findings: TriageFinding[];
}

export interface CalibrationVariant {
  variant_id: string;
  checkout_ref: string;
  expected_verdict: string;
  expected_binary_label: string;
}

export interface CalibrationCase {
  case_id: string;
  source_type: string;
  repo: { name: string; url: string };
  finding: {
    input_id?: string;
    input_id_base?: string;
    title: string;
    advisory_ids?: string[];
    weakness?: string;
    severity?: string;
    language?: string;
    anchor_locations?: { path: string; line: number }[];
    fix_patch_ref?: string;
  };
  variants: CalibrationVariant[];
}

export interface SastLocation {
  file: string;
  line_start: number;
  line_end: number;
  function?: string;
}

export interface SastBenchRecord {
  repo_name: string;
  repo_url: string;
  commit_hash: string;
  ground_truth: string;
  to_analyzer: {
    vulnerability_type: string;
    vulnerability_name: string;
    description: string;
    locations: SastLocation[];
    commit_context: { repo: string; commit: string };
    [key: string]: unknown;
  };
  metadata: { cwe_id?: string; languages?: string[]; [key: string]: unknown };
}

export interface DatasetExpectations {
  caseCount: number;
  labelCounts: Record<string, number>;
}

export interface SampleSpec {
  profile: string;
  seed: string;
  labelCounts: Record<string, number>;
}

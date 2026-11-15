export type { TraceRequest } from "./schema.ts";
import type { DiscoveryOmission } from "./discovery-scope.ts";

export interface TraceScope {
  kind: "search" | "manifests" | "file" | "source_batch" | "catalog";
  package: string;
  symbol?: string;
  source_symbol?: string;
  source_terms?: string[];
  rules?: Record<string, unknown>[];
  files?: string[];
  version?: string;
  path?: string;
}

/** A name in the provider's domain. Scope disambiguates local names. */
export interface TraceEntity {
  kind: string;
  name: string;
  scope?: string;
}

/** One normalized sampled execution witness. Frames are ordered root first. */
export interface TraceObservation {
  id: string;
  kind: "sampled_stack";
  scope: Record<string, unknown>;
  frames: TraceEntity[];
}

export interface RuleExecution {
  id: string;
  configSha256: string;
  config: { rules: Record<string, unknown>[] };
  engine: string;
  taintIntrafile: boolean;
}

export interface TraceStep {
  ruleExecutionId?: string;
  nativeRuleId?: string;
  from: TraceEntity;
  relation: string;
  /** Only present when the provider identifies a target entity. */
  to?: TraceEntity;
  /** Local names observed at an unresolved call or flow site. */
  calleeText?: string;
  sourceText?: string;
}

export interface TraceEvidence {
  step: TraceStep;
  source: string;
  line?: number;
  match?: NativeMatch;
}

/** The native match range, without widening a focused match to its call. */
export interface NativeMatch {
  start: { line: number; col: number; offset: number };
  end: { line: number; col: number; offset: number };
  ruleExecutionId?: string;
  nativeRuleId?: string;
}

/** A literal search hit. Directory discovery may only know its path. */
export interface TextMatch {
  ruleExecutionId?: string;
  nativeRuleId?: string;
  source: string;
  text: string;
  line?: number;
}

export interface ScopeResult {
  ruleExecution?: RuleExecution;
  /** Identity of the exact input analyzed, for reuse within this check. */
  fingerprint?: string;
  evidence: TraceEvidence[];
  textMatches?: TextMatch[];
  omissions?: DiscoveryOmission[];
  next: TraceScope[];
  complete: boolean;
  reason?: string;
}

export interface TraceProvider {
  run(scope: TraceScope, signal: AbortSignal): Promise<ScopeResult>;
  fingerprint?(
    scope: TraceScope,
    signal: AbortSignal,
  ): Promise<string | undefined>;
}

export interface TraceCache {
  read(key: string): ScopeResult | undefined;
  store(key: string, result: ScopeResult): void;
  clear(): void;
}

export interface TraceResult {
  /** Search coverage only. A completed search need not establish reachability. */
  complete: boolean;
  limits: string[];
  scopes: {
    id: number;
    scope: TraceScope;
    hops: number;
    complete: boolean;
    reason?: string;
    evidence: TraceEvidence[];
    textMatches?: TextMatch[];
    omissions?: DiscoveryOmission[];
    ruleExecution?: RuleExecution;
  }[];
  /** Sample of the next lookups that did not fit the hop budget. */
  frontier: TraceScope[];
}

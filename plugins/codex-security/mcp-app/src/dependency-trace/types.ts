export type { TraceRequest } from "./schema.ts";

export interface TraceScope {
  kind: "search" | "manifests" | "file" | "catalog";
  package: string;
  symbol?: string;
  source_symbol?: string;
  version?: string;
  path?: string;
}

/** A name in the provider's domain. Scope disambiguates local names. */
export interface TraceEntity {
  kind: string;
  name: string;
  scope?: string;
}

export interface TraceStep {
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
}

/** A literal search hit. Directory discovery may only know its path. */
export interface TextMatch {
  source: string;
  text: string;
  line?: number;
}

export interface ScopeResult {
  /** Identity of the exact input analyzed, for reuse within this check. */
  fingerprint?: string;
  evidence: TraceEvidence[];
  textMatches?: TextMatch[];
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
  }[];
  /** Sample of the next lookups that did not fit the hop budget. */
  frontier: TraceScope[];
  /** Which lookup led to another lookup. */
  expansions: { from: number; to: number }[];
}

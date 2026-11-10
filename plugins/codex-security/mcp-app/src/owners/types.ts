export type CodeownerIdentity =
  | { kind: "person" | "group"; provider: "github"; handle: string }
  | { kind: "person"; email: string };

export interface OwnerIdentity {
  name: string;
  email: string;
}

export interface OwnerEvidence {
  id: string;
  kind: "source" | "blame" | "history" | "codeowners";
  path: string;
  commit: string;
  /** Original blamed commit; blame citations keep commit at the checkout revision. */
  blameCommit?: string;
  commitTime?: number;
  startLine?: number;
  endLine?: number;
  rule?: string;
  matchedPath?: string;
  content: string;
  identityIndex: number | null;
}

export interface OwnerContext {
  identities: OwnerIdentity[];
  evidence: OwnerEvidence[];
  limitations: string[];
  declaredOwners: {
    owner: CodeownerIdentity;
    evidenceIds: string[];
  }[];
}

export interface OwnerCandidate {
  owner: OwnerIdentity | CodeownerIdentity;
  reason: string;
  evidence: Omit<OwnerEvidence, "identityIndex" | "content" | "blameCommit">[];
}

export interface OwnerSuggestion {
  findingId: string;
  occurrenceId: string | null;
  status: "identified" | "abstained" | "error";
  owner: OwnerCandidate["owner"] | null;
  reason: string;
  evidence: OwnerCandidate["evidence"];
  suggestions: OwnerCandidate[];
  limitations: string[];
}

export interface OwnerFinding {
  findingId: string;
  occurrenceId?: string;
  title: string;
  summary: string;
  remediation?: string;
  sourceRevision?: string;
  locations: { path: string; startLine?: number; endLine?: number }[];
  extensions?: Record<string, unknown>;
}

export type OwnerPolicy =
  | { kind: "scan"; onWarning?: (warning: string) => void }
  | {
      kind: "standalone";
      decide(finding: OwnerFinding, context: OwnerContext): unknown;
    };

export interface OwnerResolver {
  findingsAtScanRevision(
    repository: string,
    revision: string,
    findings: readonly OwnerFinding[],
    signal?: AbortSignal,
  ): Promise<OwnerFinding[]>;
  prepare(
    repository: string,
    findings: readonly OwnerFinding[],
    environment: NodeJS.ProcessEnv,
    signal?: AbortSignal,
  ): Promise<{
    revision: string;
    resolve(policy: OwnerPolicy): Promise<OwnerSuggestion[]>;
  }>;
  decisionJsonSchema(): Record<string, unknown>;
}

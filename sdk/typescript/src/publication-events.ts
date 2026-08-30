import { isLinearIssueIdentifier, linearIssueReference } from "./linear.js";
import {
  linearPublicationArguments,
  type PreparedPublicationIssue,
  type PreparedScanPublication,
} from "./publication.js";

export const MISSING_PUBLICATION_IDENTIFIER_ERROR =
  "The connected Linear app did not return a created issue identifier.";

export interface PublicationClaim {
  kind: "identifier" | "entityId" | "url";
  value: string;
}

export type ClaimResolution =
  | { state: "absent"; claims: PublicationClaim[] }
  | { state: "conflicting"; claims: PublicationClaim[] }
  | {
      state: "resolved";
      claims: PublicationClaim[];
      issueIdentifier: string;
      url?: string;
    };

export interface CompletedCreateEvidence {
  source: "event";
  status: "completed";
  rawLine: string;
  ownerFindingId?: string;
  argumentsValid: boolean;
  resolution: ClaimResolution;
}

export interface FailedCreateEvidence {
  source: "event";
  status: "failed";
  rawLine: string;
  ownerFindingId?: string;
  argumentsValid: boolean;
  resolution: ClaimResolution;
  error: string;
}

export type PublicationEventEvidence =
  | CompletedCreateEvidence
  | FailedCreateEvidence;

export function collectPublicationEvents(
  output: string,
  publication: PreparedScanPublication,
  failureMessage: string,
): PublicationEventEvidence[] {
  const evidence: PublicationEventEvidence[] = [];

  for (const rawLine of output.split(/\r?\n/)) {
    if (rawLine.trim().length === 0) continue;
    let event: unknown;
    try {
      event = JSON.parse(rawLine) as unknown;
    } catch {
      continue;
    }
    if (!isRecord(event) || event["type"] !== "item.completed") continue;
    const item = event["item"];
    if (!isLinearCreateCall(item)) continue;

    const arguments_ = item["arguments"];
    const owner = isRecord(arguments_)
      ? matchPublicationIssue(publication, arguments_)
      : undefined;
    const argumentsValid =
      owner !== undefined &&
      hasExpectedPublicationArguments(publication, owner, arguments_);
    if (item["status"] === "completed") {
      evidence.push({
        source: "event",
        status: "completed",
        rawLine,
        ...(owner === undefined ? {} : { ownerFindingId: owner.findingId }),
        argumentsValid,
        resolution: resolvePublicationClaims(item["result"]),
      });
      continue;
    }

    const error = item["error"];
    evidence.push({
      source: "event",
      status: "failed",
      rawLine,
      ...(owner === undefined ? {} : { ownerFindingId: owner.findingId }),
      argumentsValid,
      resolution: resolvePublicationClaims(item["result"]),
      error:
        isRecord(error) && typeof error["message"] === "string"
          ? error["message"]
          : failureMessage,
    });
  }

  return evidence;
}

export function hasExpectedPublicationArguments(
  publication: PreparedScanPublication,
  issue: PreparedPublicationIssue,
  actual: unknown,
): boolean {
  if (!isRecord(actual)) return false;
  const expected = linearPublicationArguments(publication.destination, issue);
  return (
    Object.keys(actual).length === Object.keys(expected).length &&
    Object.entries(expected).every(
      ([key, value]) =>
        Object.hasOwn(actual, key) && Object.is(actual[key], value),
    )
  );
}

export function matchPublicationIssue(
  publication: PreparedScanPublication,
  arguments_: Record<string, unknown>,
): PreparedPublicationIssue | undefined {
  const exactMatches = publication.issues.filter((issue) =>
    hasExpectedPublicationArguments(publication, issue, arguments_),
  );
  if (exactMatches.length === 1) return exactMatches[0];

  const description = arguments_["description"];
  if (typeof description !== "string") return undefined;
  const matches = publication.issues.filter(
    (issue) =>
      containsIdentifier(description, issue.findingId) &&
      containsIdentifier(description, issue.occurrenceId),
  );
  return matches.length === 1 ? matches[0] : undefined;
}

export function resolvePublicationClaims(value: unknown): ClaimResolution {
  const claims: PublicationClaim[] = [];
  collectPublicationClaims(value, claims);
  return resolveClaims(claims);
}

export function resolveClaims(
  claims: readonly PublicationClaim[],
): ClaimResolution {
  const seen = new Set<string>();
  const normalized = claims.flatMap<PublicationClaim>((claim) => {
    const trimmed = claim.value.trim();
    if (trimmed.length === 0) return [];
    const value = isCanonicalUuid(trimmed) ? trimmed.toLowerCase() : trimmed;
    return [{ kind: claim.kind, value }];
  });
  const retained = normalized
    .filter((claim) => {
      const key = `${claim.kind}\0${claim.value}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort(compareClaims);
  const identifiers = new Set(
    retained
      .filter((claim) => claim.kind === "identifier")
      .map((claim) => claim.value),
  );
  const entityIds = new Set(
    retained
      .filter((claim) => claim.kind === "entityId")
      .map((claim) => claim.value),
  );
  const urls = new Set(
    retained
      .filter((claim) => claim.kind === "url")
      .map((claim) => claim.value),
  );
  const canonicalUrls = new Set([...urls].map(canonicalPublicationUrlClaim));
  const urlContradictsIdentifier =
    identifiers.size > 0 &&
    [...urls]
      .map(linearIssueReferenceFromUrl)
      .some(
        (reference) =>
          reference !== undefined && !identifiers.has(reference.id),
      );
  const overlappingIdentity = [...identifiers].some((identifier) =>
    entityIds.has(identifier),
  );
  if (
    identifiers.size > 1 ||
    entityIds.size > 1 ||
    canonicalUrls.size > 1 ||
    urlContradictsIdentifier ||
    overlappingIdentity
  ) {
    return { state: "conflicting", claims: retained };
  }
  if (identifiers.size === 0) {
    return { state: "absent", claims: retained };
  }
  return {
    state: "resolved",
    claims: retained,
    issueIdentifier: identifiers.values().next().value!,
    ...(urls.size === 0 ? {} : { url: urls.values().next().value! }),
  };
}

function isLinearCreateCall(item: unknown): item is Record<string, unknown> {
  return (
    isRecord(item) &&
    item["type"] === "mcp_tool_call" &&
    item["server"] === "codex_apps" &&
    (item["tool"] === "linear.save_issue" ||
      item["tool"] === "linear_save_issue")
  );
}

function collectPublicationClaims(
  value: unknown,
  claims: PublicationClaim[],
): void {
  const visited = new Set<Record<string, unknown>>();
  const pending: unknown[] = [value];
  while (pending.length > 0) {
    const candidate = pending.pop();
    if (!isRecord(candidate) || visited.has(candidate)) continue;
    visited.add(candidate);
    collectDirectClaims(candidate, claims);

    const data = candidate["data"];
    const nested: unknown[] = [
      candidate["structured_content"],
      candidate["structuredContent"],
      candidate["issue"],
      isRecord(data) ? data["issue"] : undefined,
    ];
    if (Array.isArray(candidate["content"])) {
      for (const content of candidate["content"]) {
        if (!isRecord(content) || typeof content["text"] !== "string") {
          continue;
        }
        try {
          nested.push(JSON.parse(content["text"]) as unknown);
        } catch {
          continue;
        }
      }
    }
    for (let index = nested.length - 1; index >= 0; index -= 1) {
      if (isRecord(nested[index])) pending.push(nested[index]);
    }
  }
}

function collectDirectClaims(
  candidate: Record<string, unknown>,
  claims: PublicationClaim[],
): void {
  for (const field of ["identifier", "issueIdentifier", "key", "id"] as const) {
    const claim = classifyIdentityClaim(field, candidate[field]);
    if (claim !== undefined) claims.push(claim);
  }
  const url = candidate["url"];
  const normalizedUrl = normalizeNonemptyString(url);
  if (normalizedUrl !== undefined) {
    claims.push({ kind: "url", value: normalizedUrl });
  }
}

function classifyIdentityClaim(
  field: "identifier" | "issueIdentifier" | "key" | "id",
  value: unknown,
): PublicationClaim | undefined {
  const normalized = normalizeNonemptyString(value);
  if (normalized === undefined) return undefined;
  if (isCanonicalUuid(normalized)) {
    return { kind: "entityId", value: normalized };
  }
  if (field === "identifier" || field === "issueIdentifier") {
    return { kind: "identifier", value: normalized };
  }
  if (isLinearIssueIdentifier(normalized)) {
    return { kind: "identifier", value: normalized };
  }
  return field === "id" ? { kind: "entityId", value: normalized } : undefined;
}

function compareClaims(
  left: PublicationClaim,
  right: PublicationClaim,
): number {
  const order = { identifier: 0, entityId: 1, url: 2 } as const;
  const kindOrder = order[left.kind] - order[right.kind];
  if (kindOrder !== 0) return kindOrder;
  if (left.value === right.value) return 0;
  return left.value < right.value ? -1 : 1;
}

function isCanonicalUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(
    value,
  );
}

function linearIssueReferenceFromUrl(
  value: string,
): { id: string; workspace: string } | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.protocol !== "https:" || url.hostname !== "linear.app") {
    return undefined;
  }
  try {
    const reference = linearIssueReference(value);
    return reference.workspace === undefined
      ? undefined
      : { id: reference.id, workspace: reference.workspace };
  } catch {
    return undefined;
  }
}

function canonicalPublicationUrlClaim(value: string): string {
  const reference = linearIssueReferenceFromUrl(value);
  return reference === undefined
    ? `raw:\0${value}`
    : `linear:\0${reference.workspace}\0${reference.id}`;
}

export function publicationClaimAliases(
  claim: PublicationClaim,
): PublicationClaim[] {
  if (claim.kind !== "url") return [claim];
  const reference = linearIssueReferenceFromUrl(claim.value);
  return reference === undefined
    ? [claim]
    : [claim, { kind: "identifier", value: reference.id }];
}

function normalizeNonemptyString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length === 0 ? undefined : normalized;
}

function containsIdentifier(value: string, identifier: string): boolean {
  const escaped = identifier.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(`(?<![\\w-])${escaped}(?![\\w-])`, "u").test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

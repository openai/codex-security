import { createHash } from "node:crypto";
import { z } from "zod";
import type { JsonValue } from "./config.js";
import {
  inventoryReceiptSelectionSchema,
  type BoundDependencyInventoryReceipt,
} from "./dependency-inventory.js";
import type { DependencyExcerpt } from "./dependency-reachability.js";
import { CodexSecurityError } from "./errors.js";
import { canonicalJson } from "./record.js";

const identity = z.string().trim().min(1);
export const dependencyClaimReferenceSchema = z.strictObject({
  id: identity,
  revision: z.number().int().positive(),
  hash: z
    .string()
    .regex(/^[a-f0-9]{64}$/u, "Use the exact host-issued SHA-256 claim hash."),
});
export type DependencyClaimReference = z.infer<
  typeof dependencyClaimReferenceSchema
>;
export const dependencyClaimQuerySchema = z
  .strictObject({
    ids: z.array(identity).optional(),
    search: identity.optional(),
    page: z
      .strictObject({
        cursor: z
          .strictObject({
            generation: z.number().int().nonnegative(),
            after: identity,
          })
          .optional(),
        limit: z.number().int().positive().optional(),
      })
      .optional()
      .describe(
        "Search index page, default 50 rows. Follow nextCursor; revisions invalidate the search cursor. Exact ids return full selected envelopes instead.",
      ),
  })
  .refine(
    (value) => (value.ids !== undefined) !== (value.search !== undefined),
    "Select exact claim IDs or a literal search, not both.",
  )
  .refine(
    (value) => !value.page || value.search !== undefined,
    "Paging applies to search; use exact IDs for complete selected claims.",
  );

export const dependencyClaimProposalSchema = z.strictObject({
  id: identity.refine(
    (value) => !value.startsWith("application:"),
    "The application: namespace is reserved for host-bound assessment conclusions.",
  ),
  payload: z
    .json()
    .describe(
      "The precise proposition or inference to verify, as arbitrary JSON. Payload fields never control host approval or identity.",
    ),
  scope: z
    .json()
    .describe(
      "The exact caller, implementation, environment or other boundary for which this proposition is asserted.",
    ),
  evidence: z
    .array(
      z
        .strictObject({
          path: identity,
          startLine: z.number().int().positive(),
          endLine: z.number().int().positive(),
        })
        .refine(
          (value) => value.startLine <= value.endLine,
          "Evidence range is reversed.",
        ),
    )
    .default([]),
  receiptIds: z.array(identity).optional(),
  receiptSelections: z.array(inventoryReceiptSelectionSchema).optional(),
  dependencies: z
    .array(dependencyClaimReferenceSchema)
    .default([])
    .describe(
      "Exact currently approved dependencies. Query pending claims to avoid duplicate work; wait for their approval before depending on them.",
    ),
  expectedRevision: z
    .number()
    .int()
    .nonnegative()
    .optional()
    .describe(
      "Exact current revision when changing an existing claim. Omit for create or an identical idempotent requeue.",
    ),
});
export const dependencyClaimQueueSchema = z.strictObject({
  claims: z.array(dependencyClaimProposalSchema).min(1),
});
export const dependencyClaimQueueDescription =
  "Propose precise reusable JSON claims with narrow scope and deciding source ranges or exact original receipt selections. The existing independent reviewer automatically saves approvals. Search claims first; unchanged approved premises retain their decisions. New caller bindings and conclusions still need independent review. Depend only on exact current approved revisions. Pending or failed reviews remain discoverable; explicitly requeue to retry a failed review. Do not propose host application: IDs.";
export const dependencyClaimQueryDescription =
  "Query the shared review ledger by exact ids or a literal search across claim IDs, scope and JSON payload. Returns current pending, approved, rejected or stale immutable revisions and compact provenance. Pending claims are discoverable so investigators can avoid duplicate research. Claim approval is limited to its exact proposition and scope; it does not approve another caller's application.";

export const dependencyApprovedClaimSchema =
  dependencyClaimReferenceSchema.extend({
    state: z.literal("approved"),
    contextHash: identity,
    payload: z.json(),
    scope: z.json(),
    dependencies: z.array(dependencyClaimReferenceSchema),
    application: z
      .strictObject({ assessmentId: identity, fingerprint: identity })
      .optional(),
    decision: z.strictObject({
      accepted: z.literal(true),
      reason: identity,
      evidenceKeys: z.array(identity),
      citedVersion: z.string().nullable().optional(),
    }),
    evidence: z.strictObject({
      sourceIds: z.array(identity),
      receiptIds: z.array(identity),
    }),
  });

export const dependencyClaimEvidenceSchema = z.strictObject({
  sources: z.record(identity, z.json()),
  receipts: z.record(identity, z.json()),
});

export type DependencyClaimState =
  "pending" | "approved" | "rejected" | "stale";
export interface PreparedDependencyClaim {
  id: string;
  payload: JsonValue;
  scope: JsonValue;
  dependencies: DependencyClaimReference[];
  excerpts: DependencyExcerpt[];
  receipts: BoundDependencyInventoryReceipt[];
  /** Set only by the host preparing an exact assessment snapshot. */
  application?: { assessmentId: string; fingerprint: string };
}
export interface DependencyClaimDecision {
  accepted: boolean;
  reason: string;
  evidenceKeys: string[];
  citedVersion?: string | null;
}
export interface DependencyClaimRecord
  extends PreparedDependencyClaim, DependencyClaimReference {
  state: DependencyClaimState;
  contextHash: string;
  decision?: DependencyClaimDecision;
  error?: string;
}

export function dependencyClaimHash(value: unknown): string {
  return createHash("sha256")
    .update(canonicalJson(value) ?? "null")
    .digest("hex");
}

function reference(record: DependencyClaimReference): DependencyClaimReference {
  return { id: record.id, revision: record.revision, hash: record.hash };
}
function sameReference(
  a: DependencyClaimReference,
  b: DependencyClaimReference,
) {
  return a.id === b.id && a.revision === b.revision && a.hash === b.hash;
}
function receiptIdentity(receipt: BoundDependencyInventoryReceipt) {
  const { server, originalPayloadSha256, origin, selection, outcome } = receipt;
  return { server, originalPayloadSha256, origin, selection, outcome };
}
function evidenceMaterial(claim: PreparedDependencyClaim) {
  const sorted = (values: unknown[]) =>
    values.sort((a, b) => {
      const left = canonicalJson(a) ?? "null";
      const right = canonicalJson(b) ?? "null";
      return left < right ? -1 : left > right ? 1 : 0;
    });
  return {
    id: claim.id,
    payload: claim.payload,
    scope: claim.scope,
    dependencies: sorted(claim.dependencies.map(reference)),
    excerpts: sorted(claim.excerpts.map((excerpt) => ({ ...excerpt }))),
    receipts: sorted(claim.receipts.map(receiptIdentity)),
    ...(claim.application && { application: claim.application }),
  };
}

/** Immutable claim revisions in the existing investigation's review lifecycle. */
export function createDependencyClaims(
  context: JsonValue,
  onInvalidatedApplication?: (assessmentId: string) => void,
) {
  const contextHash = dependencyClaimHash(context);
  const history = new Map<string, Map<number, DependencyClaimRecord>>();
  const current = new Map<string, DependencyClaimRecord>();
  const reviewing = new Set<string>();
  const dependents = new Map<string, Set<string>>();
  const recordsByKey = new Map<string, DependencyClaimRecord>();
  let generation = 0;

  const key = (ref: DependencyClaimReference) =>
    JSON.stringify([ref.id, ref.revision, ref.hash]);
  function find(
    ref: DependencyClaimReference,
  ): DependencyClaimRecord | undefined {
    const record = history.get(ref.id)?.get(ref.revision);
    return record && sameReference(record, ref) ? record : undefined;
  }
  function isCurrent(ref: DependencyClaimReference): boolean {
    const record = current.get(ref.id);
    return !!record && sameReference(record, ref);
  }
  function approved(
    ref: DependencyClaimReference,
    memo = new Map<string, boolean>(),
    visiting = new Set<string>(),
  ): boolean {
    const selected = key(ref);
    const known = memo.get(selected);
    if (known !== undefined) return known;
    const record = find(ref);
    if (
      !record ||
      !isCurrent(ref) ||
      record.state !== "approved" ||
      visiting.has(record.id)
    ) {
      memo.set(selected, false);
      return false;
    }
    const next = new Set(visiting).add(record.id);
    const result = record.dependencies.every((dependency) =>
      approved(dependency, memo, next),
    );
    memo.set(selected, result);
    return result;
  }
  function invalidate(
    ref: DependencyClaimReference,
    reason: string,
  ): DependencyClaimReference[] {
    const pending = [{ ref, reason }];
    const invalidated: DependencyClaimReference[] = [];
    const seen = new Set<string>();
    while (pending.length) {
      const next = pending.pop()!;
      const selected = key(next.ref);
      if (seen.has(selected)) continue;
      seen.add(selected);
      const record = find(next.ref);
      if (!record || record.state === "stale") continue;
      if (record.state === "approved" && record.application)
        onInvalidatedApplication?.(record.application.assessmentId);
      record.state = "stale";
      invalidated.push(reference(record));
      record.error = next.reason;
      for (const child of dependents.get(selected) ?? []) {
        const dependent = recordsByKey.get(child)!;
        pending.push({
          ref: reference(dependent),
          reason: `Dependency ${record.id} revision ${record.revision} is stale: ${next.reason}`,
        });
      }
    }
    return invalidated;
  }
  function cycle(
    id: string,
    dependencies: readonly DependencyClaimReference[],
    seen = new Set<string>(),
  ): boolean {
    for (const dependency of dependencies) {
      if (dependency.id === id) return true;
      if (seen.has(key(dependency))) continue;
      seen.add(key(dependency));
      const record = find(dependency);
      if (record && cycle(id, record.dependencies, seen)) return true;
    }
    return false;
  }
  function requireDependencies(
    dependencies: readonly DependencyClaimReference[],
  ) {
    const ids = new Set<string>();
    const memo = new Map<string, boolean>();
    for (const dependency of dependencies) {
      if (ids.has(dependency.id))
        throw new CodexSecurityError(
          `Choose one exact approved revision for dependency ${dependency.id}.`,
        );
      ids.add(dependency.id);
      if (!approved(dependency, memo))
        throw new CodexSecurityError(
          `Claim dependency ${dependency.id} revision ${dependency.revision} is missing, pending, rejected or stale. Query its current claim and use an approved exact revision.`,
        );
    }
  }
  function envelope(record: DependencyClaimRecord) {
    const { excerpts, receipts, ...data } = record;
    return structuredClone({
      ...data,
      reviewing: reviewing.has(key(record)),
      evidence: {
        sources: excerpts.map(
          ({ path, startLine, endLine, text, sourceIdentity }) => ({
            path,
            startLine,
            endLine,
            sha256: createHash("sha256").update(text).digest("hex"),
            ...(sourceIdentity && { sourceIdentity }),
          }),
        ),
        receipts: receipts.map((receipt) => ({
          receiptId: receipt.receiptId,
          ...receiptIdentity(receipt),
        })),
      },
    });
  }

  function proposal(input: PreparedDependencyClaim, expectedRevision?: number) {
    const prepared = structuredClone(input);
    if (cycle(prepared.id, prepared.dependencies))
      throw new CodexSecurityError(
        `Claim ${prepared.id} would create a dependency cycle.`,
      );
    requireDependencies(prepared.dependencies);
    const hash = dependencyClaimHash({
      contextHash,
      ...evidenceMaterial(prepared),
    });
    const previous = current.get(prepared.id);
    if (previous?.hash === hash && previous.state !== "stale")
      return { prepared, previous, hash, changed: false };
    if (previous && expectedRevision !== previous.revision)
      throw new CodexSecurityError(
        `Claim ${prepared.id} changed: expectedRevision must be ${previous.revision}. Query before revising it.`,
      );
    if (!previous && expectedRevision !== undefined && expectedRevision !== 0)
      throw new CodexSecurityError(
        `Claim ${prepared.id} does not have expected revision ${expectedRevision}.`,
      );
    return { prepared, previous, hash, changed: true };
  }

  return {
    contextHash,
    reference,
    isCurrent,
    isApproved: approved,
    state(ref: DependencyClaimReference) {
      const record = find(ref);
      return (
        record && {
          ...reference(record),
          state: record.state,
          error: record.error,
          current: isCurrent(ref),
          ...(record.application && { application: { ...record.application } }),
        }
      );
    },
    currentReference(id: string) {
      const record = current.get(id);
      return record && reference(record);
    },
    pendingReferences() {
      return [...current.values()]
        .filter(
          (record) =>
            record.state === "pending" &&
            !record.error &&
            !reviewing.has(key(record)),
        )
        .map((record) => ({
          ...reference(record),
          isApplication: record.application !== undefined,
        }));
    },
    invalidate,
    requireDependencies,
    get(ref: DependencyClaimReference) {
      const record = find(ref);
      return record && structuredClone(record);
    },
    latest(id: string) {
      const record = current.get(id);
      return record && structuredClone(record);
    },
    preview(input: PreparedDependencyClaim, expectedRevision?: number) {
      const { hash, changed, previous } = proposal(input, expectedRevision);
      return { hash, changed, currentRevision: previous?.revision };
    },
    propose(input: PreparedDependencyClaim, expectedRevision?: number) {
      const { prepared, previous, hash, changed } = proposal(
        input,
        expectedRevision,
      );
      if (!changed) return { record: envelope(previous!), changed: false };
      if (previous)
        invalidate(
          previous,
          "A new immutable revision supersedes this subject.",
        );
      const record: DependencyClaimRecord = {
        ...prepared,
        revision: (previous?.revision ?? 0) + 1,
        hash,
        contextHash,
        state: "pending",
      };
      const revisions =
        history.get(record.id) ?? new Map<number, DependencyClaimRecord>();
      revisions.set(record.revision, record);
      history.set(record.id, revisions);
      current.set(record.id, record);
      generation++;
      recordsByKey.set(key(record), record);
      for (const dependency of record.dependencies) {
        const children = dependents.get(key(dependency)) ?? new Set<string>();
        children.add(key(record));
        dependents.set(key(dependency), children);
      }
      return { record: envelope(record), changed: true };
    },
    pending() {
      return [...current.values()]
        .filter(
          (record) =>
            record.state === "pending" &&
            !record.error &&
            !reviewing.has(key(record)),
        )
        .map((record) => structuredClone(record));
    },
    lease(ref: DependencyClaimReference) {
      const record = find(ref);
      if (
        !record ||
        !isCurrent(ref) ||
        record.state !== "pending" ||
        reviewing.has(key(ref))
      )
        return undefined;
      requireDependencies(record.dependencies);
      reviewing.add(key(ref));
      return structuredClone(record);
    },
    complete(ref: DependencyClaimReference, decision: DependencyClaimDecision) {
      const record = find(ref);
      if (
        !record ||
        !reviewing.delete(key(ref)) ||
        !isCurrent(ref) ||
        record.state !== "pending"
      )
        return false;
      const memo = new Map<string, boolean>();
      if (
        !record.dependencies.every((dependency) => approved(dependency, memo))
      ) {
        invalidate(
          ref,
          "A pinned dependency changed while this subject was being reviewed.",
        );
        return false;
      }
      record.decision = structuredClone(decision);
      record.state = decision.accepted ? "approved" : "rejected";
      return true;
    },
    reviewError(ref: DependencyClaimReference, reason: string) {
      reviewing.delete(key(ref));
      const record = find(ref);
      if (record && isCurrent(ref) && record.state === "pending")
        record.error = reason;
    },
    retry(ref: DependencyClaimReference) {
      const record = find(ref);
      if (
        record &&
        isCurrent(ref) &&
        record.state === "pending" &&
        !reviewing.has(key(ref))
      )
        delete record.error;
    },
    query(value: unknown) {
      const query = dependencyClaimQuerySchema.parse(value);
      if (query.ids) {
        const ids = [...new Set(query.ids)].sort();
        return {
          claims: ids.flatMap((id) => {
            const record = current.get(id);
            return record ? [envelope(record)] : [];
          }),
          missingIds: ids.filter((id) => !current.has(id)),
          generation,
          total: ids.filter((id) => current.has(id)).length,
          nextCursor: null,
        };
      }
      const search = query.search!.toLowerCase();
      const matches = [...current.values()].filter((record) =>
        `${record.id}\n${canonicalJson(record.scope)}\n${canonicalJson(record.payload)}`
          .toLowerCase()
          .includes(search),
      );
      matches.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
      const cursor = query.page?.cursor;
      if (cursor && cursor.generation !== generation)
        throw new CodexSecurityError(
          "Claim revisions changed this search index. Start a fresh search page; no stored claims were removed.",
        );
      const after = cursor
        ? matches.findIndex((record) => record.id === cursor.after)
        : -1;
      if (cursor && after === -1)
        throw new CodexSecurityError(
          "Unknown claim search cursor for this query.",
        );
      const page = matches.slice(
        after + 1,
        after + 1 + (query.page?.limit ?? 50),
      );
      return {
        claims: page.map((record) => ({
          ...reference(record),
          state: record.state,
          reviewing: reviewing.has(key(record)),
          ...(record.error && { hasError: true }),
          sourceCount: record.excerpts.length,
          receiptCount: record.receipts.length,
          dependencyCount: record.dependencies.length,
          ...(record.application && {
            application: { assessmentId: record.application.assessmentId },
          }),
        })),
        missingIds: [],
        generation,
        total: matches.length,
        nextCursor:
          after + 1 + page.length < matches.length
            ? { generation, after: page.at(-1)!.id }
            : null,
        details:
          "Compact search index. Query exact ids to retrieve the selected payload, scope, immutable dependencies and provenance.",
      };
    },
    closure(refs: readonly DependencyClaimReference[]) {
      const selected = new Map<string, DependencyClaimRecord>();
      const memo = new Map<string, boolean>();
      const visit = (ref: DependencyClaimReference) => {
        if (!approved(ref, memo))
          throw new CodexSecurityError(
            `Claim ${ref.id} revision ${ref.revision} is not currently approved.`,
          );
        if (selected.has(key(ref))) return;
        const record = find(ref)!;
        selected.set(key(ref), record);
        for (const dependency of record.dependencies) visit(dependency);
      };
      for (const ref of refs) visit(ref);
      return [...selected.values()].map((record) => structuredClone(record));
    },
  };
}

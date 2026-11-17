import { createHash } from "node:crypto";
import { dependencyGitCommitSchema } from "./dependency-source-identity.js";
import { z } from "zod";
import type { JsonValue } from "./config.js";
import { DependencyAttemptStore } from "./dependency-attempt-store.js";
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
          commit: dependencyGitCommitSchema.optional(),
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
      "Exact current revisions this claim depends on. Investigations with independent review require each dependency to be approved first.",
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
  "pending" | "approved" | "rejected" | "stale" | "recorded";
export type DependencyClaimPolicy = "reviewed" | "single_agent";
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

/** Immutable claim revisions, scoped to one attempt and its review policy. */
export function createDependencyClaims(
  context: JsonValue,
  onInvalidatedApplication?: (assessmentId: string) => void,
  attempt = new DependencyAttemptStore(":memory:"),
  policy: DependencyClaimPolicy = "reviewed",
) {
  const contextHash = dependencyClaimHash(context);
  attempt.transaction(() => {
    const stored = attempt.get<{
      contextHash: string;
      policy: DependencyClaimPolicy;
    }>("claims", "context");
    if (!stored) attempt.set("claims", "context", { contextHash, policy });
    else if (stored.contextHash !== contextHash || stored.policy !== policy)
      throw new CodexSecurityError(
        "This claim ledger belongs to a different investigation context or review policy.",
      );
  });

  const key = (ref: DependencyClaimReference) =>
    JSON.stringify([ref.id, ref.revision, ref.hash]);
  function parseRecord(row: { [key: string]: unknown } | null | undefined) {
    return row
      ? (JSON.parse(row["value"] as string) as DependencyClaimRecord)
      : undefined;
  }
  function latest(id: string) {
    return parseRecord(
      attempt
        .statement(
          "SELECT value FROM claim_revisions WHERE id = ? ORDER BY revision DESC LIMIT 1",
        )
        .get(id),
    );
  }
  function currentRecords() {
    return attempt
      .statement(
        `
      SELECT c.value FROM claim_revisions c
      JOIN (SELECT id, MAX(revision) AS revision, MIN(rowid) AS first FROM claim_revisions GROUP BY id) latest
        ON c.id = latest.id AND c.revision = latest.revision
      ORDER BY latest.first
    `,
      )
      .all()
      .map((row) => parseRecord(row)!);
  }
  function save(record: DependencyClaimRecord) {
    attempt
      .statement(
        "UPDATE claim_revisions SET value = ? WHERE id = ? AND revision = ?",
      )
      .run(JSON.stringify(record), record.id, record.revision);
  }
  function isReviewing(ref: DependencyClaimReference) {
    return !!attempt
      .statement(
        "SELECT 1 FROM claim_review_leases WHERE id = ? AND revision = ? AND hash = ?",
      )
      .get(ref.id, ref.revision, ref.hash);
  }
  function releaseReview(ref: DependencyClaimReference) {
    return !!attempt
      .statement(
        "DELETE FROM claim_review_leases WHERE id = ? AND revision = ? AND hash = ? AND owner = ?",
      )
      .run(ref.id, ref.revision, ref.hash, attempt.reviewOwner).changes;
  }
  function find(
    ref: DependencyClaimReference,
  ): DependencyClaimRecord | undefined {
    return parseRecord(
      attempt
        .statement(
          "SELECT value FROM claim_revisions WHERE id = ? AND revision = ? AND hash = ?",
        )
        .get(ref.id, ref.revision, ref.hash),
    );
  }
  function isCurrent(ref: DependencyClaimReference): boolean {
    const row = attempt
      .statement(
        "SELECT revision, hash FROM claim_revisions WHERE id = ? ORDER BY revision DESC LIMIT 1",
      )
      .get(ref.id);
    return (
      !!row && row["revision"] === ref.revision && row["hash"] === ref.hash
    );
  }
  function usable(
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
      record.state !== (policy === "reviewed" ? "approved" : "recorded") ||
      visiting.has(record.id)
    ) {
      memo.set(selected, false);
      return false;
    }
    const next = new Set(visiting).add(record.id);
    const result = record.dependencies.every((dependency) =>
      usable(dependency, memo, next),
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
      if (
        record.state === "approved" &&
        record.application &&
        onInvalidatedApplication
      ) {
        const assessmentId = record.application.assessmentId;
        attempt.afterCommit(() => onInvalidatedApplication(assessmentId));
      }
      record.state = "stale";
      invalidated.push(reference(record));
      record.error = next.reason;
      save(record);
      const children = attempt
        .statement(
          `
        SELECT c.id, c.revision, c.hash FROM claim_dependencies d
        JOIN claim_revisions c ON c.id = d.dependent_id AND c.revision = d.dependent_revision
        WHERE d.premise_id = ? AND d.premise_revision = ? AND d.premise_hash = ?
      `,
        )
        .all(record.id, record.revision, record.hash);
      for (const child of children) {
        pending.push({
          ref: {
            id: child["id"] as string,
            revision: child["revision"] as number,
            hash: child["hash"] as string,
          },
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
      if (!usable(dependency, memo))
        throw new CodexSecurityError(
          policy === "reviewed"
            ? `Claim dependency ${dependency.id} revision ${dependency.revision} is missing, pending, rejected or stale. Query its current claim and use an approved exact revision.`
            : `Claim dependency ${dependency.id} revision ${dependency.revision} is missing or stale. Query the exact current revision.`,
        );
    }
  }
  function envelope(record: DependencyClaimRecord) {
    const { excerpts, receipts, ...data } = record;
    return structuredClone({
      ...data,
      reviewing: isReviewing(record),
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
    if (policy === "single_agent") {
      for (const excerpt of prepared.excerpts) {
        if (excerpt.sourceIdentity)
          excerpt.sourceIdentity.repositoryRoot = null;
      }
    }
    if (cycle(prepared.id, prepared.dependencies))
      throw new CodexSecurityError(
        `Claim ${prepared.id} would create a dependency cycle.`,
      );
    requireDependencies(prepared.dependencies);
    const hash = dependencyClaimHash({
      contextHash,
      ...evidenceMaterial(prepared),
    });
    const previous = latest(prepared.id);
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
    isApproved: (ref: DependencyClaimReference) =>
      policy === "reviewed" && attempt.read(() => usable(ref)),
    isUsable: (ref: DependencyClaimReference) =>
      attempt.read(() => usable(ref)),
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
      const record = latest(id);
      return record && reference(record);
    },
    pendingReferences() {
      return currentRecords()
        .filter(
          (record) =>
            record.state === "pending" && !record.error && !isReviewing(record),
        )
        .map((record) => ({
          ...reference(record),
          isApplication: record.application !== undefined,
        }));
    },
    invalidate(ref: DependencyClaimReference, reason: string) {
      return attempt.transaction(() => invalidate(ref, reason));
    },
    requireDependencies,
    get: find,
    latest,
    preview(input: PreparedDependencyClaim, expectedRevision?: number) {
      const { hash, changed, previous } = proposal(input, expectedRevision);
      return { hash, changed, currentRevision: previous?.revision };
    },
    propose(input: PreparedDependencyClaim, expectedRevision?: number) {
      return attempt.transaction(() => {
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
          state: policy === "reviewed" ? "pending" : "recorded",
        };
        attempt
          .statement(
            "INSERT INTO claim_revisions (id, revision, hash, value) VALUES (?, ?, ?, ?)",
          )
          .run(record.id, record.revision, record.hash, JSON.stringify(record));
        for (const dependency of record.dependencies) {
          attempt
            .statement(
              "INSERT INTO claim_dependencies (premise_id, premise_revision, premise_hash, dependent_id, dependent_revision) VALUES (?, ?, ?, ?, ?)",
            )
            .run(
              dependency.id,
              dependency.revision,
              dependency.hash,
              record.id,
              record.revision,
            );
        }
        return { record: envelope(record), changed: true };
      });
    },
    pending() {
      return currentRecords()
        .filter(
          (record) =>
            record.state === "pending" && !record.error && !isReviewing(record),
        )
        .map((record) => structuredClone(record));
    },
    lease(ref: DependencyClaimReference) {
      return attempt.transaction(() => {
        const record = find(ref);
        if (
          !record ||
          !isCurrent(ref) ||
          record.state !== "pending" ||
          isReviewing(ref)
        )
          return undefined;
        requireDependencies(record.dependencies);
        attempt
          .statement(
            "INSERT INTO claim_review_leases (id, revision, hash, pid, owner) VALUES (?, ?, ?, ?, ?)",
          )
          .run(
            ref.id,
            ref.revision,
            ref.hash,
            process.pid,
            attempt.reviewOwner,
          );
        return record;
      });
    },
    complete(ref: DependencyClaimReference, decision: DependencyClaimDecision) {
      return attempt.transaction(() => {
        const record = find(ref);
        if (
          !record ||
          !releaseReview(ref) ||
          !isCurrent(ref) ||
          record.state !== "pending"
        )
          return false;
        const memo = new Map<string, boolean>();
        if (
          !record.dependencies.every((dependency) => usable(dependency, memo))
        ) {
          invalidate(
            ref,
            "A pinned dependency changed while this subject was being reviewed.",
          );
          return false;
        }
        record.decision = structuredClone(decision);
        record.state = decision.accepted ? "approved" : "rejected";
        save(record);
        return true;
      });
    },
    reviewError(ref: DependencyClaimReference, reason: string) {
      attempt.transaction(() => {
        if (!releaseReview(ref) && isReviewing(ref)) return;
        const record = find(ref);
        if (record && isCurrent(ref) && record.state === "pending") {
          record.error = reason;
          save(record);
        }
      });
    },
    retry(ref: DependencyClaimReference) {
      attempt.transaction(() => {
        const record = find(ref);
        if (
          record &&
          isCurrent(ref) &&
          record.state === "pending" &&
          !isReviewing(ref)
        ) {
          delete record.error;
          save(record);
        }
      });
    },
    query(value: unknown) {
      return attempt.read(() => {
        const query = dependencyClaimQuerySchema.parse(value);
        const generation = attempt
          .statement("SELECT COUNT(*) AS generation FROM claim_revisions")
          .get()!["generation"] as number;
        if (query.ids) {
          const ids = [...new Set(query.ids)].sort();
          const claims = [];
          const missingIds = [];
          for (const id of ids) {
            const record = latest(id);
            if (record) claims.push(envelope(record));
            else missingIds.push(id);
          }
          return {
            claims,
            missingIds,
            generation,
            total: claims.length,
            nextCursor: null,
          };
        }
        const search = query.search!.toLowerCase();
        const matches = currentRecords().filter((record) =>
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
            reviewing: isReviewing(record),
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
      });
    },
    closure(refs: readonly DependencyClaimReference[]) {
      return attempt.read(() => {
        const selected = new Map<string, DependencyClaimRecord>();
        const memo = new Map<string, boolean>();
        const visit = (ref: DependencyClaimReference) => {
          if (!usable(ref, memo))
            throw new CodexSecurityError(
              `Claim ${ref.id} revision ${ref.revision} is not currently ${policy === "reviewed" ? "approved" : "recorded"}.`,
            );
          if (selected.has(key(ref))) return;
          const record = find(ref)!;
          selected.set(key(ref), record);
          for (const dependency of record.dependencies) visit(dependency);
        };
        for (const ref of refs) visit(ref);
        return [...selected.values()].map((record) => structuredClone(record));
      });
    },
  };
}

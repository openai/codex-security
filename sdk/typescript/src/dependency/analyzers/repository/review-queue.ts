import {
  bindReceiptSelections,
  dependencyReceiptSelectionSchema,
  type BoundReceiptSelection,
} from "../../graph-evidence.js";
import { z } from "zod";
import type { DependencyAttemptStore } from "../../attempt-store.js";
import { readDependencySourceCitation } from "../../source-identity.js";
import { CodexSecurityError, errorMessage } from "../../../errors.js";
import type { Claim, Decision } from "./claims.js";
import type { DependencyEvidenceRecord } from "../../evidence-sources.js";

const text = z.string().trim().min(1);
export const dependencyPremiseRefSchema = z.strictObject({
  id: text,
  revision: z.number().int().positive(),
  hash: z.string().regex(/^[a-f0-9]{64}$/u),
});
export type PremiseRef = z.infer<typeof dependencyPremiseRefSchema>;
export function reference({ id, revision, hash }: PremiseRef) {
  return { id, revision, hash };
}
export const premiseKey = ({ id, revision, hash }: PremiseRef) =>
  "claim:" + JSON.stringify([id, revision, hash]);

const REVIEW_BATCH_SIZE = 100;
const MAX_REVIEW_BATCHES = 16;

const sourceRange = z.strictObject({
  path: text,
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
});
const submission = z.strictObject({
  id: text.describe(
    "A stable name for this premise, unique within the investigation.",
  ),
  expectedRevision: z
    .number()
    .int()
    .nonnegative()
    .describe(
      "Use 0 for a new premise or its last revision when correcting it.",
    ),
  scope: text,
  statement: text,
  sources: z.array(sourceRange),
  receiptIds: z.array(text),
  receiptSelections: z.array(dependencyReceiptSelectionSchema).optional(),
  dependencies: z.array(dependencyPremiseRefSchema),
});
export const submitPremisesSchema = z.strictObject({
  claims: z.array(submission).min(1),
});
export type Premise = {
  kind: "premise";
  scope: string;
  statement: string;
  sources: Awaited<ReturnType<typeof readDependencySourceCitation>>[];
  receiptIds: string[];
  boundReceipts?: BoundReceiptSelection[];
  dependencies: PremiseRef[];
};

export function claimFinding(value: Claim["value"]) {
  if (value.kind === "use") return value.use;
  if (value.kind === "disposition") return value.disposition;
}

export function claimDependencies({ value }: Claim): PremiseRef[] {
  return value.kind === "premise"
    ? value.dependencies
    : (claimFinding(value)?.premises ?? []);
}

/** An approval is reusable only while the exact claim and all its prerequisites remain current. */
export function currentApproval(
  store: DependencyAttemptStore,
  ref: PremiseRef,
  cache = new Map<string, Decision | undefined>(),
): Decision | undefined {
  const key = premiseKey(ref);
  if (cache.has(key)) return cache.get(key);
  // An unresolved cycle cannot establish an independent premise.
  cache.set(key, undefined);
  const latest = store.claim<Claim["value"]>(ref.id);
  const historical = latest?.revision !== ref.revision;
  const decision = historical
    ? ref.id.startsWith("assessment:") &&
      store.get<Decision>("retained-use", ref.id)
    : store.get<Decision>("dependency-review", ref.id);
  if (
    !decision ||
    !decision.approved ||
    decision.revision !== ref.revision ||
    decision.hash !== ref.hash
  )
    return;
  const current = historical
    ? store.claim<Claim["value"]>(ref.id, ref.revision)
    : latest;
  if (
    current?.hash === ref.hash &&
    claimDependencies(current).every((dep) =>
      currentApproval(store, dep, cache),
    )
  ) {
    cache.set(key, decision);
    return decision;
  }
}

/** A replacement in review cannot withdraw a still-supported approved use. */
export function retainedUse(store: DependencyAttemptStore, id: string) {
  const previous =
    id.startsWith("assessment:") && store.get<Decision>("retained-use", id);
  if (previous && currentApproval(store, previous)) {
    return store.claim<Claim["value"]>(id, previous.revision);
  }
}

export function assertReviewedPremises(
  store: DependencyAttemptStore,
  refs: readonly PremiseRef[],
  cache = new Map<string, Decision | undefined>(),
) {
  for (const ref of refs) {
    if (!ref.id.startsWith("premise:") || !currentApproval(store, ref, cache)) {
      throw new CodexSecurityError(
        "An exact, currently approved premise is required: " + ref.id,
      );
    }
  }
}

export function createPremiseQueue(options: {
  store: DependencyAttemptStore;
  directory: string;
  revision: string | undefined;
  signal: AbortSignal;
  records: ReadonlyMap<string, DependencyEvidenceRecord>;
  review: (
    claims: Claim[],
    reject: (claim: Claim, reason: string) => void,
  ) => Promise<void>;
}) {
  const { store, directory, signal } = options;
  const pending = new Map<string, Claim>();
  const failures = new Map<string, string>();
  const running = new Map<string, string>();
  const batches = new Set<Promise<void>>();
  let scheduled: NodeJS.Immediate | undefined;
  function schedule() {
    if (scheduled) clearImmediate(scheduled);
    scheduled = undefined;
    while (pending.size && batches.size < MAX_REVIEW_BATCHES) {
      const batch: Claim[] = [];
      for (const [id, claim] of pending) {
        // A correction replaces a queued revision or follows its in-flight review.
        if (running.has(id)) continue;
        pending.delete(id);
        running.set(id, premiseKey(claim));
        batch.push(claim);
        if (batch.length === REVIEW_BATCH_SIZE) break;
      }
      if (!batch.length) return;
      const task = Promise.resolve()
        .then(() =>
          options.review(batch, (claim, reason) =>
            failures.set(premiseKey(claim), reason),
          ),
        )
        .catch((error: unknown) => {
          for (const c of batch)
            failures.set(premiseKey(c), errorMessage(error));
        })
        .finally(() => {
          batches.delete(task);
          for (const c of batch) running.delete(c.id);
          schedule();
        });
      batches.add(task);
    }
  }
  async function drain(ids?: string[]) {
    schedule();
    while (
      batches.size &&
      (!ids || ids.some((id) => pending.has(id) || running.has(id)))
    )
      await Promise.race(batches);
  }
  function status(c: Claim) {
    const base = { ...reference(c), payload: c.value };
    const decision = currentApproval(store, c);
    if (decision) return { ...base, state: "approved", decision };
    const previous = retainedUse(store, c.id);
    const pending = {
      ...base,
      ...(previous && { retainedUse: reference(previous) }),
    };
    const reason = failures.get(premiseKey(c));
    if (reason !== undefined) return { ...pending, state: "rejected", reason };
    const reviewed = store.get<Decision>("dependency-review", c.id);
    if (
      reviewed?.approved &&
      reviewed.hash === c.hash &&
      reviewed.revision === c.revision
    )
      return {
        ...pending,
        state: "stale",
        reason:
          "A reviewed premise changed; submit a corrected claim with current references.",
      };
    return { ...pending, state: "pending" };
  }
  function enqueue(stored: Claim[]) {
    for (const c of stored) {
      const key = premiseKey(c);
      if (running.get(c.id) !== key && !currentApproval(store, c)) {
        failures.delete(key);
        pending.set(c.id, c);
      }
    }
    // Independent submissions arriving in the same turn may share a reviewer.
    scheduled ??= setImmediate(schedule);
    return stored.map(status);
  }
  return {
    drain,
    enqueue,
    status,
    async submit(input: unknown) {
      const { claims } = submitPremisesSchema.parse(input);
      const { revision } = options;
      if (!revision)
        throw new CodexSecurityError("A pinned checkout revision is required.");
      const values = await Promise.all(
        claims.map(async (c) => {
          const {
            id,
            expectedRevision,
            sources,
            receiptIds,
            receiptSelections,
            dependencies,
            statement,
            scope,
          } = c;
          if (
            !sources.length &&
            !receiptIds.length &&
            !receiptSelections?.length &&
            !dependencies.length
          )
            throw new CodexSecurityError(
              "A premise must cite its supporting evidence.",
            );
          if (receiptIds.some((r) => !options.records.has(r)))
            throw new CodexSecurityError("Unknown premise receipt.");
          const boundReceipts = bindReceiptSelections(
            receiptSelections ?? [],
            (id) => options.records.get(id),
          );
          const verified = await Promise.all(
            sources.map((s) =>
              readDependencySourceCitation(directory, revision, s, signal),
            ),
          );
          return {
            id: "premise:" + id.replace(/^premise:/u, ""),
            expectedRevision,
            value: {
              kind: "premise",
              scope,
              statement,
              sources: verified,
              receiptIds,
              ...(boundReceipts.length && { boundReceipts }),
              dependencies,
            } satisfies Premise,
          };
        }),
      );
      signal.throwIfAborted();
      const stored = store.transaction(() =>
        values.map(({ id, expectedRevision, value }) => {
          assertReviewedPremises(store, value.dependencies);
          if (value.dependencies.some((d) => d.id === id))
            throw new CodexSecurityError("A claim cannot depend on itself.");
          return store.recordClaim(id, value, expectedRevision);
        }),
      );
      return enqueue(stored);
    },
    async query(input: unknown) {
      const { ids, wait } = z
        .strictObject({
          ids: z.array(text).optional(),
          wait: z.boolean().optional(),
        })
        .parse(input);
      if (wait) await drain(ids);
      return store
        .claims<Claim["value"]>()
        .filter(
          (c) =>
            (c.value.kind === "premise" ||
              c.value.kind === "disposition" ||
              c.id.startsWith("assessment:")) &&
            (!ids || ids.includes(c.id)),
        )
        .map(status);
    },
  };
}

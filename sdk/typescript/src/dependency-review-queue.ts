import { z } from "zod";
import type { DependencyAttemptStore } from "./dependency-attempt-store.js";
import { dependencyRecordHash } from "./dependency-attempt-store.js";
import { readDependencySourceCitation } from "./dependency-source-identity.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import type { Claim, Decision } from "./dependency-reviewed-claims.js";
import type { DependencyEvidenceRecord } from "./dependency-evidence-sources.js";

const text = z.string().trim().min(1);
export const dependencyPremiseRefSchema = z.strictObject({
  id: text,
  revision: z.number().int().positive(),
  hash: z.string().regex(/^[a-f0-9]{64}$/u),
});
export type PremiseRef = z.infer<typeof dependencyPremiseRefSchema>;
export const premiseKey = ({ id, revision, hash }: PremiseRef) =>
  "claim:" + JSON.stringify([id, revision, hash]);

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
  dependencies: PremiseRef[];
};

export function claimInputs(claim: Claim) {
  const v = claim.value;
  const sources =
    v.kind === "premise" ? v.sources : v.kind === "use" ? v.use.evidence : [];
  const receiptIds =
    v.kind === "premise"
      ? v.receiptIds
      : v.kind === "use"
        ? v.use.observations.map((r) => r.sha256)
        : [];
  const dependencies =
    v.kind === "premise"
      ? v.dependencies
      : v.kind === "use"
        ? (v.use.premises ?? [])
        : [];
  return {
    sources,
    sourceIds: sources.map(dependencyRecordHash),
    receiptIds,
    dependencies,
  };
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
  const current = store.claim<Claim["value"]>(ref.id);
  const decision = store.get<Decision>("dependency-review", ref.id);
  if (
    !current ||
    current.revision !== ref.revision ||
    current.hash !== ref.hash ||
    !decision?.approved ||
    decision.revision !== ref.revision ||
    decision.hash !== ref.hash
  )
    return;
  if (
    claimInputs(current).dependencies.every((dep) =>
      currentApproval(store, dep, cache),
    )
  ) {
    cache.set(key, decision);
    return decision;
  }
}

export function assertReviewedPremises(
  store: DependencyAttemptStore,
  refs: readonly PremiseRef[],
) {
  const cache = new Map<string, Decision | undefined>();
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
  review: (claims: Claim[]) => Promise<void>;
}) {
  const { store, directory, signal } = options;
  const pending = new Map<string, Claim>();
  const failures = new Map<string, string>();
  let active: Promise<void> | undefined;
  const ref = (c: Claim) => ({ id: c.id, revision: c.revision, hash: c.hash });
  function schedule() {
    if (active) return;
    active = Promise.resolve()
      .then(async () => {
        while (pending.size) {
          const batch = [...pending.values()];
          pending.clear();
          try {
            await options.review(batch);
          } catch (error) {
            for (const c of batch)
              failures.set(premiseKey(c), errorMessage(error));
          }
        }
      })
      .finally(() => {
        active = undefined;
        if (pending.size) schedule();
      });
  }
  async function drain() {
    while (active) await active;
  }
  function status(c: Claim) {
    const key = premiseKey(c);
    const decision = currentApproval(store, c);
    const reviewed = store.get<Decision>("dependency-review", c.id);
    const stale =
      !decision &&
      reviewed?.approved &&
      reviewed.hash === c.hash &&
      reviewed.revision === c.revision;
    return {
      ...ref(c),
      payload: c.value,
      state: decision
        ? "approved"
        : failures.has(key)
          ? "rejected"
          : stale
            ? "stale"
            : "pending",
      ...(stale && {
        reason:
          "A reviewed premise changed; submit a corrected claim with current references.",
      }),
      ...(decision && { decision }),
      ...(failures.has(key) && !decision && { reason: failures.get(key) }),
    };
  }
  function enqueue(stored: Claim[]) {
    for (const c of stored) {
      const key = premiseKey(c);
      if (!currentApproval(store, c)) {
        failures.delete(key);
        pending.set(key, c);
      }
    }
    schedule();
    return stored.map(status);
  }
  return {
    drain,
    enqueue,
    async submit(input: unknown) {
      const { claims } = submitPremisesSchema.parse(input);
      const values = await Promise.all(
        claims.map(async (c) => {
          const {
            id,
            expectedRevision,
            sources,
            receiptIds,
            dependencies,
            statement,
            scope,
          } = c;
          if (!options.revision)
            throw new CodexSecurityError(
              "A pinned checkout revision is required.",
            );
          if (!sources.length && !receiptIds.length && !dependencies.length)
            throw new CodexSecurityError(
              "A premise must cite its supporting evidence.",
            );
          if (receiptIds.some((r) => !options.records.has(r)))
            throw new CodexSecurityError("Unknown premise receipt.");
          const verified = await Promise.all(
            sources.map((s) =>
              readDependencySourceCitation(
                directory,
                options.revision!,
                s,
                signal,
              ),
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
      if (wait) await drain();
      return store
        .claims<Claim["value"]>()
        .filter(
          (c) =>
            (c.value.kind === "premise" || c.id.startsWith("assessment:")) &&
            (!ids || ids.includes(c.id)),
        )
        .map(status);
    },
    approved(refs: PremiseRef[]) {
      const closure = new Map<string, Claim>();
      for (const ref of refs) {
        const visit = (r: PremiseRef) => {
          if (closure.has(premiseKey(r))) return;
          assertReviewedPremises(store, [r]);
          const c = store.claim<Claim["value"]>(r.id, r.revision)!;
          closure.set(premiseKey(r), c);
          claimInputs(c).dependencies.forEach(visit);
        };
        visit(ref);
      }
      return [...closure.values()];
    },
  };
}

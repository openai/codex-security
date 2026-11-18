import {
  DependencyAttemptStore,
  dependencyRecordHash,
} from "./dependency-attempt-store.js";
import {
  type DependencyClaimRecord,
  stackClaimContent,
} from "./dependency-stack-claims.js";
import type { StackManifest } from "./dependency-stack-packet.js";
import { CodexSecurityError } from "./errors.js";
import { canonicalJson } from "./record.js";
import type { RuntimeDatabase } from "./runtime.js";

/** Convert an original single-investigator ledger in the transaction that installs the new schema. */
function migrateStackAttempt(
  db: RuntimeDatabase,
  store: DependencyAttemptStore,
) {
  db.exec(`
    INSERT INTO records (kind, id, value)
    SELECT CASE kind WHEN 'operation' THEN 'stack-v1-operation'
                     WHEN 'stack-assessment' THEN 'stack-v1-assessment'
                     ELSE kind END, id, value
    FROM attempt_records ORDER BY rowid;
  `);
  const active = store.get<{ manifest: StackManifest; fingerprint: string }>(
    "manifest",
    "active",
  );
  if (!active || active.fingerprint !== dependencyRecordHash(active.manifest))
    throw new CodexSecurityError(
      "Expected an initialized stack investigation.",
    );
  const { manifest } = active;
  const context = dependencyRecordHash({
    cve: manifest.cve,
    inputDigest: manifest.inputDigest,
    target: manifest.target,
  });
  const old = store.get<{ contextHash: string; policy: string }>(
    "claims",
    "context",
  );
  if (old && (old.contextHash !== context || old.policy !== "single_agent"))
    throw new CodexSecurityError(
      "The database belongs to a different investigation policy.",
    );
  store.bindIdentity(manifest);
  const select = db.prepare(
    "SELECT hash, value FROM claim_revisions WHERE id = ? AND revision = ?",
  );
  const insert = db.prepare(
    "INSERT INTO claims (id, revision, hash, value) VALUES (?, ?, ?, ?)",
  );
  const revisions = db.prepare(
    "SELECT id, revision FROM claim_revisions ORDER BY rowid",
  );
  try {
    for (const { id, revision } of revisions.all() as {
      id: string;
      revision: number;
    }[]) {
      const [row] = select.all(id, revision) as {
        hash: string;
        value: string;
      }[];
      const record = JSON.parse(row!.value) as DependencyClaimRecord & {
        contextHash: string;
      };
      const value = stackClaimContent(context, record);
      if (
        record.id !== id ||
        record.revision !== revision ||
        record.contextHash !== context ||
        record.hash !== row!.hash ||
        dependencyRecordHash(value) !== row!.hash
      )
        throw new CodexSecurityError(
          "Invalid original stack claim revision for " + id,
        );
      insert.all(id, revision, record.hash, canonicalJson(value));
      store.set("stack-claim-receipts", record.hash, record.receipts);
    }
  } finally {
    select.finalize?.();
    insert.finalize?.();
    revisions.finalize?.();
  }
  // Keep the original rows for inspection. An older process already in flight
  // must fail its write rather than silently update a retired table.
  db.exec(`
    ALTER TABLE attempt_records RENAME TO original_attempt_records;
    ALTER TABLE claim_revisions RENAME TO original_claim_revisions;
  `);
  store.set("stack-migration", "pending", true);
}

export function openStackAttempt(path: string, create = false) {
  return new DependencyAttemptStore(path, { create, migrateStackAttempt });
}

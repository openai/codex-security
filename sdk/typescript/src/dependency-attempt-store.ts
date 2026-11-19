import { hash } from "node:crypto";
import { closeSync, lstatSync, openSync } from "node:fs";
import { resolve } from "node:path";
import { CodexSecurityError } from "./errors.js";
import { canonicalJson } from "./record.js";
import { sqliteDatabaseOpener, type RuntimeDatabase } from "./runtime.js";

const applicationId = 0x43534941; // CSIA (Codex Security Investigation Attempt)
const schemaVersion = 1;
type Row = Record<string, string | number>;
type SyncCallback<T> = (() => T) &
  ([Extract<T, PromiseLike<unknown>>] extends [never] ? unknown : never);

function callSynchronously<T>(fn: () => T): T {
  const message = "Investigation database callbacks must be synchronous.";
  if (Object.prototype.toString.call(fn) === "[object AsyncFunction]")
    throw new CodexSecurityError(message);
  const result = fn();
  if (typeof (result as { then?: unknown } | null)?.then === "function") {
    // A JavaScript caller can return a rejected promise from an ordinary function.
    // The synchronous error reports the contract violation and the transaction rolls back.
    void Promise.resolve(result).catch(() => {});
    throw new CodexSecurityError(message);
  }
  return result;
}

function encode(value: unknown): string {
  const json = canonicalJson(value);
  if (json === undefined)
    throw new CodexSecurityError("Investigation records must be JSON values.");
  return json;
}

export function dependencyRecordHash(value: unknown): string {
  return hash("sha256", encode(value));
}

export interface StoredClaim<T> {
  id: string;
  revision: number;
  hash: string;
  value: T;
}

function readClaim<T>(row: Row): StoredClaim<T> {
  return {
    id: String(row["id"]),
    revision: Number(row["revision"]),
    hash: String(row["hash"]),
    value: JSON.parse(String(row["value"])) as T,
  };
}

/** Synchronous transactions keep compare-and-swap and retry receipts atomic across processes. */
export class DependencyAttemptStore {
  private readonly db: RuntimeDatabase;
  private readonly statements = new Map<
    string,
    ReturnType<RuntimeDatabase["prepare"]>
  >();
  private depth = 0;

  constructor(path: string, { create = true }: { create?: boolean } = {}) {
    let empty = true;
    if (path !== ":memory:") {
      path = resolve(path);
      if (create) {
        try {
          closeSync(openSync(path, "wx", 0o600));
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        }
      }
      const file = lstatSync(path);
      if (!file.isFile())
        throw new CodexSecurityError(
          "Investigation state must be a regular file.",
        );
      empty = file.size === 0;
    }
    this.db = sqliteDatabaseOpener()(path);
    try {
      this.db.exec("PRAGMA busy_timeout = 5000");
      this.transaction(() => {
        const app = this.rows("PRAGMA application_id")[0]?.["application_id"];
        const version = this.rows("PRAGMA user_version")[0]?.["user_version"];
        if (app === applicationId && version === schemaVersion) return;
        if (
          !create ||
          !empty ||
          app !== 0 ||
          version !== 0 ||
          this.rows("SELECT 1 FROM sqlite_schema LIMIT 1").length
        )
          throw new CodexSecurityError(
            "Unrecognized investigation database or schema version.",
          );
        this.db.exec(`
          CREATE TABLE attempt_identity (slot INTEGER PRIMARY KEY CHECK(slot = 1), value TEXT NOT NULL);
          CREATE TABLE records (kind TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (kind, id));
          CREATE TABLE operations (id TEXT PRIMARY KEY, digest TEXT NOT NULL, result TEXT NOT NULL);
          CREATE TABLE claims (id TEXT NOT NULL, revision INTEGER NOT NULL, hash TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (id, revision));
          PRAGMA application_id = ${applicationId};
          PRAGMA user_version = ${schemaVersion};
        `);
      });
    } catch (error) {
      this.close();
      throw error;
    }
  }

  private rows(sql: string, ...parameters: (string | number)[]): Row[] {
    let statement = this.statements.get(sql);
    if (!statement) {
      statement = this.db.prepare(sql);
      this.statements.set(sql, statement);
    }
    return statement.all(...parameters) as Row[];
  }

  private withTransaction<T>(begin: string, fn: () => T): T {
    const nested = this.depth > 0;
    const savepoint = `attempt_${this.depth}`;
    this.db.exec(nested ? `SAVEPOINT ${savepoint}` : begin);
    this.depth++;
    try {
      const result = fn();
      this.db.exec(nested ? `RELEASE ${savepoint}` : "COMMIT");
      return result;
    } catch (error) {
      this.db.exec(
        nested ? `ROLLBACK TO ${savepoint}; RELEASE ${savepoint}` : "ROLLBACK",
      );
      throw error;
    } finally {
      this.depth--;
    }
  }

  transaction<T>(fn: SyncCallback<T>): T {
    return this.withTransaction("BEGIN IMMEDIATE", () => callSynchronously(fn));
  }

  read<T>(fn: SyncCallback<T>): T {
    return this.depth
      ? callSynchronously(fn)
      : this.withTransaction("BEGIN", () => callSynchronously(fn));
  }

  bindIdentity(identity: unknown): void {
    const value = encode(identity);
    this.transaction(() => {
      const row = this.rows(
        "SELECT value FROM attempt_identity WHERE slot = 1",
      )[0];
      if (!row) this.rows("INSERT INTO attempt_identity VALUES (1, ?)", value);
      else if (row["value"] !== value)
        throw new CodexSecurityError(
          "Database belongs to a different investigation attempt.",
        );
    });
  }

  get<T>(kind: string, id: string): T | undefined {
    const row = this.rows(
      "SELECT value FROM records WHERE kind = ? AND id = ?",
      kind,
      id,
    )[0];
    return row && JSON.parse(String(row["value"]));
  }

  set(kind: string, id: string, value: unknown): void {
    this.rows(
      "INSERT INTO records (kind, id, value) VALUES (?, ?, ?) ON CONFLICT(kind, id) DO UPDATE SET value = excluded.value",
      kind,
      id,
      encode(value),
    );
  }

  keys(kind: string): string[] {
    return this.rows(
      "SELECT id FROM records WHERE kind = ? ORDER BY rowid",
      kind,
    ).map((row) => String(row["id"]));
  }

  size(kind: string): number {
    return Number(
      this.rows("SELECT COUNT(*) AS n FROM records WHERE kind = ?", kind)[0]![
        "n"
      ],
    );
  }

  values<T>(kind: string): T[] {
    return this.rows(
      "SELECT value FROM records WHERE kind = ? ORDER BY rowid",
      kind,
    ).map((row) => JSON.parse(String(row["value"])));
  }

  operation<T>(
    operationId: string,
    command: string,
    input: unknown,
  ): { result: T } | undefined {
    const receipt = this.rows(
      "SELECT digest, result FROM operations WHERE id = ?",
      operationId,
    )[0];
    if (!receipt) return;
    if (receipt["digest"] !== dependencyRecordHash({ command, input }))
      throw new CodexSecurityError(
        "Operation ID already belongs to a different request.",
      );
    return { result: JSON.parse(String(receipt["result"])) as T };
  }

  mutate<T>(
    operationId: string | undefined,
    command: string,
    input: unknown,
    write: SyncCallback<T>,
  ): T {
    return this.withTransaction("BEGIN IMMEDIATE", () => {
      if (operationId === undefined) return callSynchronously(write);
      const receipt = this.operation<T>(operationId, command, input);
      if (receipt) return receipt.result;
      const digest = dependencyRecordHash({ command, input });
      const result = callSynchronously(write);
      this.rows(
        "INSERT INTO operations VALUES (?, ?, ?)",
        operationId,
        digest,
        encode(result),
      );
      return result;
    });
  }

  claim<T>(id: string, revision?: number): StoredClaim<T> | undefined {
    const rows =
      revision === undefined
        ? this.rows(
            "SELECT * FROM claims WHERE id = ? ORDER BY revision DESC LIMIT 1",
            id,
          )
        : this.rows(
            "SELECT * FROM claims WHERE id = ? AND revision = ?",
            id,
            revision,
          );
    return rows[0] && readClaim<T>(rows[0]);
  }

  claims<T>(): StoredClaim<T>[] {
    return this.rows(
      "SELECT c.* FROM claims c JOIN (SELECT id, MAX(revision) AS revision FROM claims GROUP BY id) latest USING (id, revision) ORDER BY c.id",
    ).map(readClaim<T>);
  }

  recordClaim<T>(
    id: string,
    value: T,
    expectedRevision?: number,
  ): StoredClaim<T> {
    const json = encode(value);
    const digest = hash("sha256", json);
    return this.transaction(() => {
      const current = this.claim<T>(id);
      const revision = current?.revision ?? 0;
      if (expectedRevision !== undefined && expectedRevision !== revision)
        throw new CodexSecurityError(
          `Claim ${id} expected revision ${expectedRevision}, current revision is ${revision}.`,
        );
      if (current?.hash === digest) return current;
      if (current && expectedRevision === undefined)
        throw new CodexSecurityError(
          `Replacing claim ${id} requires its expected revision.`,
        );
      this.rows(
        "INSERT INTO claims VALUES (?, ?, ?, ?)",
        id,
        revision + 1,
        digest,
        json,
      );
      return {
        id,
        revision: revision + 1,
        hash: digest,
        value: JSON.parse(json),
      };
    });
  }

  close(): void {
    for (const statement of this.statements.values()) statement.finalize?.();
    this.statements.clear();
    this.db.close();
  }
}

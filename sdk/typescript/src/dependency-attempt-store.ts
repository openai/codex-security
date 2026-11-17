import { closeSync, lstatSync, openSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { CodexSecurityError } from "./errors.js";

type Parameter = string | number | null;
type Row = Record<string, string | number | null>;
interface Statement {
  run(...parameters: Parameter[]): { changes: number | bigint };
  get(...parameters: Parameter[]): Row | null | undefined;
  all(...parameters: Parameter[]): Row[];
}
interface Database {
  prepare(sql: string): Statement;
  exec(sql: string): void;
  close(): void;
}

const applicationId = 0x43534558; // CSEX
const schemaVersion = 1;

function preparePath(path: string, create: boolean): boolean {
  if (path === ":memory:") return true;
  if (create) {
    try {
      closeSync(openSync(path, "wx", 0o600));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }
  const file = lstatSync(path);
  if (!file.isFile())
    throw new CodexSecurityError("Investigation state must be a regular file.");
  return file.size === 0;
}

/** One investigation attempt, shared by the commands operating on it. */
export class DependencyAttemptStore {
  private readonly db: Database;
  readonly reviewOwner = randomUUID();
  private readonly statements = new Map<string, Statement>();
  private depth = 0;
  private commitCallbacks: (() => void)[] = [];
  private closed = false;

  constructor(path: string, { create = true }: { create?: boolean } = {}) {
    const empty = preparePath(path, create);
    const require = createRequire(import.meta.url);
    const Driver = (
      process.versions["bun"]
        ? require("bun:sqlite").Database
        : require("node:sqlite").DatabaseSync
    ) as new (path: string) => Database;
    this.db = new Driver(path);
    try {
      this.db.exec("PRAGMA busy_timeout = 5000");
      this.transaction(() => {
        const app = this.statement("PRAGMA application_id").get()?.[
          "application_id"
        ];
        const version = this.statement("PRAGMA user_version").get()?.[
          "user_version"
        ];
        if (app === applicationId && version === schemaVersion) return;
        if (
          !create ||
          !empty ||
          app !== 0 ||
          version !== 0 ||
          this.statement("SELECT 1 FROM sqlite_schema LIMIT 1").get()
        ) {
          throw new CodexSecurityError(
            "Unrecognized investigation state database or schema version.",
          );
        }
        this.db.exec(`
          CREATE TABLE attempt_records (
            kind TEXT NOT NULL,
            id TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (kind, id)
          );
          CREATE TABLE claim_revisions (
            id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            hash TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (id, revision)
          );
          CREATE TABLE claim_dependencies (
            premise_id TEXT NOT NULL,
            premise_revision INTEGER NOT NULL,
            premise_hash TEXT NOT NULL,
            dependent_id TEXT NOT NULL,
            dependent_revision INTEGER NOT NULL,
            PRIMARY KEY (premise_id, premise_revision, premise_hash, dependent_id, dependent_revision)
          ) WITHOUT ROWID;
          CREATE TABLE claim_review_leases (
            id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            hash TEXT NOT NULL,
            pid INTEGER NOT NULL,
            owner TEXT NOT NULL,
            PRIMARY KEY (id, revision)
          );
          PRAGMA application_id = ${applicationId};
          PRAGMA user_version = ${schemaVersion};
        `);
      });
      // Reviews are performed by live processes. Reopen may follow a process exit
      // which left an otherwise valid pending claim without its reviewer.
      for (const row of this.statement(
        "SELECT DISTINCT pid FROM claim_review_leases",
      ).all()) {
        const pid = row["pid"] as number;
        try {
          process.kill(pid, 0);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ESRCH") continue;
          this.statement("DELETE FROM claim_review_leases WHERE pid = ?").run(
            pid,
          );
        }
      }
    } catch (error) {
      this.db.close();
      throw error;
    }
  }

  statement(sql: string): Statement {
    let statement = this.statements.get(sql);
    if (!statement) {
      statement = this.db.prepare(sql);
      this.statements.set(sql, statement);
    }
    return statement;
  }

  /** A synchronous writer may compose a batch from several smaller mutations. */
  transaction<T>(operation: () => T): T {
    return this.withTransaction("BEGIN IMMEDIATE", operation);
  }

  read<T>(operation: () => T): T {
    if (this.depth > 0) return operation();
    return this.withTransaction("BEGIN", operation);
  }

  private withTransaction<T>(begin: string, operation: () => T): T {
    const depth = this.depth;
    const savepoint = `attempt_${depth}`;
    this.db.exec(depth === 0 ? begin : `SAVEPOINT ${savepoint}`);
    this.depth++;
    const callbackCount = this.commitCallbacks.length;
    let result: T;
    try {
      result = operation();
      this.db.exec(depth === 0 ? "COMMIT" : `RELEASE ${savepoint}`);
    } catch (error) {
      this.commitCallbacks.length = callbackCount;
      this.db.exec(
        depth === 0
          ? "ROLLBACK"
          : `ROLLBACK TO ${savepoint}; RELEASE ${savepoint}`,
      );
      throw error;
    } finally {
      this.depth--;
    }
    if (depth === 0) {
      const callbacks = this.commitCallbacks;
      this.commitCallbacks = [];
      for (const callback of callbacks) callback();
    }
    return result;
  }

  afterCommit(callback: () => void): void {
    if (this.depth === 0) callback();
    else this.commitCallbacks.push(callback);
  }

  get<T>(kind: string, id: string): T | undefined {
    const row = this.statement(
      "SELECT value FROM attempt_records WHERE kind = ? AND id = ?",
    ).get(kind, id);
    return row ? (JSON.parse(row["value"] as string) as T) : undefined;
  }

  set(kind: string, id: string, value: unknown): void {
    const json = JSON.stringify(value);
    if (json === undefined)
      throw new CodexSecurityError("Attempt records must be JSON values.");
    this.statement(
      "INSERT INTO attempt_records (kind, id, value) VALUES (?, ?, ?) ON CONFLICT(kind, id) DO UPDATE SET value = excluded.value",
    ).run(kind, id, json);
  }

  values<T>(kind: string): T[] {
    return this.statement(
      "SELECT value FROM attempt_records WHERE kind = ? ORDER BY rowid",
    )
      .all(kind)
      .map((row) => JSON.parse(row["value"] as string) as T);
  }

  keys(kind: string): string[] {
    return this.statement(
      "SELECT id FROM attempt_records WHERE kind = ? ORDER BY rowid",
    )
      .all(kind)
      .map((row) => row["id"] as string);
  }

  size(kind: string): number {
    return this.statement(
      "SELECT COUNT(*) AS size FROM attempt_records WHERE kind = ?",
    ).get(kind)!["size"] as number;
  }

  close(): void {
    if (this.closed) return;
    try {
      this.statement("DELETE FROM claim_review_leases WHERE owner = ?").run(
        this.reviewOwner,
      );
    } finally {
      this.db.close();
      this.statements.clear();
      this.closed = true;
    }
  }
}

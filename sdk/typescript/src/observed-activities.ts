import { createHash } from "node:crypto";
import { lstat, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson, isRecord } from "./record.js";
import { sqliteDatabaseOpener, type RuntimeDatabase } from "./runtime.js";
import type { ScanActivity } from "./scan-activity.js";
import { parseJson } from "./value.js";

export interface ObservedActivity {
  eventKey: string;
  paths: string[];
}

export type LiveActivityPaths = Pick<
  ScanActivity,
  "id" | "kind" | "status" | "paths"
>;

// SDK item IDs alone are neither stable across turns nor shared with native rollouts.
export function observedEventKey(
  threadId: string,
  event: Readonly<Record<string, unknown>>,
): string | undefined {
  try {
    return createHash("sha256")
      .update(canonicalJson([threadId, event]))
      .digest("hex");
  } catch {
    // Parsed rollout JSON can nest more deeply than JSON.stringify accepts.
    return undefined;
  }
}

async function activityDatabase<T>(
  codexHome: string,
  write: boolean,
  operation: (db: RuntimeDatabase) => T,
): Promise<T | undefined> {
  try {
    const directory = join(codexHome, "activity-paths");
    if (write) await mkdir(directory, { mode: 0o700, recursive: true });
    if (!(await lstat(directory)).isDirectory()) return;
    const path = join(directory, "observations.sqlite3");
    const metadata = await lstat(path).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
    });
    if (metadata ? !metadata.isFile() || metadata.nlink !== 1 : !write) return;
    const db = sqliteDatabaseOpener(write ? "read-write" : "read-existing")(
      path,
    );
    try {
      if (write) {
        // Other local scans can add independent observations to the same database.
        db.exec("PRAGMA busy_timeout = 1000");
        db.exec(`CREATE TABLE IF NOT EXISTS observed_paths (
          scan_id TEXT NOT NULL, event_key TEXT NOT NULL, paths TEXT NOT NULL,
          PRIMARY KEY (scan_id, event_key)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS live_paths (
          scan_id TEXT NOT NULL, thread_id TEXT NOT NULL, occurrence TEXT NOT NULL,
          activity_id TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
          paths TEXT NOT NULL, UNIQUE (scan_id, thread_id, occurrence)
        )`);
      }
      return operation(db);
    } finally {
      db.close();
    }
  } catch {
    // Missing or unavailable optional display metadata must not interrupt a scan or replay.
    return;
  }
}

function rows(db: RuntimeDatabase, sql: string, ...parameters: string[]) {
  const statement = db.prepare(sql);
  try {
    return statement.all(...parameters);
  } finally {
    statement.finalize?.();
  }
}

function storedPaths(json: unknown): string[] | undefined {
  if (typeof json !== "string") return;
  const paths = parseJson(() => json);
  if (
    Array.isArray(paths) &&
    paths.length &&
    paths.every((path) => typeof path === "string")
  )
    return paths;
}

export async function saveObservedActivity(
  codexHome: string,
  scanId: string,
  { eventKey, paths }: ObservedActivity,
): Promise<void> {
  if (!paths.length) return;
  await activityDatabase(codexHome, true, (db) =>
    rows(
      db,
      "INSERT OR IGNORE INTO observed_paths VALUES (?, ?, ?)",
      scanId,
      eventKey,
      JSON.stringify(paths),
    ),
  );
}

export async function readObservedActivities(
  codexHome: string,
  scanId: string,
): Promise<ObservedActivity[]> {
  return (
    (await activityDatabase(codexHome, false, (db) => {
      const records: ObservedActivity[] = [];
      for (const row of rows(
        db,
        "SELECT event_key, paths FROM observed_paths WHERE scan_id = ?",
        scanId,
      )) {
        if (!isRecord(row) || typeof row["event_key"] !== "string") continue;
        const paths = storedPaths(row["paths"]);
        if (paths) records.push({ eventKey: row["event_key"], paths });
      }
      return records;
    })) ?? []
  );
}

export async function saveLiveActivityPaths(
  codexHome: string,
  scanId: string,
  threadId: string,
  occurrenceKey: string,
  activity: LiveActivityPaths,
): Promise<void> {
  const { id, kind, status, paths } = activity;
  if (!paths.length) return;
  await activityDatabase(codexHome, true, (db) =>
    rows(
      db,
      "INSERT OR IGNORE INTO live_paths VALUES (?, ?, ?, ?, ?, ?, ?)",
      scanId,
      threadId,
      occurrenceKey,
      id,
      kind,
      status,
      JSON.stringify(paths),
    ),
  );
}

export async function readLiveActivityPaths(codexHome: string, scanId: string) {
  return (
    (await activityDatabase(codexHome, false, (db) => {
      const records: {
        threadId: string;
        occurrenceKey: string;
        activity: LiveActivityPaths;
      }[] = [];
      for (const row of rows(
        db,
        "SELECT thread_id, occurrence, activity_id, kind, status, paths FROM live_paths WHERE scan_id = ? ORDER BY rowid",
        scanId,
      )) {
        if (!isRecord(row)) continue;
        const {
          thread_id: threadId,
          occurrence: occurrenceKey,
          activity_id: id,
          kind,
          status,
        } = row;
        const paths = storedPaths(row["paths"]);
        if (
          typeof threadId === "string" &&
          typeof occurrenceKey === "string" &&
          typeof id === "string" &&
          (kind === "tool" || kind === "command") &&
          (status === "running" ||
            status === "failed" ||
            status === "completed") &&
          paths
        ) {
          records.push({
            threadId,
            occurrenceKey,
            activity: { id, kind, status, paths },
          });
        }
      }
      return records;
    })) ?? []
  );
}

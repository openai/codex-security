import { hash, randomUUID } from "node:crypto";
import { lstat, mkdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import { canonicalJson } from "./record.js";
import { sqliteDatabaseOpener, type RuntimeDatabase } from "./runtime.js";
import {
  scanActivitiesFromEvent,
  scanActivityFromSessionEvent,
  type ScanActivity,
  type sameWindowsActivityDirectory,
} from "./scan-activity.js";
import { sessionStartedAt } from "./scan-sessions.js";
import { parseJson } from "./value.js";

type LiveActivityPaths = Pick<ScanActivity, "id" | "kind" | "status" | "paths">;

export class ActivityObservations {
  #since?: number;
  #observedPaths?: Map<string, string[]>;

  constructor(
    readonly codexHome: string,
    readonly scanId: string,
    readonly repository: string,
    readonly verifyDirectory?: typeof sameWindowsActivityDirectory,
  ) {}

  beginParentTurn(): void {
    this.#since = Date.now();
  }

  async primary(
    threadId: string | null,
    event: Readonly<Record<string, unknown>>,
  ) {
    let verifiedAlias = false;
    const verify = this.verifyDirectory;
    const activities = scanActivitiesFromEvent(
      event,
      this.repository,
      verify &&
        ((repository, candidate) => {
          const same = verify(repository, candidate);
          if (same) verifiedAlias = true;
          return same;
        }),
    );
    if (verifiedAlias && threadId) {
      const lexical = scanActivitiesFromEvent(event, this.repository);
      for (const [i, activity] of activities.entries()) {
        if (!isDeepStrictEqual(activity.paths, lexical[i]?.paths)) {
          await saveLiveActivityPaths(
            this.codexHome,
            this.scanId,
            threadId,
            randomUUID(),
            activity,
          );
        }
      }
    }
    return activities;
  }

  async workerPaths(
    threadId: string,
    path: string,
    activity: ScanActivity,
    event: Record<string, unknown>,
  ): Promise<string[]> {
    const key = observedEventKey(threadId, event);
    if (key === undefined) return activity.paths;
    const { codexHome, scanId, repository, verifyDirectory } = this;
    if (!this.#observedPaths) {
      const { observedPaths } = await readActivityPaths([codexHome], scanId);
      this.#observedPaths = observedPaths;
    }
    const saved = this.#observedPaths.get(key);
    if (saved !== undefined) return saved;
    // Historical, compressed, and archived rows can originate on another host.
    const time = sessionStartedAt(event["timestamp"]);
    if (
      !verifyDirectory ||
      activity.status !== "running" ||
      time === null ||
      this.#since === undefined ||
      time < this.#since ||
      time > Date.now() ||
      !path.startsWith(join(codexHome, "sessions") + sep) ||
      !path.endsWith(".jsonl")
    )
      return activity.paths;
    const verified = scanActivityFromSessionEvent(
      event,
      repository,
      verifyDirectory,
    );
    if (!verified || isDeepStrictEqual(verified.paths, activity.paths))
      return activity.paths;
    await saveObservedActivity(codexHome, scanId, {
      eventKey: key,
      paths: verified.paths,
    });
    this.#observedPaths.set(key, verified.paths);
    return verified.paths;
  }
}

// SDK item IDs alone are neither stable across turns nor shared with native rollouts.
export function observedEventKey(
  threadId: string,
  event: Readonly<Record<string, unknown>>,
): string | undefined {
  try {
    return hash("sha256", canonicalJson([threadId, event]));
  } catch {
    // Parsed rollout JSON can nest more deeply than JSON.stringify accepts.
    return undefined;
  }
}

async function activityDatabase(
  codexHome: string,
  write: boolean,
  operation: (db: RuntimeDatabase) => void,
): Promise<void> {
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
  try {
    const statement = db.prepare(sql);
    try {
      return statement.all(...parameters);
    } finally {
      statement.finalize?.();
    }
  } catch {
    // A saved database may contain just one type of observation.
    return [];
  }
}

export async function saveObservedActivity(
  codexHome: string,
  scanId: string,
  { eventKey, paths }: { eventKey: string; paths: string[] },
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

const paths = z.preprocess(
  (json) => (typeof json === "string" ? parseJson(() => json) : undefined),
  z.array(z.string()).nonempty(),
);
const observedRow = z.object({ eventKey: z.string(), paths });
const liveRow = z.object({
  threadId: z.string(),
  occurrence: z.string(),
  id: z.string(),
  kind: z.enum(["tool", "command"]),
  status: z.enum(["running", "failed", "completed"]),
  paths,
});

export async function readActivityPaths(
  homes: Iterable<string>,
  scanId: string,
  { includeLive = false } = {},
) {
  const observedPaths = new Map<string, string[]>();
  const live = new Map<string, Map<string, LiveActivityPaths>>();
  for (const home of homes) {
    await activityDatabase(home, false, (db) => {
      for (const raw of rows(
        db,
        "SELECT event_key AS eventKey, paths FROM observed_paths WHERE scan_id = ?",
        scanId,
      )) {
        const row = observedRow.safeParse(raw).data;
        if (row && !observedPaths.has(row.eventKey))
          observedPaths.set(row.eventKey, row.paths);
      }
      if (!includeLive) return;
      for (const raw of rows(
        db,
        "SELECT thread_id AS threadId, occurrence, activity_id AS id, kind, status, paths FROM live_paths WHERE scan_id = ? ORDER BY rowid",
        scanId,
      )) {
        const row = liveRow.safeParse(raw).data;
        if (!row) continue;
        const { threadId, occurrence, ...activity } = row;
        const recorded =
          live.get(threadId) ?? new Map<string, LiveActivityPaths>();
        if (!recorded.has(occurrence)) recorded.set(occurrence, activity);
        live.set(threadId, recorded);
      }
    });
  }
  return { observedPaths, live };
}

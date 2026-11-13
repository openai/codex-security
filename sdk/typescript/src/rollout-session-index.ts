import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  writeFile,
  rm,
  type FileHandle,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";
import { z } from "zod";
import { CodexSecurityError } from "./errors.js";
import {
  acquireCodexSecurityCredentialHomeLock,
  createWindowsOutputDirectory,
  prepareOutputDir,
  runCodexCommand,
  requirePrivateDirectory,
  requirePrivateOutputDirectory,
  validatePreparedOutputDir,
} from "./runtime.js";
import type { ScanRolloutSession } from "./scan-logs.js";
import { nullIfMissingFile } from "./targets.js";
import { compareTimestamps } from "./timestamps.js";
import { notify } from "./value.js";

export const ROLLOUT_SESSION_INDEX_RELATIVE_PATH =
  "artifacts/rollout-sessions/index.json";

const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u);
const timestamp = z.iso.datetime();
const segment = z.strictObject({
  startedAt: timestamp,
  path: z
    .string()
    .regex(/^events-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.jsonl$/u),
});
const sessionEntry = z.strictObject({
  attribution: z.enum(["recorded", "inferred"]).optional(),
  threadId: id,
  parentThreadId: id.nullable(),
  eventSegments: z.array(segment).optional(),
});
const indexSchema = z.strictObject({
  schemaVersion: z.literal(1),
  scanId: id,
  rootThreadIds: z.array(id),
  sessions: z.array(sessionEntry),
});
export type RolloutSessionIndex = z.infer<typeof indexSchema>;

async function prepareDirectory(path: string, create: boolean): Promise<void> {
  if (create) {
    if (process.platform === "win32")
      await createWindowsOutputDirectory(path, true);
    else await mkdir(path, { recursive: true, mode: 0o700 });
  }
  if (!(await lstat(path)).isDirectory()) {
    throw new CodexSecurityError(
      "Rollout artifact directories must be real directories.",
    );
  }
}

async function indexDirectory(
  scanDir: string,
  create: boolean,
): Promise<string> {
  const root = await validatePreparedOutputDir(
    resolve(scanDir),
    undefined,
    true,
  );
  const artifacts = join(root, "artifacts");
  await prepareDirectory(artifacts, create);
  const directory = join(artifacts, "rollout-sessions");
  await prepareDirectory(directory, create);
  await validatePreparedOutputDir(directory, undefined, true);
  const metadata = await lstat(directory);
  if (create)
    await requirePrivateDirectory(
      metadata,
      directory,
      "rollout artifact directory",
    );
  else requirePrivateOutputDirectory(metadata, directory);
  return directory;
}

function requireUnique(items: string[]): void {
  if (new Set(items).size !== items.length) {
    throw new CodexSecurityError(
      "Duplicate identifier or event file in the rollout session index.",
    );
  }
}

async function readIndex(
  directory: string,
  scanId: string,
): Promise<RolloutSessionIndex | null> {
  const path = join(directory, "index.json");
  const file = await open(
    path,
    constants.O_RDONLY |
      (constants.O_NOFOLLOW ?? 0) |
      (constants.O_NONBLOCK ?? 0),
  ).catch(nullIfMissingFile);
  if (!file) return null;
  let index: RolloutSessionIndex;
  try {
    const metadata = await file.stat();
    if (!metadata.isFile() || metadata.nlink > 1) {
      throw new CodexSecurityError("Invalid rollout session index file.");
    }
    if (!constants.O_NOFOLLOW) {
      const leaf = await lstat(path);
      if (
        !leaf.isFile() ||
        leaf.dev !== metadata.dev ||
        leaf.ino !== metadata.ino
      )
        throw new CodexSecurityError(
          "The rollout session index must remain a regular file.",
        );
    }
    requirePrivateOutputDirectory(metadata, path);
    index = indexSchema.parse(JSON.parse(await file.readFile("utf8")));
  } finally {
    await file.close();
  }
  if (index.scanId !== scanId)
    throw new CodexSecurityError(
      "The rollout session index belongs to another scan.",
    );
  requireUnique(index.rootThreadIds);
  requireUnique(index.sessions.map(({ threadId }) => threadId));
  const eventPaths = index.sessions.flatMap(({ eventSegments = [] }) => {
    for (let i = 1; i < eventSegments.length; i++) {
      if (
        compareTimestamps(
          eventSegments[i - 1]!.startedAt,
          eventSegments[i]!.startedAt,
        ) >= 0
      )
        throw new CodexSecurityError(
          "Rollout event segments must have distinct, chronological invocation times.",
        );
    }
    return eventSegments.map(({ path }) => path);
  });
  requireUnique(eventPaths);
  for (const filename of eventPaths) {
    const eventPath = join(directory, filename);
    const event = await lstat(eventPath);
    if (!event.isFile() || event.nlink !== 1) {
      throw new CodexSecurityError("Invalid retained rollout event file.");
    }
    requirePrivateOutputDirectory(event, eventPath);
  }
  return index;
}

export async function readRolloutSessionIndex(
  scanDir: string,
  scanId: string,
): Promise<RolloutSessionIndex | null> {
  const dir = await indexDirectory(scanDir, false).catch(nullIfMissingFile);
  return dir === null ? null : readIndex(dir, scanId);
}

async function writeSegment(
  path: string,
  session: ScanRolloutSession,
): Promise<boolean> {
  let file: FileHandle | undefined;
  try {
    for await (const event of session.events()) {
      file ??= await open(path, "wx", 0o600);
      await file.writeFile(JSON.stringify(event) + "\n");
    }
    return file !== undefined;
  } finally {
    await file?.close();
  }
}

export async function rolloutDirectoryIdentity(
  scanDir: string,
): Promise<string> {
  const directory = await lstat(scanDir, { bigint: true });
  if (!directory.isDirectory() || directory.ino === 0n)
    throw new CodexSecurityError("Cannot identify the scan output directory.");
  return `${directory.dev}:${directory.ino}`;
}

export async function writeRolloutSessionIndex(options: {
  scanDir: string;
  scanId: string;
  startedAt: string;
  rootThreadIds: readonly string[];
  sessions: readonly ScanRolloutSession[];
  expectedDirectory?: string;
  stateDirectory?: string;
  retainEvents?: boolean;
  signal?: AbortSignal;
  onWarning?: (message: string) => void;
}): Promise<string> {
  const { scanDir, scanId, rootThreadIds, sessions } = options;
  const identity =
    options.expectedDirectory ?? (await rolloutDirectoryIdentity(scanDir));
  const directory = await indexDirectory(scanDir, true);
  const path = join(directory, "index.json");
  // Resume and terminal callbacks can overlap across SDK processes.
  // An archive can rename the scan directory while its exporter is paused.
  const stateRoot = options.stateDirectory ?? tmpdir();
  const writerKey = createHash("sha256").update(directory).digest("hex");
  const writerState = join(
    stateRoot,
    `codex-rollout-writer-${process.getuid?.() ?? "user"}-${writerKey}`,
  );
  await prepareDirectory(writerState, true);
  // A canceled scan can still publish diagnostics when the writer is available.
  const release = await acquireCodexSecurityCredentialHomeLock(
    writerState,
    options.signal,
    { allowImmediateAcquisitionOnAbort: true },
  );
  try {
    const previous = await readIndex(directory, scanId);
    requireUnique(sessions.map(({ threadId }) => threadId));
    const entries = new Map(
      previous?.sessions.map((entry) => [entry.threadId, entry]),
    );
    for (const { threadId, parentThreadId, attribution } of sessions) {
      const saved = entries.get(threadId);
      if (saved && saved.parentThreadId !== parentThreadId) {
        throw new CodexSecurityError(
          "The rollout session parent changed for an existing thread.",
        );
      }
      const entry = saved ?? { threadId, parentThreadId };
      if (attribution && entry.attribution !== "recorded")
        entry.attribution = attribution;
      entries.set(threadId, entry);
    }
    const index = indexSchema.parse({
      schemaVersion: 1,
      scanId,
      rootThreadIds: [
        ...new Set([...(previous?.rootThreadIds ?? []), ...rootThreadIds]),
      ],
      sessions: [...entries.values()],
    });
    const stage = await prepareOutputDir(
      undefined,
      "rollout-stage",
      writerState,
    );
    let contents = JSON.stringify(index) + "\n";
    const pending: string[] = [];
    try {
      if (options.retainEvents) {
        try {
          const startedAt = timestamp.parse(options.startedAt);
          const sources = new Map(
            sessions.map((session) => [session.threadId, session]),
          );
          for (const entry of index.sessions) {
            const source = sources.get(entry.threadId);
            // Published segments are immutable. An overlapping terminal callback for
            // this invocation may already have retained the same thread.
            const segments = entry.eventSegments ?? [];
            if (
              !source ||
              segments.some(
                (s) => compareTimestamps(s.startedAt, startedAt) === 0,
              )
            )
              continue;
            const filename = `events-${randomUUID()}.jsonl`;
            const eventPath = join(stage, filename);
            if (!(await writeSegment(eventPath, source))) continue;
            pending.push(filename);
            entry.eventSegments = [
              ...segments,
              { startedAt, path: filename },
            ].sort((a, b) => compareTimestamps(a.startedAt, b.startedAt));
          }
          contents = JSON.stringify(index) + "\n";
        } catch {
          pending.length = 0;
          notify(() =>
            options.onWarning?.(
              "Could not retain rollout events. The session index preserves available metadata and previous event files.",
            ),
          );
        }
      }
      await writeFile(join(stage, "index.json"), contents, {
        mode: 0o600,
        flag: "wx",
      });
      const result = await runCodexCommand(
        { command: process.execPath },
        [
          fileURLToPath(new URL("./rollout-publish.js", import.meta.url)),
          identity,
          stage,
        ],
        {},
        JSON.stringify(pending),
        undefined,
        { cwd: scanDir },
      );
      if (!result.success)
        throw new CodexSecurityError(
          result.stderr || "Could not publish the rollout index.",
        );
    } finally {
      await rm(stage, { recursive: true, force: true });
    }
    return path;
  } finally {
    await release();
  }
}

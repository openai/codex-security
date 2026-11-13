import { afterEach, expect, test } from "bun:test";
import {
  mkdir,
  readFile,
  readdir,
  rename,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import {
  readRolloutSessionIndex,
  rolloutDirectoryIdentity,
  writeRolloutSessionIndex,
} from "../src/rollout-session-index.js";
import { prepareScanRegistrationOutput } from "../src/runtime.js";
import { readJsonLines } from "./support/json.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures("rollout-index-");
afterEach(cleanup);

const scanId = "scan-1";
const rootThreadIds = ["parent"];
const startedAt = "2026-07-01T09:00:00.000Z";
const later = "2026-07-01T10:00:00.000Z";
function rows(threadId: string) {
  return [
    { type: "session_meta", payload: { id: threadId } },
    {
      type: "response_item",
      payload: { output: "private command output\nnext line" },
    },
  ];
}

function session(threadId: string, parentThreadId: string | null) {
  return {
    threadId,
    parentThreadId,
    async *events() {
      yield* rows(threadId);
    },
  };
}

const interrupted = {
  ...session("child", "parent"),
  async *events() {
    yield { type: "partial" };
    throw new Error("lost rollout");
  },
};

test("indexes lineage without reading rollout contents by default", async () => {
  const scanDir = await temporaryDirectory();
  expect(await readRolloutSessionIndex(scanDir, scanId)).toBeNull();
  const lineage = [
    {
      threadId: "parent",
      parentThreadId: null,
      attribution: "recorded" as const,
    },
    {
      threadId: "child",
      parentThreadId: "parent",
      attribution: "inferred" as const,
    },
  ];
  let opened = false;
  const path = await writeRolloutSessionIndex({
    scanDir,
    scanId,
    startedAt,
    rootThreadIds,
    sessions: lineage.map((entry) => ({
      ...entry,
      events() {
        opened = true;
        throw new Error("Indexing opened a rollout");
      },
    })),
  });
  expect(opened).toBe(false);
  expect(path).toBe(
    join(scanDir, "artifacts", "rollout-sessions", "index.json"),
  );
  const index = {
    schemaVersion: 1 as const,
    scanId,
    rootThreadIds,
    sessions: lineage,
  };
  expect(JSON.parse(await readFile(path, "utf8"))).toEqual(index);
  expect(await readRolloutSessionIndex(scanDir, scanId)).toEqual(index);
  expect(await readdir(dirname(path))).toEqual(["index.json"]);
});

test("round-trips large session metadata without retaining events", async () => {
  const scanDir = await temporaryDirectory();
  const threads = Array.from({ length: 16_384 }, (_, i) =>
    `worker-${i}`.padEnd(256, "x"),
  );
  const path = await writeRolloutSessionIndex({
    scanDir,
    scanId,
    startedAt,
    rootThreadIds: threads,
    sessions: threads.map((thread) => session(thread, null)),
  });
  expect((await stat(path)).size).toBeGreaterThan(8 * 1024 * 1024);
  const index = await readRolloutSessionIndex(scanDir, scanId);
  expect(index!.rootThreadIds).toEqual(threads);
  expect(index!.sessions.map((entry) => entry.threadId)).toEqual(threads);
});

test("publishes only metadata when the first event export fails partway", async () => {
  const scanDir = await temporaryDirectory();
  const warnings: string[] = [];
  const path = await writeRolloutSessionIndex({
    scanDir,
    scanId,
    startedAt,
    rootThreadIds,
    sessions: [session("parent", null), interrupted],
    retainEvents: true,
    onWarning: (warning) => warnings.push(warning),
  });
  expect(warnings).toHaveLength(1);
  const index = await readRolloutSessionIndex(scanDir, scanId);
  expect(index!.sessions).toEqual([
    { threadId: "parent", parentThreadId: null },
    { threadId: "child", parentThreadId: "parent" },
  ]);
  expect(await readdir(dirname(path))).toEqual(["index.json"]);
});

test("a canceled exporter does not wait for a paused writer", async () => {
  const scanDir = await temporaryDirectory();
  const options = { scanDir, scanId, rootThreadIds, startedAt };
  const writing = Promise.withResolvers<void>();
  const resume = Promise.withResolvers<void>();
  const writer = writeRolloutSessionIndex({
    ...options,
    retainEvents: true,
    sessions: [
      {
        ...session("parent", null),
        async *events() {
          writing.resolve();
          await resume.promise;
          yield* rows("parent");
        },
      },
    ],
  });
  await writing.promise;
  const controller = new AbortController();
  const waiting = writeRolloutSessionIndex({
    ...options,
    sessions: [session("other", null)],
    signal: controller.signal,
  });
  controller.abort();
  // Release the first writer even if a regression ignores the abort.
  const deadline = setTimeout(resume.resolve, 10_000);
  try {
    await expect(waiting).rejects.toMatchObject({ name: "AbortError" });
  } finally {
    clearTimeout(deadline);
    resume.resolve();
    await writer;
  }
  expect(
    (await readRolloutSessionIndex(scanDir, scanId))?.sessions.map(
      (s) => s.threadId,
    ),
  ).toEqual(["parent"]);
});

test("a stale exporter leaves an empty replacement available for scan registration", async () => {
  const root = await temporaryDirectory();
  const scanDir = join(root, "scan");
  await mkdir(scanDir, { mode: 0o700 });
  const expectedDirectory = await rolloutDirectoryIdentity(scanDir);
  await rename(scanDir, join(root, "archived-scan"));
  await prepareScanRegistrationOutput(scanDir, "new-scan");

  await expect(
    writeRolloutSessionIndex({
      scanDir,
      stateDirectory: join(root, "state"),
      expectedDirectory,
      scanId,
      startedAt,
      rootThreadIds,
      sessions: [session("parent", null)],
    }),
  ).rejects.toThrow("changed before rollout publication");
  expect(await readdir(scanDir)).toEqual([]);
  expect(await prepareScanRegistrationOutput(scanDir, "new-scan")).toBe(
    scanDir,
  );
});

test("a delayed export cannot publish into a replacement scan directory", async () => {
  const root = await temporaryDirectory();
  const scanDir = join(root, "scan");
  const stateDirectory = join(root, "state");
  await mkdir(scanDir, { mode: 0o700 });
  const options = { scanDir, stateDirectory, scanId, startedAt, rootThreadIds };
  const writing = Promise.withResolvers<void>();
  const resume = Promise.withResolvers<void>();
  const old = writeRolloutSessionIndex({
    ...options,
    retainEvents: true,
    sessions: [
      {
        ...session("old", null),
        async *events() {
          writing.resolve();
          await resume.promise;
          yield { text: "original scan only" };
        },
      },
    ],
  });
  await writing.promise;
  try {
    await rename(scanDir, join(root, "archive"));
    await mkdir(join(scanDir, "artifacts", "rollout-sessions"), {
      recursive: true,
      mode: 0o700,
    });
    await writeFile(
      join(scanDir, "artifacts", "rollout-sessions", "index.json"),
      "replacement",
    );
  } finally {
    resume.resolve();
  }
  await expect(old).rejects.toThrow("changed before rollout publication");
  const directory = join(scanDir, "artifacts", "rollout-sessions");
  expect(await readdir(directory)).toEqual(["index.json"]);
  expect(await readFile(join(directory, "index.json"), "utf8")).toBe(
    "replacement",
  );
});

test("metadata retries and failed refreshes preserve published events and unrelated files", async () => {
  const scanDir = await temporaryDirectory();
  const options = {
    scanDir,
    scanId,
    startedAt,
    rootThreadIds,
    sessions: [session("parent", null), session("child", "parent")],
  };
  const path = await writeRolloutSessionIndex({
    ...options,
    retainEvents: true,
  });
  const index = await readRolloutSessionIndex(scanDir, scanId);
  const directory = dirname(path);
  const logs = index!.sessions.map(({ threadId, eventSegments }) => {
    expect(eventSegments).toHaveLength(1);
    const segment = eventSegments![0]!;
    expect(segment.startedAt).toBe(startedAt);
    expect(isAbsolute(segment.path)).toBe(false);
    const log = resolve(directory, segment.path);
    expect(log.startsWith(directory + sep)).toBe(true);
    return { threadId, log };
  });
  expect(new Set(logs.map(({ log }) => log)).size).toBe(2);
  for (const { threadId, log } of logs) {
    expect(await readJsonLines(log)).toEqual(rows(threadId));
    if (process.platform !== "win32") {
      for (const artifact of [path, directory, log, dirname(log)]) {
        expect((await stat(artifact)).mode & 0o077).toBe(0);
      }
    }
  }
  await writeRolloutSessionIndex({
    ...options,
    rootThreadIds: ["resumed"],
    sessions: [session("resumed", null)],
  });
  const resumed = await readRolloutSessionIndex(scanDir, scanId);
  expect(resumed!.rootThreadIds.toSorted()).toEqual(["parent", "resumed"]);
  expect(resumed!.sessions).toHaveLength(3);
  expect(resumed!.sessions).toEqual(
    expect.arrayContaining([
      ...index!.sessions,
      { threadId: "resumed", parentThreadId: null },
    ]),
  );
  const sentinel = join(directory, "unrelated.txt");
  await writeFile(sentinel, "keep");
  const before = (await readdir(directory, { recursive: true })).toSorted();
  const warnings: string[] = [];
  await writeRolloutSessionIndex({
    ...options,
    startedAt: later,
    sessions: [
      session("parent", null),
      session("late-child", "parent"),
      interrupted,
    ],
    retainEvents: true,
    onWarning: (warning) => warnings.push(warning),
  });
  expect(warnings).toHaveLength(1);
  const recovered = await readRolloutSessionIndex(scanDir, scanId);
  expect(recovered!.rootThreadIds).toEqual(resumed!.rootThreadIds);
  expect(recovered!.sessions).toHaveLength(4);
  expect(recovered!.sessions).toEqual(
    expect.arrayContaining([
      ...resumed!.sessions,
      { threadId: "late-child", parentThreadId: "parent" },
    ]),
  );
  for (const { threadId, log } of logs)
    expect(await readJsonLines(log)).toEqual(rows(threadId));
  expect(await readFile(sentinel, "utf8")).toBe("keep");
  expect((await readdir(directory, { recursive: true })).toSorted()).toEqual(
    before,
  );
});

test("retains disjoint invocations chronologically and reads each invocation only once", async () => {
  const scanDir = await temporaryDirectory();
  const opened: string[] = [];
  const archive = (start: string, childIdentified = true) =>
    writeRolloutSessionIndex({
      scanDir,
      scanId,
      startedAt: start,
      rootThreadIds,
      retainEvents: true,
      sessions: [
        {
          threadId: "parent",
          parentThreadId: null,
          async *events() {
            opened.push(start);
            yield { invocation: start };
          },
        },
        {
          ...session("child", "parent"),
          async *events() {
            if (childIdentified) yield { invocation: start };
          },
        },
      ],
    });
  const path = await archive(later, false);
  const previous = await readRolloutSessionIndex(scanDir, scanId);
  expect(previous!.sessions[1]).toEqual({
    threadId: "child",
    parentThreadId: "parent",
  });
  expect(await readdir(dirname(path))).toHaveLength(2);
  await Promise.all([archive(startedAt), archive(startedAt)]);
  await archive(later);
  expect(opened).toEqual([later, startedAt]);
  const published = await readRolloutSessionIndex(scanDir, scanId);
  const segments = published!.sessions[0]!.eventSegments!;
  expect(segments.map((segment) => segment.startedAt)).toEqual([
    startedAt,
    later,
  ]);
  expect(segments[1]).toEqual(previous!.sessions[0]!.eventSegments![0]);
  expect(
    published!.sessions[1]!.eventSegments?.map(({ startedAt }) => startedAt),
  ).toEqual([startedAt, later]);
  for (const segment of segments) {
    expect(await readJsonLines(join(dirname(path), segment.path))).toEqual([
      { invocation: segment.startedAt },
    ]);
  }
});

test("refuses a linked artifact directory without writing through it", async () => {
  const scanDir = await temporaryDirectory();
  const other = await temporaryDirectory();
  await symlink(other, join(scanDir, "artifacts"), "junction");
  await expect(
    writeRolloutSessionIndex({
      scanDir,
      scanId,
      startedAt,
      rootThreadIds,
      sessions: [session("parent", null)],
      retainEvents: true,
    }),
  ).rejects.toThrow();
  expect(await readdir(other)).toEqual([]);
});

test("refuses mismatched or unsafe saved indexes without replacing them", async () => {
  const scanDir = await temporaryDirectory();
  const options = {
    scanDir,
    scanId,
    startedAt,
    rootThreadIds,
    sessions: [session("parent", null)],
  };
  const path = await writeRolloutSessionIndex(options);
  const valid = await readRolloutSessionIndex(scanDir, scanId);
  await expect(
    writeRolloutSessionIndex({
      ...options,
      rootThreadIds: ["other"],
      sessions: [session("other", null), session("parent", "other")],
    }),
  ).rejects.toThrow();
  expect(await readRolloutSessionIndex(scanDir, scanId)).toEqual(valid);
  for (const invalid of [
    { ...valid, scanId: "different-scan" },
    {
      ...valid,
      sessions: [
        {
          threadId: "parent",
          parentThreadId: null,
          eventSegments: [{ startedAt, path: "../private.jsonl" }],
        },
      ],
    },
  ]) {
    const original = JSON.stringify(invalid);
    await writeFile(path, original);
    await expect(readRolloutSessionIndex(scanDir, scanId)).rejects.toThrow();
    await expect(writeRolloutSessionIndex(options)).rejects.toThrow();
    expect(await readFile(path, "utf8")).toBe(original);
  }
});

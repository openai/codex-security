import { writeJsonLines } from "./support/json.js";
import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { unlinkSync } from "node:fs";
import { join } from "node:path";
import { zstdCompressSync } from "node:zlib";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import {
  findScanSession,
  readSavedScanLogs,
  readScanLogs,
} from "../src/scan-logs.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory: temporaryHome, cleanup } = createApiTestFixtures(
  "codex-security-scan-logs-",
);

afterEach(cleanup);

async function writeSession(
  home: string,
  threadId: string,
  events: Record<string, unknown>[],
  parentThreadId?: string,
  startedAt?: string,
  workingDirectory?: string,
): Promise<void> {
  const directory = join(home, "sessions", "2026", "08", "11");
  await mkdir(directory, { recursive: true });
  await writeJsonLines(join(directory, `rollout-${threadId}.jsonl`), [
    {
      type: "session_meta",
      payload: {
        id: threadId,
        ...(startedAt === undefined ? {} : { timestamp: startedAt }),
        ...(workingDirectory === undefined ? {} : { cwd: workingDirectory }),
        ...(parentThreadId === undefined
          ? {}
          : {
              source: {
                subagent: {
                  thread_spawn: { parent_thread_id: parentThreadId },
                },
              },
            }),
      },
    },
    ...events,
  ]);
}

function commandEvent(command: string, id: string, timestamp?: string) {
  return {
    type: "response_item",
    ...(timestamp === undefined ? {} : { timestamp }),
    payload: {
      type: "function_call",
      call_id: id,
      name: "exec_command",
      arguments: JSON.stringify({ cmd: command }),
    },
  };
}

function taskStarted(turnId: string, timestamp?: string) {
  return {
    type: "event_msg",
    ...(timestamp === undefined ? {} : { timestamp }),
    payload: { type: "task_started", turn_id: turnId },
  };
}

describe("saved scan logs", () => {
  test.each(["standard", "deep"])(
    "ignores model-owned log homes without host ownership for %s scans",
    async (mode) => {
      const configured = await temporaryHome();
      const foreign = await temporaryHome();
      const scanDir = await temporaryHome();
      const settings = join(scanDir, "artifacts", "deep_discovery");
      await mkdir(settings, { recursive: true });
      await writeFile(
        join(settings, "execution-settings.json"),
        JSON.stringify({ version: 1, settings: { codexHome: foreign } }),
      );
      const configuredEvent = commandEvent(
        "configured owner",
        "configured-call",
      );
      await writeSession(configured, "owner", [configuredEvent]);
      await writeSession(foreign, "owner", [
        configuredEvent,
        commandEvent("foreign suffix", "foreign-call"),
      ]);
      const result = await readSavedScanLogs(
        { scanId: "scan-1", mode, scanDir, continuationThreadId: "owner" },
        configured,
      );
      expect(result.events.map(({ event }) => event)).toEqual([
        { type: "session_meta", payload: { id: "owner" } },
        configuredEvent,
      ]);
      expect(result.sessions.map(({ path }) => path)).toEqual([
        join(configured, "sessions", "2026", "08", "11", "rollout-owner.jsonl"),
      ]);
    },
  );

  test.each(
    ["sessions", "archived_sessions"].flatMap((directory) =>
      ["prefix only", "unrelated owner turn"].map((tail) => [directory, tail]),
    ),
  )(
    "reads the complete same-thread recorded copy from %s after %s",
    async (directory, tail) => {
      const current = await temporaryHome();
      const original = await temporaryHome();
      const scanDir = await temporaryHome();
      const settings = join(scanDir, "artifacts", "deep_discovery");
      await mkdir(settings, { recursive: true });
      await writeFile(
        join(settings, "execution-settings.json"),
        JSON.stringify({ version: 1, settings: { codexHome: original } }),
      );
      const timestamp = "2026-08-11T12:01:00.000Z";
      const prefix = [
        { type: "turn_context", timestamp, payload: { turn_id: "scan-turn" } },
        commandEvent("prefix", "prefix-call", timestamp),
      ];
      const suffix = commandEvent("saved suffix", "suffix-call", timestamp);
      await writeSession(current, "owner", [
        ...prefix,
        ...(tail === "unrelated owner turn"
          ? [
              {
                type: "turn_context",
                timestamp,
                payload: { turn_id: "other-turn" },
              },
              commandEvent(
                "unrelated first copy",
                "other-first-call",
                timestamp,
              ),
            ]
          : []),
      ]);
      const currentPath = join(
        current,
        "sessions",
        "2026",
        "08",
        "11",
        "rollout-owner.jsonl",
      );
      await writeFile(
        currentPath,
        (await readFile(currentPath, "utf8")) + '\n\n42\n{"type":',
      );
      await writeSession(original, "owner", [
        ...prefix,
        suffix,
        suffix,
        { type: "turn_context", timestamp, payload: { turn_id: "other-turn" } },
        commandEvent("unrelated turn", "other-call", timestamp),
      ]);
      if (directory === "archived_sessions") {
        await rename(join(original, "sessions"), join(original, directory));
      }
      const result = await readSavedScanLogs(
        {
          scanId: "scan-1",
          mode: "deep",
          scanDir,
          continuationThreadId: "owner",
          executionAttribution: {
            formatVersion: 1,
            workerCodexHome: original,
            executionThreadIds: [],
            owner: {
              threadId: "owner",
              turnId: "scan-turn",
              startedAt: timestamp,
            },
            startedAt: timestamp,
            completedAt: timestamp,
          },
        },
        current,
      );
      expect(result.sessions.map(({ threadId }) => threadId)).toEqual([
        "owner",
      ]);
      expect(result.events.map(({ event }) => event)).toEqual([
        { type: "session_meta", payload: { id: "owner" } },
        ...prefix,
        suffix,
        suffix,
      ]);
      expect(result.sessions[0]?.path).toStartWith(join(original, directory!));
    },
  );

  test.each(["equal", "shorter", "divergent"])(
    "keeps the first rollout when attributed occurrences are %s",
    async (copy) => {
      const first = await temporaryHome();
      const second = await temporaryHome();
      const timestamp = "2026-08-11T12:01:00.000Z";
      const turn = {
        type: "turn_context",
        timestamp,
        payload: { turn_id: "scan-turn" },
      };
      const prefix = commandEvent("first", "first-call", timestamp);
      const suffix = commandEvent("complete", "complete-call", timestamp);
      const unrelated = {
        type: "turn_context",
        timestamp,
        payload: { turn_id: "other-turn" },
      };
      await writeSession(first, "owner", [turn, prefix, suffix, unrelated]);
      await writeSession(second, "owner", [
        turn,
        ...(copy === "equal"
          ? [prefix, suffix]
          : copy === "shorter"
            ? [prefix]
            : [
                prefix,
                commandEvent("different", "different-call", timestamp),
                suffix,
              ]),
        unrelated,
        commandEvent("more unrelated work", "other-call", timestamp),
      ]);
      const result = await readScanLogs({
        scanId: "scan-1",
        threadId: "owner",
        codexHome: [first, second],
        executionAttribution: {
          formatVersion: 1,
          executionThreadIds: [],
          owner: {
            threadId: "owner",
            turnId: "scan-turn",
            startedAt: timestamp,
          },
          startedAt: timestamp,
          completedAt: timestamp,
        },
      });
      expect(result.sessions[0]?.path).toStartWith(first);
      expect(result.events.map(({ event }) => event)).toEqual([
        { type: "session_meta", payload: { id: "owner" } },
        turn,
        prefix,
        suffix,
      ]);
    },
  );

  test.each(["equal", "shorter", "divergent"])(
    "keeps the first rollout when a later copy is %s",
    async (copy) => {
      const first = await temporaryHome();
      const second = await temporaryHome();
      const prefix = commandEvent("first", "first-call");
      const suffix = commandEvent("complete", "complete-call");
      await writeSession(first, "owner", [prefix, suffix]);
      await writeSession(
        second,
        "owner",
        copy === "equal"
          ? [prefix, suffix]
          : copy === "shorter"
            ? [prefix]
            : [prefix, commandEvent("different", "different-call"), suffix],
      );
      const result = await readScanLogs({
        scanId: "scan-1",
        threadId: "owner",
        codexHome: [first, second],
      });
      expect(result.sessions[0]?.path).toStartWith(first);
      expect(result.events.map(({ event }) => event)).toEqual([
        { type: "session_meta", payload: { id: "owner" } },
        prefix,
        suffix,
      ]);
    },
  );

  test.each([
    ["current", "original"],
    ["current", "substituted"],
    ["current", "deleted"],
    ["original", "original"],
    ["original", "substituted"],
    ["original", "deleted"],
  ] as const)(
    "reads recovered Deep workers with owner in %s home and %s artifact",
    async (ownerHome, artifact) => {
      const current = await temporaryHome();
      const original = await temporaryHome();
      const scanDir = await temporaryHome();
      const settingsDirectory = join(scanDir, "artifacts", "deep_discovery");
      await mkdir(settingsDirectory, { recursive: true });
      await writeFile(
        join(settingsDirectory, "execution-settings.json"),
        JSON.stringify({
          version: 1,
          settings: { codexHome: original, codexPath: join(original, "codex") },
        }),
      );
      const startedAt = "2026-08-11T12:00:00.000Z";
      const timestamp = "2026-08-11T12:01:00.000Z";
      await writeSession(
        ownerHome === "current" ? current : original,
        "owner",
        [
          {
            type: "turn_context",
            timestamp,
            payload: { turn_id: "scan-turn" },
          },
          commandEvent("scan owner", "owner-call", timestamp),
          {
            type: "turn_context",
            timestamp,
            payload: { turn_id: "later-turn" },
          },
          commandEvent("unrelated owner turn", "other-turn", timestamp),
        ],
      );
      for (const id of ["discovery", "resumed-discovery", "reducer"]) {
        await writeSession(original, id, [commandEvent(id, id, timestamp)]);
      }
      await writeSession(
        original,
        "worker-child",
        [commandEvent("worker child", "child-call", timestamp)],
        "discovery",
      );
      // Keep the existing first-home preference for duplicate active rollouts.
      await writeSession(current, "reducer", [
        commandEvent("current reducer", "current-reducer-call", timestamp),
      ]);
      for (const home of [current, original]) {
        await writeSession(home, "unrelated", [
          commandEvent("unrelated scan", "unrelated-call", timestamp),
        ]);
      }
      const settingsPath = join(settingsDirectory, "execution-settings.json");
      if (artifact === "deleted") unlinkSync(settingsPath);
      if (artifact === "substituted")
        await writeFile(
          settingsPath,
          JSON.stringify({ version: 1, settings: { codexHome: current } }),
        );
      const result = await readSavedScanLogs(
        {
          scanId: "scan-1",
          mode: "deep",
          scanDir,
          continuationThreadId: "owner",
          executionAttribution: {
            formatVersion: 1,
            workerCodexHome: original,
            executionThreadIds: ["discovery", "resumed-discovery", "reducer"],
            owner: { threadId: "owner", turnId: "scan-turn", startedAt },
            startedAt,
            completedAt: "2026-08-11T12:02:00.000Z",
          },
        },
        current,
      );
      expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual([
        "discovery",
        "owner",
        "reducer",
        "resumed-discovery",
        "worker-child",
      ]);
      expect(
        result.events.filter(({ threadId }) => threadId === "reducer"),
      ).toHaveLength(2);
      expect(JSON.stringify(result)).toContain("current reducer");
      expect(JSON.stringify(result)).not.toContain("unrelated");
    },
  );

  test("reads the complete attributed worker copy despite differing inherited history", async () => {
    const home = await temporaryHome();
    const current = await temporaryHome();
    await writeSession(home, "parent", []);
    const startedAt = "2026-08-11T12:02:00.900Z";
    await writeSession(
      home,
      "worker",
      [
        {
          type: "session_meta",
          payload: { id: "parent", timestamp: "2026-08-11T12:00:00.000Z" },
        },
        {
          type: "event_msg",
          payload: {
            type: "task_started",
            started_at: Date.parse("2026-08-11T12:00:00.000Z") / 1_000,
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_message",
            message: "PRIVATE PRE-SCAN CONVERSATION",
          },
        },
        {
          type: "event_msg",
          timestamp: startedAt,
          payload: {
            type: "task_started",
            started_at: Math.floor(Date.parse(startedAt) / 1_000),
          },
        },
        {
          type: "event_msg",
          timestamp: startedAt,
          payload: {
            type: "agent_message",
            message: "Reviewing authorization",
          },
        },
      ],
      "parent",
      startedAt,
    );

    const path = join(
      home,
      "sessions",
      "2026",
      "08",
      "11",
      "rollout-worker.jsonl",
    );
    const currentPath = join(current, "sessions", "rollout-worker.jsonl");
    await mkdir(join(current, "sessions"), { recursive: true });
    await writeFile(
      currentPath,
      (await readFile(path, "utf8"))
        .split("\n")
        .slice(0, 4)
        .join("\n")
        .replace(
          "PRIVATE PRE-SCAN CONVERSATION",
          "OTHER PRE-SCAN CONVERSATION",
        ),
    );
    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: [current, home],
      executionAttribution: {
        formatVersion: 1,
        executionThreadIds: ["worker"],
        owner: { threadId: "parent", turnId: "scan-turn", startedAt },
        startedAt,
        completedAt: null,
      },
    });
    expect(JSON.stringify(result)).toContain("Reviewing authorization");
    expect(JSON.stringify(result)).not.toContain("PRIVATE PRE-SCAN");
    expect(JSON.stringify(result)).not.toContain("OTHER PRE-SCAN");
    expect(
      result.sessions.find(({ threadId }) => threadId === "worker")?.path,
    ).toBe(path);
  });

  test.each([
    ["prefix first", [0], [0, 1, 1, 2], 1, false, false],
    ["complete first", [0, 1, 1, 2], [0], 0, false, false],
    ["identical copies", [0, 1, 1, 2], [0, 1, 1, 2], 0, false, false],
    ["longer divergent copy", [0, 2], [0, 1, 1, 2], 0, false, false],
    ["shorter divergent copy", [0, 1, 1, 2], [0, 2], 0, false, false],
    ["equal-length divergent copy", [0, 1], [0, 2], 0, false, false],
    ["complete archived copy", [0], [0, 1, 1, 2], 1, true, false],
    ["prefix archived copy", [0, 1, 1, 2], [0], 0, true, false],
    ["identical archived copy", [0, 1, 1, 2], [0, 1, 1, 2], 0, true, false],
    ["divergent archived copy", [0, 2], [0, 1, 1, 2], 0, true, false],
    ["complete compressed copy", [0], [0, 1, 1, 2], 1, false, true],
    ["prefix compressed copy", [0, 1, 1, 2], [0], 0, false, true],
    ["identical compressed copy", [0, 1, 1, 2], [0, 1, 1, 2], 0, false, true],
    ["divergent compressed copy", [0, 2], [0, 1, 1, 2], 0, false, true],
    ["complete compressed archived copy", [0], [0, 1, 1, 2], 1, true, true],
  ] as const)(
    "retains complete copied rollout events and precedence: %s",
    async (_label, first, second, selected, archived, compressed) => {
      const homes = [await temporaryHome(), await temporaryHome()];
      const activity = [
        commandEvent("first", "first-call", "2026-08-11T12:00:03Z"),
        commandEvent("repeated", "repeat-call", "2026-08-11T12:00:01Z"),
        commandEvent("last", "last-call", "2026-08-11T12:00:02Z"),
      ];
      const copies = [first, second];
      for (const [index, home] of homes.entries()) {
        await writeSession(home, "parent", []);
        await writeSession(
          home,
          "worker",
          copies[index]!.map((event) => activity[event]!),
          "parent",
        );
      }
      if (compressed) {
        const path = join(
          homes[1]!,
          "sessions",
          "2026",
          "08",
          "11",
          "rollout-worker.jsonl",
        );
        await writeFile(`${path}.zst`, zstdCompressSync(await readFile(path)));
        unlinkSync(path);
      }
      if (archived) {
        await rename(
          join(homes[1]!, "sessions"),
          join(homes[1]!, "archived_sessions"),
        );
      }
      const result = await readSavedScanLogs(
        {
          scanId: "scan-1",
          continuationThreadId: "parent",
          executionThreadIds: ["parent"],
        },
        archived ? [...homes].reverse() : homes,
      );
      expect(result.sessions.map(({ threadId }) => threadId)).toEqual([
        "parent",
        "worker",
      ]);
      expect(result.sessions[1]!.path).toBe(
        join(
          homes[selected]!,
          archived && selected === 1 ? "archived_sessions" : "sessions",
          "2026",
          "08",
          "11",
          `rollout-worker.jsonl${compressed && selected === 1 ? ".zst" : ""}`,
        ),
      );
      expect(
        result.events
          .filter(({ threadId }) => threadId === "worker")
          .slice(1)
          .map(({ event }) => event),
      ).toEqual(copies[selected]!.map((event) => activity[event]!));
    },
  );

  test("keeps first-copy ownership when a longer copy has different session metadata", async () => {
    const first = await temporaryHome();
    const second = await temporaryHome();
    const event = commandEvent("scan work", "scan-call");
    await writeSession(first, "parent", []);
    await writeSession(first, "worker", [event], "unrelated");
    await writeSession(second, "worker", [event, event], "parent");
    const result = await readSavedScanLogs(
      {
        scanId: "scan-1",
        continuationThreadId: "parent",
        executionThreadIds: ["parent"],
      },
      [first, second],
    );
    expect(result.sessions.map(({ threadId }) => threadId)).toEqual(["parent"]);
  });

  test.each([
    "original",
    "legacy archive",
    "short archive",
    "unrelated short archive",
  ])(
    "collects parentless comparisons inside a shared Desktop scan window (%s)",
    async (layout) => {
      const home = await temporaryHome();
      const scanDir = join(home, "scan");
      const cwd = join(scanDir, "artifacts", "deep_discovery");
      await writeSession(home, "owner", [], undefined, "2026-08-01T00:00:00Z");
      await writeSession(home, "other-task", [], "owner");
      await writeSession(
        home,
        "worker",
        [],
        undefined,
        "2026-08-02T00:30:00Z",
        join(cwd, "workers", "discovery-0001", "output"),
      );
      await writeSession(
        home,
        "replacement-comparison",
        [],
        undefined,
        "2026-08-02T02:00:00Z",
        cwd,
      );
      await writeSession(
        home,
        "older-comparison",
        [],
        undefined,
        "2026-08-01T01:00:00Z",
        cwd,
      );
      await writeSession(
        home,
        "comparison",
        [],
        undefined,
        "2026-08-02T01:00:00Z",
        cwd,
      );
      await writeSession(
        home,
        "unbound-sibling",
        [],
        undefined,
        "2026-08-02T01:00:00Z",
        join(home, "scan-other", "artifacts"),
      );
      const digest = createHash("sha256")
        .update(layout === "unrelated short archive" ? "scan-other" : "scan")
        .digest("hex");
      const directory =
        layout === "original"
          ? scanDir
          : layout === "legacy archive"
            ? scanDir + ".previous-test"
            : join(home, `.previous-${digest}-test`);
      const result = await readSavedScanLogs(
        {
          scanId: "scan-1",
          scanDir: directory,
          mode: "deep",
          continuationThreadId: "owner",
          lifecycle: {
            startedAt: "2026-08-02T00:00:00Z",
            finishedAt: "2026-08-02T02:00:00Z",
          },
          progress: { status: "complete", updatedAt: "2026-08-03T00:00:00Z" },
          executionThreadIds: ["worker"],
        },
        home,
      );
      expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual(
        layout === "unrelated short archive"
          ? ["owner", "worker"]
          : ["comparison", "owner", "worker"],
      );
    },
  );

  test("collects known desktop and CLI threads across active and archived homes without duplicates", async () => {
    const desktop = await temporaryHome();
    const cli = await temporaryHome();
    await writeSession(desktop, "desktop-owner", [
      commandEvent("desktop scan", "owner-call"),
    ]);
    await writeSession(desktop, "worker", [
      commandEvent("stale archived copy", "stale-call"),
    ]);
    await writeSession(
      desktop,
      "worker-child",
      [commandEvent("archived child", "child-call")],
      "worker",
    );
    await writeSession(desktop, "unrelated", [
      commandEvent("unrelated archived scan", "unrelated-call"),
    ]);
    await rename(join(desktop, "sessions"), join(desktop, "archived_sessions"));
    await writeSession(cli, "worker", [
      commandEvent("active worker", "worker-call"),
    ]);
    await writeSession(cli, "owner-child", [], "desktop-owner");
    await writeSession(cli, "other-scan", [
      commandEvent("unrelated CLI scan", "other-call"),
    ]);

    const result = await readSavedScanLogs(
      {
        scanId: "scan-1",
        threadIds: ["desktop-owner", "worker", "worker"],
        executionThreadIds: ["worker"],
      },
      [desktop, cli, desktop],
      { allowMissingRoot: true },
    );

    expect(result.threadId).toBe("desktop-owner");
    expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual([
      "desktop-owner",
      "worker",
      "worker-child",
    ]);
    expect(
      result.events.filter(({ threadId }) => threadId === "worker"),
    ).toHaveLength(2);
    expect(JSON.stringify(result)).toContain("desktop scan");
    expect(JSON.stringify(result)).toContain("active worker");
    expect(JSON.stringify(result)).toContain("archived child");
    expect(JSON.stringify(result)).not.toContain("stale archived copy");
    expect(JSON.stringify(result)).not.toContain("unrelated");
  });

  test.each([
    ["omitted", undefined],
    ["recorded", "missing-owner"],
  ] as const)(
    "feedback collects known worker descendants without the owner log with %s continuation",
    async (_label, continuationThreadId) => {
      const home = await temporaryHome();
      await writeSession(home, "owner-child", [], "missing-owner");
      await writeSession(home, "worker", [
        commandEvent("independent worker", "worker-call"),
      ]);
      await writeSession(home, "worker-child", [], "worker");
      await writeSession(home, "unrelated-child", [], "another-owner");
      const scan = {
        scanId: "scan-1",
        ...(continuationThreadId === undefined ? {} : { continuationThreadId }),
        threadIds: ["missing-owner", "worker"],
        executionThreadIds: ["worker"],
      };

      const result = await readSavedScanLogs(scan, home, {
        allowMissingRoot: true,
      });
      expect(result.threadId).toBe("missing-owner");
      expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual([
        "worker",
        "worker-child",
      ]);
      if (continuationThreadId === undefined) {
        expect(() => readSavedScanLogs(scan, home)).toThrow(
          "No session is associated with scan scan-1.",
        );
      } else {
        await expect(readSavedScanLogs(scan, home)).rejects.toThrow(
          "No saved session logs are available for scan scan-1.",
        );
      }
    },
  );

  const justBeforeCompletion = "2026-08-11T12:03:00.123Z";
  const preciseCompletion = "2026-08-11T12:03:00.123789Z";
  test.each([
    ["complete", preciseCompletion],
    ["failed", preciseCompletion],
    ["canceled", preciseCompletion],
    ["complete", null],
    ["complete", undefined],
  ] as const)(
    "preserves resumed workers with status %s and log boundary %p",
    async (status, logCompletedAt) => {
      const home = await temporaryHome();
      const scanDirectory = join(home, "scans", "resumed");
      const artifacts = join(scanDirectory, "artifacts");
      const afterCompletion = "2026-08-11T12:04:00.000Z";
      const resumed = [
        taskStarted("resume-turn", "2026-08-11T12:02:00.000Z"),
        commandEvent("resumed scan work", "resume-call"),
      ];
      const followup = [
        taskStarted("followup-turn", afterCompletion),
        commandEvent("post-scan followup", "post-call"),
      ];
      await writeSession(
        home,
        "parent",
        [...resumed, ...followup],
        undefined,
        "2026-08-11T12:00:00.000Z",
        scanDirectory,
      );
      for (const [threadId, startedAt, directory] of [
        ["recorded-worker", afterCompletion, artifacts],
        ["resumed-worker", justBeforeCompletion, artifacts],
        ["followup-worker", afterCompletion, artifacts],
        [
          "unrelated-worker",
          justBeforeCompletion,
          join(home, "other-scan", "artifacts"),
        ],
      ] as const) {
        await writeSession(home, threadId, [], undefined, startedAt, directory);
      }

      await writeSession(
        home,
        "followup-child",
        [commandEvent("post-scan child work", "child-call")],
        "parent",
        afterCompletion,
      );

      const result = await readSavedScanLogs(
        {
          scanId: "resumed-scan",
          mode: "deep",
          scanDir: scanDirectory,
          continuationThreadId: "parent",
          executionThreadIds: ["parent", "recorded-worker"],
          progress: {
            status,
            updatedAt: "2026-08-11T12:01:00.000Z",
          },
          updatedAt: "2026-08-11T12:05:00.000Z",
          ...(logCompletedAt === undefined ? {} : { logCompletedAt }),
        },
        home,
      );

      const expected =
        logCompletedAt == null ? [...resumed, ...followup] : resumed;
      expect(
        result.events.filter(({ threadId }) => threadId === "parent").slice(1),
      ).toEqual(expected.map((event) => ({ threadId: "parent", event })));
      expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual(
        logCompletedAt == null
          ? ["followup-child", "parent", "recorded-worker"]
          : ["parent", "recorded-worker", "resumed-worker"],
      );
      expect(
        result.events.some(({ threadId }) => threadId === "followup-child"),
      ).toBe(logCompletedAt == null);
    },
  );

  test("feedback returns an empty log set when no scan threads are recorded", async () => {
    const home = await temporaryHome();
    await writeSession(home, "unrelated", []);
    expect(
      await readSavedScanLogs({ scanId: "scan-1" }, home, {
        allowMissingRoot: true,
      }),
    ).toEqual({
      scanId: "scan-1",
      threadId: null,
      sessions: [],
      events: [],
    });
  });

  test("keeps worker events when the parent rollout disappears after discovery", async () => {
    const home = await temporaryHome();
    await writeSession(home, "parent", []);
    await writeSession(
      home,
      "worker",
      [commandEvent("available worker", "worker-call")],
      "parent",
    );
    const parentPath = join(
      home,
      "sessions",
      "2026",
      "08",
      "11",
      "rollout-parent.jsonl",
    );
    const originalParse = JSON.parse;
    let removed = false;
    const parseSpy = spyOn(JSON, "parse").mockImplementation(
      (text, reviver) => {
        const parsed = originalParse(text, reviver);
        if (!removed && parsed?.payload?.id === "parent") {
          unlinkSync(parentPath);
          removed = true;
        }
        return parsed;
      },
    );
    try {
      const result = await readSavedScanLogs(
        {
          scanId: "scan-1",
          continuationThreadId: "parent",
          executionThreadIds: ["parent"],
        },
        home,
        { allowMissingRoot: true },
      );
      expect(removed).toBe(true);
      expect(result.events.map(({ threadId }) => threadId)).toEqual([
        "worker",
        "worker",
      ]);
    } finally {
      parseSpy.mockRestore();
    }
  });

  test("returns complete parent and worker events without unrelated sessions", async () => {
    const home = await temporaryHome();
    await writeSession(home, "parent", [
      commandEvent(
        "OPENAI_API_KEY=sk-proj-SYNTHETIC_KEY_123 rg authorization /repo/src/auth.ts",
        "call-parent",
        "2026-08-11T12:00:00.000Z",
      ),
    ]);
    await writeSession(
      home,
      "worker",
      [
        commandEvent(
          "python3 -m pytest /repo/tests",
          "call-worker",
          "2026-08-11T12:00:01.000Z",
        ),
        {
          type: "response_item",
          payload: {
            type: "function_call_output",
            call_id: "call-worker",
            status: "failed",
            output: "private command output",
          },
        },
      ],
      "parent",
    );
    await writeSession(home, "unrelated", [
      {
        type: "event_msg",
        payload: { type: "agent_message", message: "private unrelated scan" },
      },
    ]);

    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: home,
    });

    expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual([
      "parent",
      "worker",
    ]);
    expect(result.events.map(({ threadId }) => threadId)).toEqual([
      "parent",
      "parent",
      "worker",
      "worker",
      "worker",
    ]);
    expect(result.events.at(-1)).toMatchObject({
      threadId: "worker",
      event: {
        type: "response_item",
        payload: { status: "failed", output: "private command output" },
      },
    });
    expect(JSON.stringify(result)).toContain("SYNTHETIC_KEY");
    expect(JSON.stringify(result)).toContain("private command output");
    expect(JSON.stringify(result)).not.toContain("private unrelated scan");
  });

  test("reads compressed sessions with metadata split across frames", async () => {
    const home = await temporaryHome();
    await writeSession(
      home,
      "parent",
      [commandEvent("parent work", "parent-call")],
      undefined,
      undefined,
      "/scan",
    );
    await writeSession(
      home,
      "worker",
      [commandEvent("worker work", "worker-call")],
      "parent",
    );
    const directory = join(home, "sessions", "2026", "08", "11");
    for (const threadId of ["parent", "worker"]) {
      const path = join(directory, `rollout-${threadId}.jsonl`);
      const contents = await readFile(path);
      await writeFile(
        `${path}.zst`,
        Buffer.concat([
          zstdCompressSync(contents.subarray(0, 1)),
          zstdCompressSync(contents.subarray(1)),
        ]),
      );
      unlinkSync(path);
    }

    expect(await findScanSession(home, "parent")).toMatchObject({
      workingDirectory: "/scan",
      path: join(directory, "rollout-parent.jsonl.zst"),
    });
    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: home,
    });
    expect(result.events).toEqual([
      expect.objectContaining({ threadId: "parent" }),
      {
        threadId: "parent",
        event: commandEvent("parent work", "parent-call"),
      },
      expect.objectContaining({ threadId: "worker" }),
      {
        threadId: "worker",
        event: commandEvent("worker work", "worker-call"),
      },
    ]);
  });

  test("treats a lone carriage return as a compressed metadata line boundary", async () => {
    const home = await temporaryHome();
    const directory = join(home, "sessions");
    await mkdir(directory);
    const contents =
      '{"type":"session_meta",\r"payload":{"id":"wrong"}}\n' +
      '{"type":"session_meta","payload":{"id":"actual"}}\n';
    await writeFile(
      join(directory, "rollout.jsonl.zst"),
      zstdCompressSync(Buffer.from(contents)),
    );

    expect(await findScanSession(home, "wrong")).toBeNull();
    expect(await findScanSession(home, "actual")).toMatchObject({
      threadId: "actual",
    });
  });

  test("rejects a truncated final frame in a selected rollout", async () => {
    const home = await temporaryHome();
    const directory = join(home, "sessions");
    await mkdir(directory);
    const header = '{"type":"session_meta","payload":{"id":"parent"}}\n';
    const event = JSON.stringify(commandEvent("parent work", "parent-call"));
    const tail = zstdCompressSync(Buffer.from(event + "\n"));
    await writeFile(
      join(directory, "rollout-parent.jsonl.zst"),
      Buffer.concat([
        zstdCompressSync(Buffer.from(header)),
        tail.subarray(0, tail.length - 1),
      ]),
    );
    await expect(
      readScanLogs({ scanId: "scan-1", threadId: "parent", codexHome: home }),
    ).rejects.toThrow();
  });

  test("excludes inherited parent history from worker logs", async () => {
    const home = await temporaryHome();
    await writeSession(home, "parent", []);
    const startedAt = "2026-08-11T12:02:00.900Z";
    await writeSession(
      home,
      "worker",
      [
        {
          type: "session_meta",
          payload: { id: "parent", timestamp: "2026-08-11T12:00:00.000Z" },
        },
        {
          type: "event_msg",
          payload: {
            type: "task_started",
            started_at: Date.parse("2026-08-11T12:00:00.000Z") / 1_000,
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_message",
            message: "PRIVATE PRE-SCAN CONVERSATION",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "task_started",
            started_at: Math.floor(Date.parse(startedAt) / 1_000),
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "agent_message",
            message: "Reviewing authorization",
          },
        },
      ],
      "parent",
      startedAt,
    );

    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: home,
    });
    expect(JSON.stringify(result)).toContain("Reviewing authorization");
    expect(JSON.stringify(result)).not.toContain("PRIVATE PRE-SCAN");
  });

  test("includes independent Deep workers without crossing scan boundaries", async () => {
    const home = await temporaryHome();
    const scanDirectory = join(home, "scans", "current");
    const artifacts = join(scanDirectory, "artifacts");
    await writeSession(
      home,
      "parent",
      [],
      undefined,
      "2026-08-11T12:00:00.900Z",
      scanDirectory,
    );
    const workerDirectory = join(
      artifacts,
      "deep_discovery",
      "workers",
      "worker-1",
      "output",
    );
    await writeSession(
      home,
      "worker",
      [commandEvent("review current worker", "worker-call")],
      undefined,
      "2026-08-11T12:00:00.950Z",
      process.platform === "win32"
        ? workerDirectory.toUpperCase()
        : workerDirectory,
    );
    await writeSession(
      home,
      "reducer",
      [commandEvent("reduce current findings", "reducer-call")],
      undefined,
      "2026-08-11T12:02:00.000Z",
      process.platform === "win32" ? artifacts.toUpperCase() : artifacts,
    );
    await writeSession(home, "worker-child", [], "worker");
    for (const [threadId, directory, startedAt] of [
      [
        "stale-worker",
        join(artifacts, "deep_discovery", "workers", "stale", "output"),
        "2026-08-11T11:59:00.000Z",
      ],
      ["same-second-previous-scan", artifacts, "2026-08-11T12:00:00.100Z"],
      ["completion-instant", artifacts, "2026-08-11T12:02:00.001Z"],
      ["after-completion", artifacts, "2026-08-11T12:02:00.002Z"],
      [
        "invalid-start",
        join(artifacts, "deep_discovery", "workers", "invalid", "output"),
        "not-a-timestamp",
      ],
      [
        "sibling-directory",
        join(artifacts, "deep_discovery", "output"),
        "2026-08-11T12:01:00.000Z",
      ],
      [
        "nested-scan",
        join(scanDirectory, "nested", "artifacts"),
        "2026-08-11T12:01:00.000Z",
      ],
    ] as const) {
      await writeSession(
        home,
        threadId,
        [commandEvent(`exclude ${threadId}`, `${threadId}-call`)],
        undefined,
        startedAt,
        directory,
      );
    }
    await writeSession(
      home,
      "unknown-start",
      [commandEvent("exclude unknown-start", "unknown-call")],
      undefined,
      undefined,
      join(artifacts, "deep_discovery", "workers", "unknown", "output"),
    );

    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: home,
      scanDirectory,
      completedAt: "2026-08-11T12:02:00.001Z",
    });

    expect(result.sessions.map(({ threadId }) => threadId).sort()).toEqual([
      "parent",
      "reducer",
      "worker",
      "worker-child",
    ]);
    expect(JSON.stringify(result)).toContain("review current worker");
    expect(JSON.stringify(result)).toContain("reduce current findings");
    expect(JSON.stringify(result)).not.toContain("exclude ");
  });

  test("keeps archived Deep workers without exposing later replacement sessions", async () => {
    const home = await temporaryHome();
    const original = join(home, "scans", "results");
    const archived = `${original}.previous-20260811T120300-a1b2c3d4`;
    const completedAt = "2026-08-11T12:02:00.000Z";
    await writeSession(
      home,
      "archived-parent",
      [],
      undefined,
      "2026-08-11T12:00:00.000Z",
      original,
    );
    await writeSession(
      home,
      "archived-worker",
      [commandEvent("review archived scan", "archived-call")],
      undefined,
      "2026-08-11T12:01:00.000Z",
      join(original, "artifacts", "deep_discovery", "workers", "old", "output"),
    );
    await writeSession(
      home,
      "replacement-worker",
      [commandEvent("PRIVATE REPLACEMENT SCAN", "replacement-call")],
      undefined,
      "2026-08-11T12:03:00.000Z",
      join(original, "artifacts"),
    );

    const options = {
      scanId: "archived-scan",
      threadId: "archived-parent",
      codexHome: home,
      scanDirectory: archived,
      completedAt,
    };
    const archivedLogs = await readScanLogs(options);
    expect(archivedLogs.sessions.map(({ threadId }) => threadId)).toEqual([
      "archived-parent",
      "archived-worker",
    ]);
    expect(JSON.stringify(archivedLogs)).toContain("review archived scan");
    expect(JSON.stringify(archivedLogs)).not.toContain("PRIVATE REPLACEMENT");
    const digest = createHash("sha256").update("results").digest("hex");
    const shortArchive = join(home, "scans", `.previous-${digest}-a1b2c3d4`);
    expect(
      await readScanLogs({ ...options, scanDirectory: shortArchive }),
    ).toEqual(archivedLogs);

    for (const logCompletedAt of [null, undefined]) {
      const legacyLogs = await readSavedScanLogs(
        {
          scanId: "archived-scan",
          mode: "deep",
          scanDir: archived,
          continuationThreadId: "archived-parent",
          executionThreadIds: ["archived-parent"],
          progress: { status: "complete", updatedAt: completedAt },
          ...(logCompletedAt === undefined ? {} : { logCompletedAt }),
        },
        home,
      );
      expect(legacyLogs).toEqual(archivedLogs);
    }

    const unrelatedRoot = await readScanLogs({
      ...options,
      scanDirectory: join(home, "scans", "unrelated.previous-fixture"),
    });
    expect(unrelatedRoot.sessions.map(({ threadId }) => threadId)).toEqual([
      "archived-parent",
    ]);

    const malformedCompletion = await readScanLogs({
      ...options,
      completedAt: "invalid-timestamp",
    });
    expect(
      malformedCompletion.sessions.map(({ threadId }) => threadId),
    ).toEqual(["archived-parent"]);

    const runningLogs = await readScanLogs({ ...options, completedAt: null });
    expect(runningLogs.sessions.map(({ threadId }) => threadId).sort()).toEqual(
      ["archived-parent", "archived-worker", "replacement-worker"],
    );
  });

  const scanCompletion = "2026-08-11T12:02:00.000Z";
  const followupStart = "2026-08-11T12:03:00.000Z";
  test.each([
    ["without a follow-up", scanCompletion, null, false],
    ["with a follow-up", scanCompletion, followupStart, true],
    ["with a follow-up at completion", followupStart, followupStart, true],
    [
      "with a turn just before completion",
      preciseCompletion,
      justBeforeCompletion,
      false,
    ],
    ["while running", null, followupStart, false],
    ["without completion", undefined, followupStart, false],
    ["with invalid completion", "invalid", followupStart, false],
    ["without a turn timestamp", scanCompletion, undefined, false],
    ["with an invalid turn timestamp", scanCompletion, "invalid", false],
  ] as const)(
    "preserves the finishing scan turn %s",
    async (_label, completedAt, followupAt, excludeFollowup) => {
      const home = await temporaryHome();
      const scanEvents = [
        taskStarted("scan-turn", "2026-08-11T12:00:00.000Z"),
        {
          timestamp: "2026-08-11T12:01:59.000Z",
          type: "response_item",
          payload: {
            type: "function_call",
            name: "mcp__codex_security__complete_codex_security_scan",
            call_id: "completion-call",
            arguments: "{}",
          },
        },
        {
          timestamp: "2026-08-11T12:02:01.000Z",
          type: "response_item",
          payload: {
            type: "function_call_output",
            call_id: "completion-call",
            output: "Scan completed.",
          },
        },
        {
          timestamp: "2026-08-11T12:02:02.000Z",
          type: "event_msg",
          payload: { type: "agent_message", message: "Scan report is ready." },
        },
        {
          timestamp: "2026-08-11T12:02:03.000Z",
          type: "event_msg",
          payload: { type: "task_complete", turn_id: "scan-turn" },
        },
      ];
      const followup =
        followupAt === null
          ? []
          : [
              taskStarted("followup-turn", followupAt),
              commandEvent("post-scan followup", "post-call"),
            ];
      await writeSession(home, "parent", [...scanEvents, ...followup]);

      const result = await readScanLogs({
        scanId: "scan-555",
        threadId: "parent",
        codexHome: home,
        logCompletedAt: completedAt,
      });

      const expected = excludeFollowup
        ? scanEvents
        : [...scanEvents, ...followup];
      expect(result.events.slice(1)).toEqual(
        expected.map((event) => ({ threadId: "parent", event })),
      );
    },
  );

  test.each([false, true])(
    "does not parse event bodies from unrelated saved sessions (copied: %p)",
    async (copied) => {
      const home = await temporaryHome();
      await writeSession(home, "parent", [
        commandEvent("included", "parent-call"),
      ]);
      const unrelated = commandEvent(
        "UNRELATED_PRIVATE_EVENT_BODY",
        "unrelated-call",
      );
      await writeSession(home, "unrelated", [unrelated]);
      const homes = [home];
      if (copied) {
        const copyHome = await temporaryHome();
        await writeSession(copyHome, "unrelated", [unrelated, unrelated]);
        homes.push(copyHome);
      }
      const originalParse = JSON.parse;
      let unrelatedBodies = 0;
      const parseSpy = spyOn(JSON, "parse").mockImplementation(
        (text, reviver) => {
          if (text.includes("UNRELATED_PRIVATE_EVENT_BODY")) unrelatedBodies++;
          return originalParse(text, reviver);
        },
      );

      try {
        const result = await readScanLogs({
          scanId: "scan-1",
          threadId: "parent",
          codexHome: homes,
        });
        expect(result.sessions.map(({ threadId }) => threadId)).toEqual([
          "parent",
        ]);
        expect(unrelatedBodies).toBe(0);
      } finally {
        parseSpy.mockRestore();
      }
    },
  );

  test("preserves large selected events and skips malformed metadata prefixes", async () => {
    const home = await temporaryHome();
    const output = "x".repeat(2 * 1024 * 1024 + 1);
    await writeSession(home, "parent", [
      { type: "response_item", payload: { output } },
    ]);
    const path = join(
      home,
      "sessions",
      "2026",
      "08",
      "11",
      "rollout-parent.jsonl",
    );
    await writeFile(path, `not json\n42\n${await readFile(path, "utf8")}`);

    const result = await readScanLogs({
      scanId: "scan-1",
      threadId: "parent",
      codexHome: home,
    });

    expect(result.events.at(-1)?.["event"]).toMatchObject({
      payload: { output },
    });
  });

  test("reports when the saved scan session is missing", async () => {
    const home = await temporaryHome();
    await expect(
      readScanLogs({
        scanId: "scan-1",
        threadId: "missing",
        codexHome: home,
      }),
    ).rejects.toThrow("No saved session logs are available for scan scan-1.");
  });
});

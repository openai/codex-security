import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import type { CodexRolloutSnapshot } from "../src/codex-rollouts.js";
import {
  MAX_ROLLOUT_SESSION_INDEX_ENTRIES,
  ROLLOUT_SESSION_INDEX_RELATIVE_PATH,
  writeRolloutSessionIndex,
  type RolloutSessionIndex,
} from "../src/rollout-session-index.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(prefix: string): Promise<string> {
  const directory = await realpath(await mkdtemp(join(tmpdir(), prefix)));
  temporaryDirectories.push(directory);
  return directory;
}

async function fixture(): Promise<{
  codexHome: string;
  scanDir: string;
  snapshot: CodexRolloutSnapshot;
}> {
  const root = await temporaryDirectory("codex-security-session-index-");
  const codexHome = join(root, "codex-home");
  const scanDir = join(root, "scan");
  const sessionDirectory = join(codexHome, "sessions", "2026", "08", "04");
  await mkdir(sessionDirectory, { recursive: true });
  await mkdir(scanDir, { mode: 0o700 });
  const coordinator = join(sessionDirectory, "rollout-coordinator.jsonl");
  const worker = join(sessionDirectory, "rollout-worker.jsonl");
  await writeFile(coordinator, "coordinator private source\n");
  await writeFile(worker, "worker private source\n");
  return {
    codexHome,
    scanDir,
    snapshot: {
      complete: true,
      rootThreadId: "coordinator",
      sessions: [
        {
          path: coordinator,
          threadId: "coordinator",
          parentThreadId: null,
          usage: null,
        },
        {
          path: worker,
          threadId: "worker",
          parentThreadId: "coordinator",
          usage: null,
        },
      ],
    },
  };
}

async function readIndex(path: string): Promise<RolloutSessionIndex> {
  return JSON.parse(await readFile(path, "utf8")) as RolloutSessionIndex;
}

describe("rollout session index", () => {
  test("indexes source rollouts without copying sensitive contents by default", async () => {
    const { codexHome, scanDir, snapshot } = await fixture();

    const path = await writeRolloutSessionIndex({
      codexHome,
      scanDir,
      snapshot,
      retain: false,
    });

    expect(path).toBe(join(scanDir, ...ROLLOUT_SESSION_INDEX_RELATIVE_PATH));
    expect(await readIndex(path)).toEqual({
      schemaVersion: 1,
      rootThreadId: "coordinator",
      complete: true,
      retained: false,
      sessions: [
        {
          threadId: "coordinator",
          parentThreadId: null,
          role: "coordinator",
          sourcePath: snapshot.sessions[0]!.path,
        },
        {
          threadId: "worker",
          parentThreadId: "coordinator",
          role: "worker",
          sourcePath: snapshot.sessions[1]!.path,
        },
      ],
    });
    await expect(
      lstat(join(scanDir, "artifacts", "rollout-sessions", "sessions")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("copies only indexed rollouts into private artifacts when requested", async () => {
    const { codexHome, scanDir, snapshot } = await fixture();

    const path = await writeRolloutSessionIndex({
      codexHome,
      scanDir,
      snapshot,
      retain: true,
    });
    const index = await readIndex(path);

    expect(index.retained).toBe(true);
    expect(index.sessions.map((session) => session.retainedPath)).toEqual([
      "artifacts/rollout-sessions/sessions/2026/08/04/rollout-coordinator.jsonl",
      "artifacts/rollout-sessions/sessions/2026/08/04/rollout-worker.jsonl",
    ]);
    for (const [session, source] of index.sessions.map(
      (session, index) => [session, snapshot.sessions[index]!.path] as const,
    )) {
      const retainedPath = join(scanDir, ...session.retainedPath!.split("/"));
      expect(await readFile(retainedPath, "utf8")).toBe(
        await readFile(source, "utf8"),
      );
      if (process.platform !== "win32") {
        expect((await lstat(retainedPath)).mode & 0o777).toBe(0o600);
      }
    }
    if (process.platform !== "win32") {
      expect((await lstat(path)).mode & 0o777).toBe(0o600);
      expect(
        (await lstat(join(scanDir, "artifacts", "rollout-sessions"))).mode &
          0o777,
      ).toBe(0o700);
    }
  });

  test("rejects indexes that exceed the session safety limit", async () => {
    const { codexHome, scanDir, snapshot } = await fixture();

    await expect(
      writeRolloutSessionIndex({
        codexHome,
        scanDir,
        snapshot: {
          ...snapshot,
          sessions: Array.from(
            { length: MAX_ROLLOUT_SESSION_INDEX_ENTRIES + 1 },
            (_, index) => ({
              ...snapshot.sessions[0]!,
              threadId: `thread-${index}`,
            }),
          ),
        },
        retain: false,
      }),
    ).rejects.toThrow(
      `exceeds the ${MAX_ROLLOUT_SESSION_INDEX_ENTRIES}-session safety limit`,
    );
  });

  test("accepts an index at the session safety limit", async () => {
    const { codexHome, scanDir, snapshot } = await fixture();
    const path = await writeRolloutSessionIndex({
      codexHome,
      scanDir,
      snapshot: {
        ...snapshot,
        sessions: Array.from(
          { length: MAX_ROLLOUT_SESSION_INDEX_ENTRIES },
          (_, index) => ({
            ...snapshot.sessions[0]!,
            threadId: `thread-${index}`,
          }),
        ),
      },
      retain: false,
    });

    expect((await readIndex(path)).sessions).toHaveLength(
      MAX_ROLLOUT_SESSION_INDEX_ENTRIES,
    );
  });
});

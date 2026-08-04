import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { CodexRolloutReader } from "../src/codex-rollouts.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function codexHome(): Promise<string> {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-rollouts-")),
  );
  temporaryDirectories.push(directory);
  return directory;
}

async function writeSession(
  home: string,
  threadId: string,
  parentThreadId?: string,
  nestedParent = false,
): Promise<string> {
  const directory = join(home, "sessions", "2026", "08", "04");
  await mkdir(directory, { recursive: true });
  const path = join(directory, `rollout-${threadId}.jsonl`);
  await writeFile(
    path,
    [
      "not json",
      JSON.stringify({
        type: "session_meta",
        payload: {
          id: threadId,
          ...(parentThreadId === undefined
            ? {}
            : nestedParent
              ? {
                  source: {
                    subagent: {
                      thread_spawn: { parent_thread_id: parentThreadId },
                    },
                  },
                }
              : { parent_thread_id: parentThreadId }),
        },
      }),
      JSON.stringify({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: {
            total_token_usage: {
              input_tokens: threadId.length,
              output_tokens: 1,
            },
          },
        },
      }),
      "",
    ].join("\n"),
  );
  return path;
}

describe("Codex rollout discovery", () => {
  test("indexes the coordinator and transitive workers without unrelated sessions", async () => {
    const home = await codexHome();
    const rootPath = await writeSession(home, "scan-thread");
    const childPath = await writeSession(
      home,
      "worker-thread",
      "scan-thread",
      true,
    );
    const grandchildPath = await writeSession(
      home,
      "nested-worker-thread",
      "worker-thread",
    );
    await writeSession(home, "unrelated-thread");
    await writeSession(home, "unrelated-worker", "unrelated-thread", true);

    const reader = new CodexRolloutReader(home);
    const sessions = await reader.refresh("scan-thread");

    expect(sessions).toEqual([
      {
        path: rootPath,
        threadId: "scan-thread",
        parentThreadId: null,
        usage: {
          input_tokens: 11,
          cached_input_tokens: 0,
          cache_write_input_tokens: 0,
          output_tokens: 1,
          reasoning_output_tokens: 0,
          total_tokens: 12,
        },
      },
      {
        path: grandchildPath,
        threadId: "nested-worker-thread",
        parentThreadId: "worker-thread",
        usage: expect.any(Object),
      },
      {
        path: childPath,
        threadId: "worker-thread",
        parentThreadId: "scan-thread",
        usage: expect.any(Object),
      },
    ]);
    expect(reader.snapshot("scan-thread")).toMatchObject({
      complete: true,
      rootThreadId: "scan-thread",
      sessions,
    });
  });

  test("marks discovery incomplete when the coordinator rollout is unavailable", async () => {
    const home = await codexHome();
    const childPath = await writeSession(home, "worker-thread", "scan-thread");
    const reader = new CodexRolloutReader(home);

    expect(await reader.refresh("scan-thread")).toEqual([
      {
        path: childPath,
        threadId: "worker-thread",
        parentThreadId: "scan-thread",
        usage: expect.any(Object),
      },
    ]);
    expect(reader.snapshot("scan-thread").complete).toBe(false);
  });
});

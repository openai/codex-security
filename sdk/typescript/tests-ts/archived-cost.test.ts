import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { ScanCostTracker } from "../src/cost.js";
import { findScanSession } from "../src/scan-logs.js";

test.each([false, true])(
  "recovers archived root and worker costs once (live copy: %p)",
  async (liveCopy) => {
    const home = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-archived-cost-")),
    );
    const session = (id: string, inputTokens: number, parent?: string) =>
      [
        {
          type: "session_meta",
          payload: {
            id,
            cwd: join(home, "scan"),
            timestamp: "2026-08-11T12:00:00Z",
            ...(parent === undefined
              ? {}
              : {
                  source: {
                    subagent: { thread_spawn: { parent_thread_id: parent } },
                  },
                }),
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "token_count",
            info: {
              total_token_usage: {
                input_tokens: inputTokens,
                output_tokens: 1,
              },
            },
          },
        },
      ]
        .map((event) => JSON.stringify(event))
        .join("\n") + "\n";
    try {
      await mkdir(join(home, "archived_sessions"));
      await writeFile(
        join(home, "archived_sessions", "root.jsonl"),
        session("root", 100),
      );
      await writeFile(
        join(home, "archived_sessions", "worker.jsonl"),
        session("worker", 50, "root"),
      );
      if (liveCopy) {
        await mkdir(join(home, "sessions"));
        await writeFile(
          join(home, "sessions", "root.jsonl"),
          session("root", 100),
        );
      }
      expect(await findScanSession(home, "worker")).toMatchObject({
        threadId: "worker",
        parentThreadId: "root",
      });
      const ordinary = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
      });
      ordinary.start("root");
      expect((await ordinary.stop()).cost?.inputTokens ?? null).toBe(
        liveCopy ? 100 : null,
      );
      const recovery = new ScanCostTracker({
        codexHome: home,
        model: "gpt-5.6-sol",
        includeArchivedSessions: true,
      });
      recovery.start("root");
      expect(await recovery.stop()).toMatchObject({
        usage: { input_tokens: 150, output_tokens: 2, total_tokens: 152 },
        cost: { inputTokens: 150, outputTokens: 2 },
      });
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  },
);

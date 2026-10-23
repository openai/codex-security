import {
  appendFile,
  copyFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { EventEmitter } from "node:events";
import { stripVTControlCharacters } from "node:util";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { ScanCostTracker, type ScanSessionEvent } from "../src/cost.js";
import { ScanDashboard } from "../src/scan-dashboard.js";
import { capture } from "./cli-fixtures.js";
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

test.each(["live", "archive", "both"] as const)(
  "replays copied root and worker transcripts once when %s logs arrive first",
  async (initial) => {
    const home = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-archived-events-")),
    );
    const live = join(home, "sessions");
    const archive = join(home, "archived_sessions");
    const event = (text: string) =>
      JSON.stringify({
        type: "response_item",
        payload: {
          type: "function_call",
          name: "exec_command",
          arguments: text,
        },
      }) + "\n";
    const transcript = (id: string, tokens: number, parent?: string) =>
      [
        JSON.stringify({
          type: "session_meta",
          payload: { id, ...(parent ? { parent_thread_id: parent } : {}) },
        }),
        JSON.stringify({
          type: "event_msg",
          payload: {
            type: "token_count",
            info: {
              total_token_usage: { input_tokens: tokens, output_tokens: 1 },
            },
          },
        }),
        "",
      ].join("\n") +
      event(id === "root" ? "synthetic-repeat" : "synthetic-worker") +
      (id === "root" ? event("synthetic-repeat") : "");
    const stderr = capture(true);
    const input = Object.assign(new EventEmitter(), { isTTY: true });
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 140, rows: 40 },
      {
        repository: "/synthetic/repository",
        input,
        clock: {
          now: () => 0,
          setInterval: () => ({}) as NodeJS.Timeout,
          clearInterval() {},
        },
      },
    );
    const events: ScanSessionEvent[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      includeArchivedSessions: true,
      onSessionEvent(value) {
        events.push(value);
        dashboard.recordDetails(value);
      },
    });
    try {
      await mkdir(live);
      await mkdir(archive);
      for (const directory of initial === "both"
        ? [live, archive]
        : [initial === "live" ? live : archive]) {
        await writeFile(join(directory, "root.jsonl"), transcript("root", 100));
        await writeFile(
          join(directory, "worker.jsonl"),
          transcript("worker", 50, "root"),
        );
      }
      dashboard.start();
      tracker.start("root");
      expect((await tracker.stop()).cost?.inputTokens).toBe(150);
      expect(events).toHaveLength(7);
      const earlier = initial === "archive" ? archive : live;
      const later = initial === "archive" ? live : archive;
      for (const id of ["root", "worker"]) {
        await copyFile(
          join(earlier, `${id}.jsonl`),
          join(later, `${id}.jsonl`),
        );
        await appendFile(
          join(later, `${id}.jsonl`),
          event(`synthetic-later-${id}`),
        );
      }
      expect((await tracker.refresh()).cost?.inputTokens).toBe(150);
      expect(events).toHaveLength(9);
      // Equal event contents at distinct transcript positions are real events.
      await appendFile(
        join(later, "root.jsonl"),
        event("synthetic-later-root"),
      );
      await tracker.refresh();
      expect(events).toHaveLength(10);
      for (const id of ["root", "worker"])
        await copyFile(
          join(later, `${id}.jsonl`),
          join(earlier, `${id}.jsonl`),
        );
      await tracker.refresh();
      expect(events).toHaveLength(10);
      await appendFile(
        join(earlier, "worker.jsonl"),
        event("synthetic-final-worker"),
      );
      await tracker.refresh();
      expect(events).toHaveLength(11);
      input.emit("data", "d");
      const frame = stripVTControlCharacters(
        stderr.text().split("\u001B[H").at(-1)!,
      );
      expect(frame.match(/synthetic-repeat/gu)).toHaveLength(2);
      expect(frame.match(/synthetic-later-root/gu)).toHaveLength(2);
      expect(frame.match(/synthetic-later-worker/gu)).toHaveLength(1);
      expect(frame.match(/synthetic-final-worker/gu)).toHaveLength(1);
    } finally {
      await tracker.stop();
      dashboard.stop();
      await rm(home, { recursive: true, force: true });
    }
  },
);

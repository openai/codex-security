import { describe, expect, test } from "bun:test";
import {
  scanProgressUpdatesFromEvent,
  workerStatusFromEvent,
} from "../src/worker-progress.js";

function messageEvent(text: string): Record<string, unknown> {
  return {
    type: "item.completed",
    item: { id: "message-1", type: "agent_message", text },
  };
}

describe("worker progress Markdown fences", () => {
  test("does not close a longer outer fence with a shorter backtick run", () => {
    const text = [
      "````markdown",
      "```text",
      'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":8,"filesTotal":8}',
      "```",
      "````",
    ].join("\n");

    expect(scanProgressUpdatesFromEvent(messageEvent(text))).toEqual([]);
  });

  test("ignores worker-status markers inside fenced examples", () => {
    const text = [
      "Example:",
      "```text",
      'CODEX_SECURITY_WORKER_STATUS {"phase":"file_review","planned":6,"started":6}',
      "```",
    ].join("\n");

    expect(workerStatusFromEvent(messageEvent(text))).toBeNull();
  });

  test("supports tilde fences and still reads markers after a fence closes", () => {
    const text = [
      "~~~text",
      'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":7,"filesTotal":8}',
      'CODEX_SECURITY_WORKER_STATUS {"phase":"file_review","planned":6,"started":5}',
      "~~~",
      'CODEX_SECURITY_SCAN_PROGRESS {"phase":"validation","filesCompleted":8,"filesTotal":8}',
      'CODEX_SECURITY_WORKER_STATUS {"phase":"validation","planned":2,"started":2}',
    ].join("\n");

    expect(scanProgressUpdatesFromEvent(messageEvent(text))).toEqual([
      { phase: "validation", filesCompleted: 8, filesTotal: 8 },
    ]);
    expect(workerStatusFromEvent(messageEvent(text))).toEqual({
      kind: "dispatch",
      phase: "validation",
      planned: 2,
      started: 2,
    });
  });
});

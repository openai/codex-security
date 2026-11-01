import { describe, expect, test } from "bun:test";
import {
  scanProgressUpdatesFromEvent,
  workerStatusFromEvent,
} from "../src/worker-progress.js";

function commandEvent(
  command: string,
  output: string,
): Record<string, unknown> {
  return {
    type: "item.completed",
    item: {
      id: "command-1",
      type: "command_execution",
      command,
      aggregated_output: output,
      exit_code: 0,
      status: "completed",
    },
  };
}

function messageEvent(text: string): Record<string, unknown> {
  return {
    type: "item.completed",
    item: { id: "message-1", type: "agent_message", text },
  };
}

describe("worker progress events", () => {
  test("ignores incomplete and malformed event envelopes", () => {
    const progress =
      'CODEX_SECURITY_SCAN_PROGRESS {"phase":"reporting","filesCompleted":1,"filesTotal":1}';
    const dispatch =
      'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":1,"started":1}';
    for (const event of [
      {},
      { type: "item.completed", item: null },
      { type: "item.completed", item: [] },
      { ...messageEvent(progress), type: "item.started" },
      { ...messageEvent(dispatch), type: "item.updated" },
      {
        type: "item.completed",
        item: { type: "reasoning", text: `${progress}\n${dispatch}` },
      },
      {
        type: "item.completed",
        item: { type: "reasoning", aggregated_output: progress },
      },
      { type: "item.completed", item: { type: "agent_message", text: null } },
      messageEvent(
        "CODEX_SECURITY_SCAN_PROGRESS not-json\nCODEX_SECURITY_WORKER_STATUS null",
      ),
    ]) {
      expect(workerStatusFromEvent(event)).toBeNull();
      expect(scanProgressUpdatesFromEvent(event)).toEqual([]);
    }
  });

  test("reads a dispatch marker from the agent message", () => {
    expect(
      workerStatusFromEvent(
        messageEvent(
          'Reviewing the ranked worklist.\nCODEX_SECURITY_WORKER_STATUS {"phase":"file_review","planned":6,"started":3}',
        ),
      ),
    ).toEqual({
      kind: "dispatch",
      phase: "file_review",
      planned: 6,
      started: 3,
    });
    expect(
      workerStatusFromEvent(
        messageEvent(
          'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":6,"started":0}',
        ),
      ),
    ).toEqual({ kind: "dispatch", phase: "ranking", planned: 6, started: 0 });
  });

  test("reads the current phase and fully reviewed file counts", () => {
    expect(
      scanProgressUpdatesFromEvent(
        messageEvent(
          'Reviewing the file inventory.\nCODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}',
        ),
      ),
    ).toEqual([{ phase: "discovery", filesCompleted: 3, filesTotal: 8 }]);
    expect(
      scanProgressUpdatesFromEvent(
        messageEvent(
          'CODEX_SECURITY_SCAN_PROGRESS {"phase":"validation","filesCompleted":8,"filesTotal":8}',
        ),
      ),
    ).toEqual([{ phase: "validation", filesCompleted: 8, filesTotal: 8 }]);
  });

  test("reads every file update from a completed review command", () => {
    const output = [
      "--- inventory ---",
      'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":0,"filesTotal":2}',
      "--- commands.py ---",
      "import subprocess",
      "--- server.py ---",
      "from http.server import HTTPServer",
      'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":2,"filesTotal":2}',
    ].join("\n");

    expect(
      scanProgressUpdatesFromEvent(
        commandEvent("review the full inventory", output),
      ),
    ).toEqual([
      { phase: "discovery", filesCompleted: 0, filesTotal: 2 },
      { phase: "discovery", filesCompleted: 2, filesTotal: 2 },
    ]);
  });

  test("keeps valid progress when another update is invalid", () => {
    expect(
      scanProgressUpdatesFromEvent(
        commandEvent(
          "review the full inventory",
          [
            'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":0,"filesTotal":2}',
            'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":2}',
            'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":2,"filesTotal":2}',
          ].join("\n"),
        ),
      ),
    ).toEqual([
      { phase: "discovery", filesCompleted: 0, filesTotal: 2 },
      { phase: "discovery", filesCompleted: 2, filesTotal: 2 },
    ]);
  });

  test("accepts additional progress fields, multiple markers, and verbose output", () => {
    expect(
      scanProgressUpdatesFromEvent(
        messageEvent(
          [
            "x".repeat(65 * 1024),
            'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8,"path":"/repository"}',
            'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":4,"filesTotal":8}',
          ].join("\n"),
        ),
      ),
    ).toEqual([
      { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
      { phase: "discovery", filesCompleted: 4, filesTotal: 8 },
    ]);
  });

  test("accepts verbose worker status and more than 1,024 workers", () => {
    expect(
      workerStatusFromEvent(
        messageEvent(
          `${"x".repeat(65 * 1024)}\nCODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":2048,"started":1025,"timestamp":1}`,
        ),
      ),
    ).toEqual({
      kind: "dispatch",
      phase: "ranking",
      planned: 2048,
      started: 1025,
    });
  });

  test("does not mistake documented examples for real scan progress", () => {
    const progress = {
      phase: "discovery" as const,
      filesCompleted: 3,
      filesTotal: 8,
    };
    const marker = `CODEX_SECURITY_SCAN_PROGRESS ${JSON.stringify(progress)}`;
    for (const indent of ["", " ", "  ", "   "]) {
      expect(
        scanProgressUpdatesFromEvent(
          commandEvent(
            "read the scan workflow",
            [
              "Example progress:",
              `${indent}\`\`\`text`,
              marker,
              `${indent}\`\`\``,
              marker,
            ].join("\n"),
          ),
        ),
      ).toEqual([progress]);
    }
    expect(
      scanProgressUpdatesFromEvent(
        messageEvent(`Inline \`\`\` is not a fence.\n${marker}`),
      ),
    ).toEqual([progress]);
  });

  test("ignores progress and dispatch markers inside nested or tilde fences", () => {
    const progress = {
      phase: "discovery" as const,
      filesCompleted: 3,
      filesTotal: 8,
    };
    const progressMarker = `CODEX_SECURITY_SCAN_PROGRESS ${JSON.stringify(progress)}`;
    const liveProgress = { ...progress, filesCompleted: 4 };
    const liveMarker = `CODEX_SECURITY_SCAN_PROGRESS ${JSON.stringify(liveProgress)}`;
    const dispatchMarker = `CODEX_SECURITY_WORKER_STATUS ${JSON.stringify({
      phase: "file_review",
      planned: 6,
      started: 3,
    })}`;
    // A four-backtick fence is not closed by an inner three-backtick line.
    expect(
      scanProgressUpdatesFromEvent(
        commandEvent(
          "read the scan workflow",
          [
            "````markdown",
            "```text",
            progressMarker,
            "```",
            "````",
            liveMarker,
          ].join("\n"),
        ),
      ),
    ).toEqual([liveProgress]);
    // A tilde fence is not closed by a backtick fence.
    const liveDispatch = {
      phase: "validation" as const,
      planned: 2,
      started: 2,
    };
    const text = [
      "~~~text",
      progressMarker,
      "```",
      progressMarker,
      dispatchMarker,
      "~~~",
      liveMarker,
      `CODEX_SECURITY_WORKER_STATUS ${JSON.stringify(liveDispatch)}`,
    ].join("\n");
    expect(
      scanProgressUpdatesFromEvent(
        commandEvent("read the scan workflow", text),
      ),
    ).toEqual([liveProgress]);
    const message = messageEvent(text);
    expect(scanProgressUpdatesFromEvent(message)).toEqual([liveProgress]);
    expect(workerStatusFromEvent(message)).toEqual({
      kind: "dispatch",
      ...liveDispatch,
    });
    // Dispatch markers inside a fenced block are not live worker status.
    expect(
      workerStatusFromEvent(
        messageEvent(["Example:", "```text", dispatchMarker, "```"].join("\n")),
      ),
    ).toBeNull();
  });

  test("rejects malformed or overstated file progress", () => {
    for (const text of [
      'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":9,"filesTotal":8}',
      'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":-1,"filesTotal":8}',
      'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":1.5,"filesTotal":8}',
      'CODEX_SECURITY_SCAN_PROGRESS {"phase":"unknown","filesCompleted":3,"filesTotal":8}',
    ]) {
      expect(scanProgressUpdatesFromEvent(messageEvent(text))).toEqual([]);
    }
    expect(
      scanProgressUpdatesFromEvent(commandEvent("rg scan progress", "{}")),
    ).toEqual([]);
  });

  test("ignores unrelated, malformed, or conflicting events", () => {
    for (const event of [
      messageEvent(
        'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":2,"started":3}',
      ),
      messageEvent(
        'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":-1,"started":0}',
      ),
      messageEvent(
        'CODEX_SECURITY_WORKER_STATUS {"phase":"discovery","planned":2,"started":1}',
      ),
      messageEvent(
        'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":2,"started":1}\nCODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":2,"started":0}',
      ),
    ]) {
      expect(workerStatusFromEvent(event)).toBeNull();
    }
  });
});

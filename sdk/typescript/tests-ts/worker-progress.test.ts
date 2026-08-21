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
    const preflight = JSON.stringify({
      profile: "security_scan",
      results: [{ capability: "delegated_workers", status: "pass" }],
    });
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
      {
        type: "item.completed",
        item: {
          type: "command_execution",
          command: ["config_preflight.py"],
          aggregated_output: preflight,
        },
      },
      {
        type: "item.completed",
        item: {
          type: "command_execution",
          command: "config_preflight.py",
          aggregated_output: [preflight],
        },
      },
      {
        type: "item.completed",
        item: {
          type: "command_execution",
          command: null,
          aggregated_output: 1,
        },
      },
      messageEvent(
        "CODEX_SECURITY_SCAN_PROGRESS not-json\nCODEX_SECURITY_WORKER_STATUS null",
      ),
    ]) {
      expect(workerStatusFromEvent(event)).toBeNull();
      expect(scanProgressUpdatesFromEvent(event)).toEqual([]);
    }
  });

  test("rejects conflicting preflight capacity and ignores unrelated results", () => {
    const delegated = { capability: "delegated_workers", status: "pass" };
    const capacity = { capability: "usable_worker_slots_2", actual: 2 };
    const preflight = (results: unknown[]) =>
      workerStatusFromEvent(
        commandEvent(
          "config_preflight.py",
          JSON.stringify({ profile: "security_scan", results }),
        ),
      );
    expect(
      preflight([null, {}, { capability: 42 }, delegated, capacity]),
    ).toEqual({
      kind: "preflight",
      delegation: "available",
      configuredSlots: 2,
    });
    expect(preflight([delegated, capacity, capacity])).toBeNull();
    expect(preflight([{ ...delegated, status: "invalid" }])).toBeNull();
    expect(preflight([])).toBeNull();
  });

  test("reads configured worker capacity from a completed preflight", () => {
    const output = JSON.stringify({
      profile: "security_scan",
      status: "ready",
      results: [
        { capability: "delegated_workers", status: "pass", actual: true },
        { capability: "usable_worker_slots_6", status: "pass", actual: 8 },
      ],
    });

    expect(
      workerStatusFromEvent(
        commandEvent(
          '"/managed/python" "$CODEX_SECURITY_PLUGIN_ROOT/scripts/config_preflight.py" --profile security_scan',
          output,
        ),
      ),
    ).toEqual({
      kind: "preflight",
      delegation: "available",
      configuredSlots: 8,
    });
  });

  test("keeps unavailable and unknown delegation distinct from capacity", () => {
    for (const [status, delegation] of [
      ["fail", "unavailable"],
      ["unknown", "unknown"],
    ] as const) {
      expect(
        workerStatusFromEvent(
          commandEvent(
            "python3 /plugin/scripts/config_preflight.py --profile security_scan",
            JSON.stringify({
              profile: "security_scan",
              status: "ready",
              results: [
                { capability: "delegated_workers", status },
                {
                  capability: "usable_worker_slots_6",
                  status: "pass",
                  actual: 8,
                },
              ],
            }),
          ),
        ),
      ).toEqual({ kind: "preflight", delegation, configuredSlots: 8 });
    }
  });

  test("accepts diff preflight without a worker-slot requirement", () => {
    expect(
      workerStatusFromEvent(
        commandEvent(
          "python3 C:\\plugin\\scripts\\config_preflight.py --profile security_diff_scan",
          JSON.stringify({
            profile: "security_diff_scan",
            status: "ready",
            results: [{ capability: "delegated_workers", status: "pass" }],
          }),
        ),
      ),
    ).toEqual({
      kind: "preflight",
      delegation: "available",
      configuredSlots: null,
    });
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
        commandEvent(
          "python3 /plugin/scripts/config_preflight.py",
          JSON.stringify({
            profile: "security_scan",
            details: "x".repeat(65 * 1024),
            results: [
              { capability: "delegated_workers", status: "pass" },
              {
                capability: "usable_worker_slots_2048",
                status: "pass",
                actual: 2048,
              },
            ],
          }),
        ),
      ),
    ).toEqual({
      kind: "preflight",
      delegation: "available",
      configuredSlots: 2048,
    });
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
    const preflight = JSON.stringify({
      profile: "security_scan",
      results: [{ capability: "delegated_workers", status: "pass" }],
    });
    for (const event of [
      commandEvent("rg config_preflight.py /repository", preflight),
      commandEvent("python3 /plugin/scripts/config_preflight.py", "not json"),
      commandEvent(
        "python3 /plugin/scripts/config_preflight.py",
        JSON.stringify({
          profile: "deep_security_scan",
          results: [{ capability: "delegated_workers", status: "pass" }],
        }),
      ),
      commandEvent(
        "python3 /plugin/scripts/config_preflight.py",
        JSON.stringify({
          profile: ["security_scan"],
          results: [{ capability: "delegated_workers", status: "pass" }],
        }),
      ),
      commandEvent(
        "python3 /plugin/scripts/config_preflight.py",
        JSON.stringify({
          profile: "security_scan",
          results: [
            { capability: "delegated_workers", status: "pass" },
            { capability: "delegated_workers", status: "fail" },
          ],
        }),
      ),
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

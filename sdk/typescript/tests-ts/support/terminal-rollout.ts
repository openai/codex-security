export const completedAt = "2026-08-21T12:02:00Z";

export const terminalScanEvents: Record<string, unknown>[] = [
  {
    type: "event_msg",
    timestamp: "2026-08-21T12:01:59Z",
    payload: {
      type: "task_started",
      turn_id: "scan-terminal-turn",
      started_at: Date.parse("2026-08-21T12:01:59Z") / 1_000,
    },
  },
  {
    type: "response_item",
    timestamp: "2026-08-21T12:01:59.500Z",
    payload: {
      type: "function_call",
      call_id: "complete-scan",
      name: "complete_codex_security_scan",
      arguments: JSON.stringify({ scan_id: "scan-1" }),
    },
  },
  {
    type: "response_item",
    timestamp: "2026-08-21T12:02:00.100Z",
    payload: {
      type: "function_call_output",
      call_id: "complete-scan",
      output: JSON.stringify({ scan_id: "scan-1", status: "complete" }),
    },
  },
  {
    type: "response_item",
    timestamp: "2026-08-21T12:02:01Z",
    payload: {
      type: "function_call",
      call_id: "read-completed-scan",
      name: "get_codex_security_completed_scan",
      arguments: JSON.stringify({ scan_id: "scan-1" }),
    },
  },
  {
    type: "response_item",
    timestamp: "2026-08-21T12:02:02Z",
    payload: {
      type: "function_call_output",
      call_id: "read-completed-scan",
      output: JSON.stringify({ scan_id: "scan-1", findings: [] }),
    },
  },
  {
    type: "response_item",
    timestamp: "2026-08-21T12:02:03Z",
    payload: {
      type: "message",
      role: "assistant",
      content: [{ type: "output_text", text: "The scan is complete." }],
    },
  },
  {
    type: "event_msg",
    timestamp: "2026-08-21T12:02:04Z",
    payload: { type: "task_complete", turn_id: "scan-terminal-turn" },
  },
];

export const laterTurnEvents: Record<string, unknown>[] = [
  {
    type: "event_msg",
    timestamp: "2026-08-21T12:03:00Z",
    payload: {
      type: "task_started",
      turn_id: "later-turn",
      started_at: Date.parse("2026-08-21T12:03:00Z") / 1_000,
    },
  },
  {
    type: "response_item",
    timestamp: "2026-08-21T12:03:01Z",
    payload: {
      type: "message",
      role: "user",
      content: [{ type: "input_text", text: "Help with an unrelated task." }],
    },
  },
  {
    type: "response_item",
    timestamp: "2026-08-21T12:03:02Z",
    payload: {
      type: "message",
      role: "assistant",
      content: [{ type: "output_text", text: "This is unrelated work." }],
    },
  },
];

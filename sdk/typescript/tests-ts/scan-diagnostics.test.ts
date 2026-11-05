import { afterEach, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ScanDiagnostics,
  type ScanDiagnosticOutcome,
} from "../src/scan-diagnostics.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fixture() {
  const repository = await mkdtemp(join(tmpdir(), "scan-diagnostics-"));
  directories.push(repository);
  await writeFile(join(repository, "source.ts"), "export const value = 1;\n");
  return new ScanDiagnostics({
    scanId: "scan-synthetic",
    repository,
    mode: "standard",
    model: "test-model",
    pluginVersion: "1.0.0",
    maxCostUsd: 5,
  });
}

async function saved(
  diagnostics: ScanDiagnostics,
  outcome: ScanDiagnosticOutcome = {
    status: "completed",
    turnStatus: "completed",
    stopReason: "completed",
  },
) {
  const files = new Map<string, string>();
  const paths = await diagnostics.finish(
    {
      restore: async (path, contents) => {
        files.set(path, new TextDecoder().decode(contents));
      },
    },
    outcome,
  );
  return {
    paths,
    text: [...files.values()].join("\n"),
    events: files
      .get(paths.eventsPath)!
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line)),
    summary: JSON.parse(files.get(paths.summaryPath)!),
  };
}

function session(
  diagnostics: ScanDiagnostics,
  payload: Record<string, unknown>,
  threadId = "thread-root",
  type = "response_item",
) {
  diagnostics.recordSession({
    threadId,
    parentThreadId: threadId === "thread-root" ? null : "thread-root",
    event: { type, timestamp: "2026-01-01T00:00:00Z", payload },
  });
}

test("retains public summaries and response identifiers without copying hidden fields", async () => {
  const diagnostics = await fixture();
  diagnostics.recordSdk({ type: "thread.started", thread_id: "thread-root" });
  diagnostics.recordSdk({
    type: "item.completed",
    item: {
      id: "summary-sdk",
      type: "reasoning",
      text: "Inspecting the source entry point.",
      raw_content: "private-sentinel",
      encrypted_content: "private-sentinel",
    },
  });
  session(diagnostics, {
    type: "reasoning",
    id: "summary-response",
    summary: [{ type: "summary_text", text: "Checking the caller." }],
    content: [{ type: "reasoning_text", text: "private-sentinel" }],
    encrypted_content: "private-sentinel",
  });
  session(
    diagnostics,
    {
      type: "item_completed",
      item: {
        type: "Reasoning",
        id: "summary-item",
        summary_text: ["Comparing the result."],
        raw_content: ["private-sentinel"],
      },
    },
    "thread-root",
    "event_msg",
  );
  session(
    diagnostics,
    { type: "agent_reasoning_raw_content", text: "private-sentinel" },
    "thread-root",
    "event_msg",
  );
  session(diagnostics, {
    type: "message",
    role: "assistant",
    channel: "analysis",
    content: [{ type: "output_text", text: "private-sentinel" }],
  });
  session(
    diagnostics,
    {
      type: "item_completed",
      item: {
        type: "AgentMessage",
        id: "message-1",
        content: [{ type: "Text", text: "Public assistant update." }],
      },
    },
    "thread-root",
    "event_msg",
  );
  session(
    diagnostics,
    {
      response_id: "resp-synthetic",
      thread_id: "thread-root",
      turn_id: "turn-1",
      usage: {
        input_tokens: 11,
        output_tokens: 3,
        unexpected: "private-sentinel",
      },
      unexpected: "private-sentinel",
    },
    "thread-root",
    "token_usage_record",
  );
  const result = await saved(diagnostics);
  expect(result.text).not.toContain("private-sentinel");
  expect(result.text).not.toContain("encrypted_content");
  expect(result.text).toContain("Checking the caller.");
  expect(result.text).toContain("Comparing the result.");
  expect(result.text).toContain("Public assistant update.");
  expect(result.summary.responseIds).toEqual(["resp-synthetic"]);
  expect(result.summary.requestIds).toEqual([]);
  expect(result.summary.modelExecutionCapture).toMatchObject({
    requestedByDiagnostics: false,
    serverStatus: "unverified",
  });
});

test("pairs retained outputs within each worker and preserves diagnostic text", async () => {
  const diagnostics = await fixture();
  for (const threadId of ["thread-root", "thread-worker"]) {
    session(
      diagnostics,
      {
        type: "function_call",
        call_id: "same-call",
        name: "exec_command",
        arguments: JSON.stringify({ cmd: "cat source.ts" }),
      },
      threadId,
    );
  }
  session(
    diagnostics,
    {
      type: "function_call_output",
      call_id: "same-call",
      output: "export const value = 1;\n",
    },
    "thread-worker",
  );
  session(diagnostics, {
    type: "function_call_output",
    call_id: "same-call",
    output: "export const value = 1;\n",
  });
  session(diagnostics, {
    type: "function_call_output",
    call_id: "missing-call",
    output: "synthetic diagnostic: sk-synthetic-example-kept-verbatim",
  });
  diagnostics.recordSdk(
    {
      type: "item.completed",
      item: {
        type: "command_execution",
        id: "process-1",
        command: "cat source.ts",
        aggregated_output: "export const value = 1;\n",
        status: "completed",
        exit_code: 0,
      },
    },
    "thread-root",
  );
  const result = await saved(diagnostics);
  expect(result.summary.evidence).toMatchObject({
    modelToolResponses: 3,
    pairedModelToolResponses: 2,
    capturedProcessOutputs: 1,
  });
  expect(result.text).toContain("sk-synthetic-example-kept-verbatim");
  const outputs = result.events.filter(
    (event: Record<string, unknown>) =>
      event["type"] === "function_call_output",
  );
  expect(
    outputs.map((event: Record<string, unknown>) => event["paired"]),
  ).toEqual([true, true, false]);
  expect(result.summary.threadIds).toEqual(["thread-root", "thread-worker"]);
  expect(result.summary.coverage.calls).toHaveLength(2);
});

test("records failed turns and budget interruption without inventing a completion reason", async () => {
  const diagnostics = await fixture();
  diagnostics.recordSdk(
    {
      type: "turn.failed",
      error: { message: "provider stream closed", private: "excluded" },
    },
    "thread-root",
  );
  session(
    diagnostics,
    {
      type: "task_started",
      turn_id: "turn-1",
      trace_id: "trace-synthetic",
      model_context_window: 1000,
    },
    "thread-root",
    "event_msg",
  );
  session(
    diagnostics,
    { type: "turn_aborted", turn_id: "turn-1", reason: "interrupted" },
    "thread-root",
    "event_msg",
  );
  const result = await saved(diagnostics, {
    status: "failed",
    turnStatus: "interrupted",
    stopReason: "cost_limit",
    error: "cost limit reached",
    maxCostUsd: 5,
  });
  expect(result.summary.termination).toEqual({
    status: "failed",
    turnStatus: "interrupted",
    stopReason: "cost_limit",
    error: "cost limit reached",
    maxCostUsd: 5,
  });
  expect(result.summary.traceIds).toEqual(["trace-synthetic"]);
  expect(result.summary.configuration).toMatchObject({
    maxTimeMinutes: null,
    maxCostUsd: 5,
    timeLimitEnforced: false,
  });
  expect(result.text).toContain("provider stream closed");
  expect(result.text).not.toContain("excluded");
  expect(result.events.at(-1)).toMatchObject({
    source: "recorder",
    type: "attempt_finished",
    stopReason: "cost_limit",
  });
});

test("keeps simultaneous scan instances and artifact names separate", async () => {
  const first = await fixture();
  const second = await fixture();
  session(first, {
    type: "function_call",
    call_id: "shared-id",
    name: "exec_command",
    arguments: '{"cmd":"cat source.ts"}',
  });
  session(second, {
    type: "function_call_output",
    call_id: "shared-id",
    output: "export const value = 1;\n",
  });
  const [firstSaved, secondSaved] = await Promise.all([
    saved(first),
    saved(second),
  ]);
  expect(firstSaved.paths.eventsPath).not.toBe(secondSaved.paths.eventsPath);
  expect(firstSaved.summary.evidence.modelToolResponses).toBe(0);
  expect(secondSaved.summary.evidence.modelToolResponses).toBe(1);
  expect(secondSaved.summary.evidence.pairedModelToolResponses).toBe(0);
  expect(secondSaved.events[0]).toMatchObject({ paired: false });
});

test("retains native completion timing and per-response usage metadata", async () => {
  const diagnostics = await fixture();
  session(
    diagnostics,
    {
      type: "raw_response_completed",
      response_id: "resp-native",
      token_usage: {
        input_tokens: 17,
        output_tokens: 4,
        reasoning_output_tokens: 2,
      },
      content: "private-sentinel",
    },
    "thread-root",
    "event_msg",
  );
  session(
    diagnostics,
    {
      type: "task_complete",
      turn_id: "turn-1",
      completed_at: 123,
      duration_ms: 35,
      time_to_first_token_ms: 5,
    },
    "thread-root",
    "event_msg",
  );
  const result = await saved(diagnostics);
  expect(result.summary.responseIds).toEqual(["resp-native"]);
  expect(result.events[0]).toMatchObject({
    type: "raw_response_completed",
    token_usage: {
      input_tokens: 17,
      output_tokens: 4,
      reasoning_output_tokens: 2,
    },
  });
  expect(result.events[1]).toMatchObject({
    type: "task_complete",
    completed_at: 123,
    duration_ms: 35,
    time_to_first_token_ms: 5,
  });
  expect(result.text).not.toContain("private-sentinel");
});

test("resolves retained reads using each thread's observed working directory", async () => {
  const repository = await mkdtemp(join(tmpdir(), "scan-diagnostics-cwd-"));
  directories.push(repository);
  const workerDirectory = join(repository, "worker");
  await mkdir(workerDirectory);
  await writeFile(join(repository, "source.ts"), "export const root = 1;\n");
  await writeFile(
    join(workerDirectory, "source.ts"),
    "export const child = 2;\n",
  );
  const diagnostics = new ScanDiagnostics({
    scanId: "scan-cwd",
    repository,
    scanDirectory: repository,
    mode: "standard",
    model: "test-model",
    pluginVersion: "1.0.0",
  });
  diagnostics.recordSdk({ type: "thread.started", thread_id: "thread-root" });
  session(
    diagnostics,
    {
      id: "thread-worker",
      cwd: workerDirectory,
      base_instructions: "private-sentinel",
    },
    "thread-worker",
    "session_meta",
  );
  for (const threadId of ["thread-root", "thread-worker"]) {
    session(
      diagnostics,
      {
        type: "function_call",
        call_id: "shared-call",
        name: "exec_command",
        arguments: '{"cmd":"cat source.ts"}',
      },
      threadId,
    );
  }
  session(
    diagnostics,
    {
      type: "function_call_output",
      call_id: "shared-call",
      output: "export const child = 2;\n",
    },
    "thread-worker",
  );
  session(diagnostics, {
    type: "function_call_output",
    call_id: "shared-call",
    output: "export const root = 1;\n",
  });
  session(
    diagnostics,
    { turn_id: "turn-2", cwd: workerDirectory },
    "thread-root",
    "turn_context",
  );
  session(diagnostics, {
    type: "function_call",
    call_id: "next-call",
    name: "exec_command",
    arguments: '{"cmd":"cat source.ts"}',
  });
  session(diagnostics, {
    type: "function_call_output",
    call_id: "next-call",
    output: "export const child = 2;\n",
  });
  const result = await saved(diagnostics);
  expect(
    result.summary.coverage.files
      .map((file: { path: string }) => file.path)
      .sort(),
  ).toEqual(["source.ts", "worker/source.ts"]);
  expect(
    result.events
      .filter(
        (event: Record<string, unknown>) => event["type"] === "function_call",
      )
      .map((event: Record<string, unknown>) => event["cwd"]),
  ).toEqual([repository, workerDirectory, workerDirectory]);
  expect(result.text).not.toContain("private-sentinel");
});

test("does not credit relative file reads when a worker's working directory is unknown", async () => {
  const diagnostics = await fixture();
  session(
    diagnostics,
    {
      type: "function_call",
      call_id: "call",
      name: "exec_command",
      arguments: '{"cmd":"cat source.ts"}',
    },
    "thread-worker",
  );
  session(
    diagnostics,
    {
      type: "function_call_output",
      call_id: "call",
      output: "export const value = 1;\n",
    },
    "thread-worker",
  );
  const result = await saved(diagnostics);
  expect(result.summary.coverage.files).toEqual([]);
  expect(result.summary.evidence.modelToolResponses).toBe(1);
});

test("preserves supported native termination error metadata", async () => {
  const diagnostics = await fixture();
  session(
    diagnostics,
    {
      type: "task_complete",
      turn_id: "turn-1",
      error: {
        message: "context exhausted",
        codex_error_info: "context_window_exceeded",
        content: "private-sentinel",
      },
    },
    "thread-root",
    "event_msg",
  );
  session(
    diagnostics,
    {
      type: "error",
      message: "stream disconnected",
      codex_error_info: {
        response_stream_disconnected: {
          http_status_code: 503,
          private: "private-sentinel",
        },
      },
    },
    "thread-root",
    "event_msg",
  );
  const result = await saved(diagnostics, {
    status: "failed",
    turnStatus: "failed",
    stopReason: "turn_failed",
  });
  expect(result.events[0]).toMatchObject({
    error: {
      message: "context exhausted",
      codex_error_info: "context_window_exceeded",
    },
  });
  expect(result.events[1]).toMatchObject({
    codex_error_info: {
      response_stream_disconnected: { http_status_code: 503 },
    },
  });
  expect(result.text).not.toContain("private-sentinel");
});

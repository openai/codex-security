import { afterAll, beforeAll, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { text } from "node:stream/consumers";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import type { Frame } from "./fixtures/host-protocol-node.js";
import { nodeCommand } from "./support/shell.js";

let directory: string;
let fixture: string;
const node = nodeCommand().command;

beforeAll(async () => {
  // Resolve external dependencies from the SDK, as the installed CLI does.
  directory = await mkdtemp(join(import.meta.dirname, "..", ".host-pipes-"));
  const built = await Bun.build({
    entrypoints: [
      join(import.meta.dirname, "fixtures", "host-protocol-node.ts"),
    ],
    outdir: directory,
    target: "node",
    splitting: true,
    packages: "external",
  });
  expect(built.success).toBe(true);
  fixture = built.outputs[0]!.path;
});

afterAll(async () => {
  if (directory) await rm(directory, { recursive: true, force: true });
});

function launch(...args: string[]) {
  const child = spawn(
    node,
    [
      "--input-type=module",
      "--eval",
      `await import(${JSON.stringify(pathToFileURL(fixture).href)})`,
      "synthetic-launcher",
      ...args,
    ],
    {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      timeout: 10_000,
      killSignal: "SIGKILL",
    },
  );
  const exited = once(child, "exit");
  const messages = createInterface({ input: child.stderr });
  const lines = messages[Symbol.asyncIterator]();
  child.stdin.on("error", () => {});
  return {
    child,
    exited,
    lines,
    send(value: unknown) {
      child.stdin.write(JSON.stringify(value) + "\n");
    },
    async [Symbol.asyncDispose]() {
      child.kill("SIGKILL");
      child.stdin.destroy();
      child.stdout.destroy();
      messages.close();
      child.stderr.destroy();
      await exited;
    },
  };
}

const run = { jsonrpc: "2.0", id: "run-1", method: "run", params: {} };
const result = { status: "completed" };
const completed = { jsonrpc: run.jsonrpc, id: run.id, result };

test("Node dispatches a legacy carriage-return frame while stdin stays open", async () => {
  await using host = launch("legacy");
  const response = text(host.child.stdout);
  host.child.stdin.write(JSON.stringify(run) + "\r");
  expect(await host.exited).toEqual([0, null]);
  expect(JSON.parse(await response)).toEqual(completed);
});

test("an idle unreferenced host lets Node exit", async () => {
  await using host = launch("idle-host");
  expect(await host.exited).toEqual([0, null]);
});

test.each([
  ["completed", "sync"],
  ["completed", "async"],
  ["incomplete", "sync"],
  ["incomplete", "async"],
] as const)(
  "Node terminal write failure overrides a %s result (%s callback)",
  async (status, callback) => {
    await using host = launch("failed-terminal", status, callback);
    host.send(run);
    expect(await host.exited).toEqual([2, null]);
  },
);

test("Node input EOF waits for the selected terminal response to flush", async () => {
  await using host = launch("eof-before-flush");
  host.send(run);
  expect(await host.lines.next()).toEqual({ value: "writing", done: false });
  host.child.stdin.end();
  expect(await host.lines.next()).toEqual({
    value: '{"code":0}',
    done: false,
  });
  expect(await host.exited).toEqual([0, null]);
});

test("Node output close after a successful terminal flush preserves success", async () => {
  await using host = launch("close-after-flush");
  host.send(run);
  expect(await host.exited).toEqual([0, null]);
});

test.each(["cancel", "disconnect"])(
  "Node queued stdout execution write terminates on %s without recursive teardown",
  async (action) => {
    await using host = launch("queued-execution");
    host.send(run);
    expect(await host.lines.next()).toEqual({
      value: '{"queued":true}',
      done: false,
    });
    if (action === "cancel")
      host.send({
        jsonrpc: "2.0",
        method: "cancel",
        params: { id: "run-1" },
      });
    else host.child.stdin.end();
    expect(await host.exited).toEqual([2, null]);
  },
);

test.each([
  [
    "dedupe",
    "--records",
    { version: 1, observations: [], candidateRelationships: [] },
  ],
  ["scan", "--host", {}],
] as const)(
  "Node CLI %s %s exits with a transport failure when its reader closes",
  async (command, flag, params) => {
    await using host = launch("cli", command, flag);
    const closed = once(host.child.stdout, "close");
    host.child.stdout.destroy();
    await closed;
    host.send({ ...run, params });
    expect(await host.exited).toEqual([2, null]);
  },
);

test.each([
  ["sync-adapter", 0, undefined, "output"],
  ["plain-cancel-adapter", 2, -32800, "output"],
  ["drained-cancel-output", 1, undefined, "execution"],
  ["silent-input-legacy-output", 2, -32000, "output"],
  ["silent-terminal-output", 2, undefined, "output"],
  ["close-output", 2, undefined, "output"],
  ["failed-output", 2, undefined, "output"],
  ["abort-output", 2, undefined, "output"],
  ["cancel-output", 2, undefined, "output"],
  ["eof-output", 2, undefined, "output"],
  ["sync-correction", 0, undefined, "correction"],
  ["sync-paused", 0, undefined, "correction"],
  ["reused-validation-id", 2, -32600, "correction"],
  ["sync-half-close", 0, undefined, "correction"],
  ["destroy-next-review", 2, -32000, "correction"],
  ["destroy-next-review-late", 2, -32000, "correction"],
  ["destroy-next-review-silent-late", 2, -32000, "correction"],
  ["destroy-before-start", 2, -32000, "correction"],
  ["destroy-before-start-pending", 2, -32000, "correction"],
  ["destroy-before-start-pending-error", 2, -32000, "correction"],
  ["cancel-terminal-rejection", 2, -32602, "drain"],
  ["sync-invalid-params", 2, -32602, "correction", "check-1"],
  ["eof-next-review", 2, -32000, "selection"],
  ["eof-validation-drain", 2, -32000, "selection"],
  ["eof-wrong-review", 2, -32600, "selection"],
  ["eof-selected-result", 0, undefined, "selection"],
  ["cancel-selected-result", 2, -32800, "selection"],
  ["destroy-output-validation", 2, undefined, "selection"],
  ["destroy-output-pending-open", 2, undefined, "selection"],
  ["destroy-output-selected-eof", 2, undefined, "selection"],
  ["destroy-output-selected-open", 2, undefined, "selection"],
  ["destroy-output-stale-error-open", 2, undefined, "selection"],
  ["destroy-output-late-error", 2, undefined, "selection"],
  ["destroy-output-reusable", 2, undefined, "selection"],
  ["silent-input-after-validation", 2, -32000, "selection"],
  ["eof-selected-error", 2, -32009, "selection"],
  ["input-error-selected-rejection", 2, -32009, "selection"],
  ["reentrant-close-selected-rejection", 2, -32009, "selection"],
  ["reentrant-error-selected-rejection", 2, -32009, "selection"],
  ["cancel-drained-selected-rejection", 2, -32009, "selection"],
  ["input-error-once", 2, -32000, "execution"],
  ["eof-destroy-error", 0, undefined, "teardown"],
  ["lf-eof-before-flush", 0, undefined, "teardown"],
  ["input-error-selected-result", 0, undefined, "teardown"],
  ["eof-stale-validation", 2, -32600, "teardown", "check"],
  ["drain:missing", 2, -32602, "teardown", "check"],
  ["cancel:missing", 2, -32602, "teardown", "check"],
  ["cancel:stale", 2, -32600, "teardown", "check"],
  ["abort:stale", 2, undefined, "teardown"],
  ["abort:missing", 2, undefined, "teardown"],
  ["abort-reusable:stale", 2, undefined, "teardown"],
  ["drain:malformed", 2, -32700, "teardown"],
  ["cancel-validation-write", 2, -32800, "teardown"],
  ["legacy-answer-eof", 2, -32000, "teardown"],
  ["legacy-answer-eof-destroying", 2, -32000, "teardown"],
  ["eof-conflicting-validation", 2, -32600, "overlap"],
  ["eof-initial-run-id", 2, -32600, "overlap"],
  ["cancel-conflicting-validation", 2, -32600, "overlap"],
  ["eof-overtaking-final", 2, -32600, "overlap"],
  ["cancel-next-review", 2, undefined, "overlap"],
  ["eof-blocked-next-review", 2, undefined, "overlap"],
  ["eof-truncated-blocked-next-review", 2, undefined, "overlap"],
  ["input-error-answered-write", 0, undefined, "selection"],
  ["queued-validation-output", 2, -32600, "selection"],
  ["repeated-pending-validation", 2, -32600, "selection"],
  ["eof-queued-validation", 2, -32600, "selection"],
  ["oversized-eof", 2, -32000, "overlap"],
  ["oversized-delimited", 2, -32700, "overlap"],
  ["legacy-stale-cancel", 2, undefined, "execution"],
  ["eof-stale-next-review", 2, -32600, "overlap"],
  ["eof-validation-stale-next-review", 2, -32600, "overlap", "check"],
  ["eof-stale-blocked-next-review", 2, -32600, "overlap"],
  ["silent-input-stale-blocked-next-review", 2, undefined, "overlap"],
  ["error-then-close-stale-blocked-next-review", 2, undefined, "overlap"],
  ["close-stalled-stale-next-review", 2, undefined, "overlap"],
  ["eof-slow-review-stale-next-review", 2, -32600, "overlap"],
  ["eof-slow-terminal-stale-next-review", 2, -32600, "overlap"],
  ["close-stale-blocked-next-review", 2, undefined, "overlap"],
  ["cancel-stale-blocked-next-review", 2, undefined, "overlap"],
  ["cancel-validation-stale-blocked-next-review", 2, undefined, "overlap"],
  ["input-error-validation-drain", 2, -32000, "drain", "queued"],
  ["socket-close-validation-drain", 2, -32000, "drain", "queued"],
  ["silent-validation-drain", 2, -32000, "drain", "queued"],
  ["cancel-correlated-rejection", 2, -32602, "drain"],
  ["input-error-next-review", 2, -32000, "selection"],
  ["reentrant-cancel-receipt", 1, undefined, "execution"],
] as const)("Node %s preserves the terminal exchange", async (...row) => {
  const [scenario, code, errorCode, family, failedReceiptId] = row;
  const isScenario = (...names: string[]) => names.includes(scenario);
  await using host = launch(scenario, family);
  const outcome = JSON.parse(await text(host.child.stdout));
  expect(await host.exited).toEqual([code, null]);
  if (scenario.startsWith("eof-slow-")) expect(outcome.destroyed).toBe(false);
  if (scenario === "cancel-terminal-rejection")
    expect(outcome.destroyed).toBe(true);
  const messages = outcome.messages as Frame[];
  const final = messages.at(-1);
  const previous = messages.at(-2);
  const results = messages.filter(({ result }) => result !== undefined);
  const statuses = results.map(({ result }) => result?.status);
  const terminal = messages.filter((message) => message.id === "run-1");
  if (isScenario("drained-cancel-output", "reentrant-cancel-receipt")) {
    expect(messages.map(({ method }) => method)).toContain("execution.cancel");
    expect(terminal[0]?.result).toEqual({ status: "cancelled", usage: 7 });
  }
  if (code === 0) expect(terminal).toEqual([completed]);
  else expect(statuses).not.toContain("completed");
  const error = { code: errorCode };
  const id = scenario.startsWith("destroy-before-start") ? null : run.id;
  if (errorCode !== undefined) expect(final).toMatchObject({ id, error });
  const ids = messages.map(({ id }) => id);
  if (family === "correction" && code === 0)
    expect(ids).toEqual(["review-1", "check-1", "check-2", run.id]);
  if (failedReceiptId)
    expect(previous).toMatchObject({ id: failedReceiptId, error });
  if (isScenario("eof-next-review", "eof-selected-result")) {
    const reviews = messages.filter(({ method }) => method === "review.run");
    expect(reviews).toHaveLength(1);
  }
  if (isScenario("repeated-pending-validation", "eof-queued-validation"))
    expect(results).toHaveLength(1);
  if (scenario.startsWith("abort:") || scenario.startsWith("abort-reusable:")) {
    expect(outcome.destroyed).toBe(scenario.startsWith("abort:"));
    expect(messages).toHaveLength(2);
    expect(final).toMatchObject({
      id: "check",
      error: { code: scenario.endsWith(":missing") ? -32602 : -32600 },
    });
  }
  if (isScenario("eof-validation-drain", "drain:malformed"))
    expect(previous).toMatchObject({ id: "check", result: { valid: true } });
  if (errorCode === -32009)
    expect(final?.error?.data).toHaveProperty("kind", "permanent_rejection");
  if (
    isScenario("input-error-once", "input-error-next-review") ||
    scenario.startsWith("destroy-next-review")
  ) {
    const error = { code: -32000, message: "Synthetic input error" };
    expect(terminal).toEqual([{ jsonrpc: "2.0", id: run.id, error }]);
  }
  if (isScenario("eof-destroy-error", "input-error-selected-result"))
    expect(messages).toEqual(terminal);
});

test("Node legacy rejection does not wait behind a blocked execution request", async () => {
  await using host = launch("queued-legacy-rejection");
  host.send(run);
  let marker;
  do marker = await host.lines.next();
  while (!marker.done && marker.value !== '{"queued":true}');
  expect(marker.done).toBe(false);
  host.send({
    jsonrpc: "2.0",
    id: "request-1",
    error: { code: -32001, message: "Synthetic rejection" },
  });
  expect(await host.exited).toEqual([2, null]);
});

test("Node serialization failure returns a correlated diagnostic on writable stdout", async () => {
  await using host = launch("deep-error-data");
  const response = text(host.child.stdout);
  host.send(run);
  expect(JSON.parse(await response)).toMatchObject({
    id: run.id,
    error: {
      code: -32603,
      message: expect.stringContaining("could not serialize error data"),
    },
  });
  expect(await host.exited).toEqual([2, null]);
});

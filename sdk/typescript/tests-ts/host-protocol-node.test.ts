import { afterAll, beforeAll, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
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

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mock } from "bun:test";

const home = await fs.mkdtemp(join(tmpdir(), "scan-log-io-"));
const root = join(home, "sessions", "root.jsonl");
const open = fs.open;
let release!: () => void;
const held = new Promise<void>((resolve) => {
  release = resolve;
});
mock.module("node:fs/promises", () => ({
  ...fs,
  open: async (...args: Parameters<typeof open>) => {
    if (args[0] === root) await held;
    return await open(...args);
  },
}));
const { ScanCostTracker } = await import("../../src/cost.js");
const { recordScanLogTurn, settleScanLogTurns } =
  await import("../../src/scan-logs.js");
const pendingWrites = new Set<Promise<void>>();
try {
  await fs.mkdir(join(home, "sessions"));
  await fs.writeFile(
    root,
    JSON.stringify({ type: "session_meta", payload: { id: "root" } }) + "\n",
  );
  let invoked = false;
  const events = recordScanLogTurn(
    {
      scanId: "scan",
      threadId: () => "root",
      codexHome: home,
      pendingWrites,
      tracker: new ScanCostTracker({ codexHome: home, model: "gpt-5" }),
    },
    async () => {
      invoked = true;
      return {
        events: (async function* () {
          await fs.appendFile(
            root,
            JSON.stringify({
              type: "event_msg",
              payload: { type: "task_started", turn_id: "owned" },
            }) + "\n",
          );
          yield { type: "thread.started" };
          yield { type: "turn.started" };
          yield { type: "turn.completed" };
        })(),
      };
    },
    () => {},
  );
  assert.equal((await events.next()).value?.type, "thread.started");
  assert(invoked);
  assert.equal((await events.next()).value?.type, "turn.started");
  assert.equal((await events.next()).value?.type, "turn.completed");
  assert((await events.next()).done);
  // The actual incremental reader remains held through invocation and completion.
  assert(pendingWrites.size > 0);
} finally {
  release();
  await settleScanLogTurns(pendingWrites);
  mock.restore();
  await fs.rm(home, { recursive: true, force: true });
}

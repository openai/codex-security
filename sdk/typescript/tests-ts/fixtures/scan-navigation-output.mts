import assert from "node:assert/strict";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { main } from "../../src/cli.js";
import { capture, dependencies } from "../cli-fixtures.js";
import { writeJsonLines } from "../support/json.js";
import { temporaryDirectory } from "../support/temporary-directories.js";

const command = process.argv[2]!;
const failure = process.argv[3]!;
const root = await temporaryDirectory("scan-navigation-output-");
try {
  process.env["XDG_DATA_HOME"] = root;
  const home = join(root, "codex-home");
  await mkdir(join(home, "sessions"), { recursive: true });
  await writeJsonLines(join(home, "sessions", "rollout.jsonl"), [
    { type: "session_meta", payload: { id: "saved-thread" } },
    { type: "event_msg", payload: { message: "Saved activity" } },
  ]);
  const scan = {
    scanId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    targetPath: join(root, "repository"),
    mode: "standard",
    startedAt: "2026-01-01T12:00:00Z",
    continuationThreadId: "saved-thread",
    progress: { status: "complete" },
    findings: [],
  };
  const stdout = capture();
  const error = Object.assign(new Error("Diagnostic output failed"), {
    code: failure,
  });
  let writes = 0;
  const stderr =
    failure === "sync"
      ? {
          write(): boolean {
            writes += 1;
            throw error;
          },
        }
      : new Writable({
          autoDestroy: false,
          write(_chunk, _encoding, callback) {
            writes += 1;
            setImmediate(() => callback(error));
          },
        });
  const status = await main(
    ["scans", command, scan.scanId],
    stdout.stream,
    stderr,
    dependencies({
      environment: { CODEX_HOME: home, CODEX_SECURITY_STATE_DIR: root },
      onWorkbench: () => ({ scan }),
    }),
  );
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(status, 0);
  assert.ok(writes > 0);
  assert.ok(stdout.text().includes(scan.scanId));
  if (stderr instanceof Writable) {
    assert.equal(stderr.errored, error);
    assert.equal(stderr.listenerCount("error"), 0);
  }
  process.stdout.write(JSON.stringify({ status, output: stdout.text() }));
} finally {
  await rm(root, { recursive: true, force: true });
}

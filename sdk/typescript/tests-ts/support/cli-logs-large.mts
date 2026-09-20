import { constants } from "node:buffer";
import { createHash } from "node:crypto";
import { mkdir, open, realpath } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { main } from "../../src/cli.js";
import { dependencies } from "../cli-fixtures.js";

const state = await realpath(process.argv[2]!);
const sessions = join(state, "codex-home", "sessions");
await mkdir(sessions, { recursive: true });
const path = join(sessions, "rollout.jsonl");
const metadata = { type: "session_meta", payload: { id: "thread-1" } };
let payload: unknown = Array(4096).fill(0);
// Pretty indentation expands a small input into a large document economically.
for (let i = 0; i < 32; i++) payload = { nested: payload };
const event = (sequence: number) => ({ type: "event_msg", sequence, payload });
const header = {
  scanId: "scan-1",
  threadId: "thread-1",
  sessions: [{ threadId: "thread-1", parentThreadId: null, path }],
  events: [{ threadId: "thread-1", event: metadata }],
};
const first = JSON.stringify(header, null, 2);
const prefix = first.slice(0, first.lastIndexOf("\n  ]"));
const suffix = "\n  ]\n}\n";
const record = (sequence: number) =>
  JSON.stringify(
    { events: [{ threadId: "thread-1", event: event(sequence) }] },
    null,
    2,
  ).slice('{\n  "events": [\n'.length, -"\n  ]\n}".length);
const count = Math.ceil(constants.MAX_STRING_LENGTH / record(0).length) + 1;
const expected = createHash("sha256");
let expectedBytes = 0;
function expectChunk(text: string) {
  expected.update(text);
  expectedBytes += Buffer.byteLength(text);
}
expectChunk(prefix);
const file = await open(path, "wx");
try {
  await file.write(`${JSON.stringify(metadata)}\n`);
  for (let i = 0; i < count; i++) {
    await file.write(`${JSON.stringify(event(i))}\n`);
    expectChunk(`,\n${record(i)}`);
  }
} finally {
  await file.close();
}
expectChunk(suffix);
let bytes = 0;
const actual = createHash("sha256");
const output = new Writable({
  write(chunk, _encoding, callback) {
    bytes += chunk.length;
    actual.update(chunk);
    callback();
  },
});
const deps = dependencies({
  environment: { CODEX_SECURITY_STATE_DIR: state },
  onWorkbench: () => ({
    scan: { scanId: "scan-1", continuationThreadId: "thread-1" },
  }),
});
deps.createSecurity = () => {
  throw new Error("Reading logs must not start Codex");
};
try {
  const exitCode = await main(
    ["scans", "logs", "scan-1", "--json"],
    output,
    process.stderr,
    deps,
  );
  console.log(
    JSON.stringify({
      exitCode,
      bytes,
      sha256: actual.digest("hex"),
      expectedBytes,
      expectedSha256: expected.digest("hex"),
      maximumStringLength: constants.MAX_STRING_LENGTH,
      events: count + 1,
    }),
  );
  process.exitCode = exitCode;
} catch (error) {
  console.error(error);
  process.exitCode = 2;
}

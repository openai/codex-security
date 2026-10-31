import { expect, test } from "bun:test";
import { PassThrough } from "node:stream";
import { createSeverityDiagnostics } from "../src/classify-severity-diagnostics.js";
import { runHostRecordsProtocol } from "../src/host-records-protocol.js";
import type { HostDiagnosticBatch } from "../src/host-protocol.js";

const timestamp = 1_700_000_000_000;
const original = (code: string, ordinal?: number) =>
  JSON.stringify({
    schema: "codex-security.classify-severity.v1",
    at: "2023-11-14T22:13:20.000Z",
    code,
    ordinal,
  });

test.each([false, true])(
  "uses only existing review and terminal writes (diagnostics enabled: %s)",
  async (enabled) => {
    const input = new PassThrough();
    const diagnostics = enabled
      ? createSeverityDiagnostics(() => timestamp)
      : undefined;
    const frames: {
      id: string;
      method?: string;
      result?: unknown;
      cliDiagnostics?: HostDiagnosticBatch;
    }[] = [];
    const run = runHostRecordsProtocol(
      input,
      {
        write(line) {
          const frame = JSON.parse(
            typeof line === "string"
              ? line
              : Buffer.from(line).toString("utf8"),
          );
          frames.push(frame);
          if (frame.method === "review.run")
            queueMicrotask(() =>
              input.write(
                JSON.stringify({ jsonrpc: "2.0", id: frame.id, result: {} }) +
                  "\n",
              ),
            );
          return true;
        },
      },
      async (_params, options) => {
        diagnostics?.emit("input_validated");
        diagnostics?.emit("review_requested", 1);
        await options.reviewRunner.run({ requestId: "one" });
        diagnostics?.emit("review_failed", 1);
        return { status: "unresolved" as const };
      },
      undefined,
      diagnostics?.take,
    );
    input.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: "run-one",
        method: "run",
        params: {},
      }) + "\n",
    );
    expect(await run).toBe(1);
    expect(frames.map((frame) => frame.id)).toEqual(["one", "run-one"]);
    expect(frames.map((frame) => frame.cliDiagnostics)).toEqual(
      enabled
        ? [
            {
              records: [
                original("invocation_started"),
                original("input_validated"),
                original("review_requested", 1),
              ],
              dropped: 0,
            },
            {
              records: [
                original("review_failed", 1),
                original("exit_unresolved"),
              ],
              dropped: 0,
            },
          ]
        : [undefined, undefined],
    );
  },
);

test("bounds diagnostics across writes and reserves the final record", () => {
  const diagnostics = createSeverityDiagnostics(() => timestamp);
  for (let i = 0; i < 1536; i++) diagnostics.emit("review_requested", 1);
  const request = diagnostics.take({ method: "review.run" })!;
  expect(request.records).toHaveLength(63);
  expect(request.dropped).toBe(1474);
  expect(diagnostics.take({ method: "review.run" })).toBeUndefined();
  expect(
    diagnostics.take({ error: { code: -32800, message: "private-sentinel" } }),
  ).toEqual({ records: [original("exit_cancelled")], dropped: 0 });
});

test("diagnostic clock failures only affect the reported drop count", () => {
  const diagnostics = createSeverityDiagnostics(() => Number.NaN);
  expect(
    diagnostics.take({ error: { code: -32602, message: "private-sentinel" } }),
  ).toEqual({ records: [], dropped: 2 });
});

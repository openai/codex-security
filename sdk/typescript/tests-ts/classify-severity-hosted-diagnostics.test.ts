import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { PassThrough } from "node:stream";
import { runCommand } from "./support/shell.js";
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
      "classify-severity",
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
                JSON.stringify({
                  jsonrpc: "2.0",
                  id: frame.id,
                  error: { code: -32000, message: "Review failed" },
                }) + "\n",
              ),
            );
          return true;
        },
      },
      { diagnostics, classificationRuns: 1 },
    );
    const findingJson = JSON.stringify({
      findingId: "one",
      title: "Example report",
      summary: "Example summary",
    });
    input.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: "run-one",
        method: "run",
        params: {
          version: 1,
          model: "synthetic-model",
          effort: "high",
          records: [
            {
              id: "one",
              revision: 1,
              findingJson,
              inputSha256: createHash("sha256")
                .update(findingJson)
                .digest("hex"),
            },
          ],
        },
      }) + "\n",
    );
    expect(await run).toBe(1);
    expect(frames.map((frame) => frame.method)).toEqual([
      "review.run",
      undefined,
    ]);
    expect(frames[1]?.id).toBe("run-one");
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

test("records cancellation without including the host error message", () => {
  const diagnostics = createSeverityDiagnostics(() => timestamp);
  expect(
    diagnostics.take({ error: { code: -32800, message: "private-sentinel" } }),
  ).toEqual({
    records: [original("invocation_started"), original("exit_cancelled")],
    dropped: 0,
  });
});

test("diagnostic clock failures only affect the reported drop count", () => {
  const diagnostics = createSeverityDiagnostics(() => Number.NaN);
  expect(
    diagnostics.take({ error: { code: -32602, message: "private-sentinel" } }),
  ).toEqual({ records: [], dropped: 2 });
});

test.each([
  ["long", ["--conditions=codex-security-records-logs-v1"], "", true],
  ["separate", ["--conditions", "codex-security-records-logs-v1"], "", true],
  ["short", ["-C", "codex-security-records-logs-v1"], "", true],
  ["environment", [], "--conditions=codex-security-records-logs-v1", true],
  ["unrelated", ["--conditions=another-feature"], "", false],
] as const)(
  "resolves the %s Node condition",
  async (_name, flags, options, enabled) => {
    const source = new URL(
      "../src/classify-severity-diagnostics.ts",
      import.meta.url,
    ).href;
    const js = `import { severityDiagnosticsEnabled } from ${JSON.stringify(source)}; console.log(severityDiagnosticsEnabled());`;
    const { status, stdout } = await runCommand(
      "node",
      [
        "--no-warnings",
        "--experimental-strip-types",
        ...flags,
        "--input-type=module",
        "-e",
        js,
      ],
      {
        env: { ...process.env, NODE_OPTIONS: options },
      },
    );
    expect(status).toBe(0);
    expect(stdout.trim()).toBe(String(enabled));
  },
);

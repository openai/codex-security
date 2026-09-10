import { createHash } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root";
import type { JsonCase } from "./support/scan-contract-json-fixture";
import { runCommand } from "./support/shell";

const directory = realpathSync(
  mkdtempSync(join(tmpdir(), "scan-contract-json-")),
);
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
let next = 0;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/scan-contract-json-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
    define: {
      "import.meta.url": JSON.stringify(
        pathToFileURL(join(PLUGIN_ROOT, "mcp/helpers.mjs")).href,
      ),
    },
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
async function run(cases: JsonCase[]): Promise<unknown[]> {
  const child = await runCommand(node, [fixture], {
    input: JSON.stringify({ root: join(directory, String(next++)), cases }),
    timeout: 15000,
    maxBuffer: Infinity,
    env: {
      ...process.env,
      PYTHON: join(directory, "missing-python"),
      PATH: "",
    },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as unknown[];
}
const error = (message: string) => ({ error: "ContractError", message });
const digest = (value: string) => ({
  length: Buffer.byteLength(value),
  sha256: createHash("sha256").update(value).digest("hex"),
});

test("loads contract JSON with original numeric representation and rejects overwritten nonfinite values", async () => {
  expect(
    await run([
      { operation: "loads", source: '{"10":1,"2":-0.0,"é":1e-7,"10":3}' },
      { operation: "loads", source: '{"value":NaN,"value":1}' },
      { operation: "loads", source: '{"value":Infinity}' },
      { operation: "defaultBytes", source: '{"value":NaN}' },
      { operation: "loads", source: '"\\ud800"' },
    ]),
  ).toEqual([
    { json: '{"10": 3, "2": -0.0, "\\u00e9": 1e-07}' },
    {
      error: "ValueError",
      message: "non-finite JSON number 'NaN' is not supported",
    },
    {
      error: "ValueError",
      message: "non-finite JSON number 'Infinity' is not supported",
    },
    { json: '{"value": NaN}' },
    { json: '"\\ud800"' },
  ]);
});

test("preserves UTF encodings, BOM rules, surrogatepass and precise decoding errors", async () => {
  expect(
    await run([
      { operation: "loads", hex: "fffe7b002200780022003a0031007d00" },
      { operation: "loads", hex: "0000feff0000007b0000007d" },
      { operation: "loads", hex: "22eda08022" },
      { operation: "loads", hex: "eda0" },
      { operation: "loads", hex: "eda0ff" },
      { operation: "loads", hex: "22eda022" },
      { operation: "loads", hex: "eda080ff" },
      { operation: "loads", hex: "fffe7b" },
      { operation: "loads", hex: "fffe000000001100" },
      { operation: "decode", hex: "eda080" },
      { operation: "loads", source: "\ufeff{}" },
      { operation: "loads", hex: "fffefffe7b007d00" },
      { operation: "loads", hex: "efbbbfefbbbf7b7d" },
      { operation: "defaultUtf8", source: "é😀" },
      { operation: "defaultUtf8", hex: "ff" },
    ]),
  ).toEqual([
    { json: '{"x": 1}' },
    { json: "{}" },
    { json: '"\\ud800"' },
    {
      error: "UnicodeDecodeError",
      message:
        "'utf-8' codec can't decode byte 0xed in position 0: invalid continuation byte",
    },
    {
      error: "UnicodeDecodeError",
      message:
        "'utf-8' codec can't decode byte 0xed in position 0: invalid continuation byte",
    },
    {
      error: "UnicodeDecodeError",
      message:
        "'utf-8' codec can't decode byte 0xed in position 1: invalid continuation byte",
    },
    {
      error: "UnicodeDecodeError",
      message:
        "'utf-8' codec can't decode byte 0xff in position 3: invalid start byte",
    },
    {
      error: "UnicodeDecodeError",
      message:
        "'utf-16-le' codec can't decode byte 0x7b in position 2: truncated data",
    },
    {
      error: "UnicodeDecodeError",
      message:
        "'utf-32-le' codec can't decode bytes in position 4-7: code point not in range(0x110000)",
    },
    {
      error: "UnicodeDecodeError",
      message:
        "'utf-8' codec can't decode byte 0xed in position 0: invalid continuation byte",
    },
    {
      error: "JSONDecodeError",
      message:
        "Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)",
    },
    {
      error: "JSONDecodeError",
      message: "Expecting value: line 1 column 1 (char 0)",
    },
    {
      error: "JSONDecodeError",
      message: "Expecting value: line 1 column 1 (char 0)",
    },
    { text: "é😀" },
    {
      error: "TypeError",
      message: "The encoded data was not valid for encoding utf-8",
    },
  ]);
});

test("rejects unsafe JSON numbers and strings without exposing property names", async () => {
  const sources = [
    '{"private-key":9007199254740992}',
    '{"private-key":9007199254740992.0}',
    '{"private-key":1e309}',
    '{"private-key":"\\ud800"}',
    '{"\\ud800":1}',
    "[0,9007199254740992]",
  ];
  expect(
    await run(
      sources.map((source) => ({ operation: "contractBytes", source })),
    ),
  ).toEqual([
    error(
      "document.<property>: unsafe integer-valued JSON numbers are not supported",
    ),
    error(
      "document.<property>: unsafe integer-valued JSON numbers are not supported",
    ),
    error("document.<property>: non-finite JSON numbers are not supported"),
    error("document.<property>: expected well-formed Unicode JSON strings"),
    error("document: expected well-formed Unicode JSON strings"),
    error("document[1]: unsafe integer-valued JSON numbers are not supported"),
  ]);
  expect(
    await run([
      {
        operation: "validate",
        source: '{"\\ud800":"\\udfff"}',
        validateStrings: false,
      },
      {
        operation: "validate",
        source: '[9007199254740991,-9007199254740991,1.5,true,null,"😀"]',
      },
      { operation: "string", source: "😀" },
    ]),
  ).toEqual([null, null, null]);
});

test("keeps schema-file and scan-local validation order, raw bytes and newline behavior", async () => {
  const raw = '{\r\n "note":"é", "note":"kept", "surrogate":"\\ud800"\r\n}\r\n';
  const results = await run([
    { operation: "read", source: "[9007199254740992]" },
    { operation: "scanRead", source: "[9007199254740992]" },
    { operation: "read", source: '{"note":"\\ud800"}' },
    { operation: "scanReadBytes", source: raw },
    { operation: "read", source: '{\r"value":}' },
    { operation: "scanRead", source: '{\r"value":}' },
    { operation: "read", missing: true },
    { operation: "read", directory: true },
  ]);
  expect((results[0] as { message: string }).message).toEndWith(
    "data.json[0]: unsafe integer-valued JSON numbers are not supported",
  );
  expect(results[1]).toEqual(error("document: expected a JSON object"));
  expect((results[2] as { message: string }).message).toEndWith(
    "data.json.<property>: expected well-formed Unicode JSON strings",
  );
  expect(results[3]).toEqual({
    json: '{"note": "kept", "surrogate": "\\ud800"}',
    raw: digest(raw),
  });
  expect((results[4] as { message: string }).message).toEndWith(
    "invalid JSON: Expecting value: line 2 column 9 (char 10)",
  );
  expect(results[5]).toEqual(
    error(
      "document: invalid JSON: Expecting value: line 1 column 11 (char 10)",
    ),
  );
  expect((results[6] as { message: string }).message).toStartWith(
    "missing required contract artifact:",
  );
  expect(results[7]).toEqual({
    osError: process.platform === "win32" ? "EACCES" : "EISDIR",
  });
});

test("writes exact canonical bytes and validates before opening or replacing output", async () => {
  const source = '{"😀":1,"\ue000":2,"z":-0.0,"a":[1.0,"é"]}';
  const canonical =
    '{\n  "a": [\n    1.0,\n    "\\u00e9"\n  ],\n  "z": -0.0,\n  "\\ue000": 2,\n  "\\ud83d\\ude00": 1\n}\n';
  const unchanged = Buffer.from("previous contents").toString("hex");
  expect(
    await run([
      { operation: "contractBytes", source },
      { operation: "write", source, relative: "exports/result.json" },
      {
        operation: "write",
        source: '{"private-key":NaN}',
        missing: true,
        relative: "../escape.json",
      },
      { operation: "jsonBytes", source: '{"score":NaN}' },
    ]),
  ).toEqual([
    { hex: Buffer.from(canonical).toString("hex") },
    { hex: Buffer.from(canonical).toString("hex") },
    {
      ...error(
        "../escape.json.<property>: non-finite JSON numbers are not supported",
      ),
      after: unchanged,
    },
    error(
      "cannot encode canonical JSON: Out of range float values are not JSON compliant: nan",
    ),
  ]);
});

test("accepts formerly limited document sizes and nesting and retains the original integer parser boundary", async () => {
  const size = 4 * 1024 * 1024;
  const results = await run([
    { operation: "read", size, summarize: true },
    { operation: "scanReadBytes", size: 16 * 1024 * 1024, summarize: true },
    {
      operation: "scanRead",
      size: 8 * 1024 * 1024,
      escaped: true,
      summarize: true,
    },
    { operation: "validate", depth: 258 },
    { operation: "loads", source: "1".repeat(4301) },
  ]);
  expect(results[0]).toEqual(
    digest('{"metadata": "' + "x".repeat(size) + '"}'),
  );
  expect(results[1]).toEqual({
    ...digest('{"metadata": "' + "x".repeat(16 * 1024 * 1024) + '"}'),
    raw: digest('{"metadata":"' + "x".repeat(16 * 1024 * 1024) + '"}'),
  });
  expect(results[2]).toEqual(
    digest('{"metadata": "' + "\\n".repeat(8 * 1024 * 1024) + '"}'),
  );
  expect(results[3]).toBeNull();
  expect(results[4]).toEqual({
    error: "ValueError",
    message:
      "Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits; use sys.set_int_max_str_digits() to increase the limit",
  });
});

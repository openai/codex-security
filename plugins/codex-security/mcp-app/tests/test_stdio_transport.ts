import assert from "node:assert/strict";
import { PassThrough, Writable } from "node:stream";
import test from "node:test";
import { serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import {
  ErrorCode,
  type JSONRPCMessage,
} from "@modelcontextprotocol/sdk/types.js";
import { CodexSecurityStdioTransport } from "../src/stdio-transport.ts";

const nativeLineLimitBytes = 16 * 1024 * 1024;

function captureTransport() {
  const lines: string[] = [];
  const stdout = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      lines.push(chunk.toString("utf8"));
      callback();
    },
  });
  return {
    transport: new CodexSecurityStdioTransport(new PassThrough(), stdout),
    lines,
  };
}

test("stdio preserves ordinary result and error responses exactly", async () => {
  const { transport, lines } = captureTransport();
  const messages: JSONRPCMessage[] = [
    { jsonrpc: "2.0", id: 0, result: { text: 'A quote: " and a newline:\n' } },
    {
      jsonrpc: "2.0",
      id: "",
      error: { code: ErrorCode.InvalidParams, message: "Invalid page cursor" },
    },
  ];
  for (const message of messages) await transport.send(message);
  assert.deepEqual(lines, messages.map(serializeMessage));
});

test("stdio counts UTF-8 JSON escaping and the LF at the native line boundary", async () => {
  for (const bytes of [nativeLineLimitBytes, nativeLineLimitBytes + 1]) {
    const { transport, lines } = captureTransport();
    const message = {
      jsonrpc: "2.0" as const,
      id: "boundary",
      result: { text: 'é😀\n"' },
    };
    message.result.text += "a".repeat(
      bytes - Buffer.byteLength(serializeMessage(message)),
    );
    const serialized = serializeMessage(message);
    assert.equal(Buffer.byteLength(serialized), bytes);
    assert.ok(serialized.length < bytes);

    await transport.send(message);
    assert.equal(lines.length, 1);
    if (bytes === nativeLineLimitBytes) {
      assert.equal(lines[0], serialized);
    } else {
      const response = JSON.parse(lines[0]!);
      assert.equal(response.id, message.id);
      assert.equal(response.error.code, ErrorCode.InternalError);
      assert.match(response.error.message, /16777217 bytes.*16777216 bytes/);
      assert.match(
        response.error.message,
        /reduce the requested page byte budget/,
      );
      assert.match(
        response.error.message,
        /operation may already have completed/,
      );
    }
  }
});

test("an oversized error keeps its request ID and the next response succeeds", async () => {
  const { transport, lines } = captureTransport();
  await transport.send({
    jsonrpc: "2.0",
    id: 0,
    error: {
      code: ErrorCode.InternalError,
      message: "Large diagnostic",
      data: "a".repeat(nativeLineLimitBytes),
    },
  });
  const next: JSONRPCMessage = { jsonrpc: "2.0", id: 1, result: { ok: true } };
  await transport.send(next);

  const response = JSON.parse(lines[0]!);
  assert.equal(response.id, 0);
  assert.equal(response.error.code, ErrorCode.InternalError);
  assert.equal(response.error.data, undefined);
  assert.ok(Buffer.byteLength(lines[0]!) <= nativeLineLimitBytes);
  assert.equal(lines[1], serializeMessage(next));
});

test("stdio leaves outgoing requests and notifications unchanged", async () => {
  const { transport, lines } = captureTransport();
  const messages: JSONRPCMessage[] = [
    {
      jsonrpc: "2.0",
      id: "server-request",
      method: "sampling/createMessage",
      params: { text: "a".repeat(nativeLineLimitBytes) },
    },
    {
      jsonrpc: "2.0",
      method: "notifications/message",
      params: { data: "a".repeat(nativeLineLimitBytes) },
    },
  ];
  for (const message of messages) await transport.send(message);
  assert.deepEqual(lines, messages.map(serializeMessage));
});

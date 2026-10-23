import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { importSource } from "./import-module.ts";

const { createZstdDecompress } = await importSource(
  fileURLToPath(new URL("../src/session-decompression.ts", import.meta.url)),
);

// One frame containing 128 KiB of "a", compressed with Zstandard level 3.
const frame = Buffer.from("KLUv/aAAAAIAVQAAEGFhAQD7/znAAg==", "base64");
const decodedFrame = Buffer.alloc(128 * 1024, "a");

test("ended input waits for readable demand before expanding queued frames", async () => {
  const stream = createZstdDecompress();
  try {
    stream.write(frame);
    stream.write(frame);
    stream.end(frame);

    assert.equal(stream.readableLength, decodedFrame.length);
    const first = stream.read(decodedFrame.length);
    assert.deepEqual(first, decodedFrame);
    assert.ok(
      stream.readableLength <= decodedFrame.length,
      "a single read must not expand every queued compressed frame",
    );

    const chunks = [first];
    for await (const chunk of stream) chunks.push(chunk);
    assert.deepEqual(
      Buffer.concat(chunks),
      Buffer.concat([decodedFrame, decodedFrame, decodedFrame]),
    );
  } finally {
    stream.destroy();
  }
});

test("decodes concatenated frames split across compressed chunks", async () => {
  const stream = createZstdDecompress();
  const input = Buffer.concat([frame, frame]);
  for (let offset = 0; offset < input.length; offset += 5) {
    stream.write(input.subarray(offset, offset + 5));
  }
  stream.end();
  const chunks = [];
  for await (const chunk of stream) chunks.push(chunk);
  assert.deepEqual(
    Buffer.concat(chunks),
    Buffer.concat([decodedFrame, decodedFrame]),
  );
});

test("reports a truncated tail after a complete concatenated frame", async () => {
  const stream = createZstdDecompress();
  stream.end(Buffer.concat([frame, frame.subarray(0, frame.length - 3)]));
  await assert.rejects(async () => {
    for await (const _chunk of stream) {
      // Consume the complete prefix so the decoder can validate the tail.
    }
  }, /unexpected EOF/);
});

test("cancellation during decoded output completes the current write", async () => {
  const stream = createZstdDecompress();
  const cancellation = new Error("synthetic cancellation");
  const closed = new Promise<void>((resolve) => stream.once("close", resolve));
  let emittedError: Error | undefined;
  let writeCompleted = false;
  stream.on("error", (error: Error) => {
    emittedError = error;
  });
  stream.once("data", () => stream.destroy(cancellation));
  stream.write(Buffer.concat([frame, frame]), () => {
    writeCompleted = true;
  });
  await closed;
  assert.equal(emittedError, cancellation);
  assert.equal(writeCompleted, true);
});

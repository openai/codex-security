import { Transform, type TransformCallback } from "node:stream";
import { Decompress } from "fzstd";

/** Streaming decoder for concatenated Zstandard rollouts on supported Node versions. */
export function createZstdDecompress(): Transform {
  let decoder: Decompress;
  let backpressured = false;
  let pending: TransformCallback | undefined;
  const stream = new Transform({
    transform(
      chunk: Buffer,
      _encoding: BufferEncoding,
      callback: TransformCallback,
    ) {
      try {
        backpressured = false;
        decoder.push(chunk);
        // Transform's automatic backpressure stops delaying writes after end().
        // Keep queued compressed chunks pending until the reader asks for more.
        if (backpressured && !this.destroyed) pending = callback;
        else callback();
      } catch (error) {
        callback(error as Error);
      }
    },
    read(size: number) {
      const callback = pending;
      pending = undefined;
      callback?.();
      Transform.prototype._read.call(this, size);
    },
    flush(callback: TransformCallback) {
      try {
        decoder.push(new Uint8Array(), true);
        callback();
      } catch (error) {
        callback(error as Error);
      }
    },
  });
  decoder = new Decompress((chunk) => {
    if (!stream.push(chunk)) backpressured = true;
  });
  return stream;
}

import { run } from "zstd-codec/lib/module.js";

interface Decoder {
  begin(): boolean;
  transform(input: Uint8Array, output: (chunk: Uint8Array) => void): boolean;
  end(output: (chunk: Uint8Array) => void): boolean;
  delete(): void;
}

interface Binding {
  ZstdDecompressStreamBinding: new () => Decoder;
}

let binding: Promise<Binding> | undefined;

/** Decode incrementally without reopening the caller's already-inspected file. */
export async function* decodeZstd(
  source: AsyncIterable<Uint8Array>,
): AsyncGenerator<Uint8Array> {
  binding ??= new Promise((resolve) =>
    run((value) =>
      resolve({
        ZstdDecompressStreamBinding: (value as Binding)
          .ZstdDecompressStreamBinding,
      }),
    ),
  );
  const decoder = new (await binding).ZstdDecompressStreamBinding();
  const frames = new FrameSegments();
  try {
    if (!decoder.begin())
      throw new Error("Could not initialize Zstandard decoder.");
    for await (const input of source) {
      for (const segment of frames.push(input)) {
        const output: Uint8Array[] = [];
        if (!decoder.transform(segment, (chunk) => output.push(chunk)))
          throw new Error("Invalid Zstandard compressed data or checksum.");
        for (const chunk of output) if (chunk.length) yield chunk;
      }
    }
    // The binding checks compressed blocks/checksums but does not reject a
    // truncated frame at end(). Framing supplies that missing EOF check.
    frames.finish();
    const output: Uint8Array[] = [];
    if (!decoder.end((chunk) => output.push(chunk)))
      throw new Error("Invalid Zstandard compressed data or checksum.");
    for (const chunk of output) if (chunk.length) yield chunk;
  } finally {
    decoder.delete();
  }
}

type Part =
  | "magic"
  | "descriptor"
  | "frameHeader"
  | "blockHeader"
  | "block"
  | "checksum"
  | "skipLength"
  | "skip";

/**
 * Zstandard's frame and block boundaries, not its compressed payload format.
 * Feeding at most one block per call bounds synchronous decoder output before
 * the consumer can return after reading a logical prefix.
 * https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md
 */
class FrameSegments {
  private part: Part = "magic";
  private remaining = 4;
  private header = new Uint8Array(18); // Maximum Zstandard frame header size.
  private received = 0;
  private checksum = false;
  private lastBlock = false;
  private completed = false;

  *push(input: Uint8Array): Generator<Uint8Array> {
    let offset = 0;
    while (offset < input.length) {
      const length = Math.min(this.remaining, input.length - offset);
      const segment = input.subarray(offset, offset + length);
      offset += length;
      this.remaining -= length;
      if (this.part === "block" || this.part === "skip") {
        if (this.remaining === 0) this.endPayload();
        yield segment;
        continue;
      }
      this.header.set(segment, this.received);
      this.received += length;
      if (this.remaining !== 0) continue;
      const header = this.header.slice(0, this.received);
      this.received = 0;
      switch (this.part) {
        case "magic": {
          const magic = new DataView(header.buffer).getUint32(0, true);
          if (magic === 0xfd2fb528) this.next("descriptor", 1);
          else if ((magic & 0xfffffff0) === 0x184d2a50)
            this.next("skipLength", 4);
          else throw new Error("Invalid Zstandard frame magic.");
          break;
        }
        case "descriptor": {
          const descriptor = header[0]!;
          const single = (descriptor & 0x20) !== 0;
          const contentFlag = descriptor >>> 6;
          const contentSize =
            contentFlag === 0 ? (single ? 1 : 0) : 2 ** contentFlag;
          const dictionarySize = [0, 1, 2, 4][descriptor & 3]!;
          this.checksum = (descriptor & 4) !== 0;
          this.next(
            "frameHeader",
            Number(!single) + dictionarySize + contentSize,
          );
          break;
        }
        case "frameHeader":
          this.next("blockHeader", 3);
          break;
        case "blockHeader": {
          const block = header[0]! | (header[1]! << 8) | (header[2]! << 16);
          const type = (block >>> 1) & 3;
          if (type === 3) throw new Error("Invalid Zstandard block type.");
          this.lastBlock = (block & 1) !== 0;
          this.next("block", type === 1 ? 1 : block >>> 3);
          if (this.remaining === 0) this.endPayload();
          break;
        }
        case "checksum":
          this.endFrame();
          break;
        case "skipLength":
          this.next("skip", new DataView(header.buffer).getUint32(0, true));
          if (this.remaining === 0) this.endFrame();
          break;
      }
      yield header;
    }
  }

  finish(): void {
    if (!this.completed || this.part !== "magic" || this.received !== 0)
      throw new Error("Incomplete Zstandard frame at end of stream.");
  }

  private next(part: Part, length: number): void {
    this.part = part;
    this.remaining = length;
  }

  private endPayload(): void {
    if (this.part === "skip") this.endFrame();
    else if (!this.lastBlock) this.next("blockHeader", 3);
    else if (this.checksum) this.next("checksum", 4);
    else this.endFrame();
  }

  private endFrame(): void {
    this.completed = true;
    this.next("magic", 4);
  }
}

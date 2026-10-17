import { windowsFiles } from "./resolve-security-md";
import { decodePosixBytes } from "./posix-path";
import { readChunks } from "./helper-files";

export const PREVIEW_BYTES = 1024;
export const PREVIEW_READ_BYTES = 64 * 1024;

const bomEncoding = (data: Buffer) =>
  data[0] === 0xff && data[1] === 0xfe
    ? "utf-16le"
    : data[0] === 0xfe && data[1] === 0xff
      ? "utf-16be"
      : "utf-8";

function decodeSource(data: Buffer): string {
  // Preview decoding historically ignores malformed or incomplete source units.
  if (bomEncoding(data) === "utf-8")
    return decodePosixBytes(data)
      .replace(/^[\ufeff]/u, "")
      .replace(/[\udc80-\udcff]/gu, "");
  const units = Buffer.from(data.subarray(2, data.length - (data.length % 2)));
  if (bomEncoding(data) === "utf-16be") units.swap16();
  return units.toString("utf16le").replace(/[\ud800-\udfff]/gu, "");
}

export function isBinarySample(data: Buffer): boolean {
  return bomEncoding(data) === "utf-8"
    ? data.includes(0)
    : decodeSource(data).includes("\0");
}

export function truncateUtf8(text: string, budget: number): string {
  if (budget <= 0) return "";
  const bytes = Buffer.from(text);
  if (bytes.length <= budget) return text;
  let end = Math.min(budget, bytes.length);
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) end--;
  return bytes.subarray(0, end).toString("utf8");
}

export function previewForBytes(
  data: Buffer,
  budget = PREVIEW_BYTES,
): [string, boolean] {
  if (isBinarySample(data)) return ["", true];
  if (budget <= 0) return ["", false];
  let lines = decodeSource(data).replace(/\r\n?/gu, "\n").split("\n");
  let first = 0,
    last = lines.length;
  while (first < last && !lines[first]!.trim()) first++;
  while (last > first && !lines[last - 1]!.trim()) last--;
  lines = lines.slice(first, last);
  const complete = lines.join("\n");
  if (Buffer.byteLength(complete) <= budget) return [complete, false];
  const nonblank = lines.filter((line) => line.trim());
  const remainder = nonblank.slice(12);
  lines =
    remainder.length <= 10
      ? nonblank
      : [
          ...nonblank.slice(0, 12),
          "...",
          ...Array.from(
            { length: 10 },
            (_, index) =>
              remainder[Math.floor((index * (remainder.length - 1)) / 9)]!,
          ),
        ];
  if (!lines.length) return ["", false];
  const sampled = lines.join("\n");
  if (Buffer.byteLength(sampled) <= budget) return [sampled, false];
  const render = (size: number) =>
    lines
      .map((line) => (line === "..." ? line : truncateUtf8(line, size)))
      .join("\n");
  let low = 0,
    high = Math.max(...lines.map((line) => Buffer.byteLength(line))),
    best = "";
  while (low <= high) {
    const middle = Math.floor((low + high) / 2),
      candidate = render(middle);
    if (Buffer.byteLength(candidate) <= budget) {
      best = candidate;
      low = middle + 1;
    } else high = middle - 1;
  }
  return [
    best.trim() && best.trim() !== "..." ? best : truncateUtf8(sampled, budget),
    false,
  ];
}

/** Share bounded preview and binary classification across file and Git reads. */
export function createSourceSampler() {
  let sample = Buffer.alloc(0),
    binary = false,
    bom = Buffer.alloc(0),
    unitTail = Buffer.alloc(0);
  return {
    consume(data: Buffer): boolean {
      if (sample.length < PREVIEW_READ_BYTES)
        sample = Buffer.concat([
          sample,
          data.subarray(0, PREVIEW_READ_BYTES - sample.length),
        ]);
      const classified = Buffer.concat([unitTail, data]);
      if (!bom.length && sample.length >= 2 && bomEncoding(sample) !== "utf-8")
        bom = sample.subarray(0, 2);
      // Hold one byte until encoding can be identified, and preserve UTF-16 unit alignment.
      const classifyLength =
        classified.length -
        (bom.length || sample.length < 2 ? classified.length % 2 : 0);
      if (classifyLength)
        binary ||= bom.length
          ? isBinarySample(
              Buffer.concat([bom, classified.subarray(0, classifyLength)]),
            )
          : classified.subarray(0, classifyLength).includes(0);
      unitTail = classified.subarray(classifyLength);
      return !binary;
    },
    finish(): [Buffer, boolean] {
      if (!bom.length && unitTail.length) binary ||= unitTail.includes(0);
      return [binary ? Buffer.alloc(0) : sample, binary];
    },
  };
}

/** Retain a bounded preview while checking every byte for binary content. */
export function sampleFile(path: string): [Buffer, boolean] {
  try {
    const sampler = createSourceSampler();
    if (process.platform === "win32")
      windowsFiles().readChunks(Buffer.from(path, "utf16le"), sampler.consume);
    else
      for (const chunk of readChunks(path)) if (!sampler.consume(chunk)) break;
    return sampler.finish();
  } catch {
    return [Buffer.alloc(0), true];
  }
}

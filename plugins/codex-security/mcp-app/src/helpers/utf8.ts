import { isUtf8 } from "node:buffer";

export function decodeUtf8(bytes: Buffer): string {
  // Node 20's fatal TextDecoder can silently replace invalid input bytes.
  if (!isUtf8(bytes))
    throw new TypeError("The encoded data was not valid for encoding utf-8");
  return bytes.toString("utf8");
}

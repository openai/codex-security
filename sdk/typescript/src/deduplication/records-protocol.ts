import type { Readable } from "node:stream";
import {
  runHostRecordsProtocol,
  type RecordsProtocolOutput,
} from "../host-records-protocol.js";
import { deduplicateRecords, type DeduplicateRecordsInput } from "./records.js";

/** One bidirectional deduplication run. Stdout contains JSON-RPC envelopes only. */
export function runRecordsProtocol(
  input: Readable,
  output: RecordsProtocolOutput,
  signal?: AbortSignal,
): Promise<number> {
  return runHostRecordsProtocol(
    input,
    output,
    (value, options) =>
      deduplicateRecords(value as DeduplicateRecordsInput, options),
    signal,
    "Deduplication canceled.",
  );
}

import { Formatter } from "incur";
import { estimateTokenCount, sliceByTokens } from "tokenx";
import { asRecord } from "./record.js";

export interface TokenView {
  count?: boolean;
  limit?: number;
  offset?: number;
}

/** Apply a window to the serialized data. Keep failure details and pagination
 * metadata readable even when the caller requests a single token.
 */
export function formatJsonTokenView(
  response: string,
  format: "json" | "jsonl",
  fullOutput: boolean,
  view: TokenView,
): string {
  const envelope = fullOutput ? asRecord(JSON.parse(response)) : undefined;
  const failed = envelope?.["ok"] === false;
  if (failed && envelope["data"] == null) return response;
  const text = envelope
    ? Formatter.format(envelope["data"], format)
    : response.replace(/\n$/u, "");
  const total = estimateTokenCount(text);
  if (view.count) {
    if (!failed) return `${total}\n`;
    const { data: _data, ...failure } = envelope;
    return (
      Formatter.format(
        {
          ...failure,
          meta: { ...asRecord(failure["meta"]), tokenCount: total },
        },
        format,
      ) + "\n"
    );
  }
  const start = Math.min(view.offset ?? 0, total);
  const end = Math.min(start + (view.limit ?? total), total);
  if (start === 0 && end === total) return response;
  const page = `${sliceByTokens(text, start, end)}\n[truncated: showing tokens ${start}–${end} of ${total}]`;
  if (!envelope) return JSON.stringify(page) + "\n";
  return (
    Formatter.format(
      {
        ...envelope,
        data: page,
        meta: {
          ...asRecord(envelope["meta"]),
          ...(start < end && end < total && { nextOffset: end }),
        },
      },
      format,
    ) + "\n"
  );
}

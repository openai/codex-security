import { Formatter } from "incur";
import type { readSavedScanLogs } from "./scan-logs.js";

// Format records separately: a saved log document can exceed the runtime's
// maximum string length even though each session and event fits comfortably.
export async function* scanLogsJson(
  logs: Awaited<ReturnType<typeof readSavedScanLogs>>,
  cta?: unknown,
): AsyncGenerator<Uint8Array> {
  yield Buffer.from(
    `{\n  "scanId": ${JSON.stringify(logs.scanId)},\n  "threadId": ${JSON.stringify(logs.threadId)}`,
  );
  for (const key of ["sessions", "events"] as const) {
    yield Buffer.from(`,\n  "${key}": [`);
    let first = true;
    for (const record of logs[key]) {
      const formatted = Formatter.format(record, "json").replaceAll(
        "\n",
        "\n    ",
      );
      yield Buffer.from(`${first ? "\n" : ",\n"}    ${formatted}`);
      first = false;
    }
    yield Buffer.from(first ? "]" : "\n  ]");
  }
  if (cta !== undefined) {
    const formatted = Formatter.format(cta, "json").replaceAll("\n", "\n  ");
    yield Buffer.from(`,\n  "cta": ${formatted}`);
  }
  yield Buffer.from("\n}\n");
}

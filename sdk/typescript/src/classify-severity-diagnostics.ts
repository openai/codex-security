import type { SeverityDiagnosticCode } from "./classify-severity-records.js";
import type { HostDiagnosticBatch } from "./host-protocol.js";

const maxRecords = 64;

/** The host receives the CLI's original JSON lines on existing protocol writes. */
export function createSeverityDiagnostics(now: () => number) {
  let records: string[] = [];
  let accepted = 0;
  let dropped = 0;

  function emit(code: SeverityDiagnosticCode, ordinal?: number) {
    // Reserve a record for the terminal result, even for large SDK batches.
    if (
      accepted >= maxRecords ||
      (accepted >= maxRecords - 1 && !code.startsWith("exit_"))
    ) {
      dropped++;
      return;
    }
    try {
      records.push(
        JSON.stringify({
          schema: "codex-security.classify-severity.v1",
          at: new Date(now()).toISOString(),
          code,
          ordinal,
        }),
      );
      accepted++;
    } catch {
      dropped++;
    }
  }

  emit("invocation_started");
  return {
    emit,
    take(message: object): HostDiagnosticBatch | undefined {
      if ("error" in message) {
        const error = message.error;
        const cancelled =
          typeof error === "object" &&
          error !== null &&
          "code" in error &&
          error.code === -32800;
        emit(cancelled ? "exit_cancelled" : "exit_error");
      } else if ("result" in message) {
        const result = message.result;
        const completed =
          typeof result === "object" &&
          result !== null &&
          "status" in result &&
          result.status === "completed";
        emit(completed ? "exit_completed" : "exit_unresolved");
      }
      if (!records.length && !dropped) return;
      const batch = { records, dropped };
      records = [];
      dropped = 0;
      return batch;
    },
  };
}

import type { SeverityDiagnosticCode } from "./classify-severity-records.js";
import type { HostDiagnosticBatch } from "./host-protocol.js";

const maxRecords = 64;

/** Node resolves the private import only when the host activates this condition. */
export function severityDiagnosticsEnabled(): boolean {
  try {
    import.meta.resolve("#classify-severity-records-logs");
    return true;
  } catch {
    return false;
  }
}

/** The host receives the CLI's original JSON lines on existing protocol writes. */
export function createSeverityDiagnostics(now: () => number) {
  let records: string[] = [];
  let dropped = 0;

  function emit(code: SeverityDiagnosticCode, ordinal?: number) {
    // Reserve space in the pending frame for the terminal result.
    if (
      records.length >= maxRecords ||
      (records.length >= maxRecords - 1 && !code.startsWith("exit_"))
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

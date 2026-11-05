import { isRecord } from "./record.js";
import { isSafeNonNegativeInteger } from "./value.js";

/** Service coverage from the built-in graph server for one ephemeral check. */
export class DependencyReportCoverage {
  private calls = new Map<string, number>();
  private failures = 0;
  private unreadable = false;
  private revision = -1;
  private pending = 0;
  private unresolved = 0;
  private truncated = false;
  generation = 0;

  observe(
    phase: "item/started" | "item/completed",
    item: Record<string, unknown>,
  ) {
    if (
      item["type"] !== "mcpToolCall" ||
      item["server"] !== "codex_security_dependency" ||
      typeof item["id"] !== "string"
    )
      return;
    if (phase === "item/started") {
      this.calls.set(item["id"], this.failures);
      return;
    }
    const startedAfterFailures = this.calls.get(item["id"]);
    this.calls.delete(item["id"]);
    const result = item["result"];
    const payload =
      isRecord(result) &&
      result["isError"] !== true &&
      result["is_error"] !== true
        ? result["structuredContent"]
        : undefined;
    const status = isRecord(payload)
      ? payload["service_resolution"]
      : undefined;
    if (
      item["status"] !== "completed" ||
      item["error"] != null ||
      !isRecord(status) ||
      !isSafeNonNegativeInteger(status["revision"]) ||
      !isSafeNonNegativeInteger(status["pending"]) ||
      (status["unresolved"] !== undefined &&
        !isSafeNonNegativeInteger(status["unresolved"]))
    ) {
      this.failures++;
      this.unreadable = true;
      this.generation++;
      return;
    }
    if (status["revision"] < this.revision) return;
    if (status["revision"] > this.revision) {
      this.revision = status["revision"];
      this.pending = status["pending"];
      this.unresolved = status["unresolved"] ?? 0;
      this.truncated = status["truncated"] === true;
      this.generation++;
    }
    // A query already in flight when a mutation failed cannot attest recovery.
    if (this.unreadable && startedAfterFailures === this.failures) {
      this.unreadable = false;
      this.generation++;
    }
  }

  get busy() {
    return this.calls.size > 0;
  }

  endTurn() {
    if (this.busy) {
      this.calls.clear();
      this.failures++;
      this.unreadable = true;
      this.generation++;
    }
  }

  get outstanding() {
    return this.unreadable || this.pending > 0;
  }

  limitation() {
    const reasons = [];
    if (this.unreadable)
      reasons.push(
        "the graph did not return current service resolution coverage",
      );
    if (this.pending)
      reasons.push(
        `the last graph snapshot had ${this.pending} pending service ${this.pending === 1 ? "lookup" : "lookups"}`,
      );
    if (this.unresolved)
      reasons.push(
        `${this.unresolved} service ${this.unresolved === 1 ? "lookup remains" : "lookups remain"} unresolved after catalog investigation`,
      );
    if (this.truncated)
      reasons.push(
        "the graph reached its limit for retaining service questions",
      );
    return reasons.length
      ? `Service resolution is partial because ${reasons.join(" and ")}.`
      : undefined;
  }
}

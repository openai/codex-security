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
  private sourceEvidenceCount = 0;
  private discoveryOmissions = new Set<string>();
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
    const evidenceCount = isRecord(payload)
      ? payload["source_evidence_count"]
      : undefined;
    if (
      isSafeNonNegativeInteger(evidenceCount) &&
      evidenceCount > this.sourceEvidenceCount
    ) {
      this.sourceEvidenceCount = evidenceCount;
      this.generation++;
    }
    const traceCoverage = isRecord(payload) ? payload["coverage"] : undefined;
    if (
      isRecord(traceCoverage) &&
      Array.isArray(traceCoverage["discovery_omissions"])
    ) {
      for (const entry of traceCoverage["discovery_omissions"]) {
        if (
          isRecord(entry) &&
          typeof entry["path"] === "string" &&
          !this.discoveryOmissions.has(entry["path"])
        ) {
          this.discoveryOmissions.add(entry["path"]);
          this.generation++;
        }
      }
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

  /** Missing graph coverage or omitted source cannot establish an overall exclusion. */
  get incomplete() {
    return (
      this.outstanding || this.truncated || this.discoveryOmissions.size > 0
    );
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

  discoveryLimitation() {
    const files = this.discoveryOmissions.size;
    if (files)
      return `Operator scope omitted ${files} matched source ${files === 1 ? "file" : "files"} from one or more broad structural searches. The search audit records the exact locations. Exact-file follow-up remains available.`;
  }
}

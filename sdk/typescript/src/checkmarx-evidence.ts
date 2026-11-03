import {
  type ExternalImportTarget,
  validateExternalEvidence,
} from "./external-import-contract.js";
import { text } from "./scanner-import.js";

interface CheckmarxOccurrence {
  format: "checkmarx-one-json" | "cxsast-xml";
  repository: string;
  scanId: string;
  title: string;
  ruleId: string | null;
  severity: unknown;
  description?: string | null;
  status?: string | null;
  verdict?: string | null;
  cwe?: unknown;
  sourceData: Record<string, unknown>;
}

function severity(value: unknown): string {
  const level = text(value)?.toLowerCase();
  switch (level) {
    case "critical":
    case "high":
    case "medium":
    case "low":
      return level;
    case "info":
    case "information":
    case "informational":
      return "informational";
    default:
      return "unknown";
  }
}

export function checkmarxEvidence(
  row: CheckmarxOccurrence,
  target: ExternalImportTarget,
) {
  const one = row.format === "checkmarx-one-json";
  const cwe =
    typeof row.cwe === "number" || typeof row.cwe === "string"
      ? String(row.cwe)
      : "";
  return validateExternalEvidence(
    {
      title: row.title,
      severity: severity(row.severity),
      description: row.description,
      source_scan_id: row.scanId,
      // Filenames are relative to the scanned sources, which can be a ZIP or subdirectory.
      locations: [],
      details: {
        kind: "sast",
        repository: { url: row.repository },
        scanner_origin: one ? "Checkmarx One SAST" : "CxSAST",
        rule: { id: row.ruleId, name: row.title },
        source_status: row.status,
        scanner_verdict: row.verdict,
        weakness_ids: /^[1-9]\d*$/u.test(cwe) ? [`CWE-${cwe}`] : [],
      },
      source_data: {
        ...row.sourceData,
        format: row.format,
        sourceRepositoryUrl: row.repository,
      },
    },
    target,
  );
}

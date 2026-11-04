import {
  type ExternalImportTarget,
  validateExternalEvidence,
} from "./external-import-contract.js";
import { scannerSeverity, text } from "./scanner-import.js";

interface CheckmarxReport extends Record<string, unknown> {
  format: "checkmarx-one-json" | "cxsast-xml";
  sourceRepositoryUrl: string;
  scanId: string;
}

interface CheckmarxOccurrence {
  title: string;
  ruleId: unknown;
  severity: unknown;
  description?: unknown;
  status?: unknown;
  verdict?: unknown;
  cwe?: unknown;
  sourceData: Record<string, unknown>;
}

function idText(value: unknown) {
  return typeof value === "number" ? String(value) : text(value);
}

export function checkmarxEvidence(
  report: CheckmarxReport,
  row: CheckmarxOccurrence,
  target: ExternalImportTarget,
) {
  const severity = text(row.severity)?.toLowerCase();
  const cwe = idText(row.cwe) ?? "";
  return validateExternalEvidence(
    {
      title: row.title,
      severity:
        severity === "info" || severity === "information"
          ? "informational"
          : scannerSeverity(severity),
      description: text(row.description),
      source_scan_id: report.scanId,
      // Filenames are relative to the scanned sources, which can be a ZIP or subdirectory.
      locations: [],
      details: {
        kind: "sast",
        repository: { url: report.sourceRepositoryUrl },
        scanner_origin:
          report.format === "checkmarx-one-json"
            ? "Checkmarx One SAST"
            : "CxSAST",
        rule: { id: idText(row.ruleId), name: row.title },
        source_status: text(row.status),
        scanner_verdict: text(row.verdict),
        weakness_ids: /^[1-9]\d*$/u.test(cwe) ? [`CWE-${cwe}`] : [],
      },
      source_data: {
        ...row.sourceData,
        format: report.format,
        sourceRepositoryUrl: report.sourceRepositoryUrl,
      },
    },
    target,
  );
}

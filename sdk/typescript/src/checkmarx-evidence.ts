import {
  type ExternalImportTarget,
  validateExternalEvidence,
} from "./external-import-contract.js";
import { repositoryFilePath, text } from "./scanner-import.js";

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
  nodes: { fileName: unknown; line: unknown }[];
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
  const locations: { path: string; line: number | null }[] = [];
  const seen = new Set<string>();
  for (const node of row.nodes) {
    const file = text(node.fileName);
    // Checkmarx One prefixes paths with the scan root, even for top-level files.
    const path = repositoryFilePath(
      one && file?.startsWith("/") ? file.slice(1) : file,
    );
    if (!path) continue;
    const number =
      typeof node.line === "string" && /^\d+$/u.test(node.line)
        ? Number(node.line)
        : node.line;
    const line =
      typeof number === "number" && Number.isSafeInteger(number) && number > 0
        ? number
        : null;
    const key = JSON.stringify([path, line]);
    if (seen.has(key)) continue;
    seen.add(key);
    locations.push({ path, line });
  }
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
      locations,
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

import { CodexSecurityError } from "./errors.js";
import type {
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import {
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import { asRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  requiredText,
  scannerSeverity,
  text,
} from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

export const tenzaiReportFormat = "tenzai-test-findings/v1";

function testScope(rows: Record<string, unknown>[]) {
  const tests = new Set(
    rows.map((row) => requiredText(row["testId"], "Tenzai Test ID")),
  );
  const apps = new Set(
    rows.flatMap((row) =>
      row["appId"] == null
        ? []
        : [requiredText(row["appId"], "Tenzai application ID")],
    ),
  );
  if (tests.size > 1 || apps.size > 1)
    throw new CodexSecurityError(
      "Select Tenzai findings from one Test and application.",
    );
  return { testId: [...tests][0] ?? null, appId: [...apps][0] ?? null };
}

function reportRows(input: unknown) {
  if (Array.isArray(input)) return input;
  const document = record(input, "Tenzai report");
  if (document["items"] !== undefined) {
    const items = array(document["items"], "Tenzai findings");
    if (
      document["page"] !== 1 ||
      (document["pages"] !== 0 && document["pages"] !== 1) ||
      document["total"] !== items.length
    )
      throw new CodexSecurityError(
        "Export every Tenzai findings page with tenzai finding list --test-id UUID --paginate --output json.",
      );
    return items;
  }
  if (document["id"] !== undefined) return [document];
  throw new CodexSecurityError(
    "Expected Tenzai Test findings JSON: an array, a complete items page, or one finding.",
  );
}

/** Read the public CLI's per-Test JSON export, retaining the complete native evidence. */
export async function readTenzaiFindings(
  path: string,
  sourceRepositoryUrl: string,
): Promise<ExternalFindings> {
  const repositoryUrl = declaredScannerRepositoryUrl(
    sourceRepositoryUrl,
    "Tenzai",
    "local",
  );
  const rows = reportRows(await readScannerJson(path)).map((row) =>
    record(row, "Tenzai finding"),
  );
  const scope = testScope(rows);
  return normalizeRecords(
    rows,
    (finding) => {
      const remediation = asRecord(finding["remediation"]);
      const fixes = array(remediation?.["codeFixes"] ?? [], "Tenzai code fixes")
        .map((fix) => {
          const item = record(fix, "Tenzai code fix");
          return [text(item["title"]), text(item["description"])]
            .filter(Boolean)
            .join(": ");
        })
        .filter(Boolean);
      const description = [
        text(finding["description"]),
        text(finding["impact"]) && `Impact: ${finding["impact"]}`,
        fixes.length ? `Remediation:\n${fixes.join("\n\n")}` : null,
      ]
        .filter(Boolean)
        .join("\n\n");
      const cve = text(finding["cve"]);
      return validateExternalEvidence(
        {
          title: requiredText(finding["name"], "Tenzai finding name"),
          severity: scannerSeverity(text(finding["severity"])?.toLowerCase()),
          description: description || null,
          url: text(finding["ui_link"]),
          advisory_ids: cve ? [cve] : [],
          packages: [],
          // Tenzai paths are relative to its source bundle, which may span repositories.
          locations: [],
          source_scan_id: scope.testId,
          source_data: {
            format: tenzaiReportFormat,
            finding: structuredClone(finding),
          },
        },
        "local",
      );
    },
    (finding) => requiredText(finding["id"], "Tenzai finding ID"),
    "local",
    { report: { format: tenzaiReportFormat, repositoryUrl, ...scope } },
  );
}

/** Keep normalized reimports bound to their native finding and declared repository. */
export function tenzaiSourceRepository(
  input: ExternalFindings,
  declared: string | undefined,
  references: readonly ExternalSourceRepository[],
): ExternalSourceRepository {
  const url = declaredScannerRepositoryUrl(declared, "Tenzai", "local");
  if (input.report?.["format"] !== tenzaiReportFormat)
    throw new CodexSecurityError(
      "Tenzai imports require a report from the tenzai reader.",
    );
  for (const claim of [
    input.report["repositoryUrl"],
    ...references.map((ref) => ref.url),
  ]) {
    if (
      repositoryUrlKey(
        declaredScannerRepositoryUrl(claim, "Tenzai", "local"),
      ) !== repositoryUrlKey(url)
    )
      throw new CodexSecurityError(
        "Tenzai repository URL does not match --source-repository-url.",
      );
  }
  const rows = input.findings.map(({ source_finding_id, evidence }) => {
    validateExternalEvidence(evidence, "local");
    const data = evidence.source_data;
    const finding = record(data?.["finding"], "Tenzai retained finding");
    if (
      data?.["format"] !== tenzaiReportFormat ||
      finding["id"] !== source_finding_id ||
      finding["testId"] !== input.report!["testId"] ||
      (finding["appId"] != null && finding["appId"] !== input.report!["appId"])
    )
      throw new CodexSecurityError(
        "Tenzai findings must retain their native identity, Test and application.",
      );
    return finding;
  });
  testScope(rows);
  return { url };
}

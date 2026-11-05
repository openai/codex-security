import { z } from "zod";
import type { ExternalFindings } from "./external-findings.js";
import {
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import {
  readScannerJson,
  repositoryFilePath,
  scannerSeverity,
} from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

export const tenableReportFormat = "tenable-one-code-repository/v1";

// The capture joins inventory exports on asset_id and records the operator's SCM binding.
const nonblank = z.string().regex(/\S/u);
const assetId = z.guid().toLowerCase();
const selection = z.object({
  format: z.literal(tenableReportFormat),
  asset: z.object({
    asset_class: z.literal("CODE_REPOSITORY"),
    asset_id: assetId,
    asset_name: nonblank,
  }),
  repository_url: nonblank,
  findings: z.array(
    z.object({
      asset_id: assetId,
      finding_id: nonblank,
      finding_name: nonblank,
      severity: nonblank,
      state: nonblank,
      description: z.string().optional(),
      solution: z.string().optional(),
      code_file_path: nonblank.optional(),
      code_line_number: z
        .union([z.int().positive(), z.string().regex(/^\d+$/u)])
        .optional(),
    }),
  ),
});

function findingLocations(rawPath?: string, rawLine?: number | string) {
  if (rawPath === undefined && rawLine === undefined) return [];
  const path = repositoryFilePath(rawPath);
  if (!path)
    throw new Error(
      "Tenable code locations require a repository-relative file path.",
    );
  const line = rawLine === undefined ? null : Number(rawLine);
  if (line !== null && (!Number.isSafeInteger(line) || line < 1))
    throw new Error("Tenable code line number must be a positive integer.");
  return [{ path, line }];
}

export async function readTenableFindings(
  path: string,
  sourceRepositoryUrl: string,
): Promise<ExternalFindings> {
  const declared = declaredScannerRepositoryUrl(
    sourceRepositoryUrl,
    "Tenable",
    "local",
  );
  const {
    asset,
    repository_url,
    findings: rows,
  } = selection.parse(await readScannerJson(path));
  const repository = declaredScannerRepositoryUrl(
    repository_url,
    "Tenable capture",
    "local",
  );
  if (repositoryUrlKey(repository) !== repositoryUrlKey(declared))
    throw new Error(
      "Tenable repository URL does not match --source-repository-url.",
    );

  const ids = new Set<string>();
  const findings = rows.map((finding) => {
    if (finding.asset_id !== asset.asset_id)
      throw new Error(
        "Every Tenable finding must belong to the selected Code Repository asset.",
      );
    if (ids.has(finding.finding_id))
      throw new Error(`Duplicate Tenable finding ID: ${finding.finding_id}`);
    ids.add(finding.finding_id);
    const severity = finding.severity.trim().toLowerCase();
    return {
      source_finding_id: finding.finding_id,
      evidence: validateExternalEvidence(
        {
          title: finding.finding_name,
          severity: scannerSeverity(
            severity === "info" ? "informational" : severity,
          ),
          description: finding.description,
          locations: findingLocations(
            finding.code_file_path,
            finding.code_line_number,
          ),
          source_data: {
            format: tenableReportFormat,
            repository_url,
            asset,
            finding,
          },
        },
        "local",
      ),
    };
  });
  return {
    read: rows.length,
    report: { format: tenableReportFormat, repositoryUrl: repository, asset },
    findings,
    excluded: [],
  };
}

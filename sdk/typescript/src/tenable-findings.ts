import { z } from "zod";
import { CodexSecurityError } from "./errors.js";
import { asRecord } from "./record.js";
import { isGitHubCloudHost } from "./git-remote.js";
import type {
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import {
  repositoryUrlKey,
  type ExternalImportTarget,
  validateExternalEvidence,
} from "./external-import-contract.js";
import {
  appendFinding,
  readScannerJson,
  repositoryFilePath,
  scannerSeverity,
  text,
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

function assertRepository(
  claim: unknown,
  expected: string,
  target: ExternalImportTarget,
) {
  const url = declaredScannerRepositoryUrl(claim, "Tenable", target);
  if (repositoryUrlKey(url) !== repositoryUrlKey(expected))
    throw new CodexSecurityError(
      "Tenable repository URL does not match --source-repository-url.",
    );
  return url;
}

/** Verify retained identities when importing a normalized selection through the SDK. */
export function tenableSourceRepository(
  input: Pick<ExternalFindings, "findings" | "report">,
  declared: string | undefined,
  references: readonly ExternalSourceRepository[],
  target: ExternalImportTarget = "local",
): ExternalSourceRepository {
  const first =
    target === "cloud" ? input.findings[0]?.evidence.source_data : undefined;
  const header = input.report ?? first;
  const asset = asRecord(header?.["asset"]);
  if (
    header?.["format"] !== tenableReportFormat ||
    asset?.["asset_class"] !== "CODE_REPOSITORY" ||
    !(target === "cloud" ? assetId : nonblank).safeParse(asset["asset_id"])
      .success
  )
    throw new CodexSecurityError(
      "Tenable imports require a report for one code repository asset.",
    );
  const url = declaredScannerRepositoryUrl(
    declared ??
      (target === "cloud"
        ? (input.report?.["repositoryUrl"] ?? first?.["repository_url"])
        : undefined),
    "Tenable",
    target,
  );
  if (input.report)
    assertRepository(input.report["repositoryUrl"], url, target);
  for (const ref of references) assertRepository(ref.url, url, target);
  for (const { source_finding_id, evidence } of input.findings) {
    validateExternalEvidence(evidence, target);
    const data = evidence.source_data;
    const rowAsset = asRecord(data?.["asset"]);
    const finding = asRecord(data?.["finding"]);
    if (
      data?.["format"] !== tenableReportFormat ||
      rowAsset?.["asset_class"] !== asset["asset_class"] ||
      rowAsset["asset_id"] !== asset["asset_id"] ||
      finding?.["asset_id"] !== asset["asset_id"] ||
      finding?.["finding_id"] !== source_finding_id
    )
      throw new CodexSecurityError(
        "Tenable findings must retain their native finding ID and one code repository asset.",
      );
    assertRepository(data["repository_url"], url, target);
    if (evidence.details?.repository?.url !== undefined)
      assertRepository(evidence.details.repository.url, url, target);
  }
  const { hostname } = new URL(url);
  return {
    url,
    platform: isGitHubCloudHost(hostname)
      ? "github"
      : hostname === "gitlab.com"
        ? "gitlab"
        : undefined,
  };
}

export async function readTenableFindings(
  path: string,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "local",
): Promise<ExternalFindings> {
  const declared = declaredScannerRepositoryUrl(
    sourceRepositoryUrl,
    "Tenable",
    target,
  );
  const {
    asset,
    repository_url,
    findings: rows,
  } = selection.parse(await readScannerJson(path));
  const repository = assertRepository(repository_url, declared, target);
  const ids = new Set<string>();
  const result: ExternalFindings = {
    read: rows.length,
    report: { format: tenableReportFormat, repositoryUrl: repository, asset },
    findings: [],
    excluded: [],
  };
  for (const [index, finding] of rows.entries()) {
    if (finding.asset_id !== asset.asset_id)
      throw new Error(
        "Every Tenable finding must belong to the selected Code Repository asset.",
      );
    if (ids.has(finding.finding_id))
      throw new Error(`Duplicate Tenable finding ID: ${finding.finding_id}`);
    ids.add(finding.finding_id);
    const severity = finding.severity.trim().toLowerCase();
    const locations = findingLocations(
      finding.code_file_path,
      finding.code_line_number,
    );
    const evidence = () =>
      validateExternalEvidence(
        {
          title: finding.finding_name,
          severity: scannerSeverity(
            severity === "info" ? "informational" : severity,
          ),
          description: text(finding.description),
          locations,
          source_data: {
            format: tenableReportFormat,
            repository_url,
            asset,
            finding,
          },
        },
        target,
      );
    if (target === "cloud")
      appendFinding(result, index + 1, finding.finding_id, evidence);
    else
      result.findings.push({
        source_finding_id: finding.finding_id,
        evidence: evidence(),
      });
  }
  return result;
}

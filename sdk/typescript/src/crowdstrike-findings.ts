import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { CodexSecurityError } from "./errors.js";
import type {
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import {
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import { isGitHubCloudHost } from "./git-remote.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  repositoryFilePath,
  requiredText,
  scannerSeverity,
  stableId,
  text,
} from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

export const crowdstrikeReportFormat = "crowdstrike-fcs-iac/v1";

type NativeRecord = Record<string, unknown>;

interface Entry {
  rule: NativeRecord;
  detection: NativeRecord;
}

function joined(...values: (string | null)[]): string | null {
  return values.filter((value) => value !== null).join("\n\n") || null;
}

function positive(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0
    ? value
    : null;
}

// FCS writes paths relative to its working directory. A remote git:: scan
// writes them relative to the clone root with a leading slash.
function detectionPath(detection: NativeRecord, remote: boolean) {
  const raw = text(detection["file"]);
  const path = repositoryFilePath(remote ? raw?.replace(/^\//u, "") : raw);
  if (!path)
    throw new Error(
      "CrowdStrike detection file must be checkout-relative. Run the FCS CLI from the checkout root.",
    );
  return path;
}

// A detection in a registry or Git module names the calling file, but its line
// is inside the module. FCS states the call line only in module_remediation.
function detectionLine(detection: NativeRecord, path: string): number | null {
  const line = positive(detection["line"]);
  const source = text(detection["module_source"]);
  if (
    detection["is_from_module"] !== true ||
    !source ||
    path.startsWith(`${source}/`)
  )
    return line;
  // Search for this file's exact phrase; the remediation text comes from the report.
  const remediation = text(detection["module_remediation"]) ?? "";
  const marker = `called by ${path} at line `;
  const start = remediation.indexOf(marker);
  const call =
    start === -1
      ? null
      : /^\d+\b/u.exec(remediation.slice(start + marker.length));
  return call ? positive(Number(call[0])) : null;
}

/** Check repository claims, and that each finding's file is in the selected checkout. */
export async function crowdstrikeCheckout(
  input: ExternalFindings,
  declared: string | undefined,
  references: readonly ExternalSourceRepository[],
  repository: string,
): Promise<{ url: string; platform?: string } | undefined> {
  if (input.report?.["format"] !== crowdstrikeReportFormat)
    throw new CodexSecurityError(
      "CrowdStrike imports require a report from the crowdstrike reader.",
    );
  const claims: unknown[] = [
    declared,
    input.report["repositoryUrl"],
    ...references.map(({ url }) => url),
  ];
  const paths = new Set<string>();
  for (const { evidence } of input.findings) {
    validateExternalEvidence(evidence, "local");
    const data = evidence.source_data;
    if (data?.["format"] !== crowdstrikeReportFormat)
      throw new CodexSecurityError(
        "CrowdStrike findings must retain their native detection.",
      );
    claims.push(data["repository_url"], evidence.details?.repository?.url);
    for (const { path } of evidence.locations ?? []) {
      const file = repositoryFilePath(path);
      if (!file)
        throw new CodexSecurityError(
          "CrowdStrike finding locations must be checkout-relative files.",
        );
      paths.add(file);
    }
  }
  const urls = claims
    .filter((claim) => claim != null)
    .map((claim) =>
      declaredScannerRepositoryUrl(claim, "CrowdStrike", "local"),
    );
  if (new Set(urls.map((url) => repositoryUrlKey(url))).size > 1)
    throw new CodexSecurityError(
      "CrowdStrike findings name a different repository than --source-repository-url.",
    );
  // Paths are relative to where FCS ran, so a missing file means a different root or checkout.
  for (const file of paths)
    if (!(await lstat(join(repository, ...file.split("/"))).catch(() => null)))
      throw new CodexSecurityError(
        `${JSON.stringify(file)} is not in ${JSON.stringify(repository)}. Select the checkout that FCS scanned, and run the FCS CLI from its root.`,
      );
  const url = urls[0];
  if (url === undefined) return undefined;
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

/** Read a saved FCS CLI 4.x IaC JSON report. */
export async function readCrowdStrikeFindings(
  path: string,
  sourceRepositoryUrl?: string,
): Promise<ExternalFindings> {
  const repositoryUrl =
    sourceRepositoryUrl === undefined
      ? undefined
      : declaredScannerRepositoryUrl(
          sourceRepositoryUrl,
          "CrowdStrike",
          "local",
        );
  const document = record(await readScannerJson(path), "CrowdStrike report");
  if (!Array.isArray(document["rule_detections"]))
    throw new CodexSecurityError(
      "Expected an FCS CLI 4.x IaC JSON report with rule_detections.",
    );
  const version = text(document["fcs_version"]);
  const remote = text(document["path"])?.startsWith("git::") ?? false;
  const entries: Entry[] = array(
    document["rule_detections"],
    "CrowdStrike rule_detections",
  ).flatMap((value) => {
    const { detections, ...rule } = record(value, "CrowdStrike rule");
    return array(detections ?? [], "CrowdStrike detections").map(
      (detection) => ({
        rule,
        detection: record(detection, "CrowdStrike detection"),
      }),
    );
  });
  return normalizeRecords(
    entries,
    ({ rule, detection }) => {
      const kind =
        rule["rule_category"] === "Secret Management" ? "secret" : "iac";
      const reason = text(detection["reason"]);
      const recommendation = text(detection["recommendation"]);
      const file = detectionPath(detection, remote);
      return validateExternalEvidence(
        {
          title: requiredText(rule["rule_name"], "CrowdStrike rule_name"),
          severity: scannerSeverity(text(rule["severity"])?.toLowerCase()),
          description: joined(text(rule["description"]), reason),
          locations: [{ path: file, line: detectionLine(detection, file) }],
          source_scan_id: text(document["scan_uuid"]),
          // Typed IaC and secret details must name their source repository.
          details: repositoryUrl && {
            kind,
            repository: { url: repositoryUrl },
            rule: {
              id: text(rule["rule_uuid"]),
              name: text(rule["rule_name"]),
            },
            configuration:
              kind === "iac"
                ? {
                    platform: text(rule["platform"]),
                    cloud_platform: text(rule["cloud_provider"]),
                    expected: recommendation,
                    actual: reason,
                  }
                : null,
            remediation_instructions: joined(
              recommendation,
              text(detection["module_remediation"]),
            ),
            scanner_origin: version
              ? `CrowdStrike FCS CLI ${version}`
              : "CrowdStrike FCS CLI",
          },
          source_data: structuredClone({
            format: crowdstrikeReportFormat,
            fcs_version: version,
            ...(repositoryUrl && { repository_url: repositoryUrl }),
            rule,
            detection,
          }),
        },
        "local",
      );
    },
    ({ rule, detection }) =>
      stableId("crowdstrike", [
        requiredText(rule["rule_uuid"], "CrowdStrike rule_uuid"),
        detectionPath(detection, remote),
        positive(detection["line"]),
        detection["resource_type"] ?? null,
        detection["resource_name"] ?? null,
        detection["reason"] ?? null,
        detection["module_path"] ?? null,
      ]),
    "local",
    {
      report: {
        format: crowdstrikeReportFormat,
        ...(repositoryUrl && { repositoryUrl }),
        fcs_version: version,
        scan_uuid: text(document["scan_uuid"]),
      },
    },
  );
}

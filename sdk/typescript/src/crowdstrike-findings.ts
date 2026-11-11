import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
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
import {
  declaredScannerRepositoryUrl,
  validScannerRepositoryUrl,
} from "./scanner-repository-url.js";

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

// A git:: scan path without its ?ref= query. When the scanned URL has a user
// name, FCS writes each detection path after this prefix.
function gitScan(path: unknown): string | undefined {
  const value = text(path);
  return value?.startsWith("git::") ? value.split("?", 1)[0] : undefined;
}

// The repository of an HTTPS git:: scan, without its //subdirectory. Checkouts
// fetch over HTTPS or SSH, which do not match an http:// URL.
function gitScanRepository(scan: string): string | undefined {
  const source = scan.slice("git::".length);
  const scheme = /^https:\/\//iu.exec(source)?.[0];
  if (!scheme) return undefined;
  const subdirectory = source.indexOf("//", scheme.length);
  const url = subdirectory === -1 ? source : source.slice(0, subdirectory);
  return validScannerRepositoryUrl(url, "local") ? url : undefined;
}

// FCS writes paths relative to its working directory. A git:: scan writes them
// from the scan root, after a slash or after the scan path.
function detectionPath(detection: NativeRecord, scan: string | undefined) {
  const raw = text(detection["file"]);
  const relative =
    scan === undefined || !raw
      ? raw
      : raw.startsWith(`${scan}/`)
        ? raw.slice(scan.length + 1)
        : raw.replace(/^\//u, "");
  const path = repositoryFilePath(relative);
  if (!path)
    throw new CodexSecurityError(
      "CrowdStrike detection file must be checkout-relative. Run the FCS CLI from the checkout root.",
    );
  return path;
}

// A detection in a registry or Git module names the calling file, but its line
// is inside the module. FCS states the call line only in module_remediation.
// FCS writes the file, module source and calling file in one form, so compare them as written.
function detectionLine(detection: NativeRecord): number | null {
  const line = positive(detection["line"]);
  const file = text(detection["file"]);
  const source = text(detection["module_source"]);
  if (
    detection["is_from_module"] !== true ||
    !file ||
    !source ||
    file.startsWith(`${source}/`)
  )
    return line;
  // Search for this file's exact phrase; the remediation text comes from the report.
  const remediation = text(detection["module_remediation"]) ?? "";
  const marker = `called by ${file} at line `;
  const start = remediation.indexOf(marker);
  const call =
    start === -1
      ? null
      : /^\d+\b/u.exec(remediation.slice(start + marker.length));
  return call ? positive(Number(call[0])) : null;
}

/** Check repository claims, and that each finding's file is the scanned version in the selected checkout. */
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
  // Only a declared URL binds the checkout to its fetch remotes. A git:: report's
  // own repository is recorded and must agree with it.
  const declarations: unknown[] = [
    declared,
    input.report["repositoryUrl"],
    ...references.map(({ url }) => url),
  ];
  const reportScan = gitScan(input.report["git_scan"]);
  const claims = [...declarations, reportScan && gitScanRepository(reportScan)];
  const files = new Map<string, Set<unknown>>();
  for (const { evidence } of input.findings) {
    validateExternalEvidence(evidence, "local");
    const data = evidence.source_data;
    if (data?.["format"] !== crowdstrikeReportFormat)
      throw new CodexSecurityError(
        "CrowdStrike findings must retain their native detection.",
      );
    const scan = gitScan(data["git_scan"]);
    claims.push(
      data["repository_url"],
      evidence.details?.repository?.url,
      scan && gitScanRepository(scan),
    );
    // Check the retained detection's file, and that the shown location is the same.
    const detection = record(data["detection"], "CrowdStrike detection");
    const file = detectionPath(detection, scan);
    const [location, ...others] = evidence.locations ?? [];
    if (
      !location ||
      others.length > 0 ||
      location.path !== file ||
      (location.line ?? null) !== detectionLine(detection)
    )
      throw new CodexSecurityError(
        "CrowdStrike finding locations must match the native detection file and line.",
      );
    files.set(
      file,
      (files.get(file) ?? new Set()).add(detection["file_sha256"]),
    );
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
  // FCS follows file symlinks and records each file's SHA-256; another version gives stale lines.
  for (const [file, hashes] of files) {
    const path = join(repository, ...file.split("/"));
    if (!(await stat(path).catch(() => null))?.isFile())
      throw new CodexSecurityError(
        `${JSON.stringify(file)} is not in ${JSON.stringify(repository)}. Select the checkout that FCS scanned, and run the FCS CLI from its root.`,
      );
    const hash = createHash("sha256")
      .update(await readFile(path))
      .digest("hex");
    if ([...hashes].some((expected) => expected !== hash))
      throw new CodexSecurityError(
        `${JSON.stringify(file)} changed after the FCS scan. Select a checkout of the scanned commit, or scan again.`,
      );
  }
  const url = urls[0];
  if (url === undefined || declarations.every((claim) => claim == null))
    return undefined;
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
  const document = record(await readScannerJson(path), "CrowdStrike report");
  if (!Array.isArray(document["rule_detections"]))
    throw new CodexSecurityError(
      "Expected an FCS CLI 4.x IaC JSON report with rule_detections.",
    );
  const version = text(document["fcs_version"]);
  const scan = gitScan(document["path"]);
  const declared =
    sourceRepositoryUrl === undefined
      ? undefined
      : declaredScannerRepositoryUrl(
          sourceRepositoryUrl,
          "CrowdStrike",
          "local",
        );
  // A git:: report names the repository that FCS cloned.
  const repositoryUrl = declared ?? (scan && gitScanRepository(scan));
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
      const file = detectionPath(detection, scan);
      return validateExternalEvidence(
        {
          title: requiredText(rule["rule_name"], "CrowdStrike rule_name"),
          severity: scannerSeverity(text(rule["severity"])?.toLowerCase()),
          description: joined(text(rule["description"]), reason),
          locations: [{ path: file, line: detectionLine(detection) }],
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
            ...(scan !== undefined && { git_scan: scan }),
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
        detectionPath(detection, scan),
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
        ...(declared && { repositoryUrl: declared }),
        ...(scan !== undefined && { git_scan: scan }),
        fcs_version: version,
        scan_uuid: text(document["scan_uuid"]),
      },
    },
  );
}

import { CodexSecurityError } from "./errors.js";
import type {
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import {
  repositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
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

function detectionLine(detection: NativeRecord): number | null {
  const line = detection["line"];
  return typeof line === "number" && Number.isSafeInteger(line) && line > 0
    ? line
    : null;
}

function assertRepository(claim: unknown, expected: string) {
  const url = declaredScannerRepositoryUrl(claim, "CrowdStrike", "local");
  if (repositoryUrlKey(url) !== repositoryUrlKey(expected))
    throw new CodexSecurityError(
      "CrowdStrike repository URL does not match --source-repository-url.",
    );
}

/** Verify retained identities when importing a normalized selection through the SDK. */
export function crowdstrikeSourceRepository(
  input: ExternalFindings,
  declared: string | undefined,
  references: readonly ExternalSourceRepository[],
): string {
  const url = declaredScannerRepositoryUrl(declared, "CrowdStrike", "local");
  if (input.report?.["format"] !== crowdstrikeReportFormat)
    throw new CodexSecurityError(
      "CrowdStrike imports require a report from the crowdstrike reader.",
    );
  assertRepository(input.report["repositoryUrl"], url);
  for (const ref of references) assertRepository(ref.url, url);
  for (const { evidence } of input.findings) {
    validateExternalEvidence(evidence, "local");
    const data = evidence.source_data;
    if (data?.["format"] !== crowdstrikeReportFormat)
      throw new CodexSecurityError(
        "CrowdStrike findings must retain their native detection.",
      );
    assertRepository(data["repository_url"], url);
    if (evidence.details?.repository?.url !== undefined)
      assertRepository(evidence.details.repository.url, url);
  }
  return url;
}

/** Read a saved FCS CLI 4.x IaC JSON report for one local checkout. */
export async function readCrowdStrikeFindings(
  path: string,
  sourceRepositoryUrl: string,
): Promise<ExternalFindings> {
  const repositoryUrl = declaredScannerRepositoryUrl(
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
      return validateExternalEvidence(
        {
          title: requiredText(rule["rule_name"], "CrowdStrike rule_name"),
          severity: scannerSeverity(text(rule["severity"])?.toLowerCase()),
          description: joined(text(rule["description"]), reason),
          locations: [
            {
              path: detectionPath(detection, remote),
              line: detectionLine(detection),
            },
          ],
          source_scan_id: text(document["scan_uuid"]),
          details: {
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
            repository_url: repositoryUrl,
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
        detectionLine(detection),
        detection["resource_type"] ?? null,
        detection["resource_name"] ?? null,
        detection["reason"] ?? null,
      ]),
    "local",
    {
      report: {
        format: crowdstrikeReportFormat,
        repositoryUrl,
        fcs_version: version,
        scan_uuid: text(document["scan_uuid"]),
      },
    },
  );
}

import type { ExternalImportTarget } from "./external-import-contract.js";
import { validateExternalEvidence } from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import type { ExternalFindingEvidence } from "./external-import-models.js";
import { isRecord } from "./record.js";
import {
  normalizeRecords,
  record,
  requiredText,
  text,
} from "./scanner-import.js";

type ArmorCodeFinding = Record<string, unknown>;

function armorCodeId(value: unknown): string {
  if (typeof value === "string")
    return requiredText(value, "ArmorCode finding ID");
  if (typeof value === "number" && Number.isSafeInteger(value))
    return String(value);
  throw new Error("ArmorCode finding ID must be text or a safe integer.");
}

function stringValues(value: unknown): string[] {
  const values = Array.isArray(value) ? value : value == null ? [] : [value];
  return values.flatMap((item) => {
    if (typeof item === "string" && item.trim()) return [item];
    if (typeof item === "number" && Number.isSafeInteger(item))
      return [String(item)];
    return [];
  });
}

/** Normalize stable finding records while retaining the original ArmorCode row. */
export function normalizeArmorCodeFindings(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const document = Array.isArray(input)
    ? { findings: input }
    : record(input, "ArmorCode report");
  const raw =
    document["findings"] ??
    document["issues"] ??
    (isRecord(document["data"]) ? document["data"]["findings"] : undefined);
  if (!Array.isArray(raw))
    throw new Error("ArmorCode report must contain a findings array.");
  const report = { ...document };
  delete report["findings"];
  delete report["issues"];
  if (isRecord(report["data"])) {
    const data = { ...report["data"] };
    delete data["findings"];
    if (Object.keys(data).length) report["data"] = data;
    else delete report["data"];
  }
  return normalizeRecords(
    raw as ArmorCodeFinding[],
    (finding) => {
      const severity = (text(finding["severity"]) ?? "unknown").toLowerCase();
      const locations = Array.isArray(finding["locations"])
        ? finding["locations"]
        : finding["location"]
          ? [finding["location"]]
          : text(finding["filePath"])
            ? [{ path: finding["filePath"], line: finding["lineNumber"] }]
            : [];
      const description = text(
        finding["description"] ??
          finding["details"] ??
          finding["toolDescription"],
      );
      const mitigation = text(finding["mitigation"]);
      const lastUpdated = finding["lastUpdated"];
      const isSast =
        Array.isArray(finding["scanType"]) &&
        finding["scanType"].some(
          (value) =>
            typeof value === "string" && value.toLowerCase() === "sast",
        );
      const ruleIds = stringValues(finding["ruleId"]);
      const weaknessIds = [
        ...stringValues(finding["cwe"]),
        ...stringValues(finding["cwesStrings"]),
      ];
      const repository = finding["repository"];
      const repositoryUrl = text(
        finding["sourceRepositoryUrl"] ??
          finding["repositoryUrl"] ??
          (isRecord(repository) ? repository["url"] : repository),
      );
      const evidence: ExternalFindingEvidence = {
        title: requiredText(
          finding["title"] ?? finding["name"] ?? finding["findingName"],
          "ArmorCode finding title",
        ),
        severity: ([
          "critical",
          "high",
          "medium",
          "low",
          "informational",
        ].includes(severity)
          ? severity
          : "unknown") as ExternalFindingEvidence["severity"],
        description: isSast
          ? description
          : description && mitigation
            ? `${description}\n\nMitigation: ${mitigation}`
            : (description ?? mitigation),
        // ArmorCode's findingUrl remains available in source_data; url points
        // to the originating scanner when ArmorCode provides both links.
        url: text(finding["url"] ?? finding["findingUrl"]),
        ...(Array.isArray(finding["cve"]) && {
          advisory_ids: finding["cve"].filter(
            (value): value is string => typeof value === "string",
          ),
        }),
        locations: locations.flatMap((value) => {
          if (!isRecord(value)) return [];
          const path = text(
            value["path"] ?? value["filePath"] ?? value["file"],
          );
          if (!path) return [];
          const line =
            value["line"] ?? value["startLine"] ?? value["lineNumber"];
          return [
            {
              path,
              line:
                Number.isSafeInteger(line) && Number(line) > 0
                  ? Number(line)
                  : null,
            },
          ];
        }),
        ...(typeof lastUpdated === "number" &&
          Number.isSafeInteger(lastUpdated) && {
            source_updated_at: Math.floor(lastUpdated / 1000),
          }),
        ...(isSast && {
          details: {
            kind: "sast",
            ...(repositoryUrl && { repository: { url: repositoryUrl } }),
            source_status: text(
              finding["status"] ?? finding["toolFindingStatus"],
            ),
            scanner_origin: text(finding["source"]),
            scanner_verdict: text(finding["toolStatusOriginal"]),
            ...(ruleIds.length > 0 && { rule: { id: ruleIds.join(", ") } }),
            ...(weaknessIds.length > 0 && {
              weakness_ids: [...new Set(weaknessIds)],
            }),
            ...(mitigation && { remediation_instructions: mitigation }),
          },
        }),
        source_data: structuredClone(finding),
      };
      validateExternalEvidence(evidence, target);
      return evidence;
    },
    (finding) =>
      armorCodeId(
        finding["source_finding_id"] ??
          finding["findingId"] ??
          finding["id"] ??
          finding["finding_id"],
      ),
    target,
    { report },
  );
}

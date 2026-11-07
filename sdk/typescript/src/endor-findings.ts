import { markPreviousCloudProjection } from "./reader-selection.js";
import {
  type ExternalImportTarget,
  validateEnrichedExternalEvidence,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import { asRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  sarifRunRepositories,
  sarifRunResults,
  strings,
  readSarifRuns,
  text,
  validateSarifRuleReference,
} from "./scanner-import.js";

/** @internal Repository claims retained in the adapter's original SARIF context. */
export function endorRepositoryUrls(
  sourceData: unknown,
  retainedUrlsOnly = false,
): string[] {
  const run = asRecord(sourceData)?.["runContext"];
  if (run == null) return [];
  if (retainedUrlsOnly) {
    // Historical projections can retain opaque run metadata alongside explicit URLs.
    const entries = asRecord(run)?.["versionControlProvenance"];
    if (!Array.isArray(entries)) return [];
    return entries
      .map((entry) => asRecord(entry)?.["repositoryUri"])
      .filter((url) => typeof url === "string");
  }
  return sarifRunRepositories(run, "Endor").map((ref) => ref.url);
}

function positiveCount(value: unknown): boolean {
  return (
    (typeof value === "number" || typeof value === "string") &&
    Number(value) > 0
  );
}

function endorListObjects(root: Record<string, unknown>): unknown[] {
  const list = record(root["list"], "Endor list");
  const response = record(list["response"] ?? {}, "Endor list response");
  const {
    next_page_id: nextId,
    next_page_token: token,
    total_size: total,
  } = response;
  if (nextId != null && typeof nextId !== "string")
    throw new Error("Endor next_page_id must be a string.");
  if (
    text(nextId) ||
    (token != null && token !== 0 && token !== "0" && token !== "")
  )
    throw new Error(
      "The Endor list response has another page. Supply a complete export or an explicitly selected array.",
    );
  const values = array(list["objects"] ?? [], "Endor list.objects");
  if (values.length) return values;

  // Protobuf can omit an empty repeated field. Recognize only its known
  // pagination envelope; don't mistake an unrecognized payload for no matches.
  if (
    positiveCount(total) ||
    (list["objects"] == null &&
      (Object.keys(list).some(
        (key) => key !== "response" && key !== "objects",
      ) ||
        Object.keys(response).some(
          (key) =>
            !["next_page_token", "next_page_id"].includes(key) &&
            !(key === "total_size" && (total === 0 || total === "0")),
        )))
  )
    throw new Error("Expected Endor list.objects in the finding export.");

  const { count } = record(
    root["count_response"] ?? {},
    "Endor count response",
  );
  const { groups } = record(
    root["group_response"] ?? {},
    "Endor group response",
  );
  if (
    positiveCount(count) ||
    (groups != null && Object.keys(record(groups, "Endor groups")).length)
  )
    throw new Error(
      "The Endor report contains a summary without finding objects. Supply the complete finding export.",
    );
  return values;
}

/** Saved Endor Finding objects, an array, or an unmasked ListFindingsResponse. */
export function normalizeEndorFindings(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  return normalizeReport(input, target, false);
}

const reducedReports = new WeakSet<ExternalFindings>();

/** A native upload would ask the worker to reconstruct fields that Cloud could not accept. */
export function requiresStructuredEndorReport(findings: ExternalFindings) {
  return reducedReports.has(findings);
}

/** @internal Reproduce the selection from before malware and fully qualified package mapping. */
export function normalizePreviousEndorFindings(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  return normalizeReport(input, target, true);
}

function normalizeReport(
  input: unknown,
  target: ExternalImportTarget,
  previous: boolean,
): ExternalFindings {
  const root = Array.isArray(input) ? null : record(input, "Endor report");
  if (root?.["version"] === "2.1.0" && root["runs"] !== undefined)
    return normalizeEndorSarif(root, target);
  const values =
    root?.["list"] !== undefined
      ? endorListObjects(root)
      : Array.isArray(input)
        ? input
        : [input];
  let changed = false;
  let reduced = false;
  const result = normalizeRecords(
    values,
    (value) => {
      const finding = record(value, "Endor finding");
      const meta = record(finding["meta"], "Endor meta");
      const spec = record(finding["spec"], "Endor spec");
      requiredText(spec["project_uuid"], "Endor project_uuid");
      const bareName = text(spec["target_dependency_name"]);
      const name =
        bareName ??
        (previous ? null : text(spec["target_dependency_package_name"]));
      const paths = [
        ...new Set(
          strings(spec["dependency_file_paths"])
            .map(relativePath)
            .filter((p): p is string => p !== null),
        ),
      ];
      const metadata = record(
        spec["finding_metadata"] ?? {},
        "Endor finding_metadata",
      );
      const codeLocations = ["sast_data", "ai_sast_data"].flatMap((field) => {
        const data = record(metadata[field] ?? {}, `Endor ${field}`);
        const location = record(
          data["location"] ?? {},
          `Endor ${field} location`,
        );
        const path = relativePath(location["relative_path"]);
        if (path === null) return [];
        const line = location["start_line"];
        return [
          {
            path,
            line:
              typeof line === "number" && Number.isSafeInteger(line) && line > 0
                ? line
                : null,
          },
        ];
      });
      const locations = [
        ...paths
          .filter(
            (path) => !codeLocations.some((location) => location.path === path),
          )
          .map((path) => ({ path })),
        ...new Map(
          codeLocations.map((location) => [JSON.stringify(location), location]),
        ).values(),
      ];
      const vulnerability = record(
        metadata["vulnerability"] ?? {},
        "Endor vulnerability",
      );
      const advisory = text(
        record(vulnerability["meta"] ?? {}, "Vulnerability meta")["name"],
      );
      const aliases = strings(
        record(vulnerability["spec"] ?? {}, "Vulnerability spec")["aliases"],
      );
      const vulnerabilityIds = [
        ...new Set([...(advisory ? [advisory] : []), ...aliases]),
      ];
      const malware = previous ? undefined : asRecord(metadata["malware"]);
      const advisories = new Set([
        ...vulnerabilityIds,
        ...strings([asRecord(malware?.["meta"])?.["name"]]),
        ...strings(asRecord(malware?.["spec"])?.["aliases"]),
      ]);
      const level = text(spec["level"])
        ?.replace(/^FINDING_LEVEL_/u, "")
        .toLowerCase();
      const severity =
        level && ["critical", "high", "medium", "low"].includes(level)
          ? level
          : "unknown";
      // A recommended version can refer to an introducing dependency; retain it in source_data.
      const packages = name
        ? (paths.length ? paths : [null]).map((path) => ({
            name,
            ecosystem:
              text(spec["ecosystem"])
                ?.replace(/^ECOSYSTEM_/u, "")
                .toLowerCase() ?? null,
            installed_version: text(spec["target_dependency_version"]),
            manifest_path: path,
            fixed_versions: [],
          }))
        : [];
      const context = record(finding["context"] ?? {}, "Endor context");
      const updated = text(meta["update_time"]);
      const malwareIds =
        advisories.size > vulnerabilityIds.length
          ? { advisory_ids: [...advisories] }
          : undefined;
      const fallbackPackage = name !== bareName ? { packages } : undefined;
      const evidence = validateEnrichedExternalEvidence(
        {
          title: requiredText(meta["name"], "Endor finding title"),
          description:
            [
              text(spec["summary"]),
              text(spec["explanation"]),
              text(spec["remediation"]),
            ]
              .filter(Boolean)
              .join("\n\n") || text(meta["description"]),
          severity,
          branch:
            context["type"] === "CONTEXT_TYPE_REF" ? text(context["id"]) : null,
          code_revision: text(
            record(
              spec["source_code_version"] ?? {},
              "Endor source code version",
            )["sha"],
          ),
          source_updated_at:
            updated === null ? null : Math.floor(Date.parse(updated) / 1000),
          advisory_ids: vulnerabilityIds,
          packages: bareName ? packages : [],
          locations,
          source_data: structuredClone(finding),
        },
        target,
        malwareIds && fallbackPackage && { ...malwareIds, ...fallbackPackage },
        malwareIds,
        fallbackPackage,
      );
      const acceptedIds = evidence.advisory_ids!.length;
      const acceptedPackages = evidence.packages!.length;
      changed ||=
        acceptedIds > vulnerabilityIds.length ||
        (!bareName && acceptedPackages > 0);
      reduced ||=
        acceptedIds < advisories.size || acceptedPackages < packages.length;
      return evidence;
    },
    (value) =>
      requiredText(
        record(value, "Endor finding")["uuid"],
        "Endor finding uuid",
      ),
    target,
  );
  if (target === "cloud") {
    if (changed) markPreviousCloudProjection(result);
    if (reduced) reducedReports.add(result);
  }
  return result;
}

/** Endor's documented SARIF producer uses properties.finding-uuid, not its rule name. */
export function normalizeEndorSarif(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const entries = readSarifRuns(input, "Endor", (context) => {
    if (context.driver["name"] !== "endorctl")
      throw new Error("Expected the endorctl SARIF producer.");
    return sarifRunResults(context, "Endor");
  });
  return normalizeRecords(
    entries,
    ({ result: value, context }) => {
      const result = record(value, "Endor result");
      const properties = record(
        result["properties"],
        "Endor result properties",
      );
      requiredText(properties["project-uuid"], "Endor project-uuid");
      const ruleId = requiredText(result["ruleId"], "Endor ruleId");
      const selectedRule = context.rulesById.get(ruleId);
      if (!selectedRule)
        throw new Error(
          "Endor result must reference exactly one rule in its run.",
        );
      const { rule } = selectedRule;
      validateSarifRuleReference(result, ruleId, selectedRule, "Endor");
      const message = record(result["message"], "Endor message");
      const short = record(
        rule["shortDescription"] ?? {},
        "Endor shortDescription",
      );
      const full = record(
        rule["fullDescription"] ?? {},
        "Endor fullDescription",
      );
      const help = record(rule["help"] ?? {}, "Endor help");
      const hasCodeLocations = strings(properties["categories"]).some(
        (category) => category === "SAST" || category === "SECRETS",
      );
      const locations = array(
        result["locations"] ?? [],
        "Endor locations",
      ).flatMap((v) => {
        const physical = record(
          record(v, "Endor location")["physicalLocation"] ?? {},
          "Physical location",
        );
        const artifact = record(
          physical["artifactLocation"] ?? {},
          "Artifact location",
        );
        if (
          artifact["index"] !== undefined ||
          artifact["uriBaseId"] !== undefined
        )
          return [];
        const uri = text(artifact["uri"]);
        if (uri === null || /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(uri)) return [];
        let path: string | null;
        try {
          path = relativePath(decodeURIComponent(uri));
        } catch {
          return [];
        }
        if (path === null) return [];
        const line = hasCodeLocations
          ? record(physical["region"] ?? {}, "Endor region")["startLine"]
          : null;
        return [
          {
            path,
            line:
              typeof line === "number" && Number.isSafeInteger(line) && line > 0
                ? line
                : null,
          },
        ];
      });
      return validateExternalEvidence(
        {
          title: text(short["text"]) ?? text(rule["name"]) ?? ruleId,
          url: text(properties["finding-url"]),
          description: [
            text(message["markdown"]) ?? text(message["text"]),
            text(full["text"]),
            text(help["markdown"]) ?? text(help["text"]),
          ]
            .filter(Boolean)
            .join("\n\n"),
          // Diagnostic level and CVSS are not Endor's finding severity. Keep both as source evidence.
          severity: "unknown",
          locations: [
            ...new Map(
              locations.map((location) => [JSON.stringify(location), location]),
            ).values(),
          ],
          source_data: context.sourceData(result, rule),
        },
        target,
      );
    },
    ({ result }) =>
      requiredText(
        record(
          record(result, "Endor result")["properties"],
          "Endor result properties",
        )["finding-uuid"],
        "Endor finding-uuid",
      ),
    target,
  );
}

export async function readEndorFindings(
  path: string,
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  return normalizeEndorFindings(await readScannerJson(path), target);
}

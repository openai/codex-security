import type { ExternalImportTarget } from "./external-import-contract.js";
import { validateExternalEvidence } from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import { isRecord } from "./record.js";
import {
  array,
  hasSarifExternalPropertyReferences,
  indexSarifRules,
  normalizeRecords,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  sarifRunContextSelector,
  strings,
  text,
} from "./scanner-import.js";

/** @internal Repository claims retained in the adapter's original SARIF context. */
export function endorRepositoryUrls(sourceData: unknown): string[] {
  if (!isRecord(sourceData)) return [];
  const run = sourceData["runContext"];
  if (run == null) return [];
  return array(
    record(run, "Endor run context")["versionControlProvenance"] ?? [],
    "Endor version control provenance",
  ).map((entry) =>
    requiredText(
      record(entry, "Endor repository provenance")["repositoryUri"],
      "Endor repository URI",
    ),
  );
}

/** Saved Endor Finding objects, an array, or an unmasked ListFindingsResponse. */
export function normalizeEndorFindings(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const root = Array.isArray(input) ? null : record(input, "Endor report");
  if (root?.["version"] === "2.1.0" && root["runs"] !== undefined)
    return normalizeEndorSarif(root, target);
  const list =
    root?.["list"] === undefined ? null : record(root["list"], "Endor list");
  if (list) {
    const response = record(list["response"] ?? {}, "Endor list response");
    const token = response["next_page_token"];
    if (
      text(response["next_page_id"]) ||
      (token != null && token !== 0 && token !== "0" && token !== "")
    ) {
      throw new Error(
        "The Endor list response has another page. Supply a complete export or an explicitly selected array.",
      );
    }
  }
  const values = list
    ? array(list["objects"] ?? [], "Endor list.objects")
    : Array.isArray(input)
      ? input
      : [input];
  return normalizeRecords(
    values,
    (value) => {
      const finding = record(value, "Endor finding");
      const meta = record(finding["meta"], "Endor meta");
      const spec = record(finding["spec"], "Endor spec");
      requiredText(spec["project_uuid"], "Endor project_uuid");
      const name = text(spec["target_dependency_name"]);
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
      return validateExternalEvidence(
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
          advisory_ids: [
            ...new Set([...(advisory ? [advisory] : []), ...aliases]),
          ],
          packages,
          locations,
          source_data: structuredClone(finding),
        },
        target,
      );
    },
    (value) =>
      requiredText(
        record(value, "Endor finding")["uuid"],
        "Endor finding uuid",
      ),
    target,
  );
}

/** Endor's documented SARIF producer uses properties.finding-uuid, not its rule name. */
export function normalizeEndorSarif(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const document = record(input, "Endor SARIF");
  if (document["version"] !== "2.1.0")
    throw new Error("Expected Endor SARIF 2.1.0.");
  const entries = array(document["runs"], "SARIF runs").flatMap((value) => {
    const run = record(value, "SARIF run");
    const tool = record(run["tool"], "SARIF tool");
    const driver = record(tool["driver"], "SARIF driver");
    if (driver["name"] !== "endorctl")
      throw new Error("Expected the endorctl SARIF producer.");
    if (
      hasSarifExternalPropertyReferences(run["externalPropertyFileReferences"])
    )
      throw new Error("Use a self-contained Endor SARIF report.");
    const rules = array(driver["rules"] ?? [], "Endor rules").map((r) =>
      record(r, "Endor rule"),
    );
    const rulesById = indexSarifRules(rules);
    const { runs: _runs, ...documentContext } = document;
    const { results: _results, tool: _tool, ...runContext } = run;
    const { rules: _rules, ...driverContext } = driver;
    const { driver: _driver, ...toolContext } = tool;
    const selectRunContext = sarifRunContextSelector(runContext);
    return array(run["results"] ?? [], "Endor results").map((result) => ({
      result,
      rulesById,
      selectRunContext,
      documentContext,
      runContext,
      driverContext,
      toolContext,
    }));
  });
  return normalizeRecords(
    entries,
    ({ result: value, rulesById, selectRunContext, ...context }) => {
      const result = record(value, "Endor result");
      const properties = record(
        result["properties"],
        "Endor result properties",
      );
      requiredText(properties["project-uuid"], "Endor project-uuid");
      const ruleId = requiredText(result["ruleId"], "Endor ruleId");
      const selectedRule = rulesById.get(ruleId);
      if (!selectedRule)
        throw new Error(
          "Endor result must reference exactly one rule in its run.",
        );
      const { rule, index: ruleIndex } = selectedRule;
      if (
        result["ruleIndex"] !== undefined &&
        result["ruleIndex"] !== ruleIndex
      )
        throw new Error("Endor ruleIndex and ruleId disagree.");
      if (result["rule"] !== undefined) {
        const reference = record(result["rule"], "Endor rule reference");
        if (
          reference["toolComponent"] !== undefined ||
          (reference["id"] !== undefined && reference["id"] !== ruleId) ||
          (reference["index"] !== undefined &&
            reference["index"] !== ruleIndex) ||
          (reference["guid"] !== undefined &&
            reference["guid"] !== rule["guid"])
        )
          throw new Error("Inconsistent or external Endor rule reference.");
      }
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
          source_data: structuredClone({
            ...context,
            runContext: selectRunContext(
              result,
              rule,
              context.documentContext,
              context.driverContext,
              context.toolContext,
            ),
            rule,
            result,
          }),
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

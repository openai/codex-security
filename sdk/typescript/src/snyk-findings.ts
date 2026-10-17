import { validateExternalEvidence } from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  stableId,
  text,
} from "./scanner-import.js";

function snykIdentity(value: unknown): string {
  const result = record(value, "SARIF result");
  const id = requiredText(result["ruleId"], "Snyk advisory ruleId");
  const paths = array(result["locations"] ?? [], "Result locations")
    .map((value) => {
      const physical = record(
        record(value, "Location")["physicalLocation"] ?? {},
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
        throw new Error(
          "Snyk SARIF artifact references are unsupported; use direct manifest URIs from the Snyk Open Source formatter.",
        );
      return text(artifact["uri"]);
    })
    .filter((path): path is string => path !== null);
  return stableId("snyk-sarif", [id, [...new Set(paths)].sort()]);
}

/** @internal Repository claims retained in the adapter's original SARIF context. */
export function snykRepositoryUrls(sourceData: unknown): string[] {
  if (
    !sourceData ||
    typeof sourceData !== "object" ||
    Array.isArray(sourceData)
  )
    return [];
  const run = (sourceData as Record<string, unknown>)["run"];
  if (run == null) return [];
  return array(
    record(run, "Snyk run context")["versionControlProvenance"] ?? [],
    "Snyk version control provenance",
  ).map((entry) =>
    requiredText(
      record(entry, "Snyk repository provenance")["repositoryUri"],
      "Snyk repository URI",
    ),
  );
}

/** Snyk Open Source's formatter groups all dependency paths for an advisory in a project. */
export function normalizeSnykSarif(input: unknown): ExternalFindings {
  const document = record(input, "Snyk SARIF");
  if (document["version"] !== "2.1.0")
    throw new Error("Expected Snyk Open Source SARIF 2.1.0.");
  const entries = array(document["runs"], "SARIF runs").flatMap((value) => {
    const run = record(value, "SARIF run");
    const driver = record(
      record(run["tool"], "SARIF tool")["driver"],
      "SARIF driver",
    );
    if (driver["name"] !== "Snyk Open Source")
      throw new Error(
        "Only Snyk Open Source SARIF is supported; Code, Container, and IaC need separate mappings.",
      );
    if (run["externalPropertyFileReferences"])
      throw new Error(
        "External SARIF property files are unsupported; use a self-contained report.",
      );
    const rules = array(driver["rules"], "SARIF rules").map((rule) =>
      record(rule, "SARIF rule"),
    );
    const { results: _results, tool: _tool, ...runContext } = run;
    const { rules: _rules, ...driverContext } = driver;
    const { driver: _driver, ...toolContext } = record(
      run["tool"],
      "SARIF tool",
    );
    runContext["tool"] = toolContext;
    const { runs: _runs, ...documentContext } = document;
    return array(run["results"], "SARIF results").map((result) => ({
      result,
      rules,
      runContext,
      driverContext,
      documentContext,
    }));
  });
  return normalizeRecords(
    entries,
    ({ result: value, rules, runContext, driverContext, documentContext }) => {
      const result = record(value, "SARIF result");
      const id = requiredText(result["ruleId"], "Snyk advisory ruleId");
      const matches = rules.filter((rule) => rule["id"] === id);
      if (matches.length !== 1)
        throw new Error("Result must reference exactly one rule in its run.");
      const rule = matches[0]!;
      const index = rules.indexOf(rule);
      if (result["ruleIndex"] !== undefined && result["ruleIndex"] !== index)
        throw new Error("Result ruleIndex and ruleId disagree.");
      if (result["rule"] !== undefined) {
        const ref = record(result["rule"], "Rule reference");
        if (
          ref["toolComponent"] !== undefined ||
          (ref["id"] !== undefined && ref["id"] !== id) ||
          (ref["index"] !== undefined && ref["index"] !== index) ||
          (ref["guid"] !== undefined && ref["guid"] !== rule["guid"])
        )
          throw new Error(
            "Result uses an inconsistent or external rule reference.",
          );
      }
      const help = requiredText(
        record(rule["help"], "Rule help")["markdown"],
        "Rule help markdown",
      );
      const manager = /^\* Package Manager: (.+)$/mu.exec(help)?.[1] ?? null;
      if (!manager || !/^\* Vulnerable module: .+$/mu.test(help))
        throw new Error(
          "Expected the Snyk Open Source vulnerability profile; license findings are unsupported.",
        );
      const title = requiredText(
        record(rule["shortDescription"], "Rule shortDescription")["text"],
        "Rule title",
      );
      const severity =
        /^(Critical|High|Medium|Low) severity - /u
          .exec(title)?.[1]
          ?.toLowerCase() ?? "unknown";
      const message = requiredText(
        record(result["message"], "Result message")["text"],
        "Result message text",
      );
      const locations = array(
        result["locations"] ?? [],
        "Result locations",
      ).map((v) => record(v, "Location"));
      const manifests: string[] = [];
      const packages: {
        name: string;
        ecosystem: string;
        installed_version: string | null;
        manifest_path: string | null;
        fixed_versions: string[];
      }[] = [];
      for (const location of locations) {
        const physical = record(
          location["physicalLocation"] ?? {},
          "Physical location",
        );
        const artifact = record(
          physical["artifactLocation"] ?? {},
          "Artifact location",
        );
        const uri = text(artifact["uri"]);
        if (uri) manifests.push(uri);
        // Snyk's startLine may be a synthetic 1. Keep it in raw evidence, not as a verified source line.
        for (const logical of array(
          location["logicalLocations"] ?? [],
          "Logical locations",
        )) {
          const coordinate = text(
            record(logical, "Logical location")["fullyQualifiedName"],
          );
          if (!coordinate) continue;
          const split = coordinate.lastIndexOf("@");
          if (split <= 0) continue;
          packages.push({
            name: coordinate.slice(0, split),
            ecosystem: manager,
            installed_version: coordinate.slice(split + 1) || null,
            manifest_path: relativePath(uri),
            fixed_versions: [],
          });
        }
      }
      const manifestIds = [...new Set(manifests)].sort();
      const description = [message, help].join("\n\n");
      // Use the advisory group + literal manifest set within the caller's stable project/branch namespace.
      // Automation IDs contain export timestamps and run indexes, so are provenance only.
      return {
        source_finding_id: snykIdentity(result),
        evidence: validateExternalEvidence({
          title,
          description,
          severity,
          advisory_ids: [
            ...new Set([
              id,
              ...(text(
                record(rule["fullDescription"] ?? {}, "Full description")[
                  "text"
                ],
              )?.match(/\bCVE-\d{4}-\d+\b/gu) ?? []),
            ]),
          ],
          packages,
          locations: [
            ...new Set(
              manifestIds
                .map(relativePath)
                .filter((p): p is string => p !== null),
            ),
          ].map((path) => ({ path })),
          source_data: structuredClone({
            document: documentContext,
            run: runContext,
            driver: driverContext,
            rule,
            result,
          }),
        }),
      };
    },
    ({ result }) => snykIdentity(result),
  );
}

export async function readSnykFindings(
  path: string,
): Promise<ExternalFindings> {
  return normalizeSnykSarif(await readScannerJson(path));
}

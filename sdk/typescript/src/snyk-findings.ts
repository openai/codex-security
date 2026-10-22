import { validateExternalEvidence } from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import {
  array,
  hasSarifExternalPropertyReferences,
  normalizeRecords,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  sarifRunContextForResult,
  stableId,
  strings,
  text,
} from "./scanner-import.js";

function snykManifestPath(value: unknown): string | null {
  const path = text(value);
  // The Snyk formatter writes literal paths, not percent-encoded URI components.
  return path && !/^[a-z][a-z0-9+.-]*:\/\//iu.test(path)
    ? relativePath(path)
    : null;
}

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

function pluginIdentity(value: unknown): string {
  const finding = record(value, "Snyk plugin finding");
  const id = record(finding["id"], "Snyk plugin identity");
  return stableId("snyk-plugin", [
    requiredText(id["kind"], "Identity kind"),
    requiredText(id["value"], "Finding identity"),
  ]);
}

/** Import the official Snyk Codex plugin's documented local SCA bundle. */
export function normalizeSnykFindingsExport(input: unknown): ExternalFindings {
  const document = record(input, "Snyk plugin export");
  if (
    document["format"] !== "snyk-findings-export/v1" ||
    document["provider"] !== "snyk"
  )
    throw new Error("Expected a snyk-findings-export/v1 bundle from Snyk.");
  const collection = record(document["collection"], "Snyk collection");
  const target = record(collection["target"], "Snyk target");
  const { findings: _findings, ...context } = document;
  return normalizeRecords(
    array(document["findings"], "Snyk findings"),
    (value, sourceFindingId) => {
      const finding = record(value, "Snyk plugin finding");
      const observation = record(finding["observation"], "Snyk observation");
      if (
        finding["originatingScanner"] !== "snyk-open-source" ||
        finding["category"] !== "dependency_vulnerability" ||
        observation["scan"] !== "sca"
      )
        throw new Error(
          "Only Snyk Open Source SCA vulnerability findings are supported from plugin bundles.",
        );
      record(finding["nativeRecord"], "Snyk native MCP record");
      const asset = record(finding["asset"], "Snyk asset");
      const pkg = record(asset["package"], "Snyk package");
      const rule = record(finding["rule"], "Snyk rule");
      const aliases = record(rule["aliases"] ?? {}, "Snyk rule aliases");
      const remediation = record(
        finding["remediation"] ?? {},
        "Snyk remediation",
      );
      const severity = text(
        record(finding["severity"], "Snyk severity")["value"],
      )?.toLowerCase();
      const revision = text(target["revision"]);
      return {
        source_finding_id: sourceFindingId,
        evidence: validateExternalEvidence({
          title: requiredText(finding["title"], "Snyk title"),
          description: text(
            record(finding["description"] ?? {}, "Snyk description")["text"],
          ),
          severity: ["critical", "high", "medium", "low"].includes(
            severity ?? "",
          )
            ? severity
            : "unknown",
          advisory_ids: [
            ...new Set([
              requiredText(rule["id"], "Snyk advisory ID"),
              ...strings(aliases["cve"]),
            ]),
          ],
          packages: [
            {
              name: requiredText(pkg["name"], "Snyk package name"),
              ecosystem: text(pkg["ecosystem"]),
              installed_version: text(pkg["version"]),
              // Plugin v1 manifests are target-relative, without a Git-root offset.
              manifest_path: null,
              fixed_versions: strings(remediation["fixedIn"]),
            },
          ],
          locations: [],
          code_revision:
            target["workingTreeDirty"] === false && revision !== "unknown"
              ? revision
              : null,
          source_data: structuredClone({ ...context, finding }),
        }),
      };
    },
    pluginIdentity,
  );
}

function pluginRepositoryUrl(value: unknown): string | null {
  const repository = text(value);
  if (repository === null || repository === "unknown") return null;
  // git remote get-url commonly returns GitHub's SSH clone syntax. Compare
  // the repository over HTTPS while retaining the original remote in evidence.
  const scp = /^git@([^/:]+):(.+)$/u.exec(repository);
  if (scp) return `https://${scp[1]}/${scp[2]}`;
  if (repository.startsWith("ssh://git@")) {
    const url = new URL(repository);
    // Keep nondefault SSH ports distinct from the default HTTPS repository.
    const host = url.port === "22" ? url.hostname : url.host;
    return `https://${host}${url.pathname}`;
  }
  return repository;
}

/** @internal Repository claims retained in original Snyk evidence. */
export function snykRepositoryUrls(
  sourceData: unknown,
  { normalizeGitRemote = true }: { normalizeGitRemote?: boolean } = {},
): string[] {
  if (
    !sourceData ||
    typeof sourceData !== "object" ||
    Array.isArray(sourceData)
  )
    return [];
  const source = sourceData as Record<string, unknown>;
  if (source["format"] === "snyk-findings-export/v1") {
    const collection = record(source["collection"], "Snyk collection");
    const target = record(collection["target"], "Snyk target");
    const url = normalizeGitRemote
      ? pluginRepositoryUrl(target["repository"])
      : text(target["repository"]);
    return url && url !== "unknown" ? [url] : [];
  }
  const run = source["run"];
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
    if (
      hasSarifExternalPropertyReferences(run["externalPropertyFileReferences"])
    )
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
    (
      { result: value, rules, runContext, driverContext, documentContext },
      sourceFindingId,
    ) => {
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
            manifest_path: snykManifestPath(uri),
            fixed_versions: [],
          });
        }
      }
      const manifestIds = [...new Set(manifests)].sort();
      const description = [message, help].join("\n\n");
      // Use the advisory group + literal manifest set within the caller's stable project/branch namespace.
      // Automation IDs contain export timestamps and run indexes, so are provenance only.
      return {
        source_finding_id: sourceFindingId,
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
                .map(snykManifestPath)
                .filter((p): p is string => p !== null),
            ),
          ].map((path) => ({ path })),
          source_data: structuredClone({
            document: documentContext,
            run: sarifRunContextForResult(
              runContext,
              result,
              rule,
              driverContext,
              documentContext,
            ),
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

/** Import native `snyk test --json` Open Source vulnerability occurrences. */
export function normalizeSnykJson(input: unknown): ExternalFindings {
  const projects = Array.isArray(input) ? input : [input];
  const entries = projects.flatMap((value) => {
    const project = record(value, "Snyk Open Source project");
    if (project["error"])
      throw new Error(`Snyk scan failed: ${String(project["error"])}`);
    if (project["docker"] || project["applications"])
      throw new Error(
        "Snyk Container JSON is unsupported; use Open Source SCA results.",
      );
    if (typeof project["ok"] !== "boolean")
      throw new Error("Expected a completed Snyk Open Source test result.");
    const manager = requiredText(
      project["packageManager"],
      "Snyk package manager",
    );
    const manifest =
      text(project["displayTargetFile"]) ?? text(project["targetFile"]);
    const { vulnerabilities, ...context } = project;
    return array(vulnerabilities, "Snyk vulnerabilities").map((value) => ({
      value,
      context,
      manager,
      manifest,
    }));
  });
  return normalizeRecords(
    entries,
    ({ value, context, manager }, sourceFindingId) => {
      const vulnerability = record(value, "Snyk vulnerability");
      if (vulnerability["type"] === "license")
        throw new Error(
          "Snyk license findings are unsupported; only Open Source SCA vulnerabilities are imported.",
        );
      const identifiers = record(
        vulnerability["identifiers"] ?? {},
        "Snyk identifiers",
      );
      const severity = text(vulnerability["severity"])?.toLowerCase();
      return {
        source_finding_id: sourceFindingId,
        evidence: validateExternalEvidence({
          title: requiredText(
            vulnerability["title"],
            "Snyk vulnerability title",
          ),
          description: text(vulnerability["description"]),
          severity: ["critical", "high", "medium", "low"].includes(
            severity ?? "",
          )
            ? severity
            : "unknown",
          advisory_ids: [
            ...new Set([
              requiredText(vulnerability["id"], "Snyk advisory ID"),
              ...strings(identifiers["CVE"]),
            ]),
          ],
          packages: [
            {
              name: requiredText(
                vulnerability["name"] ?? vulnerability["packageName"],
                "Snyk package name",
              ),
              ecosystem: manager,
              installed_version: text(vulnerability["version"]),
              // Native test paths are scan-target-relative, without a Git-root offset.
              manifest_path: null,
              fixed_versions: strings(vulnerability["fixedIn"]),
            },
          ],
          locations: [],
          source_data: structuredClone({ project: context, vulnerability }),
        }),
      };
    },
    ({ value, manager, manifest }) => {
      const vulnerability = record(value, "Snyk vulnerability");
      return stableId("snyk-json", [
        manager,
        manifest,
        requiredText(vulnerability["id"], "Snyk advisory ID"),
        requiredText(
          vulnerability["name"] ?? vulnerability["packageName"],
          "Snyk package name",
        ),
        text(vulnerability["version"]),
        array(vulnerability["from"] ?? [], "Snyk dependency path").map((item) =>
          requiredText(item, "Snyk dependency"),
        ),
      ]);
    },
  );
}

export async function readSnykFindings(
  path: string,
): Promise<ExternalFindings> {
  const input = await readScannerJson(path);
  if (Array.isArray(input)) return normalizeSnykJson(input);
  const document = record(input, "Snyk findings");
  if (document["format"] === "snyk-findings-export/v1")
    return normalizeSnykFindingsExport(document);
  if (document["version"] === "2.1.0") return normalizeSnykSarif(document);
  return normalizeSnykJson(document);
}

import type { ExternalImportTarget } from "./external-import-contract.js";
import { validateExternalEvidence } from "./external-import-contract.js";
import type {
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import type { SnykIssuesFindings } from "./snyk-rest-findings.js";
import { normalizeHostedGitRepositoryUrl } from "./hosted-git-repository.js";
import { isRecord } from "./record.js";
import {
  array,
  indexSarifRules,
  normalizeRecords,
  optionalArray,
  readScannerJson,
  record,
  reportableScannerSeverity,
  requiredText,
  sarifRunRepositories,
  sarifRunContextSelector,
  stableId,
  strings,
  readSarifRuns,
  text,
  validateSarifRun,
  validateSarifRuleReference,
} from "./scanner-import.js";

function snykIdentity(value: unknown, project: string | null): string {
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
  const fields: unknown[] = [id, [...new Set(paths)].sort()];
  if (project !== null) fields.push(project);
  return stableId("snyk-sarif", fields);
}

function snykSarifProject(run: Record<string, unknown>): string | null {
  const details = run["automationDetails"];
  const id = isRecord(details) ? text(details["id"]) : null;
  // The formatter appends a run index and export timestamp after the project name.
  return /^Snyk\/Open Source\/(.+)\/\d+\/[^/]+$/su.exec(id ?? "")?.[1] ?? null;
}

function pluginIdentity(value: unknown): string {
  const finding = record(value, "Snyk plugin finding");
  const id = record(finding["id"], "Snyk plugin identity");
  return stableId("snyk-plugin", [
    requiredText(id["kind"], "Identity kind"),
    requiredText(id["value"], "Finding identity"),
  ]);
}

function requireEmptyIssueCount(value: unknown, label: string): void {
  if (value === undefined || value === 0) return;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
    throw new Error(`${label} must be a nonnegative integer.`);
  throw new Error(`${label} reported issues but the findings array is empty.`);
}

/** Import the official Snyk Codex plugin's documented local SCA bundle. */
export function normalizeSnykFindingsExport(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const document = record(input, "Snyk plugin export");
  if (
    document["format"] !== "snyk-findings-export/v1" ||
    document["provider"] !== "snyk"
  )
    throw new Error("Expected a snyk-findings-export/v1 bundle from Snyk.");
  const collection = record(document["collection"], "Snyk collection");
  const sourceTarget = record(collection["target"], "Snyk target");
  const { findings, ...context } = document;
  const parsed = normalizeRecords(
    array(findings, "Snyk findings"),
    (value) => {
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
      const revision = text(sourceTarget["revision"]);
      return validateExternalEvidence(
        {
          title: requiredText(finding["title"], "Snyk title"),
          description: text(
            record(finding["description"] ?? {}, "Snyk description")["text"],
          ),
          severity: reportableScannerSeverity(
            record(finding["severity"], "Snyk severity")["value"],
          ),
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
            sourceTarget["workingTreeDirty"] === false && revision !== "unknown"
              ? revision
              : null,
          source_data: structuredClone({ ...context, finding }),
        },
        target,
      );
    },
    pluginIdentity,
    target,
  );
  let successfulSca = false;
  for (const entry of optionalArray(
    collection["scans"],
    "Snyk collection scans",
  )) {
    const scan = record(entry, "Snyk collection scan");
    if (!parsed.read && scan["outcome"] === "succeeded")
      requireEmptyIssueCount(scan["issueCount"], "Snyk plugin issueCount");
    if (scan["category"] !== "sca") continue;
    if (scan["outcome"] !== "succeeded") {
      const failure = `Snyk plugin SCA scan did not succeed (outcome: ${String(scan["outcome"])}).${scan["error"] ? " " + JSON.stringify(scan["error"]) : ""}`;
      if (parsed.read && !parsed.findings.length)
        return {
          ...parsed,
          report: {
            collection: structuredClone(collection),
            errors: [failure],
          },
        };
      throw new Error(failure);
    }
    successfulSca = true;
  }
  if (parsed.read) return parsed;
  if (!successfulSca)
    throw new Error(
      "An empty Snyk plugin bundle must identify a successful SCA scan.",
    );
  return { ...parsed, report: { collection: structuredClone(collection) } };
}

function normalizeGitRepositoryUrl(
  repository: string,
  cloudRepositoryUrl?: string,
): string {
  // Without a selected Cloud repository, only the public GitHub host is established.
  return normalizeHostedGitRepositoryUrl(
    repository,
    cloudRepositoryUrl ?? "https://github.com",
    cloudRepositoryUrl !== undefined,
  );
}

function snykJsonProjectRepository(
  project: Record<string, unknown>,
): string | undefined {
  // A remote Snyk test puts its GitHub URL and optional ref in the same
  // path field that local scans use for a directory or npm package name.
  const repository = text(project["path"])?.split("#", 1)[0];
  if (
    repository &&
    /^https?:\/\/github\.com(?::\d+)?\/[^/?#\\\s]+\/[^/?#\\\s]+\/?$/iu.test(
      repository,
    )
  )
    return repository;
}

/** Empty plugin and CLI JSON exports have no rows to carry their repository. */
export function emptySnykReportRepositories(input: unknown): { url: string }[] {
  if (isRecord(input) && input["format"] === "snyk-findings-export/v1")
    return snykRepositoryUrls(input, { normalizeGitRemote: false }).map(
      (url) => ({ url }),
    );
  return (Array.isArray(input) ? input : [input]).flatMap((project) => {
    const url = isRecord(project) && snykJsonProjectRepository(project);
    return url ? [{ url }] : [];
  });
}

/** @internal Repository claims retained in original Snyk evidence. */
export function snykRepositoryUrls(
  sourceData: unknown,
  {
    normalizeGitRemote = true,
    cloudRepositoryUrl,
  }: {
    normalizeGitRemote?: boolean;
    /** The selected destination from the authenticated Cloud repository catalog. */
    cloudRepositoryUrl?: string;
  } = {},
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
    const repository = text(target["repository"]);
    if (repository === null || repository === "unknown") return [];
    return [
      normalizeGitRemote
        ? normalizeGitRepositoryUrl(repository, cloudRepositoryUrl)
        : repository,
    ];
  }
  const project = source["project"];
  if (
    isRecord(project) &&
    typeof project["ok"] === "boolean" &&
    text(project["packageManager"]) &&
    isRecord(source["vulnerability"])
  ) {
    const repository = snykJsonProjectRepository(project);
    if (repository) return [repository];
  }
  // Generic normalized evidence may use these field names for opaque metadata.
  const document = source["document"];
  const driver = source["driver"];
  if (
    !isRecord(document) ||
    document["version"] !== "2.1.0" ||
    !isRecord(driver) ||
    driver["name"] !== "Snyk Open Source"
  )
    return [];
  const urls = sarifRunRepositories(source["run"], "Snyk").map(
    (ref) => ref.url,
  );
  return normalizeGitRemote
    ? urls.map((url) => normalizeGitRepositoryUrl(url, cloudRepositoryUrl))
    : urls;
}

/** Snyk Open Source's formatter groups all dependency paths for an advisory in a project. */
export function normalizeSnykSarif(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const entries = readSarifRuns(
    input,
    "Snyk",
    ({ document, run, tool, driver }) => {
      if (driver["name"] !== "Snyk Open Source")
        throw new Error(
          "Only Snyk Open Source SARIF is supported; Code, Container, and IaC need separate mappings.",
        );
      validateSarifRun(run, "Snyk");
      const rules = array(driver["rules"], "SARIF rules").map((rule) =>
        record(rule, "SARIF rule"),
      );
      // SDK inputs can leave descriptor slots empty. Keep the original rule indexes.
      const rulesById = indexSarifRules(
        rules.entries().filter(([index]) => index in rules),
      );
      const project = snykSarifProject(run);
      const { results: _results, tool: _tool, ...runContext } = run;
      const { rules: _rules, ...driverContext } = driver;
      const { driver: _driver, ...toolContext } = tool;
      runContext["tool"] = toolContext;
      const { runs: _runs, ...documentContext } = document;
      const selectRunContext = sarifRunContextSelector(runContext);
      return optionalArray(run["results"], "SARIF results").map((result) => ({
        result,
        rulesById,
        project,
        selectRunContext,
        driverContext,
        documentContext,
      }));
    },
  );
  return normalizeRecords(
    entries,
    ({
      result: value,
      rulesById,
      selectRunContext,
      driverContext,
      documentContext,
    }) => {
      const result = record(value, "SARIF result");
      const id = requiredText(result["ruleId"], "Snyk advisory ruleId");
      const match = rulesById.get(id);
      if (!match)
        throw new Error("Result must reference exactly one rule in its run.");
      const { rule } = match;
      validateSarifRuleReference(result, id, match, "Snyk");
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
      const packages: {
        name: string;
        ecosystem: string;
        installed_version: string | null;
        manifest_path: string | null;
        fixed_versions: string[];
      }[] = [];
      for (const location of locations) {
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
            manifest_path: null,
            fixed_versions: [],
          });
        }
      }
      const description = [message, help].join("\n\n");
      // Use the project, advisory group, and literal manifest set within the caller's namespace.
      return validateExternalEvidence(
        {
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
          // Snyk emits target-relative paths without a Git-root offset and may
          // synthesize startLine=1. Keep both only in the original evidence.
          locations: [],
          source_data: structuredClone({
            document: documentContext,
            run: selectRunContext(result, rule, driverContext, documentContext),
            driver: driverContext,
            rule,
            result,
          }),
        },
        target,
      );
    },
    ({ result, project }) => snykIdentity(result, project),
    target,
  );
}

/** Import native `snyk test --json` Open Source vulnerability occurrences. */
export function normalizeSnykJson(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const projects = Array.isArray(input) ? input : [input];
  if (!projects.length)
    throw new Error("The Snyk report contains no scanned projects.");
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
    const records = array(vulnerabilities, "Snyk vulnerabilities");
    if (!records.length) {
      if (!project["ok"])
        throw new Error(
          "Snyk reported issues but the findings array is empty.",
        );
      requireEmptyIssueCount(project["uniqueCount"], "Snyk native uniqueCount");
    }
    return records.map((value) => ({
      value,
      context,
      manager,
      manifest,
    }));
  });
  return normalizeRecords(
    entries,
    ({ value, context, manager }) => {
      const vulnerability = record(value, "Snyk vulnerability");
      if (vulnerability["type"] === "license")
        throw new Error(
          "Snyk license findings are unsupported; only Open Source SCA vulnerabilities are imported.",
        );
      const identifiers = record(
        vulnerability["identifiers"] ?? {},
        "Snyk identifiers",
      );
      return validateExternalEvidence(
        {
          title: requiredText(
            vulnerability["title"],
            "Snyk vulnerability title",
          ),
          description: text(vulnerability["description"]),
          severity: reportableScannerSeverity(vulnerability["severity"]),
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
        },
        target,
      );
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
    target,
  );
}

export const SNYK_REST_ISSUES_FORMAT = "snyk-rest-issues/v2";
export function isSnykRestFormat(format: unknown): boolean {
  return typeof format === "string" && format.startsWith("snyk-rest-issues/");
}

export async function readSnykFindings(
  path: string,
  target: ExternalImportTarget = "cloud",
  references: readonly ExternalSourceRepository[] = [],
): Promise<ExternalFindings & Partial<SnykIssuesFindings>> {
  return normalizeSnykFile(await readScannerJson(path), target, references);
}

/** @internal Dispatch a parsed Snyk file using the same rules as readSnykFindings. */
export async function normalizeSnykFile(
  input: unknown,
  target: ExternalImportTarget,
  references: readonly ExternalSourceRepository[],
): Promise<ExternalFindings & Partial<SnykIssuesFindings>> {
  if (Array.isArray(input)) return normalizeSnykJson(input, target);
  const document = record(input, "Snyk findings");
  if (isSnykRestFormat(document["format"])) {
    const { normalizeSnykIssues } = await import("./snyk-rest-findings.js");
    return normalizeSnykIssues(document, target, references);
  }
  if (document["format"] === "snyk-findings-export/v1")
    return normalizeSnykFindingsExport(document, target);
  if (document["version"] === "2.1.0")
    return normalizeSnykSarif(document, target);
  return normalizeSnykJson(document, target);
}

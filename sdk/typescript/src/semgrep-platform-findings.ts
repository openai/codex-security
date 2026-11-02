import { validateExternalEvidence } from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import { isRecord } from "./record.js";
import { position, weaknessIds } from "./native-json-findings.js";
import {
  array,
  normalizeRecords,
  record,
  relativePath,
  repositoryFilePath,
  requiredText,
  stableId,
  text,
} from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

// These v1 Findings API response fields belong only to AI detections or Supply Chain.
const nonSastFields = [
  "ai_impact",
  "epss_score",
  "fix_recommendations",
  "found_dependency",
  "is_malicious",
  "reachability",
  "reachable_condition",
  "usage",
  "vulnerability_identifier",
];

function identifiesNonSastProduct(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return (
    nonSastFields.some((field) => value[field] != null) ||
    [value["issue_type"], value["product"]].some(
      (product) =>
        typeof product === "string" &&
        /^(?:sca|ai_sast|secrets)$/iu.test(product),
    )
  );
}

// Node 22 supports JSON source text and raw values. The SDK targets the ES2022 type library.
const wireJson = JSON as JSON & {
  rawJSON(source: string): { rawJSON: string };
  isRawJSON(value: unknown): value is { rawJSON: string };
};

// A retained JSON number is represented as an object in JavaScript.
function responseRecord(value: unknown, label: string) {
  return record(wireJson.isRawJSON(value) ? undefined : value, label);
}

// Normalize equivalent JSON numbers exactly. Keep very large exponents compact.
function canonicalNumber(token: string): string {
  const [, sign = "", integer, fraction = "", exponent = "0"] =
    /^(-?)(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/iu.exec(token)!;
  const significant = (integer + fraction).replace(/^0+/u, "");
  if (!significant) return "0";
  let end = significant.length;
  while (significant[end - 1] === "0") end--;
  const digits = significant.slice(0, end);
  const point = BigInt(exponent) + BigInt(significant.length - fraction.length);
  // Ordinary evidence follows JSON.stringify’s fixed/scientific notation thresholds.
  if (point > -6n && point <= 21n) {
    const split = Number(point);
    if (split <= 0) return sign + "0." + "0".repeat(-split) + digits;
    if (split >= digits.length) return sign + digits.padEnd(split, "0");
    return sign + digits.slice(0, split) + "." + digits.slice(split);
  }
  const trailing = digits.slice(1);
  const scientific = point - 1n;
  return (
    sign +
    digits.charAt(0) +
    (trailing ? "." + trailing : "") +
    "e" +
    (scientific >= 0n ? "+" : "") +
    scientific
  );
}

function sourceLine(value: unknown): number | null {
  if (value == null) return null;
  if (!wireJson.isRawJSON(value)) return position(value, "Semgrep source line");
  const exact = canonicalNumber(value.rawJSON);
  return position(
    /^\d+$/u.test(exact) ? Number(exact) : undefined,
    "Semgrep source line",
  );
}

/** Keep original number tokens, including adjacent int64 IDs above Number.MAX_SAFE_INTEGER. */
function parseSemgrepResponse(json: string): Record<string, unknown> {
  return responseRecord(
    JSON.parse(
      json.replace(/^\uFEFF/u, ""),
      (_key: string, value: unknown, context?: { source?: string }) =>
        typeof value === "number" ? wireJson.rawJSON(context!.source!) : value,
    ),
    "Semgrep API response",
  );
}

function platformId(value: unknown): string | undefined {
  let token: string;
  if (wireJson.isRawJSON(value)) token = value.rawJSON;
  else if (typeof value === "string" && /^[1-9][0-9]*$/u.test(value))
    token = value;
  else return undefined;
  const id = canonicalNumber(token);
  if (/^[1-9][0-9]*$/u.test(id)) return id;
  // A large scientific value is an integer only when every significant digit lies left of its decimal point.
  const scientific = /^[1-9](?:\.(\d+))?e\+(\d+)$/u.exec(id);
  return scientific && BigInt(scientific[2]!) >= (scientific[1]?.length ?? 0)
    ? id
    : undefined;
}

function requiredPlatformId(value: unknown): string {
  const id = platformId(value);
  if (!id) throw new Error("Expected an exact, positive Semgrep Platform ID.");
  return id;
}

/** Select SAST findings from operator-supplied Web API responses for local SDK import. */
export function normalizeSelectedSemgrepPlatformFindings(options: {
  deployment: string;
  ref: string;
  /** Independently supplied by the operator for the selected local checkout. */
  sourceRepositoryUrl: string;
  projectResponse: string;
  findingsResponses: Iterable<string>;
  findingIds: readonly string[];
}): ExternalFindings {
  const native = responseRecord(
    parseSemgrepResponse(options.projectResponse)["project"],
    "Semgrep project",
  );
  const scope = {
    deployment: requiredText(options.deployment, "Semgrep deployment"),
    project: {
      id: requiredPlatformId(native["id"]),
      name: requiredText(native["name"], "Semgrep project name"),
      url: declaredScannerRepositoryUrl(
        options.sourceRepositoryUrl,
        "Semgrep",
        "local",
      ),
    },
    ref: requiredText(options.ref, "Semgrep ref"),
    product: "sast",
  };
  // git-check-ref-format distinguishes literal branch/tag names from revision expressions.
  const refParts = scope.ref.split("/");
  if (
    refParts[0] !== "refs" ||
    refParts.length < 2 ||
    refParts.some(
      (part) => !part || part.startsWith(".") || part.endsWith(".lock"),
    ) ||
    scope.ref.endsWith(".") ||
    scope.ref.includes("..") ||
    scope.ref.includes("@{") ||
    /[\u0000-\u0020\u007f~^:?*\[\\]/u.test(scope.ref)
  )
    throw new Error(
      "Use a fully qualified Semgrep ref such as refs/heads/topic.",
    );
  if (native["url"] !== scope.project.url)
    throw new Error(
      "Selected Semgrep project does not match the operator's source repository URL.",
    );
  const wanted = new Set(
    options.findingIds.map((id) =>
      requiredPlatformId(requiredText(id, "Selected Semgrep finding ID")),
    ),
  );
  if (!wanted.size) throw new Error("Select at least one Semgrep finding ID.");
  const selected = new Map<string, Record<string, unknown>>();
  const pages =
    typeof options.findingsResponses === "string"
      ? [options.findingsResponses]
      : options.findingsResponses;
  const projectPath = decodeURIComponent(
    new URL(scope.project.url).pathname,
  ).replace(/^\/|\/$/gu, "");
  for (const response of pages) {
    const findings = array(
      parseSemgrepResponse(response)["findings"],
      "Semgrep findings",
    );
    const previousCount = selected.size;
    for (const finding of findings) {
      if (!isRecord(finding)) continue;
      const id = platformId(finding["id"]);
      if (!id || !wanted.has(id)) continue;
      if (selected.has(id))
        throw new Error(`Duplicate selected Semgrep finding ${id}.`);
      const repo = responseRecord(
        finding["repository"],
        "Semgrep finding repository",
      );
      const repositoryId =
        repo["id"] == null ? undefined : requiredPlatformId(repo["id"]);
      const url = repo["url"];
      const name = repo["name"];
      const matchesQualifiedPath =
        name === projectPath && projectPath.includes("/");
      if (
        finding["ref"] !== scope.ref ||
        (repositoryId !== undefined && repositoryId !== scope.project.id) ||
        (url != null
          ? url !== scope.project.url
          : repositoryId === undefined || !matchesQualifiedPath)
      )
        throw new Error(
          "Selected Semgrep finding does not belong to the selected project and ref.",
        );
      if (
        [finding["issue_type"], finding["product"]].some(
          (product) =>
            product != null &&
            (typeof product !== "string" ||
              !["sast", "code"].includes(product.toLowerCase())),
        )
      )
        throw new Error("Select Semgrep Code (SAST) findings.");
      selected.set(id, finding);
    }
    // The v1 findings endpoint returns a single product per response page.
    if (
      selected.size !== previousCount &&
      findings.some(identifiesNonSastProduct)
    )
      throw new Error("Select Semgrep Code (SAST) findings.");
  }
  const rows = Array.from(wanted, (id) => {
    const found = selected.get(id);
    if (!found) throw new Error(`Selected Semgrep finding ${id} is missing.`);
    return found;
  });
  // Older Platform imports hash safe integers as numbers, and larger IDs as strings.
  const exact = (id: string) =>
    Number.isSafeInteger(Number(id)) ? Number(id) : id;
  return normalizeRecords(
    rows,
    (finding) => {
      const rule = responseRecord(finding["rule"] ?? {}, "Semgrep rule");
      const name = text(rule["name"]) ?? text(finding["rule_name"]);
      const severity = text(finding["severity"])?.toLowerCase() ?? "";
      const description =
        text(rule["message"]) ?? text(finding["rule_message"]);
      const location = responseRecord(
        finding["location"] ?? {},
        "Semgrep location",
      );
      const rawPath = text(location["file_path"]);
      const relative = relativePath(rawPath);
      const path =
        relative && !relative.endsWith("/.") && repositoryFilePath(relative)
          ? rawPath
          : null;
      const startLine = path ? sourceLine(location["line"]) : null;
      return validateExternalEvidence(
        {
          title: requiredText(name ?? description, "Semgrep finding title"),
          description,
          severity: ["low", "medium", "high", "critical"].includes(severity)
            ? severity
            : "unknown",
          locations: path ? [{ path, line: startLine }] : [],
          branch: scope.ref,
          details: {
            kind: "sast",
            repository: { url: scope.project.url },
            scanner_origin: "Semgrep",
            rule: name ? { id: name } : null,
            source_status: text(finding["status"]),
            weakness_ids: weaknessIds(rule["cwe_names"]),
            code: {
              end_line:
                startLine !== null ? sourceLine(location["end_line"]) : null,
            },
          },
          source_data: {
            format: "semgrep-platform-selection/v1",
            ...scope,
            project: {
              ...scope.project,
              id: text(native["id"]) ?? scope.project.id,
            },
            semgrepPlatformFindingJson: JSON.stringify(
              finding,
              (_key, value: unknown) => {
                if (wireJson.isRawJSON(value))
                  return wireJson.rawJSON(canonicalNumber(value.rawJSON));
                // Native object key order can vary across otherwise identical reads.
                if (isRecord(value))
                  return Object.fromEntries(
                    Object.keys(value)
                      .sort()
                      .map((key) => [key, value[key]]),
                  );
                return value;
              },
            ),
          },
        },
        "local",
      );
    },
    (finding) =>
      stableId("semgrep-platform", [
        scope.deployment,
        exact(scope.project.id),
        scope.product,
        scope.ref,
        exact(requiredPlatformId(finding["id"])),
      ]),
    "local",
  );
}

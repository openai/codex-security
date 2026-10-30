import { validateExternalEvidence } from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import { isRecord } from "./record.js";
import { position, weaknessIds } from "./native-json-findings.js";
import {
  array,
  normalizeRecords,
  record,
  relativePath,
  requiredText,
  stableId,
  text,
} from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

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
  const digits = significant.replace(/0+$/u, "");
  const point = BigInt(exponent) + BigInt(significant.length - fraction.length);
  // Use the same fixed/scientific notation thresholds as JSON.stringify.
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
      (_key: string, value: unknown, context?: { source?: string }) => {
        if (typeof value === "number")
          return wireJson.rawJSON(context!.source!);
        // Vendor object order can change between reads without a finding changing.
        if (isRecord(value))
          return Object.fromEntries(
            Object.keys(value)
              .sort()
              .map((key) => [key, value[key]]),
          );
        return value;
      },
    ),
    "Semgrep API response",
  );
}

function platformId(value: unknown): string | undefined {
  const id = wireJson.isRawJSON(value)
    ? value.rawJSON
    : typeof value === "number" && Number.isSafeInteger(value)
      ? String(value)
      : value;
  return typeof id === "string" && /^[1-9][0-9]*$/u.test(id) ? id : undefined;
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
  if (!/^refs\/[^/]+(?:\/[^/]+)*$/u.test(scope.ref))
    throw new Error(
      "Use a fully qualified Semgrep ref such as refs/heads/topic.",
    );
  if (native["url"] !== scope.project.url)
    throw new Error(
      "Selected Semgrep project does not match the operator's source repository URL.",
    );
  const wanted = new Set(options.findingIds.map(requiredPlatformId));
  if (!wanted.size) throw new Error("Select at least one Semgrep finding ID.");
  const selected = new Map<string, Record<string, unknown>>();
  const pages =
    typeof options.findingsResponses === "string"
      ? [options.findingsResponses]
      : options.findingsResponses;
  const projectPath = new URL(scope.project.url).pathname.replace(
    /^\/|\/$/gu,
    "",
  );
  for (const response of pages) {
    for (const finding of array(
      parseSemgrepResponse(response)["findings"],
      "Semgrep findings",
    )) {
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
      const fullName = scope.project.name;
      const urlPathName =
        typeof name === "string" &&
        (name === projectPath || name + ".git" === projectPath);
      const qualifiedName =
        typeof name === "string" &&
        /^[^/]+(?:\/[^/]+)+$/u.test(name) &&
        (name === fullName || urlPathName);
      const matchesName =
        name === fullName ||
        name === fullName.split("/").at(-1) ||
        (urlPathName && fullName === name.split("/").at(-1));
      if (
        finding["ref"] !== scope.ref ||
        (repositoryId !== undefined && repositoryId !== scope.project.id) ||
        (repositoryId === undefined && name != null && !matchesName) ||
        (url != null
          ? url !== scope.project.url
          : repositoryId === undefined || !qualifiedName)
      )
        throw new Error(
          "Selected Semgrep finding does not belong to the selected project and ref.",
        );
      if (
        [finding["issue_type"], finding["product"]].some(
          (product) =>
            product != null &&
            !["sast", "code"].includes(String(product).toLowerCase()),
        ) ||
        finding["found_dependency"] != null ||
        finding["vulnerability_identifier"] != null
      )
        throw new Error("Select Semgrep Code (SAST) findings.");
      selected.set(id, finding);
    }
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
      const description =
        text(rule["message"]) ?? text(finding["rule_message"]);
      const location = responseRecord(
        finding["location"] ?? {},
        "Semgrep location",
      );
      const filePath = text(location["file_path"]);
      const path =
        filePath &&
        (/^[a-z][a-z0-9+.-]*:[/\\]/iu.test(filePath) ||
          filePath.includes("://"))
          ? null
          : relativePath(filePath);
      const startLine = path ? sourceLine(location["line"]) : null;
      return validateExternalEvidence(
        {
          title:
            name ??
            description ??
            `Semgrep finding ${requiredPlatformId(finding["id"])}`,
          description,
          severity: text(finding["severity"])?.toLowerCase() ?? "unknown",
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
            project: { ...scope.project },
            semgrepPlatformFindingJson: JSON.stringify(
              finding,
              (_key, value: unknown) =>
                wireJson.isRawJSON(value)
                  ? wireJson.rawJSON(canonicalNumber(value.rawJSON))
                  : value,
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

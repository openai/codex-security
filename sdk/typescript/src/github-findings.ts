import type { ExternalImportTarget } from "./external-import-contract.js";
import { hash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { GHSA_ID, githubRepositoryParts } from "./github-identifiers.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import {
  exportedGitHubEvidence,
  validateExternalEvidenceFields,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import type { ImportedGitHubCodeScanningAlert } from "./github.js";
import type { ImportedGitHubAdvisory } from "./github-advisories.js";
import {
  isGitHubDependabotAlert,
  normalizeGitHubDependabotAlerts,
} from "./github-dependabot-findings.js";
import { asRecord, canonicalJson } from "./record.js";
import { parseJsonOrJsonl, readScannerText, text } from "./scanner-import.js";

function repositoryName(value: unknown): string {
  const repository = text(value);
  if (!repository || !githubRepositoryParts(repository))
    throw new Error("GitHub repository must be OWNER/REPO.");
  return repository;
}

function sourceUrl(value: string): {
  parsed: URL;
  host: string;
  origin: string;
} {
  const parsed = new URL(value);
  const origin = /^(https?:\/\/([^/?#]+))/iu.exec(value);
  if (!origin) throw new Error("GitHub evidence URL must be an HTTP(S) link.");
  // URL.origin/host remove explicit default ports; Cloud keeps those distinct.
  return { parsed, host: origin[2]!.toLowerCase(), origin: origin[1]! };
}

function sourceTimestamp(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  const seconds = typeof value === "string" ? Date.parse(value) / 1000 : NaN;
  if (!Number.isFinite(seconds) || seconds < 0)
    throw new Error("GitHub updated_at is not a valid timestamp.");
  return Math.floor(seconds);
}

function severity(value: unknown): string {
  // SARIF error/warning/note are not vulnerability severity ratings.
  return typeof value === "string" &&
    ["critical", "high", "medium", "low", "informational"].includes(value)
    ? value
    : "unknown";
}

function codeScanningFinding(record: Record<string, unknown>): {
  source_finding_id: string;
  evidence: unknown;
} {
  const repository = repositoryName(record["repository"]);
  const alert = asRecord(record["alert"]);
  const number = record["number"];
  if (
    !alert ||
    typeof number !== "number" ||
    !Number.isSafeInteger(number) ||
    number < 1 ||
    alert["number"] !== number
  )
    throw new Error(
      "Expected a GitHub code-scanning import with matching alert numbers.",
    );
  const url = text(record["url"]);
  if (!url || url !== alert["html_url"])
    throw new Error("GitHub alert URL must match the original alert.");
  const { parsed: parsedUrl, host, origin } = sourceUrl(url);
  if (
    !["security/code-scanning", "code-scanning"].some(
      (route) =>
        parsedUrl.pathname.toLowerCase() ===
        `/${repository}/${route}/${number}`.toLowerCase(),
    )
  )
    throw new Error(
      "GitHub alert URL does not match the selected repository and alert.",
    );
  const rule = asRecord(alert["rule"]);
  const instance = asRecord(alert["most_recent_instance"]);
  const ref = text(instance?.["ref"]);
  if (!ref)
    throw new Error(
      "GitHub code-scanning evidence requires the selected instance ref.",
    );
  const location = asRecord(instance?.["location"]);
  const tool = asRecord(alert["tool"]);
  const message = text(asRecord(instance?.["message"])?.["text"]);
  const description =
    text(rule?.["full_description"]) ?? text(rule?.["description"]);
  const tags = Array.isArray(rule?.["tags"]) ? rule["tags"] : [];
  const weaknessIds = [
    ...new Set(
      tags.flatMap((tag: unknown) => {
        const match =
          typeof tag === "string"
            ? /^external\/cwe\/cwe-(\d+)$/iu.exec(tag)
            : null;
        return match ? [`CWE-${Number(match[1])}`] : [];
      }),
    ),
  ];
  const path = text(location?.["path"]);
  const sourceId = `${host}/${repository.toLowerCase()}/code-scanning/${number}/${hash("sha256", ref)}`;
  return {
    source_finding_id: sourceId,
    evidence: {
      title:
        text(rule?.["name"]) ??
        text(rule?.["description"]) ??
        `GitHub code-scanning alert #${number}`,
      severity: severity(rule?.["security_severity_level"]),
      description:
        [...new Set([message, description].filter(Boolean))].join("\n\n") ||
        null,
      url,
      locations: path ? [{ path, line: location?.["start_line"] ?? null }] : [],
      branch: ref,
      code_revision: text(instance?.["commit_sha"]),
      source_updated_at: sourceTimestamp(alert["updated_at"]),
      source_data: record,
      details: {
        kind: "sast",
        repository: {
          url: `${origin}/${repository}`,
          name: repository,
        },
        // Dismissal covers every branch; detection state belongs to the selected ref.
        source_status:
          alert["state"] === "dismissed"
            ? "dismissed"
            : (text(instance?.["state"]) ?? text(alert["state"])),
        scanner_origin: text(tool?.["name"]),
        rule: { id: text(rule?.["id"]), name: text(rule?.["name"]) },
        weakness_ids: weaknessIds,
        remediation_instructions: text(rule?.["help"]),
        code: path ? { end_line: location?.["end_line"] ?? null } : null,
      },
    },
  };
}

function advisoryFinding(record: Record<string, unknown>): {
  source_finding_id: string;
  evidence: unknown;
} {
  const repository = repositoryName(record["repository"]);
  const advisory = asRecord(record["advisory"]);
  const id = text(record["ghsaId"]);
  const selection = record["selection"];
  if (
    !advisory ||
    !id ||
    !GHSA_ID.test(id) ||
    text(advisory["ghsa_id"])?.toUpperCase() !== id.toUpperCase()
  )
    throw new Error(
      "Expected a GitHub advisory import with matching GHSA IDs.",
    );
  if (selection !== "repository" && selection !== "global")
    throw new Error("GitHub advisory selection must be repository or global.");
  const url = text(record["url"]);
  if (!url || url !== advisory["html_url"])
    throw new Error("GitHub advisory URL must match the original advisory.");
  const { parsed: parsedUrl, host: linkHost, origin } = sourceUrl(url);
  const host = text(record["githubHost"])?.toLowerCase();
  // Enterprise APIs may return the public advisory database's canonical link.
  const canonicalGlobalLink =
    selection === "global" && parsedUrl.host === "github.com";
  const expectedPath =
    selection === "repository"
      ? `/${repository}/security/advisories/${id}`
      : `/advisories/${id}`;
  if (
    !host ||
    (linkHost !== host && !canonicalGlobalLink) ||
    parsedUrl.pathname.toLowerCase() !== expectedPath.toLowerCase()
  )
    throw new Error(
      "GitHub advisory URL does not match the selected source and GHSA ID.",
    );
  const vulnerabilities =
    advisory["vulnerabilities"] === null ? [] : advisory["vulnerabilities"];
  if (!Array.isArray(vulnerabilities))
    throw new Error("GitHub advisory vulnerabilities must be an array.");
  const identifiers = Array.isArray(advisory["identifiers"])
    ? advisory["identifiers"]
    : [];
  const advisoryIds = [
    id,
    text(advisory["cve_id"]),
    ...identifiers.map((identifier) => text(asRecord(identifier)?.["value"])),
  ].filter((value): value is string => value !== null);
  const packages = vulnerabilities.flatMap((value) => {
    const vulnerability = asRecord(value);
    const pkg = asRecord(vulnerability?.["package"]);
    const name = text(pkg?.["name"]);
    // GitHub permits incomplete package metadata in advisory disclosures.
    // Preserve it in source_data without inventing a typed package identity.
    if (!name) return [];
    const fixedVersion =
      text(vulnerability?.["first_patched_version"]) ??
      text(vulnerability?.["patched_versions"]);
    return [
      {
        name,
        ecosystem: text(pkg?.["ecosystem"]),
        vulnerable_version_range: text(
          vulnerability?.["vulnerable_version_range"],
        ),
        fixed_versions: fixedVersion ? [fixedVersion] : [],
      },
    ];
  });
  const cwes = Array.isArray(advisory["cwes"]) ? advisory["cwes"] : [];
  return {
    source_finding_id: `${host}/${selection === "repository" ? repository.toLowerCase() : "global"}/security-advisory/${id.toUpperCase()}`,
    evidence: {
      title: text(advisory["summary"]) ?? id,
      severity: severity(advisory["severity"]),
      description: text(advisory["description"]),
      url,
      advisory_ids: [...new Set(advisoryIds)],
      packages,
      source_updated_at: sourceTimestamp(advisory["updated_at"]),
      source_data: record,
      details: {
        kind: "advisory",
        advisory: { source: selection },
        ...(selection === "repository"
          ? {
              repository: {
                url: `${origin}/${repository}`,
                name: repository,
              },
            }
          : {}),
        source_status: text(advisory["withdrawn_at"])
          ? "withdrawn"
          : (text(advisory["state"]) ??
            (selection === "global" ? "published" : null)),
        scanner_origin: "GitHub Security Advisories",
        weakness_ids: cwes
          .map((value) => text(asRecord(value)?.["cwe_id"]))
          .filter((value): value is string => value !== null),
      },
    },
  };
}

interface LegacyGitHubSelection {
  sourceFindingIds: string[];
  snapshot?: ExternalFindings;
}
const previousSelections = new WeakMap<
  ExternalFindings,
  { exported: string; previous: LegacyGitHubSelection }
>();

/** Only unchanged SDK output can identify an older, differently serialized selection. */
export function legacyGitHubFindings(
  input: ExternalFindings,
  current: ExternalFindings,
): LegacyGitHubSelection | undefined {
  const selection = previousSelections.get(input);
  if (!selection) return undefined;
  return hash("sha256", canonicalJson(current)) === selection.exported
    ? selection.previous
    : { sourceFindingIds: selection.previous.sourceFindingIds };
}

function normalizeRecords(
  records: readonly unknown[],
  target: ExternalImportTarget = "cloud",
  snapshot = false,
): ExternalFindings {
  const result: ExternalFindings = {
    read: records.length,
    findings: [],
    excluded: [],
  };
  const originals =
    snapshot && target === "cloud" ? ([] as ExternalFinding[]) : undefined;
  const oldExcluded: ExternalFindings["excluded"] = [];
  const identities = new Set<string>();
  for (const [index, value] of records.entries()) {
    const record = asRecord(value);
    let oldChecked = false;
    try {
      if (!record) throw new Error("GitHub finding must be an object.");
      let candidate;
      if (record["source"] === "github-code-scanning")
        candidate = codeScanningFinding(record);
      else if (record["source"] === "github-security-advisory")
        candidate = advisoryFinding(record);
      else
        throw new Error(
          "Expected saved output from import github or import github-advisories; raw or incomplete API responses need an explicit mapping.",
        );
      const id = candidate.source_finding_id;
      let evidence;
      if (snapshot) {
        const raw = validateExternalEvidenceFields(candidate.evidence, target);
        evidence = exportedGitHubEvidence(
          raw,
          target,
          originals
            ? (exclusion) => {
                oldChecked = true;
                if (!exclusion)
                  originals.push({ source_finding_id: id, evidence: raw });
                else
                  oldExcluded.push({
                    position: index + 1,
                    source_finding_id: text(record["url"]),
                    reason: exclusion,
                  });
              }
            : undefined,
        );
      } else evidence = validateExternalEvidence(candidate.evidence, target);
      if (identities.has(id))
        throw new CodexSecurityError(
          `Duplicate source finding id ${JSON.stringify(id)}. Select each GitHub occurrence once.`,
        );
      identities.add(id);
      result.findings.push({ source_finding_id: id, evidence });
    } catch (error) {
      if (error instanceof CodexSecurityError) throw error;
      const excluded = {
        position: index + 1,
        source_finding_id: text(record?.["url"]),
        reason: errorMessage(error),
      };
      result.excluded.push(excluded);
      if (originals && !oldChecked) oldExcluded.push({ ...excluded });
    }
  }
  if (originals?.length) {
    let native: ExternalFinding[] | undefined;
    try {
      native = structuredClone(originals);
    } catch {
      /* No complete previous SDK snapshot could be reproduced. */
    }
    if (!isDeepStrictEqual(native, result.findings)) {
      const previous: LegacyGitHubSelection = {
        sourceFindingIds: originals.map((row) => row.source_finding_id),
      };
      if (native)
        previous.snapshot = {
          read: result.read,
          findings: native,
          excluded: oldExcluded,
        };
      previousSelections.set(result, {
        exported: hash("sha256", canonicalJson(result)),
        previous,
      });
    }
  }
  return result;
}

/** Map selected code-scanning instances while retaining complete upstream evidence. */
export function normalizeGitHubCodeScanningAlerts(
  alerts: readonly ImportedGitHubCodeScanningAlert[],
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  return normalizeRecords(alerts, target, true);
}

/** Map advisory disclosures without asserting an installed vulnerable dependency. */
export function normalizeGitHubAdvisories(
  advisories: readonly ImportedGitHubAdvisory[],
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  return normalizeRecords(advisories, target, true);
}

/** Read unfiltered JSON/JSONL output saved by the read-only GitHub import commands. */
export async function readGitHubFindings(
  path: string,
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  try {
    const payload = parseJsonOrJsonl(await readScannerText(path));
    const rows = Array.isArray(payload) ? payload : [payload];
    if (
      (rows.length > 0 && rows.every(Array.isArray)) ||
      rows.some((row) =>
        Array.isArray(row)
          ? row.some(isGitHubDependabotAlert)
          : isGitHubDependabotAlert(row),
      )
    )
      return normalizeGitHubDependabotAlerts(payload, target);
    return normalizeRecords(rows, target);
  } catch (cause) {
    throw new CodexSecurityError(
      `Could not read GitHub findings as UTF-8 JSON or JSONL: ${errorMessage(cause)}`,
      { cause },
    );
  }
}

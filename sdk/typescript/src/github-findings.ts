import type { ExternalImportTarget } from "./external-import-contract.js";
import { hash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { isProxy } from "node:util/types";
import { GHSA_ID, githubRepositoryParts } from "./github-identifiers.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import {
  CloudEvidenceDepthError,
  exportedGitHubRecord,
  previousGitHubExclusion,
  validateExternalEvidenceFields,
  validateExternalEvidenceJson,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import type { ImportedGitHubCodeScanningAlert } from "./github.js";
import type { ImportedGitHubAdvisory } from "./github-advisories.js";
import {
  isGitHubDependabotAlert,
  normalizeGitHubDependabotAlerts,
} from "./github-dependabot-findings.js";
import { asRecord, canSnapshotWithoutGetters } from "./record.js";
import { parseJsonOrJsonl, readScannerText, text } from "./scanner-import.js";

import {
  rememberPreviousSelection,
  type LegacyReaderSelection,
} from "./reader-selection.js";

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

function mapRecord(input: unknown) {
  const record = asRecord(input);
  if (!record) throw new Error("GitHub finding must be an object.");
  if (record["source"] === "github-code-scanning")
    return codeScanningFinding(record);
  if (record["source"] === "github-security-advisory")
    return advisoryFinding(record);
  throw new Error(
    "Expected saved output from import github or import github-advisories; raw or incomplete API responses need an explicit mapping.",
  );
}

function nativeGitHubRecord(
  value: unknown,
  observe?: (value: object) => boolean | void,
): Record<string, unknown> | undefined {
  if (!canSnapshotWithoutGetters(value, true, observe)) return;
  try {
    return asRecord(structuredClone(value));
  } catch {
    return;
  }
}

function codeOccurrencePrefix(value: unknown): string | undefined {
  if (!value || typeof value !== "object" || isProxy(value)) return;
  const field = (key: string): unknown =>
    Object.getOwnPropertyDescriptor(value, key)?.value;
  const repository = field("repository"),
    number = field("number"),
    url = field("url");
  if (
    field("source") !== "github-code-scanning" ||
    typeof repository !== "string" ||
    !githubRepositoryParts(repository) ||
    typeof number !== "number" ||
    !Number.isSafeInteger(number) ||
    number <= 0 ||
    typeof url !== "string"
  )
    return;
  try {
    const { parsed, host } = sourceUrl(url);
    if (
      ["security/code-scanning", "code-scanning"].some(
        (route) =>
          parsed.pathname.toLowerCase() ===
          `/${repository.toLowerCase()}/${route}/${number}`,
      )
    )
      return `${host}/${repository.toLowerCase()}/code-scanning/${number}/`;
  } catch {
    /* No validated occurrence anchor. */
  }
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
  const previous = snapshot
    ? ({
        read: records.length,
        findings: [],
        excluded: [],
      } as ExternalFindings)
    : undefined;
  const checks: { input: unknown; before: unknown; uncertain: () => void }[] =
    [];
  const uncertainIds = new Set<string>();
  let largeLocalSelection = false;
  const potentialIds: string[] = [];
  const prefixes = new Set<string>();
  let uncertain = false;
  const identities = new Set<string>();
  for (const [index, input] of records.entries()) {
    let exported = input;
    // The released reader measured the caller's source_data JSON before native capture.
    // Its byte count can be reconstructed for plain JSON containing ordinary Buffers.
    let plainBufferWire = true;
    let buffers: Buffer[] | undefined;
    let hiddenFields = false;
    let largeLocalRow = false;
    const before = previous
      ? nativeGitHubRecord(input, (value) => {
          const prototype = Object.getPrototypeOf(value);
          if (
            target === "local" &&
            ((Array.isArray(value) && value.length > 256 * 1024) ||
              (prototype === Buffer.prototype &&
                Buffer.isBuffer(value) &&
                !Object.hasOwn(value, "byteLength") &&
                value.byteLength > 256 * 1024))
          ) {
            largeLocalRow = true;
            return false;
          }
          // Native capture drops non-enumerable fields the released vendor mapper could read.
          if (
            (prototype === Object.prototype || prototype === null) &&
            Object.getOwnPropertyNames(value).some(
              (key) =>
                key !== "toJSON" &&
                !Object.prototype.propertyIsEnumerable.call(value, key),
            )
          )
            hiddenFields = true;
          if (!plainBufferWire) return;
          if (Buffer.isBuffer(value)) (buffers ??= []).push(value);
          plainBufferWire = Buffer.isBuffer(value)
            ? prototype === Buffer.prototype &&
              !Object.hasOwn(value, "toJSON") &&
              !Object.hasOwn(value, "length") &&
              !("_arr" in value)
            : (prototype === Object.prototype ||
                prototype === null ||
                prototype === Array.prototype) &&
              !("toJSON" in value);
        })
      : undefined;
    let prefix = previous ? codeOccurrencePrefix(input) : undefined;
    const rowIds = new Set<string>();
    let rowUncertain = false;
    function possible() {
      uncertain = rowUncertain = true;
      for (const id of rowIds) uncertainIds.add(id);
      if (prefix) prefixes.add(prefix);
    }
    const exclusion = (record: unknown, reason: string) => ({
      position: index + 1,
      source_finding_id: text(asRecord(record)?.["url"]),
      reason,
    });
    let possibleFreshId = false;
    try {
      if (snapshot) {
        const source = exportedGitHubRecord(
          input,
          index,
          target,
          target === "local" && !largeLocalRow,
        );
        exported = source.record;
        if (previous) {
          prefix ??= codeOccurrencePrefix(exported);
          if (
            target === "local" &&
            (largeLocalRow || source.bytes > 256 * 1024)
          ) {
            largeLocalSelection = true;
            possible();
            possibleFreshId = true;
          } else if (
            !before &&
            source.previousInvalid &&
            !source.skippedRawValue &&
            canSnapshotWithoutGetters(input, true)
          ) {
            previous.excluded.push(
              exclusion(exported, errorMessage(source.previousInvalid)),
            );
          } else if (!before) {
            // With no independent native observation, only an occurrence can
            // identify a possible older approval. It cannot authorize a retry.
            const rawSizeExcludes =
              source.adjustment === Infinity ||
              source.bytes + source.adjustment > 256 * 1024;
            if (
              target === "local" ||
              !rawSizeExcludes ||
              !canSnapshotWithoutGetters(input, true) ||
              (input && typeof input === "object" && "toJSON" in input)
            ) {
              possible();
              possibleFreshId = true;
            } else
              previous.excluded.push(
                exclusion(
                  exported,
                  "Evidence exceeds the Cloud limit of 256 KiB.",
                ),
              );
          } else {
            checks.push({ input, before, uncertain: possible });
            if (hiddenFields || source.skippedRawValue) possible();
            try {
              const row = mapRecord(before);
              const knownOldId = row.source_finding_id;
              rowIds.add(knownOldId);
              if (rowUncertain) uncertainIds.add(knownOldId);
              const evidence = validateExternalEvidenceFields(
                row.evidence,
                target,
              );
              if (source.previousInvalid) throw source.previousInvalid;
              const keySensitive =
                input && typeof input === "object" && "toJSON" in input;
              if (keySensitive) possible();
              const reason =
                keySensitive || target === "local"
                  ? undefined
                  : previousGitHubExclusion(
                      evidence,
                      source.bytes,
                      source.adjustment,
                    );
              if (reason) previous.excluded.push(exclusion(before, reason));
              else {
                previous.findings.push({
                  source_finding_id: knownOldId,
                  evidence,
                });
                potentialIds.push(knownOldId);
              }
            } catch (error) {
              previous.excluded.push(exclusion(before, errorMessage(error)));
            }
          }
        }
        if (source.invalid) throw source.invalid;
      }
      const mapped = mapRecord(exported),
        id = mapped.source_finding_id;
      rowIds.add(id);
      if (rowUncertain) uncertainIds.add(id);
      if (possibleFreshId) potentialIds.push(id);
      const evidence = validateExternalEvidence(mapped.evidence, target);
      if (identities.has(id))
        throw new CodexSecurityError(
          `Duplicate source finding id ${JSON.stringify(id)}. Select each GitHub occurrence once.`,
        );
      identities.add(id);
      result.findings.push({ source_finding_id: id, evidence });
    } catch (error) {
      if (error instanceof CodexSecurityError) throw error;
      const reason = errorMessage(error);
      result.excluded.push(
        exclusion(snapshot && exported === input ? before : exported, reason),
      );
      if (previous && exported === input) {
        if (
          error instanceof CloudEvidenceDepthError &&
          before &&
          plainBufferWire &&
          // Extra Buffer fields were inspected by the old row validator, but
          // structuredClone does not retain them as part of the typed array.
          (buffers?.every(
            (buffer) => Object.keys(buffer).length === buffer.length,
          ) ??
            true)
        ) {
          // Exported JSON can be deeper than an approved native snapshot.
          // Retain only the independently observed, valid prior selection.
          try {
            const row = mapRecord(before);
            const evidence = validateExternalEvidence(row.evidence, target);
            const savedSource = JSON.stringify(evidence.source_data);
            // structuredClone turns each Buffer into a Uint8Array. Reconstruct its
            // original serialized size on detached data without running caller hooks.
            const oldSource = JSON.stringify(
              evidence.source_data,
              (_key, value: unknown) =>
                value instanceof Uint8Array
                  ? { type: "Buffer", data: [...value] }
                  : value,
            );
            validateExternalEvidenceJson(
              evidence,
              target,
              Buffer.byteLength(oldSource) - Buffer.byteLength(savedSource),
            );
            previous.findings.push({
              source_finding_id: row.source_finding_id,
              evidence,
            });
            potentialIds.push(row.source_finding_id);
            checks.push({ input, before, uncertain: possible });
          } catch (priorError) {
            previous.excluded.push(exclusion(before, errorMessage(priorError)));
          }
          continue;
        }
        // A serializer may throw at its array key while the old source_data
        // key produced a valid record. Keep only evidence for refusing a match.
        possible();
        if (before)
          try {
            const id = mapRecord(before).source_finding_id;
            potentialIds.push(id);
            uncertainIds.add(id);
          } catch {
            /* No old identity. */
          }
      }
    }
  }
  if (previous) {
    for (const check of checks) {
      if (!isDeepStrictEqual(check.before, nativeGitHubRecord(check.input)))
        check.uncertain();
    }
    if (uncertain || !isDeepStrictEqual(previous.findings, result.findings)) {
      const prior: LegacyReaderSelection = { sourceFindingIds: potentialIds };
      if (uncertain) {
        prior.unprovenIdPrefixes = [...prefixes];
        prior.uncertainFindingIds = [...uncertainIds];
        if (!largeLocalSelection)
          prior.knownFindings = previous.findings.filter(
            (finding) => !uncertainIds.has(finding.source_finding_id),
          );
      } else prior.snapshot = previous;
      rememberPreviousSelection(result, prior);
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

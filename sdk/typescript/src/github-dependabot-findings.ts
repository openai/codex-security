import { z } from "zod";
import { GHSA_ID, githubRepositoryParts } from "./github-identifiers.js";
import { CodexSecurityError } from "./errors.js";
import {
  type ExternalImportTarget,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import { isGitHubCloudHost } from "./git-remote.js";
import { isRecord } from "./record.js";
import {
  appendReaderFinding,
  finishReaderSizeSelection,
  record,
  relativePath,
  requiredText,
  text,
} from "./scanner-import.js";

export function isGitHubDependabotAlert(
  value: unknown,
): value is Record<string, unknown> {
  return (
    isRecord(value) &&
    ("security_vulnerability" in value ||
      ("dependency" in value && "security_advisory" in value) ||
      [value["url"], value["html_url"]].some(
        (url) =>
          typeof url === "string" &&
          /^\/(?:[^/]+\/[^/]+\/security\/dependabot|(?:api\/v3\/)?repos\/[^/]+\/[^/]+\/dependabot\/alerts)\/\d+$/iu.test(
            URL.parse(url)?.pathname ?? "",
          ),
      ))
  );
}

function webIdentity(url: string) {
  const match =
    /^(https?):\/\/([^/?#@\\\s]+)\/([^/?#]+\/[^/?#]+)\/security\/dependabot\/([1-9]\d*)$/iu.exec(
      url,
    );
  if (!match || !githubRepositoryParts(match[3]!)) return null;
  const parsed = URL.parse(url);
  if (
    !parsed ||
    (parsed.protocol === "http:" && isGitHubCloudHost(parsed.hostname))
  )
    return null;
  const host = match[2]!.toLowerCase();
  const repository = match[3]!.toLowerCase();
  const origin = `${parsed.protocol}//${host}`;
  const number = match[4]!;
  const apiBase = isGitHubCloudHost(parsed.hostname)
    ? `https://api.${host}`
    : `${origin}/api/v3`;
  const repositoryUrl = `${origin}/${repository}`;
  const apiRepo = `${apiBase}/repos/${repository}`;
  return {
    repository,
    repositoryUrl,
    apiRepo,
    number,
    sourceId: `${host}/${repository}/dependabot/${number}`,
    htmlUrl: `${repositoryUrl}/security/dependabot/${number}`,
    apiUrl: `${apiRepo}/dependabot/alerts/${number}`,
  };
}

// Normalized SDK evidence may link to either REST or the web UI.
function alertUrlIdentity(url: unknown) {
  if (typeof url !== "string") return null;
  const web = webIdentity(url);
  if (web) return web;
  const api =
    /^(https?:\/\/)([^/?#@\\\s]+)\/(api\/v3\/)?repos\/([^/]+\/[^/]+)\/dependabot\/alerts\/([1-9]\d*)$/iu.exec(
      url,
    );
  if (!api) return null;
  const host = api[3] ? api[2] : api[2]!.replace(/^api\./iu, "");
  const parsed = webIdentity(
    `${api[1]}${host}/${api[4]}/security/dependabot/${api[5]}`,
  );
  return parsed?.apiUrl === url.toLowerCase() ? parsed : null;
}

function checkSourceFamily(alert: Record<string, unknown>) {
  if (
    alert["source"] === "github-code-scanning" ||
    alert["source"] === "github-security-advisory"
  )
    throw new Error(
      "Dependabot alert conflicts with its GitHub source family.",
    );
}

function checkNativeClaims(
  alert: Record<string, unknown>,
  occurrence: NonNullable<ReturnType<typeof webIdentity>>,
) {
  if ("number" in alert && alert["number"] !== Number(occurrence.number))
    throw new Error(
      "Dependabot alert number must match the repository alert URL.",
    );
  if (
    ("url" in alert &&
      text(alert["url"])?.toLowerCase() !== occurrence.apiUrl) ||
    ("html_url" in alert &&
      text(alert["html_url"])?.toLowerCase() !== occurrence.htmlUrl)
  )
    throw new Error(
      "Dependabot API url and html_url must identify the same host, repository and alert number.",
    );
  if ("repository" in alert) {
    const declared = record(alert["repository"], "Dependabot repository");
    if (
      text(declared["full_name"])?.toLowerCase() !== occurrence.repository ||
      ("html_url" in declared &&
        text(declared["html_url"])?.toLowerCase() !==
          occurrence.repositoryUrl) ||
      ("url" in declared &&
        text(declared["url"])?.toLowerCase() !== occurrence.apiRepo)
    )
      throw new Error(
        "Dependabot repository metadata conflicts with its alert URLs.",
      );
  }
}

function identity(alert: Record<string, unknown>) {
  checkSourceFamily(alert);
  const number = alert["number"];
  if (typeof number !== "number" || !Number.isSafeInteger(number) || number < 1)
    throw new Error("Dependabot alert number must be a positive safe integer.");
  const url = requiredText(alert["html_url"], "Dependabot html_url");
  const parsed = webIdentity(url);
  if (!parsed || parsed.number !== String(number))
    throw new Error(
      "Dependabot html_url must identify the repository and alert number.",
    );
  requiredText(alert["url"], "Dependabot API url");
  checkNativeClaims(alert, parsed);
  return {
    repositoryUrl: parsed.repositoryUrl,
    sourceId: parsed.sourceId,
    url,
  };
}

export function dependabotRepository({
  source_finding_id: id,
  evidence: { source_data: sourceData, url },
}: ExternalFinding): string | undefined {
  const native = isGitHubDependabotAlert(sourceData) ? sourceData : null;
  const raw =
    native &&
    (alertUrlIdentity(native["html_url"]) ?? alertUrlIdentity(native["url"]));
  const projected = alertUrlIdentity(url);
  const occurrence = raw ?? projected;
  const structuredId =
    /^[^/]+\/[^/]+\/[^/]+\/(?:dependabot|code-scanning|security-advisory)\//u.test(
      id,
    );
  if (!occurrence) {
    if (/^[^/]+\/[^/]+\/[^/]+\/dependabot\/[1-9]\d*$/u.test(id))
      throw new CodexSecurityError(
        "The normalized Dependabot occurrence needs the original alert or its repository alert URL.",
      );
    return;
  }
  if (isRecord(sourceData)) checkSourceFamily(sourceData);
  if (native) checkNativeClaims(native, occurrence);
  // A caller may have stored this occurrence under an opaque ID before native imports existed.
  if ((structuredId || id === "") && id !== occurrence.sourceId)
    throw new CodexSecurityError(
      "The normalized source finding ID does not match the original Dependabot alert.",
    );
  if (raw && projected && raw.htmlUrl !== projected.htmlUrl)
    throw new CodexSecurityError(
      "The normalized alert URL does not match the original Dependabot alert.",
    );
  return occurrence.repositoryUrl;
}

function selectedAlerts(input: unknown) {
  const selection = Array.isArray(input) ? input : [input];
  const hasPages = selection.some(Array.isArray);
  if (hasPages && !selection.every(Array.isArray))
    throw new Error(
      "Dependabot input must not mix alert records and page arrays.",
    );
  const rows: unknown[] = hasPages ? selection.flat() : selection;
  if (!rows.every(isGitHubDependabotAlert))
    throw new Error(
      "Expected complete native Dependabot repository alerts, not mixed families, page shapes or API envelopes.",
    );
  return rows;
}

// Parse only the matched vulnerability projection. Keep the complete upstream alert as evidence.
const nonblank = z.string().regex(/\S/u);
const matchedVulnerability = z.object({
  package: z.object({ name: nonblank, ecosystem: nonblank }),
  vulnerable_version_range: nonblank,
  first_patched_version: z.object({ identifier: nonblank }).nullable(),
  severity: z.enum(["critical", "high", "medium", "low"]),
});

function evidence(alert: Record<string, unknown>, url: string) {
  const dependency = record(alert["dependency"], "Dependabot dependency");
  const advisory = record(
    alert["security_advisory"],
    "Dependabot security_advisory",
  );
  const {
    package: { name, ecosystem },
    vulnerable_version_range: range,
    first_patched_version: patch,
    severity,
  } = matchedVulnerability.parse(alert["security_vulnerability"]);
  if ("package" in dependency) {
    const observed = record(
      dependency["package"],
      "Dependabot dependency package",
    );
    if (observed["name"] !== name || observed["ecosystem"] !== ecosystem)
      throw new Error(
        "Dependabot dependency and matched vulnerability packages disagree.",
      );
  }
  const path = dependency["manifest_path"] ?? null;
  if (path !== null) {
    const filename = relativePath(path)?.split("/").at(-1);
    if (
      typeof path !== "string" ||
      /^[a-z][a-z\d+.-]*:/iu.test(path) ||
      !filename ||
      filename === "."
    )
      throw new Error(
        "Dependabot manifest_path must identify a repository-relative file.",
      );
  }
  const ghsa = requiredText(advisory["ghsa_id"], "Dependabot GHSA ID");
  if (!GHSA_ID.test(ghsa))
    throw new Error("Dependabot security_advisory must identify a GHSA.");
  const affected = advisory["vulnerabilities"];
  if (
    !Array.isArray(affected) ||
    !affected.some(
      (entry) =>
        isRecord(entry) &&
        isRecord(entry["package"]) &&
        entry["package"]["name"] === name &&
        entry["package"]["ecosystem"] === ecosystem &&
        entry["vulnerable_version_range"] === range,
    )
  )
    throw new Error(
      "Dependabot advisory does not cover the matched package and vulnerable range.",
    );
  const state = alert["state"];
  if (
    typeof state !== "string" ||
    !["open", "dismissed", "auto_dismissed", "fixed"].includes(state)
  )
    throw new Error(
      "Dependabot alert state must be open, dismissed, auto_dismissed or fixed.",
    );
  const updated =
    Date.parse(requiredText(alert["updated_at"], "Dependabot updated_at")) /
    1000;
  if (!Number.isFinite(updated) || updated < 0)
    throw new Error("Dependabot updated_at must be a valid timestamp.");
  const advisoryIds = new Set([ghsa]);
  const cve = text(advisory["cve_id"]);
  if (cve) advisoryIds.add(cve);
  const identifiers = advisory["identifiers"];
  if (Array.isArray(identifiers)) {
    for (const item of identifiers) {
      const value = isRecord(item) && text(item["value"]);
      if (!value) continue;
      if (
        (item["type"] === "GHSA" || /^GHSA-/iu.test(value)) &&
        value.toUpperCase() !== ghsa.toUpperCase()
      )
        throw new Error(
          "Dependabot advisory identifiers disagree on the GHSA.",
        );
      advisoryIds.add(value);
    }
  }
  return {
    title: requiredText(advisory["summary"], "Dependabot advisory summary"),
    description: text(advisory["description"]),
    severity,
    url,
    advisory_ids: [...advisoryIds],
    packages: [
      {
        name,
        ecosystem,
        manifest_path: path,
        vulnerable_version_range: range,
        fixed_versions: patch ? [patch.identifier] : [],
      },
    ],
    locations: path ? [{ path }] : [],
    source_updated_at: Math.floor(updated),
    source_data: structuredClone(alert),
  };
}

export function normalizeGitHubDependabotAlerts(
  input: unknown,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const alerts = selectedAlerts(input);
  const result: ExternalFindings = {
    read: alerts.length,
    findings: [],
    excluded: [],
  };
  const ids = new Set<string>();
  let sourceRepository: string | undefined;
  for (const [index, alert] of alerts.entries()) {
    const { repositoryUrl, sourceId, url } = identity(alert);
    if (sourceRepository !== undefined && sourceRepository !== repositoryUrl)
      throw new CodexSecurityError(
        "Select Dependabot alerts from only one GitHub host and repository.",
      );
    sourceRepository = repositoryUrl;
    if (ids.has(sourceId))
      throw new CodexSecurityError(
        `Duplicate source finding id ${JSON.stringify(sourceId)}. Select each Dependabot alert once.`,
      );
    ids.add(sourceId);
    const inputEvidence = evidence(alert, url);
    appendReaderFinding(result, index + 1, sourceId, () => {
      if (target === "cloud" && Buffer.byteLength(sourceId) > 512)
        throw new Error(
          "Source finding ID exceeds the Cloud limit of 512 UTF-8 bytes.",
        );
      return validateExternalEvidence(inputEvidence, target);
    });
  }
  return finishReaderSizeSelection(result);
}

import { CodexSecurityError } from "./errors.js";
import type { ExternalFindings } from "./external-findings.js";
import { validateExternalEvidence } from "./external-import-contract.js";
import { asRecord, isRecord } from "./record.js";
import {
  array,
  manifestPath,
  normalizeRecords,
  record,
  repositoryFilePath,
  requiredText,
  scannerJsonReader,
  scannerSeverity,
  stableId,
  strings,
  text,
} from "./scanner-import.js";

export const grypeReportFormat = "grype-scan/v1";

type NativeRecord = Record<string, unknown>;

function matchFields(value: unknown) {
  const match = record(value, "Grype match");
  return {
    match,
    vulnerability: record(match["vulnerability"], "Grype vulnerability"),
    artifact: record(match["artifact"], "Grype artifact"),
  };
}

// Grype ranks Negligible below Low; treat it as the informational floor.
function grypeSeverity(value: unknown) {
  const level = text(value)?.toLowerCase();
  return scannerSeverity(level === "negligible" ? "informational" : level);
}

function ecosystem(artifact: NativeRecord): string | null {
  const purl = text(artifact["purl"]);
  const fromPurl = purl
    ?.match(/^pkg:([a-z][a-z\d.+-]*)\//iu)?.[1]
    ?.toLowerCase();
  return fromPurl ?? text(artifact["language"]) ?? text(artifact["type"]);
}

function artifactPaths(artifact: NativeRecord): string[] {
  const paths = new Set<string>();
  for (const value of array(
    artifact["locations"] ?? [],
    "Grype artifact locations",
  )) {
    const path = text(record(value, "Grype location")["path"]);
    if (path) paths.add(path);
  }
  return [...paths].sort();
}

function advisoryIds(match: NativeRecord, primary: string): string[] {
  const related = array(
    match["relatedVulnerabilities"] ?? [],
    "Grype relatedVulnerabilities",
  ).flatMap((value) => {
    const id = text(record(value, "Grype related vulnerability")["id"]);
    return id ? [id] : [];
  });
  return [...new Set([primary, ...related])];
}

function advisoryUrl(vulnerability: NativeRecord): string | null {
  const url =
    text(vulnerability["dataSource"]) ?? strings(vulnerability["urls"])[0];
  return url && /^https?:\/\//iu.test(url) ? url : null;
}

function fixedVersions(vulnerability: NativeRecord): string[] {
  const fix = vulnerability["fix"];
  return strings(isRecord(fix) ? fix["versions"] : undefined);
}

/** Import native `grype -o json` SCA matches as one dependency finding each. Grype
 * records no source-control URL, so findings bind to the selected local checkout. */
export function normalizeGrypeFindings(input: unknown): ExternalFindings {
  const document = record(input, "Grype report");
  if (!Array.isArray(document["matches"]))
    throw new CodexSecurityError(
      "Expected a native `grype -o json` report with matches.",
    );
  const descriptor = asRecord(document["descriptor"]);
  const version = text(descriptor?.["version"]);
  const source = asRecord(document["source"]);
  const directory = source?.["type"] === "directory";
  return normalizeRecords(
    document["matches"],
    (value) => {
      const { match, vulnerability, artifact } = matchFields(value);
      const advisory = requiredText(
        vulnerability["id"],
        "Grype vulnerability id",
      );
      const name = requiredText(artifact["name"], "Grype artifact name");
      const paths = directory
        ? [
            ...new Set(
              artifactPaths(artifact)
                .map(repositoryFilePath)
                .filter((path) => path !== null),
            ),
          ]
        : [];
      const manifests = paths.filter((path) => manifestPath(path) !== null);
      return validateExternalEvidence(
        {
          title: `${advisory} in ${name}`,
          severity: grypeSeverity(vulnerability["severity"]),
          description: text(vulnerability["description"]),
          url: advisoryUrl(vulnerability),
          advisory_ids: advisoryIds(match, advisory),
          packages: [
            {
              name,
              ecosystem: ecosystem(artifact),
              installed_version: text(artifact["version"]),
              fixed_versions: fixedVersions(vulnerability),
              manifest_path: manifests.length === 1 ? manifests[0] : null,
            },
          ],
          locations: paths.map((path) => ({ path, line: null })),
          source_data: structuredClone({
            format: grypeReportFormat,
            ...(version ? { grype_version: version } : {}),
            ...(source ? { source } : {}),
            match,
          }),
        },
        "local",
      );
    },
    (value) => {
      const { vulnerability, artifact } = matchFields(value);
      return stableId("grype", [
        ecosystem(artifact),
        requiredText(vulnerability["id"], "Grype vulnerability id"),
        requiredText(artifact["name"], "Grype artifact name"),
        artifactPaths(artifact),
      ]);
    },
    "local",
    {
      report: {
        format: grypeReportFormat,
        ...(version ? { grype_version: version } : {}),
      },
    },
  );
}

export const readGrypeFindings = scannerJsonReader(normalizeGrypeFindings);

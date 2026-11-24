import { CodexSecurityError } from "./errors.js";
import type { ExternalFindings } from "./external-findings.js";
import { validateExternalEvidence } from "./external-import-contract.js";
import { asRecord } from "./record.js";
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
  const vulnerability = record(match["vulnerability"], "Grype vulnerability");
  const artifact = record(match["artifact"], "Grype artifact");
  const advisory = requiredText(vulnerability["id"], "Grype vulnerability id");
  const name = requiredText(artifact["name"], "Grype artifact name");
  return { match, vulnerability, artifact, advisory, name };
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

function artifactPaths(artifact: NativeRecord, directory: boolean): string[] {
  const paths = new Set<string>();
  for (const value of array(
    artifact["locations"] ?? [],
    "Grype artifact locations",
  )) {
    const location = record(value, "Grype location");
    const raw = text(location["path"]);
    // Directory scans can pair an absolute resolved path with a relative accessPath.
    const path = directory
      ? (repositoryFilePath(raw) ??
        repositoryFilePath(location["accessPath"]) ??
        raw)
      : raw;
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
  return (
    [text(vulnerability["dataSource"]), ...strings(vulnerability["urls"])].find(
      (url) => url && /^https?:\/\//iu.test(url),
    ) ?? null
  );
}

/** Import native `grype -o json` SCA matches as one dependency finding each. Grype
 * records no source-control URL, so findings bind to the selected local checkout. */
export function normalizeGrypeFindings(input: unknown): ExternalFindings {
  const document = record(input, "Grype report");
  if (!Array.isArray(document["matches"]))
    throw new CodexSecurityError(
      "Expected a native `grype -o json` report with matches.",
    );
  const version = text(asRecord(document["descriptor"])?.["version"]);
  const report = {
    format: grypeReportFormat,
    ...(version && { grype_version: version }),
  };
  const source = asRecord(document["source"]);
  const directory = source?.["type"] === "directory";
  // Grype embeds whole image manifests, configs and layer lists in the target.
  // Keep those once in the report and copy only source identifiers to each finding.
  const target = asRecord(source?.["target"]);
  const { config, manifest, layers, ...identifiers } = target ?? {};
  const findingSource = target ? { ...source, target: identifiers } : source;
  return normalizeRecords(
    document["matches"],
    (value) => {
      const { match, vulnerability, artifact, advisory, name } =
        matchFields(value);
      const paths = directory
        ? artifactPaths(artifact, directory).filter(
            (path) => repositoryFilePath(path) !== null,
          )
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
              fixed_versions: strings(
                asRecord(vulnerability["fix"])?.["versions"],
              ),
              manifest_path: manifests.length === 1 ? manifests[0] : null,
            },
          ],
          locations: paths.map((path) => ({ path, line: null })),
          source_data: structuredClone({
            ...report,
            ...(findingSource && { source: findingSource }),
            match,
          }),
        },
        "local",
      );
    },
    (value) => {
      const { artifact, advisory, name } = matchFields(value);
      return stableId("grype", [
        ecosystem(artifact),
        advisory,
        name,
        artifactPaths(artifact, directory),
      ]);
    },
    "local",
    {
      report: { ...report, ...(source && { source: structuredClone(source) }) },
    },
  );
}

export const readGrypeFindings = scannerJsonReader(normalizeGrypeFindings);

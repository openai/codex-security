import type { ExternalImportTarget } from "./external-import-contract.js";
import Papa from "papaparse";
import { text } from "./scanner-import.js";
import { validateExternalEvidence } from "./external-import-contract.js";
import type { ExternalFindingEvidence } from "./external-import-models.js";
import type { VendorFinding } from "./wiz-findings.js";

const profile = "wiz-code-vulnerability-csv";
const requiredHeaders = [
  "ID",
  "Name",
  "DetailedName",
  "AssetID",
  "WizURL",
  "CloudPlatform",
  "CloudProviderURL",
];

/** Recognize the supported Wiz vulnerability CSV columns, retaining every cell. */
export function readWizCsv(
  contents: string,
): Record<string, string>[] | undefined {
  // JSONL can retain CSV column names in its evidence. Recognize the first
  // JSON value before interpreting all of its quoted records as CSV.
  try {
    JSON.parse(contents.trimStart().split(/\r?\n/u, 1)[0]!);
    return undefined;
  } catch {
    // A CSV header is not a JSON value.
  }
  // Read arrays so duplicate headers cannot be silently renamed, and unknown
  // columns (including object-prototype names) remain ordinary source data.
  const parsed = Papa.parse<string[]>(contents, {
    delimiter: ",",
    skipEmptyLines: true,
  });
  const [headers, ...rows] = parsed.data;
  if (!headers || !requiredHeaders.every((name) => headers.includes(name)))
    return undefined;
  if (parsed.errors.length)
    throw new Error(`Invalid Wiz CSV: ${parsed.errors[0]!.message}`);
  if (new Set(headers).size !== headers.length)
    throw new Error("Wiz CSV contains duplicate column names.");
  return rows.map((cells, index) => {
    if (cells.length !== headers.length)
      throw new Error(`Wiz CSV row ${index + 2} has the wrong column count.`);
    return Object.fromEntries(headers.map((name, i) => [name, cells[i]!]));
  });
}

function repositoryUrl(row: Record<string, unknown>): string {
  if (text(row["CloudPlatform"])?.trim().toLowerCase() !== "github")
    throw new Error(
      "Wiz CSV imports require GitHub repository-branch findings. Workload and other provider CSV reports need an explicit normalized JSONL mapping.",
    );
  const value = text(row["CloudProviderURL"]);
  const url = value ? new URL(value) : undefined;
  const origin = value?.match(/^(https?:\/\/[^/?#]+)/iu)?.[1];
  const path = url?.pathname.match(/^\/([^/]+)\/([^/]+)\/tree\/(.+)$/u);
  if (
    !url ||
    !origin ||
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    !path
  )
    throw new Error("Wiz CSV finding requires a GitHub repository-branch URL.");
  // URL.origin removes explicit default ports, which the Cloud contract keeps.
  return `${origin}/${path[1]}/${path[2]}`;
}

/** Keep repository binding available after a normalized JSONL round trip. */
export function wizCsvRepositoryUrl(
  evidence: ExternalFindingEvidence,
): string | undefined {
  const source = evidence.source_data;
  if (source?.["format"] !== profile) return undefined;
  const row = source["row"];
  if (!row || typeof row !== "object" || Array.isArray(row))
    throw new Error("Wiz CSV source evidence is missing its original row.");
  return repositoryUrl(row as Record<string, unknown>);
}

export function wizCsvFinding(
  row: Record<string, unknown>,
  sourceFindingId: string,
  target: ExternalImportTarget = "cloud",
): VendorFinding {
  repositoryUrl(row);
  const name = text(row["Name"]);
  const packageName = text(row["DetailedName"]);
  if (!name || !packageName || !text(row["AssetID"]))
    throw new Error(
      "Wiz CSV finding requires Name, DetailedName, and AssetID.",
    );
  const path = text(text(row["LocationPath"])?.replace(/^\/+/, ""));
  const fixedVersion = text(row["FixedVersion"]);
  const severity = (
    text(row["Severity"]) ??
    text(row["VendorSeverity"]) ??
    text(row["CVSSSeverity"])
  )
    ?.trim()
    .toLowerCase();
  return {
    source_finding_id: sourceFindingId,
    evidence: validateExternalEvidence(
      {
        title: [packageName, text(row["Version"]), name]
          .filter(Boolean)
          .join(" "),
        description: text(row["Description"]),
        severity: severity === "none" ? "unknown" : severity,
        url: text(row["WizURL"]),
        advisory_ids: [name],
        packages: [
          {
            name: packageName,
            ecosystem: null,
            installed_version: text(row["Version"]),
            manifest_path: path,
            fixed_versions: fixedVersion ? [fixedVersion] : [],
          },
        ],
        locations: path ? [{ path }] : [],
        // A tree URL does not distinguish a slash-containing ref from a directory.
        branch: null,
        code_revision: null,
        source_scan_id: null,
        source_updated_at: null,
        image_digests: [],
        source_data: { format: profile, row },
      },
      target,
    ),
  };
}

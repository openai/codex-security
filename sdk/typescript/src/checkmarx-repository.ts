import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import type { Provider } from "./external-import-models.js";
import { isRecord } from "./record.js";
import { requiredText } from "./scanner-import.js";
import { checkmarxOneId } from "./checkmarx-one.js";
import { checkmarxXmlId } from "./checkmarx-xml.js";
import {
  declaredScannerRepositoryUrl,
  repositoryScopeValidator,
} from "./scanner-repository-url.js";

const nativeId = /^checkmarx-(?:one|cxsast):[a-f0-9]{64}$/u;

function checkmarxFormat(value: unknown) {
  return value === "cxsast-xml" || value === "checkmarx-one-json";
}

function retainedFormat({ source_finding_id: id, evidence }: ExternalFinding) {
  const data = evidence.source_data;
  const format = data?.["format"];
  if (checkmarxFormat(format)) return format;
  if (!data || (!("sourceRepositoryUrl" in data) && !nativeId.test(id))) return;
  const row = data["row"];
  if (isRecord(row) && row["type"] === "sast" && "similarityId" in row)
    return "checkmarx-one-json";
  const path = data["path"];
  if ("projectId" in data && isRecord(path) && "SimilarityId" in path)
    return "cxsast-xml";
}

/** Bind explicitly retained URLs even when a projection cannot establish the provider. */
export function projectedCheckmarxRepositoryUrl(
  finding: ExternalFinding,
  target: ExternalImportTarget,
) {
  if (!nativeId.test(finding.source_finding_id) && !retainedFormat(finding))
    return;
  const source = finding.evidence.source_data?.["sourceRepositoryUrl"];
  return typeof source === "string"
    ? declaredScannerRepositoryUrl(source, "Checkmarx", target)
    : (finding.evidence.details?.repository?.url ?? undefined);
}

function requireCheckmarx(provider: Provider) {
  if (provider !== "checkmarx")
    throw new Error(
      "Retained Checkmarx evidence requires the checkmarx provider.",
    );
}

/** The native reader also retains scope when a report has no accepted rows. */
export function checkmarxReportRepository(
  provider: Provider,
  findings: ExternalFindings["findings"],
  report: ExternalFindings["report"],
  target: ExternalImportTarget,
  historical = false,
): string | undefined {
  if (!report) return;
  const format = report["format"];
  if (!checkmarxFormat(format) || (historical && provider !== "checkmarx")) {
    const source = report["sourceRepositoryUrl"];
    if (
      provider === "checkmarx" &&
      "sourceRepositoryUrl" in report &&
      "scanId" in report
    )
      throw new Error("Expected the original Checkmarx report format.");
    if (
      typeof source === "string" &&
      (provider === "checkmarx" || checkmarxFormat(format))
    )
      return declaredScannerRepositoryUrl(source, "Checkmarx", target);
    return;
  }
  requireCheckmarx(provider);
  const scan = requiredText(report["scanId"], "Checkmarx report scan ID");
  const project =
    format === "cxsast-xml"
      ? requiredText(report["projectId"], "CxSAST report project ID")
      : undefined;
  for (const { evidence } of findings) {
    const data = evidence.source_data;
    if (
      data?.["format"] !== format ||
      evidence.source_scan_id !== scan ||
      (project !== undefined && data["projectId"] !== project)
    )
      throw new Error(
        "Checkmarx finding does not match the retained report format, scan or project.",
      );
  }
  return declaredScannerRepositoryUrl(
    report["sourceRepositoryUrl"],
    "Checkmarx",
    target,
  );
}

export const checkmarxReportRepositories = repositoryScopeValidator(
  {
    provider: "checkmarx",
    label: "Checkmarx",
    scope: "product, project and scan",
  },
  (provider, finding, target) => {
    const { source_finding_id: id, evidence } = finding;
    const data = evidence.source_data;
    const format = retainedFormat(finding);
    if (!format || !data) {
      if (provider === "checkmarx" && nativeId.test(id))
        throw new Error(
          "Checkmarx source finding ID requires its original evidence.",
        );
      const url =
        provider === "checkmarx" && data && "sourceRepositoryUrl" in data
          ? declaredScannerRepositoryUrl(
              data["sourceRepositoryUrl"],
              "Checkmarx",
              target,
            )
          : projectedCheckmarxRepositoryUrl(finding, target);
      return url ? { url } : undefined;
    }
    requireCheckmarx(provider);
    const scan = requiredText(
      evidence.source_scan_id,
      "Checkmarx source scan ID",
    );
    const expected =
      format === "cxsast-xml"
        ? checkmarxXmlId(data, scan)
        : checkmarxOneId(data["row"]);
    if (id !== expected)
      throw new Error(
        "Checkmarx source finding ID does not match the retained occurrence.",
      );
    return {
      url: declaredScannerRepositoryUrl(
        data["sourceRepositoryUrl"],
        "Checkmarx",
        target,
      ),
      scope: JSON.stringify([
        format,
        format === "cxsast-xml" ? data["projectId"] : null,
        scan,
      ]),
    };
  },
);

import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import type { Provider } from "./external-import-models.js";
import { isRecord } from "./record.js";
import { requiredText } from "./scanner-import.js";
import { checkmarxOneId } from "./checkmarx-one.js";
import {
  checkmarxResultViewer,
  checkmarxXmlId,
  checkmarxXmlInstance,
  checkmarxXmlScope,
} from "./checkmarx-xml.js";
import {
  declaredScannerRepositoryUrl,
  repositoryScopeValidator,
} from "./scanner-repository-url.js";

const nativeId = /^checkmarx-(?:one|cxsast):[a-f0-9]{64}$/u;

function checkmarxFormat(value: unknown) {
  return value === "cxsast-xml" || value === "checkmarx-one-json";
}

function scanKey(value: unknown, xml: boolean) {
  const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/iu;
  return !xml && typeof value === "string" && uuid.test(value)
    ? value.toLowerCase()
    : value;
}

/** A native payload can verify its occurrence ID. A projection can still identify its source. */
function checkmarxSource({ source_finding_id: id, evidence }: ExternalFinding) {
  const data = evidence.source_data;
  const format = data?.["format"];
  if (checkmarxFormat(format)) return format;
  const scanner = evidence.details?.scanner_origin;
  const projected =
    nativeId.test(id) ||
    scanner === "CxSAST" ||
    scanner === "Checkmarx One SAST" ||
    Boolean(checkmarxResultViewer(data));
  if (data && (projected || "sourceRepositoryUrl" in data)) {
    const row = data["row"];
    if (isRecord(row) && row["type"] === "sast" && "similarityId" in row)
      return "checkmarx-one-json";
    const path = data["path"];
    if ("projectId" in data && isRecord(path) && "SimilarityId" in path)
      return "cxsast-xml";
  }
  if (projected) return "projection";
}

/** Bind explicitly retained URLs even when a projection cannot establish the provider. */
export function projectedCheckmarxRepositoryUrl(
  finding: ExternalFinding,
  target: ExternalImportTarget,
) {
  if (!checkmarxSource(finding)) return;
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

/** Compare each explicit claim, including selections that omit the original report. */
function checkBatchScope(
  findings: ExternalFindings["findings"],
  report: ExternalFindings["report"],
) {
  let project = report?.["projectId"];
  let scanner: unknown;
  let instance: string | undefined;
  function agree(current: unknown, value: unknown) {
    if (current != null && value != null && current !== value)
      throw new Error(
        report
          ? "Checkmarx finding does not match the retained report format, scan or project."
          : "Checkmarx occurrences must belong to the same product, project and scan.",
      );
    return current ?? value;
  }
  function checkFormat(format: unknown) {
    if (checkmarxFormat(format))
      scanner = agree(
        scanner,
        format === "cxsast-xml" ? "CxSAST" : "Checkmarx One SAST",
      );
  }
  checkFormat(report?.["format"]);
  for (const finding of findings) {
    checkFormat(checkmarxSource(finding));
    const { evidence } = finding;
    project = agree(project, evidence.source_data?.["projectId"]);
    scanner = agree(scanner, evidence.details?.scanner_origin);
  }
  // A projected row can retain a viewer link even when it omits the product and path.
  const sources = [
    report,
    ...findings.map(({ evidence }) => evidence.source_data),
  ];
  const xml = scanner === "CxSAST" || sources.some(checkmarxResultViewer);
  if (xml) agree(scanner, "CxSAST");
  let scan = scanKey(report?.["scanId"], xml);
  for (const { evidence } of findings)
    scan = agree(scan, scanKey(evidence.source_scan_id, xml));

  for (const data of sources) {
    if (!data) continue;
    if (!xml) {
      // A retained deployment URL distinguishes this claim from opaque SDK metadata.
      const value = data["instance"];
      const protocol = typeof value === "string" && URL.parse(value)?.protocol;
      if (protocol !== "http:" && protocol !== "https:") continue;
    }
    const scope = checkmarxXmlScope(data);
    instance = checkmarxXmlInstance(instance, scope.instance);
    scan = agree(scan, scope.scanId);
    project = agree(project, scope.projectId);
  }
}

/** The native reader also retains scope when a report has no accepted rows. */
export function checkmarxReportRepository(
  provider: Provider,
  findings: ExternalFindings["findings"],
  report: ExternalFindings["report"],
  target: ExternalImportTarget,
  historical = false,
): string | undefined {
  if (provider === "checkmarx") checkBatchScope(findings, report);
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
      (provider === "checkmarx" ||
        checkmarxFormat(format) ||
        (format == null && findings.some(checkmarxSource)))
    )
      return declaredScannerRepositoryUrl(source, "Checkmarx", target);
    return;
  }
  requireCheckmarx(provider);
  const xml = format === "cxsast-xml";
  const scan = scanKey(
    requiredText(report["scanId"], "Checkmarx report scan ID"),
    xml,
  );
  const project = xml
    ? requiredText(report["projectId"], "CxSAST report project ID")
    : undefined;
  for (const finding of findings) {
    const { evidence } = finding;
    const data = evidence.source_data;
    const rowFormat =
      data && "format" in data ? data["format"] : checkmarxSource(finding);
    if (
      rowFormat !== format ||
      scanKey(evidence.source_scan_id, xml) !== scan ||
      (project !== undefined && data?.["projectId"] !== project)
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
    const format = checkmarxSource(finding);
    if (!checkmarxFormat(format) || !data) {
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
        scanKey(scan, format === "cxsast-xml"),
      ]),
    };
  },
);

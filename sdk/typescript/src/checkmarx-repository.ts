import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import type { Provider } from "./external-import-models.js";
import { isRecord } from "./record.js";
import { requiredText, text } from "./scanner-import.js";
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
function checkmarxSource(
  { source_finding_id: id, evidence }: ExternalFinding,
  provider?: Provider,
) {
  const data = evidence.source_data;
  const format = data?.["format"];
  if (checkmarxFormat(format)) return format;
  const scanner = evidence.details?.scanner_origin;
  const projected =
    nativeId.test(id) ||
    scanner === "CxSAST" ||
    scanner === "Checkmarx One SAST" ||
    Boolean(checkmarxResultViewer(data));
  if (
    data &&
    (provider === "checkmarx" || projected || "sourceRepositoryUrl" in data)
  ) {
    const row = data["row"];
    if (isRecord(row) && row["type"] === "sast" && "similarityId" in row)
      return "checkmarx-one-json";
    const path = data["path"];
    if ("projectId" in data && isRecord(path) && "SimilarityId" in path)
      return "cxsast-xml";
  }
  if (projected) return "projection";
}

const mismatch =
  "Checkmarx finding does not match the retained report format, scan or project.";

/** Compare the claims present across the whole batch, including projected SDK rows. */
function checkBatchScope(
  findings: readonly ExternalFinding[],
  formats: Iterable<string>,
  report: ExternalFindings["report"],
) {
  function single(values: unknown[]) {
    const claims = new Set(values.filter((value) => value != null));
    if (claims.size > 1)
      throw new Error(
        report
          ? mismatch
          : "Checkmarx occurrences must belong to the same product, project and scan.",
      );
    return claims.values().next().value;
  }
  const evidence = findings.map((finding) => finding.evidence);
  const sources = [report, ...evidence.map((row) => row.source_data)].filter(
    isRecord,
  );
  const scanner = single([
    ...[report?.["format"], ...formats]
      .filter(checkmarxFormat)
      .map((format) =>
        format === "cxsast-xml" ? "CxSAST" : "Checkmarx One SAST",
      ),
    ...evidence.map((row) => row.details?.scanner_origin),
    sources.some(checkmarxResultViewer) ? "CxSAST" : undefined,
  ]);
  const xml = scanner === "CxSAST";
  if (xml || sources.some((data) => text(data["teamFullPathOnReportDate"]))) {
    single(sources.map((data) => text(data["projectName"])));
    single(
      sources.map((data) =>
        text(data["teamFullPathOnReportDate"])
          ?.replaceAll("\\", "/")
          .replace(/^\/+|\/+$/gu, "")
          .replace(/[A-Z]/gu, (c) => c.toLowerCase()),
      ),
    );
  }
  const scopes = sources
    .filter((data) => {
      // An explicit deployment URL distinguishes an instance from opaque SDK metadata.
      const instance = data["instance"];
      return (
        xml ||
        (typeof instance === "string" &&
          /^https?:$/u.test(URL.parse(instance)?.protocol ?? ""))
      );
    })
    .map((data) => checkmarxXmlScope(data));
  let instance: string | undefined;
  for (const scope of scopes)
    instance = checkmarxXmlInstance(instance, scope.instance);
  single([
    ...sources.map((data) => data["projectId"]),
    ...scopes.map((scope) => scope.projectId),
  ]);
  single([
    scanKey(report?.["scanId"], xml),
    ...evidence.map((row) => scanKey(row.source_scan_id, xml)),
    ...scopes.map((scope) => scope.scanId),
  ]);
}

/** Identify report and row provenance once for both import destinations. */
export function checkmarxSelection(
  provider: Provider,
  findings: ExternalFindings["findings"],
  report: ExternalFindings["report"],
  target: ExternalImportTarget,
  historical = false,
) {
  const selected = provider === "checkmarx";
  const replay = historical && !selected;
  const format = report?.["format"];
  const nativeReport = checkmarxFormat(format);
  const formats = new Map<ExternalFinding, string>();
  for (const finding of findings) {
    const kind = checkmarxSource(finding, provider);
    if (kind) formats.set(finding, kind);
  }
  const validateUrl = (value: unknown) =>
    declaredScannerRepositoryUrl(value, "Checkmarx", target);
  function requireProvider() {
    if (!selected)
      throw new Error(
        "Retained Checkmarx evidence requires the checkmarx provider.",
      );
  }
  if (selected) checkBatchScope(findings, formats.values(), report);
  let reportUrl: string | undefined;
  if (report && nativeReport && !replay) {
    requireProvider();
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
      if (
        (data && "format" in data ? data["format"] : formats.get(finding)) !==
          format ||
        scanKey(evidence.source_scan_id, xml) !== scan ||
        (xml && data?.["projectId"] !== project)
      )
        throw new Error(mismatch);
    }
    reportUrl = validateUrl(report["sourceRepositoryUrl"]);
  } else if (report) {
    if (selected && "sourceRepositoryUrl" in report && "scanId" in report)
      throw new Error("Expected the original Checkmarx report format.");
    if (
      typeof report["sourceRepositoryUrl"] === "string" &&
      (selected || nativeReport || formats.size)
    )
      reportUrl = validateUrl(report["sourceRepositoryUrl"]);
  }
  const marked = new Set(nativeReport || reportUrl ? findings : formats.keys());
  function projectedRepository({ evidence }: ExternalFinding) {
    const source = evidence.source_data?.["sourceRepositoryUrl"];
    const url =
      typeof source === "string"
        ? validateUrl(source)
        : evidence.details?.repository?.url;
    return url ? { url } : undefined;
  }
  const validateRows = repositoryScopeValidator(
    {
      provider: "checkmarx",
      label: "Checkmarx",
      scope: "product, project and scan",
    },
    (_, finding) => {
      const { source_finding_id: id, evidence } = finding;
      const data = evidence.source_data;
      const kind = formats.get(finding);
      if (checkmarxFormat(kind) && data) {
        requireProvider();
        const scan = requiredText(
          evidence.source_scan_id,
          "Checkmarx source scan ID",
        );
        const expected =
          kind === "cxsast-xml"
            ? checkmarxXmlId(data, scan)
            : checkmarxOneId(data["row"]);
        if (id !== expected)
          throw new Error(
            "Checkmarx source finding ID does not match the retained occurrence.",
          );
        return { url: validateUrl(data["sourceRepositoryUrl"]), scope: kind };
      }
      if (selected && nativeId.test(id))
        throw new Error(
          "Checkmarx source finding ID requires its original evidence.",
        );
      if (selected && data && "sourceRepositoryUrl" in data)
        return { url: validateUrl(data["sourceRepositoryUrl"]) };
      return kind ? projectedRepository(finding) : undefined;
    },
  );
  return {
    reportUrl,
    projections: selected ? new Set<ExternalFinding>() : marked,
    repositories(sameRepositories?: (urls: Iterable<string>) => boolean) {
      const rows =
        replay || (!selected && !formats.size)
          ? undefined
          : validateRows(provider, findings, target, sameRepositories);
      return (finding: ExternalFinding) =>
        rows?.get(finding.source_finding_id) ??
        (marked.has(finding) ? projectedRepository(finding) : undefined);
    },
  };
}

import type { ExternalFindings } from "./external-findings.js";
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

function checkmarxFormat(value: unknown) {
  return value === "cxsast-xml" || value === "checkmarx-one-json";
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
): string | undefined {
  if (!report) return;
  const format = report["format"];
  if (!checkmarxFormat(format)) {
    if (
      provider === "checkmarx" &&
      "sourceRepositoryUrl" in report &&
      "scanId" in report
    )
      throw new Error("Expected the original Checkmarx report format.");
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
  { provider: "checkmarx", label: "Checkmarx", scope: "product and project" },
  (provider, { source_finding_id: id, evidence }, target) => {
    const data = evidence.source_data;
    if (!data || !checkmarxFormat(data["format"])) {
      const native = /^checkmarx-(one|cxsast):[a-f0-9]{64}$/u.exec(id);
      const row = data?.["row"];
      const path = data?.["path"];
      if (
        native &&
        (native[1] === "one"
          ? isRecord(row) && row["type"] === "sast" && "similarityId" in row
          : isRecord(path) &&
            "SimilarityId" in path &&
            data?.["projectId"] !== undefined)
      )
        requireCheckmarx(provider);
      if (native && provider === "checkmarx")
        throw new Error(
          "Checkmarx source finding ID requires its original evidence.",
        );
      return;
    }
    requireCheckmarx(provider);
    const format = data["format"];
    const expected =
      format === "cxsast-xml"
        ? checkmarxXmlId(data)
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
      scope:
        format === "cxsast-xml" ? `${format}/${data["projectId"]}` : format,
    };
  },
);

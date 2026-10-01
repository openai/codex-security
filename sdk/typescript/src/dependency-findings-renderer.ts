import type { JsonObject } from "./config.js";
import type {
  DependencyAssessmentDetails,
  DependencyFindingAssessment,
  DependencyReport,
  DependencyReportDetails,
  DependencyReportList,
  ImportedDependencyFinding,
} from "./dependency-findings.js";

export type DependencyFindingsCommand = "import" | "list" | "show" | "assess";

type RendererOptions = {
  columns?: number;
  color?: boolean;
  offset?: number;
  limit?: number;
  verdict?: string;
};

const VERDICTS = {
  affects_application: "Affects application",
  not_applicable: "Not applicable",
  inconclusive: "Inconclusive",
  pending: "Not assessed",
};

/** Display the vendor severity without its export enum prefix. */
export function dependencySeverityLabel(severity: string | null): string {
  const value = severity?.replace(/^FINDING_LEVEL_/, "").toLowerCase();
  return value ? value[0]!.toUpperCase() + value.slice(1) : "Unspecified";
}

/** Render saved scanner claims and application assessments for terminal readers. */
export function renderDependencyFindings(
  result: JsonObject,
  command: DependencyFindingsCommand,
  options: RendererOptions = {},
): string {
  const width = Math.max(48, Math.min(options.columns ?? 96, 120));
  const paint = (value: string, code: number): string =>
    options.color === false ? value : `\u001B[${code}m${value}\u001B[0m`;
  const strong = (value: string): string => paint(value, 1);
  const lines = ["", `  ${strong("CODEX SECURITY / DEPENDENCY FINDINGS")}`, ""];
  const wrap = (value: string, indent = 2): void => {
    let line = "";
    for (const word of value.split(/\s+/)) {
      if (line && line.length + word.length + 1 > width - indent) {
        lines.push(`${" ".repeat(indent)}${line}`);
        line = word;
      } else {
        line = line ? `${line} ${word}` : word;
      }
    }
    if (line) lines.push(`${" ".repeat(indent)}${line}`);
  };
  const next = (value: string): void => {
    lines.push("", `  ${strong("Next")}`, `    ${value}`);
  };
  const reportDetails = (report: DependencyReport): void => {
    wrap(report.reportName);
    wrap(
      `${report.vendor} · ${report.findingCount.toLocaleString("en-US")} imported findings`,
    );
    wrap(`Repository: ${report.targetPath}`);
    wrap(`Imported revision: ${report.targetRevision}`);
    lines.push(`  Report ID: ${report.id}`);
    if (report.warnings.length) {
      lines.push("", `  ${strong("Import notes")}`);
      for (const warning of report.warnings) wrap(`• ${warning}`, 4);
    }
  };
  const assessmentDetails = (assessment: DependencyFindingAssessment): void => {
    wrap(assessment.summary, 4);
    if (assessment.applicability !== assessment.summary) {
      wrap(assessment.applicability, 4);
    }
    for (const unknown of assessment.unknowns) wrap(`Unknown: ${unknown}`, 4);
    for (const limitation of assessment.limitations ?? []) {
      wrap(`Limitation: ${limitation}`, 4);
    }
  };
  const finding = (
    entry: ImportedDependencyFinding,
    assessment = entry.assessment,
  ): void => {
    const severity = dependencySeverityLabel(entry.originalSeverity);
    const verdict = VERDICTS[assessment?.verdict ?? "pending"];
    const packageName = String(entry.package["name"] ?? "Unknown package");
    const version = String(entry.package["version"] ?? "Unknown version");
    const ecosystem = entry.package["ecosystem"];
    lines.push("");
    wrap(entry.title);
    if (width >= 80) {
      lines.push(
        `    ${strong("SCANNER SEVERITY".padEnd(26))} ${strong("APPLICATION IMPACT")}`,
        `    ${severity.padEnd(26)} ${verdict}`,
      );
    } else {
      wrap(`Scanner severity: ${severity}`, 4);
      wrap(`Application impact: ${verdict}`, 4);
    }
    wrap(
      `Package: ${packageName}@${version}${ecosystem ? ` (${ecosystem})` : ""}`,
      4,
    );
    lines.push(`    Finding ID: ${entry.id}`);
    for (const warning of entry.inputWarnings)
      wrap(`Import note: ${warning}`, 4);
    if (assessment) {
      wrap(
        `Assessed version: ${assessment.packageVersion ?? "Unverified"}${assessment.versionBasis ? ` (${assessment.versionBasis})` : ""} · revision ${assessment.targetRevision}`,
        4,
      );
      if (command === "assess") assessmentDetails(assessment);
      else wrap(assessment.summary, 4);
    }
  };

  if (command === "list") {
    const { reports, nextOffset } = result as unknown as DependencyReportList;
    if (reports.length === 0) {
      wrap(
        (options.offset ?? 0) > 0
          ? "No more imported reports."
          : "No imported reports found.",
      );
    }
    for (const report of reports) {
      wrap(report.reportName);
      wrap(
        `${report.vendor} · ${report.findingCount.toLocaleString("en-US")} findings · ${report.createdAt.slice(0, 10)}`,
      );
      wrap(`Repository: ${report.targetPath}`);
      lines.push(`  Report ID: ${report.id}`, "");
    }
    if (nextOffset !== null) {
      wrap(
        `More reports available. Repeat this list command with --offset ${nextOffset}.`,
      );
    }
    if (reports.length) {
      next("codex-security dependency-findings show REPORT_ID");
    } else if ((options.offset ?? 0) === 0) {
      next(
        "codex-security dependency-findings import REPORT_FILE --vendor VENDOR",
      );
    }
  } else if (command === "import") {
    const report = result["report"] as unknown as DependencyReport;
    reportDetails(report);
    lines.push("");
    wrap("Imported successfully. Importing does not start an assessment.");
    next(`codex-security dependency-findings show ${report.id}`);
  } else if (command === "show") {
    const { report, findings, total, nextOffset } =
      result as unknown as DependencyReportDetails;
    reportDetails(report);
    lines.push("");
    if (findings.length) {
      const offset = options.offset ?? 0;
      wrap(
        `Showing ${offset + 1}–${offset + findings.length} of ${total.toLocaleString("en-US")} findings${options.verdict ? ` (${VERDICTS[options.verdict as keyof typeof VERDICTS]})` : ""}.`,
      );
      for (const entry of findings) finding(entry);
    } else {
      wrap("No findings match this page or filter.");
    }
    if (nextOffset !== null) {
      const filters = `${options.limit === undefined ? "" : ` --limit ${options.limit}`}${options.verdict === undefined ? "" : ` --verdict ${options.verdict}`}`;
      lines.push(
        "",
        "  Next page:",
        `    codex-security dependency-findings show ${report.id} --offset ${nextOffset}${filters}`,
      );
    }
    if (total > 0)
      next(`codex-security dependency-findings assess ${report.id}`);
  } else {
    const { report, findings, results, assessment } =
      result as unknown as DependencyAssessmentDetails;
    reportDetails(report);
    lines.push(
      "",
      `  ${strong(assessment.state === "complete" ? "Assessment complete" : "Assessment pending")}`,
    );
    lines.push(`  Assessment ID: ${assessment.id}`);
    const counts = {
      affects_application: 0,
      not_applicable: 0,
      inconclusive: 0,
    };
    for (const entry of results ?? []) counts[entry.verdict] += 1;
    if (results?.length) {
      wrap(
        Object.entries(counts)
          .map(
            ([verdict, count]) =>
              `${count} ${VERDICTS[verdict as keyof typeof counts].toLowerCase()}`,
          )
          .join(" · "),
      );
    }
    const assessments = new Map(
      results?.map((entry) => [entry.findingId, entry]),
    );
    for (const entry of findings)
      finding(entry, assessments.get(entry.id) ?? null);
    next(`codex-security dependency-findings show ${report.id}`);
    wrap("Add --format json to inspect the complete saved evidence.");
  }
  lines.push("");
  return lines.join("\n");
}

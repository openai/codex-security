import { basename, relative } from "node:path";
import type { JsonObject } from "./config.js";

export type HistoryCommand =
  | "list"
  | "show"
  | "findings"
  | "compare"
  | "match-all";
type RendererOptions = {
  columns?: number;
  color?: boolean;
  now?: number;
  repository?: string;
  scanRoot?: string;
  showLinkedFindings?: boolean;
};

const STALE_SCAN_MILLISECONDS = 24 * 60 * 60 * 1_000;

const STATUS_STYLES: Record<string, { color: number; icon: string }> = {
  resolved: { color: 32, icon: "✓" },
  reopened: { color: 31, icon: "↻" },
  new: { color: 31, icon: "+" },
  persisting: { color: 33, icon: "●" },
  not_rescanned: { color: 36, icon: "○" },
  unknown: { color: 35, icon: "?" },
};

const SEVERITY_COLORS: Record<string, number> = {
  CRITICAL: 31,
  HIGH: 31,
  MEDIUM: 33,
  LOW: 36,
  INFORMATIONAL: 37,
};

const KNOWN_SINCE_DATE = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "numeric",
  year: "numeric",
  timeZone: "UTC",
});

function clean(value: unknown): string {
  return String(value)
    .replace(/\u001B\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, " ");
}

function findingSeverity(finding: JsonObject): string {
  const severity = finding["severity"];
  return clean(
    typeof severity === "string" ? severity : (severity as JsonObject)["level"],
  ).toUpperCase();
}

export function renderScanHistory(
  result: JsonObject,
  command: HistoryCommand,
  options: RendererOptions = {},
): string {
  const color = options.color ?? true;
  const width = Math.max(48, Math.min(options.columns ?? 96, 120));
  const paint = (value: string, code: number): string =>
    color ? `\u001B[${code}m${value}\u001B[0m` : value;
  const dim = (value: string): string => paint(value, 90);
  const strong = (value: string): string => paint(value, 1);
  const accent = (value: string): string => paint(value, 36);
  const labels: Record<HistoryCommand, string> = {
    list: "SCAN HISTORY",
    show: "SCAN DETAILS",
    findings: "REPOSITORY FINDINGS",
    compare: "SCAN COMPARISON",
    "match-all": "MATCH RESULTS",
  };
  const lines = [
    "",
    `  ${accent("◆")} ${strong("CODEX SECURITY")}  ${accent("/")}  ${strong(labels[command])}`,
    `  ${accent("━".repeat(width - 4))}`,
  ];

  const wrap = (value: string, indent: number, prefix?: string): void => {
    const available = width - indent - 2;
    let line = "";
    let first = true;
    for (const word of clean(value).split(/\s+/)) {
      if (line.length > 0 && line.length + word.length + 1 > available) {
        lines.push(`${first && prefix ? prefix : " ".repeat(indent)}${line}`);
        first = false;
        line = word;
      } else {
        line = line.length > 0 ? `${line} ${word}` : word;
      }
    }
    if (line.length > 0) {
      lines.push(`${first && prefix ? prefix : " ".repeat(indent)}${line}`);
    }
  };

  const finding = (entry: JsonObject, includeReason = true): void => {
    const severity = findingSeverity(entry);
    const title = clean(entry["title"]);
    const badge = paint(severity.padEnd(8), SEVERITY_COLORS[severity] ?? 37);
    wrap(title, 14, `    ${badge}  `);
    const before = entry["beforeOccurrenceIds"] as string[] | undefined;
    const after = entry["afterOccurrenceIds"] as string[] | undefined;
    const grouped =
      before?.length || after?.length
        ? `  ${accent("·")}  ${before?.length ?? 1} → ${after?.length ?? 1}`
        : "";
    const matches = entry["matches"] as JsonObject[] | undefined;
    const related = entry["related"] as JsonObject[] | undefined;
    const knownScanIds = entry["knownScanIds"] as string[] | undefined;
    const knownScans = knownScanIds?.length
      ? ` in ${clean(knownScanIds[0]).slice(0, 8)}${knownScanIds.length > 1 ? ` … ${clean(knownScanIds[knownScanIds.length - 1]).slice(0, 8)}` : ""}`
      : "";
    const knownSince =
      command === "show" && matches?.length && entry["knownSince"]
        ? `  ${accent("·")}  ${strong(`Known since ${KNOWN_SINCE_DATE.format(new Date(clean(entry["knownSince"])))}`)}${knownScans}`
        : "";
    const location = (entry["locations"] as JsonObject[] | undefined)?.[0];
    const path =
      entry["path"] ??
      entry["locationPath"] ??
      `${location?.["path"]}${location?.["startLine"] ? `:${location["startLine"]}` : ""}`;
    lines.push(`              ${dim(clean(path))}${grouped}${knownSince}`);
    const showLinkedFindings = command !== "show" || options.showLinkedFindings;
    if (matches?.length && showLinkedFindings) {
      lines.push(`              ${accent("↔")} ${strong("LINKED FINDINGS")}`);
      for (const match of matches) {
        lines.push(
          `                ${strong("MATCHED SCAN")} ${accent(clean(match["scanId"]).slice(0, 8))}`,
        );
        wrap(`↳ ${clean(match["title"])}`, 18);
      }
    }
    if (related?.length) {
      lines.push(
        `              ${accent("↔")} ${related.length} related finding${related.length === 1 ? "" : "s"}, kept separate`,
      );
      if (showLinkedFindings) {
        for (const relation of related) {
          if (relation["scanId"] !== undefined) {
            lines.push(
              `                ${strong("RELATED SCAN")} ${accent(clean(relation["scanId"]).slice(0, 8))}`,
            );
          }
          wrap(`↳ ${clean(relation["title"])}`, 18);
          wrap(clean(relation["reason"]), 20);
        }
      }
    }
    const reason =
      entry["matchReason"] ??
      entry["reason"] ??
      (matches?.length
        ? [...new Set(matches.map((match) => clean(match["reason"])))].join(
            "; ",
          )
        : undefined);
    if (includeReason && reason && (!matches?.length || showLinkedFindings)) {
      if (matches?.length) {
        lines.push(`                ${strong("SAME ROOT CAUSE")}`);
        wrap(clean(reason), 18);
      } else {
        wrap(`↳ ${clean(reason)}`, 14);
      }
    }
  };

  if (command === "list") {
    const scans = (result["scans"] as JsonObject[]).filter((scan) => {
      if ((scan["progress"] as JsonObject)["status"] !== "running") {
        return true;
      }
      const updated = Date.parse(scan["updatedAt"] as string);
      return (
        !Number.isFinite(updated) ||
        (options.now ?? Date.now()) - updated < STALE_SCAN_MILLISECONDS
      );
    });
    const repository = basename(
      String(
        options.scanRoot ??
          options.repository ??
          scans[0]?.["targetPath"] ??
          "",
      ),
    );
    const latest = scans.find(
      (scan) => (scan["progress"] as JsonObject)["status"] === "complete",
    )?.["findingCount"];
    const multipleRepositories =
      options.repository === undefined &&
      new Set(scans.map((scan) => scan["targetPath"])).size > 1;
    const wide = width >= (multipleRepositories ? 96 : 80);
    lines.push(
      `  ${strong(clean(repository))}  ${accent("·")}  ${scans.length} ${scans.length === 1 ? "scan" : "scans"}${latest === undefined ? "" : `  ${accent("·")}  latest: ${clean(latest)} findings`}`,
      "",
    );
    if (wide) {
      lines.push(
        `  ${strong("SCAN".padEnd(36))} ${strong("DATE".padEnd(10))} ${strong("MODE".padEnd(8))}${multipleRepositories ? ` ${strong("REPOSITORY".padEnd(18))}` : ""} ${strong("FINDINGS")} ${strong("STATUS")}`,
      );
    }
    for (const scan of scans) {
      const status = clean((scan["progress"] as JsonObject)["status"]);
      const complete = status === "complete";
      const statusColor = complete ? 32 : status === "running" ? 36 : 31;
      const statusLabel = paint(
        `${complete ? "✓" : "●"} ${status.toUpperCase()}`,
        statusColor,
      );
      const started = clean(scan["startedAt"]).slice(0, 10);
      const findings = clean(scan["findingCount"]);
      const scanRepository = basename(clean(scan["targetPath"]));
      if (wide) {
        lines.push(
          `  ${clean(scan["scanId"]).padEnd(36)} ${started.padEnd(10)} ${clean(scan["mode"]).padEnd(8)}${multipleRepositories ? ` ${scanRepository.slice(0, 18).padEnd(18)}` : ""} ${findings.padEnd(8)} ${statusLabel}`,
        );
      } else {
        lines.push(
          `  ${clean(scan["scanId"])}`,
          `    ${started}${multipleRepositories ? `  ${accent("·")}  ${clean(scanRepository)}` : ""}  ${accent("·")}  ${findings} findings  ${accent("·")}  ${statusLabel}`,
        );
      }
    }
  } else if (command === "findings") {
    const findings = result["findings"] as JsonObject[];
    lines.push(
      `  ${strong(clean(basename(result["repository"] as string)))}  ${accent("·")}  ${findings.length} open finding${findings.length === 1 ? "" : "s"}`,
    );
    for (const entry of findings) {
      lines.push(
        "",
        `  ${strong(entry["confirmedInLatestScan"] ? "Seen this scan" : "Not confirmed in latest scan")}`,
      );
      finding(entry);
    }
  } else if (command === "show") {
    const status = clean((result["progress"] as JsonObject)["status"]);
    const statusColor =
      status === "complete" ? 32 : status === "running" ? 36 : 31;
    lines.push(
      `  ${strong(clean(basename(result["targetPath"] as string)))}  ${accent("·")}  ${clean(result["scanId"])}`,
      `  ${paint(`${status === "complete" ? "✓" : "●"} ${status.toUpperCase()}`, statusColor)}  ${accent("·")}  ${clean(result["mode"])}`,
    );
    if (result["failureMessage"]) {
      wrap(String(result["failureMessage"]), 11, `  ${paint("ERROR", 31)}  `);
    }
    const warnings = result["warnings"];
    if (Array.isArray(warnings)) {
      for (const warning of warnings) {
        if (typeof warning === "string") {
          wrap(warning, 11, `  ${paint("WARNING", 33)}  `);
        }
      }
    }
    if (result["parentScanId"]) {
      lines.push(
        `  ${strong("PARENT SCAN")}  ${clean(result["parentScanId"]).slice(0, 8)}`,
      );
    }
    const summary = result["severityCounts"] as JsonObject | undefined;
    if (summary) {
      lines.push(
        `  ${Object.entries(summary)
          .filter(([, count]) => count)
          .map(([severity, count]) => {
            const label = severity.toUpperCase();
            return paint(
              `${clean(count)} ${label}`,
              SEVERITY_COLORS[label] ?? 37,
            );
          })
          .join(`  ${accent("·")}  `)}`,
      );
    }
    const recipe = result["recipe"] as JsonObject | undefined;
    const config = recipe?.["config"] as JsonObject | undefined;
    if (config && Object.keys(config).length > 0) {
      lines.push(
        `  ${strong("CONFIGURATION")}  ${Object.entries(config)
          .map(([key, value]) => {
            const rendered =
              typeof value === "object" ? JSON.stringify(value) : value;
            return `${clean(key)}=${clean(rendered)}`;
          })
          .join(`  ${accent("·")}  `)}`,
      );
    }
    const coverage = (result["progress"] as JsonObject)["coverage"] as
      | JsonObject
      | undefined;
    if (coverage) {
      const parts = [
        ...(coverage["worklistRows"] == null
          ? []
          : [
              `${clean(coverage["closedRows"])} of ${clean(coverage["worklistRows"])} reviewed`,
            ]),
        ...(coverage["filesTotal"] == null
          ? []
          : [`${clean(coverage["filesTotal"])} files`]),
      ];
      if (parts.length > 0) {
        lines.push(
          `  ${strong("COVERAGE")}  ${parts.join(`  ${accent("·")}  `)}`,
        );
      }
    }
    const knowledgeBase = recipe?.["knowledgeBasePaths"] as
      | string[]
      | undefined;
    if (knowledgeBase?.length) {
      lines.push(
        `  ${strong("KNOWLEDGE BASE")}  ${knowledgeBase.map((path) => dim(clean(path))).join(", ")}`,
      );
    }
    const artifacts = result["artifacts"] as JsonObject | undefined;
    if (artifacts && Object.keys(artifacts).length > 0) {
      lines.push(`  ${strong("ARTIFACTS")}`);
      const scanDirectory = result["scanDir"] as string | undefined;
      if (scanDirectory) lines.push(`    ${dim(clean(scanDirectory))}`);
      for (const [kind, path] of Object.entries(artifacts)) {
        const label = kind.replace(/([a-z])([A-Z])/g, "$1 $2").toUpperCase();
        const artifactPath = scanDirectory
          ? relative(scanDirectory, String(path))
          : String(path);
        lines.push(
          `    ${strong(clean(label).padEnd(15))}  ${dim(clean(artifactPath))}`,
        );
      }
    }
    const findings = result["findings"] as JsonObject[];
    if (findings.length > 0) {
      const count =
        typeof result["findingCount"] === "number"
          ? result["findingCount"]
          : findings.length;
      lines.push(
        "",
        `  ${strong("FINDINGS")}  ${strong(
          result["findingsTruncated"] || count > findings.length
            ? `${findings.length} of ${count}`
            : String(count),
        )}`,
      );
      for (const entry of findings) {
        lines.push("");
        finding(entry);
      }
    }
  } else if (command === "compare") {
    if (result["repository"]) {
      lines.push(
        `  ${strong(clean(basename(result["repository"] as string)))}`,
      );
    }
    lines.push(
      `  ${clean(result["beforeScanId"]).slice(0, 8)} → ${clean(result["afterScanId"]).slice(0, 8)}`,
    );
    const coverage = (result["coverage"] as JsonObject)["afterCompleteness"];
    if (coverage !== "complete") {
      lines.push(
        `  ${paint(`⚠ Follow-up coverage is ${clean(coverage)}; resolved findings cannot be confirmed.`, 33)}`,
      );
    }
    const findings = (result["findings"] as JsonObject[]).map((entry) =>
      entry["status"] === "unknown" &&
      entry["reason"] ===
        "The affected path was excluded or outside the later scope."
        ? { ...entry, status: "not_rescanned" }
        : entry,
    );
    const notRescanned = findings.filter(
      (entry) => entry["status"] === "not_rescanned",
    ).length;
    const summary: JsonObject = {
      ...(result["summary"] as JsonObject),
      ...(notRescanned
        ? {
            unknown:
              Number((result["summary"] as JsonObject)["unknown"] ?? 0) -
              notRescanned,
            not_rescanned: notRescanned,
          }
        : {}),
    };
    lines.push("");
    let summaryLine = "  ";
    let summaryLength = 2;
    for (const [status, style] of Object.entries(STATUS_STYLES)) {
      const value = summary[status];
      if (!value) continue;
      const label = `${style.icon} ${clean(value)} ${status.replaceAll("_", " ")}`;
      if (summaryLength > 2 && summaryLength + label.length + 4 > width - 2) {
        lines.push(summaryLine);
        summaryLine = "  ";
        summaryLength = 2;
      }
      summaryLine += `${summaryLength > 2 ? "    " : ""}${paint(label, style.color)}`;
      summaryLength += label.length + (summaryLength > 2 ? 4 : 0);
    }
    if (summaryLength > 2) lines.push(summaryLine);

    for (const status of Object.keys(STATUS_STYLES)) {
      const group = findings.filter(
        (entry) => String(entry["status"]).toLowerCase() === status,
      );
      if (group.length === 0) continue;
      group.sort(
        (first, second) =>
          Object.keys(SEVERITY_COLORS).indexOf(findingSeverity(first)) -
          Object.keys(SEVERITY_COLORS).indexOf(findingSeverity(second)),
      );
      const style = STATUS_STYLES[status]!;
      const title = `${style.icon} ${status[0]!.toUpperCase()}${status.slice(1).replaceAll("_", " ")}`;
      const heading = `${title} (${group.length} finding${group.length === 1 ? "" : "s"})`;
      const rule = "━".repeat(Math.max(2, width - heading.length - 8));
      lines.push("", `  ${paint(`━━ ${heading} ${rule}`, style.color)}`);
      if (status === "not_rescanned") {
        lines.push(`    ${accent("Outside follow-up scan coverage")}`);
      }
      for (const entry of group) {
        lines.push("");
        finding(entry, status !== "not_rescanned");
      }
    }
    const related = result["related"] as JsonObject[] | undefined;
    if (related?.length) {
      lines.push("", `  ${strong("Related findings, kept separate")}`);
      for (const relation of related) {
        wrap(
          `${clean(relation["beforeTitle"])} ↔ ${clean(relation["afterTitle"])}`,
          4,
        );
        wrap(clean(relation["reason"]), 6);
      }
    }
  } else {
    lines.push(
      `  ${strong(clean(basename(result["repository"] as string)))}`,
      "",
      `  ${paint("●", 36)} ${clean(result["scanCount"])} scans    ${paint("↔", 36)} ${clean(result["matchedPairs"])} comparisons    ${paint("◆", 32)} ${clean(result["findingMatches"])} root-cause matches`,
    );
    if (result["relatedPairs"] || result["uncertainPairs"]) {
      const related = result["relatedPairs"] ?? 0;
      const uncertain = result["uncertainPairs"] ?? 0;
      lines.push(
        `  ${clean(related)} related pair${related === 1 ? "" : "s"} recorded    ${clean(uncertain)} uncertain pair${uncertain === 1 ? "" : "s"}`,
      );
    }
    if (result["unavailableScans"]) {
      lines.push(
        `  ${paint(`${clean(result["unavailableScans"])} scans unavailable`, 33)}`,
      );
    }
  }

  return `${lines.join("\n")}\n\n`;
}

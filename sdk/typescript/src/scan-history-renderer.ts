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

const SEVERITY_ORDER = Object.keys(SEVERITY_COLORS);
const MAX_KNOWN_SINCE_LENGTH = 32;

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

// The workbench response is only checked for being a JSON object before it
// reaches this renderer, so every field read here is treated as optional. A
// history view degrades rather than aborting the command on a payload the
// installed plugin did not produce.
function record(value: unknown): JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : {};
}

function records(value: unknown): JsonObject[] {
  return Array.isArray(value)
    ? value.filter(
        (entry): entry is JsonObject =>
          typeof entry === "object" && entry !== null && !Array.isArray(entry),
      )
    : [];
}

function text(value: unknown, fallback = ""): string {
  return value === undefined || value === null ? fallback : clean(value);
}

function findingSeverity(finding: JsonObject): string {
  const severity = finding["severity"];
  const level =
    typeof severity === "string" ? severity : record(severity)["level"];
  return text(level).toUpperCase();
}

function severityRank(finding: JsonObject): number {
  const index = SEVERITY_ORDER.indexOf(findingSeverity(finding));
  return index < 0 ? Number.MAX_SAFE_INTEGER : index;
}

function knownSinceLabel(value: unknown): string {
  const raw = clean(value);
  const parsed = Date.parse(raw);
  return Number.isFinite(parsed)
    ? KNOWN_SINCE_DATE.format(parsed)
    : raw.slice(0, MAX_KNOWN_SINCE_LENGTH);
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
    const matches = records(entry["matches"]);
    const knownScanIds = entry["knownScanIds"] as string[] | undefined;
    const knownScans = knownScanIds?.length
      ? ` in ${clean(knownScanIds[0]).slice(0, 8)}${knownScanIds.length > 1 ? ` … ${clean(knownScanIds[knownScanIds.length - 1]).slice(0, 8)}` : ""}`
      : "";
    const knownSince =
      command === "show" && matches.length && entry["knownSince"]
        ? `  ${accent("·")}  ${strong(`Known since ${knownSinceLabel(entry["knownSince"])}`)}${knownScans}`
        : "";
    const location = records(entry["locations"])[0];
    const path =
      entry["path"] ??
      entry["locationPath"] ??
      `${location?.["path"]}${location?.["startLine"] ? `:${location["startLine"]}` : ""}`;
    lines.push(`              ${dim(clean(path))}${grouped}${knownSince}`);
    const showLinkedFindings = command !== "show" || options.showLinkedFindings;
    if (matches.length && showLinkedFindings) {
      lines.push(`              ${accent("↔")} ${strong("LINKED FINDINGS")}`);
      for (const match of matches) {
        lines.push(
          `                ${strong("MATCHED SCAN")} ${accent(clean(match["scanId"]).slice(0, 8))}`,
        );
        wrap(`↳ ${clean(match["title"])}`, 18);
      }
    }
    const reason =
      entry["matchReason"] ??
      entry["reason"] ??
      (matches.length
        ? [...new Set(matches.map((match) => clean(match["reason"])))].join(
            "; ",
          )
        : undefined);
    if (includeReason && reason && (!matches.length || showLinkedFindings)) {
      if (matches.length) {
        lines.push(`                ${strong("SAME ROOT CAUSE")}`);
        wrap(clean(reason), 18);
      } else {
        wrap(`↳ ${clean(reason)}`, 14);
      }
    }
  };

  if (command === "list") {
    const scans = records(result["scans"]).filter((scan) => {
      if (record(scan["progress"])["status"] !== "running") {
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
      (scan) => record(scan["progress"])["status"] === "complete",
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
      const status = text(record(scan["progress"])["status"], "unknown");
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
    const status = text(record(result["progress"])["status"], "unknown");
    const statusColor =
      status === "complete" ? 32 : status === "running" ? 36 : 31;
    lines.push(
      `  ${strong(clean(basename(text(result["targetPath"]))))}  ${accent("·")}  ${clean(result["scanId"])}`,
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
    const summary = record(result["severityCounts"]);
    if (Object.keys(summary).length > 0) {
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
    const recipe = record(result["recipe"]);
    const config = record(recipe["config"]);
    if (Object.keys(config).length > 0) {
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
    const coverage = record(record(result["progress"])["coverage"]);
    if (Object.keys(coverage).length > 0) {
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
    const knowledgeBase = recipe["knowledgeBasePaths"] as string[] | undefined;
    if (knowledgeBase?.length) {
      lines.push(
        `  ${strong("KNOWLEDGE BASE")}  ${knowledgeBase.map((path) => dim(clean(path))).join(", ")}`,
      );
    }
    const artifacts = record(result["artifacts"]);
    if (Object.keys(artifacts).length > 0) {
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
    const findings = records(result["findings"]);
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
      lines.push(`  ${strong(clean(basename(text(result["repository"]))))}`);
    }
    lines.push(
      `  ${clean(result["beforeScanId"]).slice(0, 8)} → ${clean(result["afterScanId"]).slice(0, 8)}`,
    );
    const coverage = record(result["coverage"])["afterCompleteness"];
    if (coverage !== "complete") {
      lines.push(
        `  ${paint(`⚠ Follow-up coverage is ${clean(coverage)}; resolved findings cannot be confirmed.`, 33)}`,
      );
    }
    const findings = records(result["findings"]).map((entry) =>
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
      ...record(result["summary"]),
      ...(notRescanned
        ? {
            unknown:
              Number(record(result["summary"])["unknown"] ?? 0) - notRescanned,
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
      group.sort((first, second) => severityRank(first) - severityRank(second));
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
  } else {
    lines.push(
      `  ${strong(clean(basename(text(result["repository"]))))}`,
      "",
      `  ${paint("●", 36)} ${clean(result["scanCount"])} scans    ${paint("↔", 36)} ${clean(result["matchedPairs"])} comparisons    ${paint("◆", 32)} ${clean(result["findingMatches"])} root-cause matches`,
    );
    if (result["unavailableScans"]) {
      lines.push(
        `  ${paint(`${clean(result["unavailableScans"])} scans unavailable`, 33)}`,
      );
    }
  }

  return `${lines.join("\n")}\n\n`;
}

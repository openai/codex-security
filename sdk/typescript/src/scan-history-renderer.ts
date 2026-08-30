import { basename, join, relative } from "node:path";
import type { JsonObject } from "./config.js";

export type HistoryCommand =
  | "list"
  | "show"
  | "compare"
  | "match-all"
  | "findings"
  | "finding";
export type HistoryRendererOptions = {
  columns?: number;
  color?: boolean;
  now?: number;
  currentDirectory?: string;
  repository?: string;
  scanRoot?: string;
  showLinkedFindings?: boolean;
  status?: "open" | "closed";
  query?: string;
  severity?: string;
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

const CLOSE_REASON_LABELS: Record<string, string> = {
  already_fixed: "Fixed",
  false_positive: "False Positive",
  wont_fix: "Ignored",
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
  options: HistoryRendererOptions = {},
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
    compare: "SCAN COMPARISON",
    "match-all": "MATCH RESULTS",
    findings:
      typeof result["scanId"] === "string"
        ? "SAVED FINDINGS"
        : "REPOSITORY FINDINGS",
    finding: "FINDING DETAILS",
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
    const knownScanIds = entry["knownScanIds"] as string[] | undefined;
    const knownScans = knownScanIds?.length
      ? ` in ${clean(knownScanIds[0]).slice(0, 8)}${knownScanIds.length > 1 ? ` … ${clean(knownScanIds[knownScanIds.length - 1]).slice(0, 8)}` : ""}`
      : "";
    const knownSince =
      (command === "show" || command === "finding") &&
      (matches?.length || (knownScanIds?.length ?? 0) > 1) &&
      entry["knownSince"]
        ? `  ${accent("·")}  ${strong(`Known since ${KNOWN_SINCE_DATE.format(new Date(clean(entry["knownSince"])))}`)}${knownScans}`
        : "";
    const location = (entry["locations"] as JsonObject[] | undefined)?.[0];
    const path =
      entry["path"] ??
      entry["locationPath"] ??
      `${location?.["path"]}${location?.["startLine"] ? `:${location["startLine"]}` : ""}`;
    lines.push(`              ${dim(clean(path))}${grouped}${knownSince}`);
    if (command === "findings" || command === "finding" || command === "show") {
      const occurrenceId = entry["occurrenceId"];
      const triage = entry["triage"] as JsonObject | undefined;
      const status = triage?.["status"] ?? entry["status"];
      const closeReason = triage?.["closeReason"];
      const statusLabel =
        status === "closed" && typeof closeReason === "string"
          ? CLOSE_REASON_LABELS[closeReason] ?? clean(status)
          : clean(status);
      const scanId = entry["scanId"];
      const occurrenceCount = entry["occurrenceCount"];
      const scanCount = knownScanIds?.length;
      const details = [
        ...(occurrenceId ? [`${strong("ID")} ${clean(occurrenceId)}`] : []),
        ...(status ? [strong(statusLabel.toUpperCase())] : []),
        ...(command === "findings" && scanId
          ? [`${strong("SCAN")} ${clean(scanId).slice(0, 8)}`]
          : []),
        ...(command === "findings" &&
        options.repository === undefined &&
        typeof entry["targetPath"] === "string"
          ? [`${strong("REPOSITORY")} ${clean(entry["targetPath"])}`]
          : []),
        ...(typeof occurrenceCount === "number" && occurrenceCount > 1
          ? [
              scanCount
                ? `${clean(scanCount)} ${scanCount === 1 ? "scan" : "scans"}`
                : `${clean(occurrenceCount)} occurrences`,
            ]
          : []),
      ];
      if (details.length > 0) {
        lines.push(`              ${details.join(`  ${accent("·")}  `)}`);
      }
    }
    const showLinkedFindings =
      command === "compare" ||
      command === "finding" ||
      (command === "show" && options.showLinkedFindings);
    if (matches?.length && showLinkedFindings) {
      lines.push(`              ${accent("↔")} ${strong("LINKED FINDINGS")}`);
      for (const match of matches) {
        lines.push(
          `                ${strong("MATCHED SCAN")} ${accent(clean(match["scanId"]).slice(0, 8))}${match["occurrenceId"] ? `  ${accent("·")}  ${strong("ID")} ${clean(match["occurrenceId"])}` : ""}`,
        );
        wrap(`↳ ${clean(match["title"])}`, 18);
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

  if (command === "findings") {
    const findings = result["findings"] as JsonObject[];
    const scanId = result["scanId"];
    const repository = options.repository ?? result["repository"];
    const scope =
      typeof scanId === "string"
        ? `scan ${clean(scanId).slice(0, 8)}`
        : typeof repository === "string"
          ? clean(basename(repository))
          : "all repositories";
    const offset = Number(result["offset"] ?? 0);
    const total = result["total"];
    const range =
      typeof total === "number"
        ? findings.length > 0
          ? `${offset + 1}-${offset + findings.length} of ${total}`
          : `0 of ${total}`
        : `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
    lines.push(`  ${strong(scope)}  ${accent("·")}  ${range}`);
    wrap(
      [
        `Status: ${options.status ?? "all"}`,
        ...(options.severity === undefined
          ? []
          : [`Severity: ${options.severity}`]),
        ...(options.query === undefined ? [] : [`Search: "${options.query}"`]),
      ].join(" · "),
      2,
    );
    if (findings.length === 0) {
      lines.push(
        "",
        offset > 0
          ? `  No findings at offset ${offset}. Rerun with --offset 0 to start over.`
          : `  No ${options.status ?? "saved"} findings match this view.`,
      );
    }
    for (const entry of findings) {
      lines.push("");
      if (typeof entry["confirmedInLatestScan"] === "boolean") {
        lines.push(
          `  ${strong(entry["confirmedInLatestScan"] ? "Seen in latest scan" : "Not confirmed in latest scan")}`,
        );
      }
      finding(entry, false);
    }
    if (typeof result["nextOffset"] === "number") {
      lines.push(
        "",
        `  ${strong("NEXT PAGE")}  rerun with --offset ${clean(result["nextOffset"])}`,
      );
    }
  } else if (command === "finding") {
    const repository = result["currentTargetPath"] ?? result["targetPath"];
    const scanId = result["scanId"];
    if (typeof repository === "string") {
      lines.push(
        `  ${strong(clean(basename(repository)))}${scanId ? `  ${accent("·")}  ${clean(scanId).slice(0, 8)}` : ""}`,
      );
    }
    lines.push("");
    finding(result);
    if (typeof result["summary"] === "string" && result["summary"]) {
      lines.push("", `  ${strong("SUMMARY")}`);
      wrap(result["summary"], 4);
    }
    const locations = result["locations"];
    if (Array.isArray(locations) && locations.length > 1) {
      lines.push("", `  ${strong("AFFECTED LOCATIONS")}`);
      for (const location of locations) {
        if (
          typeof location !== "object" ||
          location === null ||
          Array.isArray(location)
        ) {
          continue;
        }
        const path = location["path"];
        if (typeof path !== "string") continue;
        const startLine = location["startLine"];
        const endLine = location["endLine"];
        const range =
          typeof startLine === "number"
            ? `:${startLine}${typeof endLine === "number" && endLine !== startLine ? `-${endLine}` : ""}`
            : "";
        const role =
          typeof location["role"] === "string"
            ? `  ${accent("·")}  ${clean(location["role"])}`
            : "";
        lines.push(`    ${dim(clean(`${path}${range}`))}${role}`);
      }
    }
    const description = (value: unknown): string | undefined => {
      if (typeof value === "string") return value;
      if (typeof value !== "object" || value === null) return undefined;
      for (const key of [
        "summary",
        "narrative",
        "description",
        "detail",
        "conclusion",
        "rationale",
        "explanation",
        "why",
      ]) {
        const candidate = (value as JsonObject)[key];
        if (typeof candidate === "string" && candidate) return candidate;
      }
      return undefined;
    };
    const appendDescriptions = (
      sections: string[],
      value: JsonObject,
      key: string,
      label: string,
    ): void => {
      const items = value[key];
      if (!Array.isArray(items)) return;
      for (const item of items) {
        const detail = description(item);
        if (detail !== undefined) sections.push(`${label}: ${detail}`);
      }
    };
    for (const [label, key] of [
      ["SEVERITY", "severity"],
      ["CONFIDENCE", "confidence"],
    ] as const) {
      const value = result[key];
      if (typeof value !== "object" || value === null || Array.isArray(value)) {
        continue;
      }
      const level = value["level"];
      const rationale = description(value);
      if (
        (key === "severity" && rationale === undefined) ||
        (typeof level !== "string" && rationale === undefined)
      ) {
        continue;
      }
      lines.push(
        "",
        `  ${strong(label)}${typeof level === "string" ? `  ${strong(clean(level).toUpperCase())}` : ""}`,
      );
      if (rationale !== undefined) wrap(rationale, 4);
    }
    for (const [label, key] of [
      ["ROOT CAUSE", "rootCause"],
      ["VALIDATION", "validation"],
      ["ATTACK PATH", "attackPath"],
    ] as const) {
      const value =
        key === "rootCause" ? result[key] ?? result["root_cause"] : result[key];
      const detail = description(value);
      const sections = detail === undefined ? [] : [detail];
      if (
        typeof value === "object" &&
        value !== null &&
        !Array.isArray(value)
      ) {
        if (key === "validation") {
          if (typeof value["method"] === "string") {
            sections.push(`Method: ${value["method"]}`);
          }
          for (const [evidenceLabel, evidenceKey] of [
            ["Verified", "assertions"],
            ["Evidence", "evidence"],
            ["Counterevidence", "counterEvidence"],
          ] as const) {
            appendDescriptions(sections, value, evidenceKey, evidenceLabel);
          }
        }
        if (key === "attackPath") {
          for (const [nestedLabel, nestedKey] of [
            ["Dataflow", "dataflow"],
            ["Dataflow", "dataFlow"],
            ["Reachability", "reachability"],
            ["Impact", "impact"],
            ["Likelihood", "likelihood"],
          ] as const) {
            const nestedValue = value[nestedKey];
            const nested = description(nestedValue);
            if (nested !== undefined) {
              sections.push(`${nestedLabel}: ${nested}`);
            }
            if (
              typeof nestedValue !== "object" ||
              nestedValue === null ||
              Array.isArray(nestedValue)
            ) {
              continue;
            }
            const attributes: ReadonlyArray<readonly [string, string]> =
              nestedKey === "dataflow" || nestedKey === "dataFlow"
                ? [
                    ["Source", "source"],
                    ["Sink", "sink"],
                    ["Outcome", "outcome"],
                  ]
                : nestedKey === "reachability"
                  ? [
                      ["Attacker", "attacker"],
                      ["Entry point", "entrypoint"],
                      ["Outcome", "outcome"],
                    ]
                  : [];
            for (const [attributeLabel, attributeKey] of attributes) {
              const detail = description(nestedValue[attributeKey]);
              if (detail !== undefined) {
                sections.push(`${attributeLabel}: ${detail}`);
              }
            }
            if (nestedKey === "reachability") {
              appendDescriptions(
                sections,
                nestedValue,
                "preconditions",
                "Precondition",
              );
            }
          }
        }
        const caveats: ReadonlyArray<readonly [string, string]> =
          key === "validation"
            ? [["Limitation", "limitations"]]
            : key === "attackPath"
              ? [
                  ["Precondition", "preconditions"],
                  ["Limitation", "limitations"],
                ]
              : [];
        for (const [caveatLabel, caveatKey] of caveats) {
          appendDescriptions(sections, value, caveatKey, caveatLabel);
        }
      }
      if (sections.length > 0) {
        lines.push("", `  ${strong(label)}`);
        for (const section of sections) wrap(section, 4);
      }
    }
    const codeEvidence = result["codeEvidence"] ?? result["code_evidence"];
    const rootCause = result["rootCause"] ?? result["root_cause"];
    const legacyRootCode =
      typeof rootCause === "object" &&
      rootCause !== null &&
      !Array.isArray(rootCause) &&
      typeof rootCause["code"] === "string"
        ? rootCause["code"]
        : undefined;
    const evidenceEntries: JsonObject[] =
      Array.isArray(codeEvidence) && codeEvidence.length > 0
        ? codeEvidence.filter(
            (entry): entry is JsonObject =>
              typeof entry === "object" &&
              entry !== null &&
              !Array.isArray(entry),
          )
        : legacyRootCode === undefined
          ? []
          : [{ label: "Root-cause source", code: legacyRootCode }];
    if (evidenceEntries.length > 0) {
      lines.push("", `  ${strong("CODE EVIDENCE")}`);
      for (const evidence of evidenceEntries) {
        if (typeof evidence["label"] === "string") {
          lines.push(`    ${strong(clean(evidence["label"]))}`);
        }
        if (typeof evidence["path"] === "string") {
          const line =
            typeof evidence["startLine"] === "number"
              ? `:${evidence["startLine"]}`
              : "";
          lines.push(`      ${dim(clean(`${evidence["path"]}${line}`))}`);
        }
        if (typeof evidence["explanation"] === "string") {
          wrap(evidence["explanation"], 6);
        }
        if (typeof evidence["code"] === "string") {
          for (const sourceLine of evidence["code"].split("\n")) {
            lines.push(`      ${dim(clean(sourceLine))}`);
          }
        }
      }
    }
    const sourceExcerpt = result["sourceExcerpt"];
    if (typeof sourceExcerpt === "string" && sourceExcerpt) {
      lines.push("", `  ${strong("SOURCE EXCERPT")}`);
      for (const sourceLine of sourceExcerpt.split("\n")) {
        lines.push(`    ${dim(clean(sourceLine))}`);
      }
    }
    if (typeof result["remediation"] === "string" && result["remediation"]) {
      lines.push("", `  ${strong("REMEDIATION")}`);
      wrap(result["remediation"], 4);
    }
    for (const [label, key] of [
      ["REMEDIATION TESTS", "remediationTests"],
      ["PREVENTIVE CONTROLS", "preventiveControls"],
    ] as const) {
      const items = result[key];
      if (!Array.isArray(items)) continue;
      const guidance = items.filter(
        (item): item is string => typeof item === "string" && item.length > 0,
      );
      if (guidance.length === 0) continue;
      lines.push("", `  ${strong(label)}`);
      for (const item of guidance) wrap(item, 6, "    • ");
    }
    const artifactPaths = result["artifactPaths"];
    if (Array.isArray(artifactPaths) && artifactPaths.length > 0) {
      lines.push("", `  ${strong("EVIDENCE ARTIFACTS")}`);
      const scanDirectory = result["scanDir"];
      for (const path of artifactPaths) {
        if (typeof path !== "string") continue;
        const artifactPath =
          typeof scanDirectory === "string" ? join(scanDirectory, path) : path;
        lines.push(`    ${dim(clean(artifactPath))}`);
      }
    }
    if (typeof result["occurrenceId"] === "string") {
      const triage = result["triage"];
      const details =
        typeof triage === "object" && triage !== null && !Array.isArray(triage)
          ? triage
          : undefined;
      const action =
        details?.["status"] === "closed"
          ? ""
          : `  codex-security findings false-positive ${clean(result["occurrenceId"])} --reason TEXT`;
      lines.push("", `  ${strong("TRIAGE")}${action}`);
      for (const [label, key] of [
        ["Reason", "closeReason"],
        ["Note", "note"],
      ] as const) {
        if (typeof details?.[key] === "string" && details[key]) {
          const value =
            key === "closeReason"
              ? CLOSE_REASON_LABELS[details[key]] ?? details[key]
              : details[key];
          wrap(`${label}: ${value}`, 4);
        }
      }
    }
  } else if (command === "list") {
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
    const completed = scans.filter(
      (scan) => (scan["progress"] as JsonObject)["status"] === "complete",
    );
    const latest = completed[0]?.["findingCount"];
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
    if (completed.length > 0) {
      const latest = completed[0]!;
      const scanPrefix = clean(latest["scanId"]).slice(0, 8);
      const scanQualifiedFindings =
        options.scanRoot !== undefined ||
        (options.currentDirectory !== undefined &&
          (options.repository ?? latest["targetPath"]) !==
            options.currentDirectory);
      lines.push(
        "",
        `  ${strong("VIEW LATEST")}  codex-security scans show ${scanPrefix}`,
        `  ${strong("FINDINGS")}     codex-security findings list${scanQualifiedFindings ? ` --scan ${scanPrefix}` : ""}`,
      );
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
      const truncated =
        Boolean(result["findingsTruncated"]) || count > findings.length;
      lines.push(
        "",
        `  ${strong("FINDINGS")}  ${strong(
          truncated ? `${findings.length} of ${count}` : String(count),
        )}`,
      );
      for (const entry of findings) {
        lines.push("");
        finding(entry);
      }
      if (truncated) {
        lines.push(
          "",
          `  ${strong("MORE FINDINGS")}  codex-security findings list --scan ${clean(result["scanId"]).slice(0, 8)} --offset ${findings.length}`,
        );
      }
      const linked = findings.some(
        (entry) => (entry["matches"] as JsonObject[] | undefined)?.length,
      );
      if (linked && !options.showLinkedFindings) {
        lines.push(
          "",
          `  ${strong("FINDING HISTORY")}  codex-security scans show ${clean(result["scanId"]).slice(0, 8)} --show-linked-findings`,
        );
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
  } else {
    lines.push(
      `  ${strong(clean(basename(result["repository"] as string)))}`,
      "",
      `  ${paint("●", 36)} ${clean(result["scanCount"])} scans    ${paint("↔", 36)} ${clean(result["matchedPairs"])} comparisons    ${paint("◆", 32)} ${clean(result["findingMatches"])} root-cause matches`,
    );
    if (result["unavailableScans"]) {
      lines.push(
        `  ${paint(`${clean(result["unavailableScans"])} scans unavailable`, 33)}`,
      );
    }
  }

  if (
    (command === "findings" || command === "show") &&
    (result["findings"] as JsonObject[]).length > 0
  ) {
    lines.push(
      "",
      `  ${strong("DETAILS")}  codex-security findings show OCCURRENCE_ID`,
    );
  }
  return `${lines.join("\n")}\n\n`;
}

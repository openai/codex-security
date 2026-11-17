import { closeSync, openSync, writeFileSync } from "node:fs";
import { stripVTControlCharacters } from "node:util";
import stringWidth from "string-width";
import type { DependencyUse } from "./dependency-reachability.js";
import { dependencyVerdictLabels } from "./dependency-verdict-labels.js";
import { errorMessage } from "./errors.js";
import { formatSecurityPolicyText } from "./security-policy.js";

const activities = {
  opengrep: "Searching with OpenGrep",
  trace: "Tracing source call paths",
  source_search: "Searching source",
  source_read: "Reading source",
  upstream: "Fetching upstream source",
  catalog: "Looking up services in the catalog",
  runtime: "Checking runtime inventory",
  profiles: "Checking runtime stacks",
} as const;

type Activity = keyof typeof activities;

export interface DependencyProgressScope {
  directories?: readonly string[];
  files?: readonly string[];
  symbol?: string;
  upstream?: string;
}

type SinkOrigin = "supplied" | "advisory_record" | "advisory" | "discovered";
type Verdict = DependencyUse["verdict"];
type VerdictCounts = Record<Verdict, number>;
export type DependencyAccessProgram =
  "daybreak_blue" | "daybreak_red" | "standard" | "unconfirmed";
const verdictLabels = dependencyVerdictLabels;
const verdictTones: Record<Verdict, number> = {
  ruled_out: 32,
  unknown: 33,
  potentially_exploitable: 33,
  exploitable: 31,
};
const verdictOrder: readonly Verdict[] = [
  "exploitable",
  "potentially_exploitable",
  "unknown",
  "ruled_out",
];
const stages = {
  osv: "Looking up advisories in OSV",
  advisory_lookup: "Looking up advisories",
  supplied_advisory: "Using the supplied vulnerability description",
  investigate: "Starting source investigation",
  review: "Reviewing evidence",
} as const;

export type DependencyProgressEvent =
  | { type: "started"; subject: string; checkout: string }
  | { type: "stage"; subject: string; stage: keyof typeof stages }
  | { type: "advisories_loaded"; subject: string; count: number }
  | {
      type: "access_program";
      subject: string;
      program: DependencyAccessProgram;
    }
  | {
      type: "advisory_summary";
      subject: string;
      summary: string;
      advisoryId?: string;
    }
  | {
      type: "proposed_sink";
      subject: string;
      function: string;
      origin: SinkOrigin;
      path?: string;
      line?: number;
    }
  | {
      type: "activity_started" | "activity_finished";
      subject: string;
      id: number;
      activity: Activity;
      scope?: DependencyProgressScope;
      searchedPaths?: readonly string[];
      outcome?: "returned" | "partial" | "failed";
    }
  | {
      type: "reviewed";
      subject: string;
      location: string;
      locationKind: "caller" | "sink";
      scope?: string;
      verdict: Verdict;
      component: string;
      version?: string;
      previousVerdict?: Verdict;
      reason: string;
      groupId?: string;
    }
  | {
      type: "reviewed_group";
      subject: string;
      location: string;
      verdict: Verdict;
      reason: string;
      groupId: string;
      callsites: number;
      assessments: number;
    }
  | { type: "assessment_finished"; subject: string; uses: number }
  | {
      type: "report_ready";
      subject: string;
      verdicts: VerdictCounts;
      limitations: number;
      path?: string;
    }
  | {
      type: "finished";
      subject: string;
      outcome: "completed" | "blocked" | "failed" | "interrupted";
    };

export function progressText(value: string): string {
  return formatSecurityPolicyText(
    stripVTControlCharacters(value)
      .replaceAll(/[\u0000-\u001F\u007F-\u009F\u2028\u2029\s]+/gu, " ")
      .trim(),
  );
}

const CLEAR_LINE = "\r\x1b[2K";
const spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const rowStyles = {
  active: { marker: "›", tone: 36 },
  detail: { marker: "·", tone: 2 },
  complete: { marker: "✓", tone: 32 },
  warning: { marker: "!", tone: 33 },
} as const;
const graphemes = new Intl.Segmenter(undefined, { granularity: "grapheme" });

function fit(text: string, width: number) {
  if (stringWidth(text) <= width) return text;
  let used = 0;
  for (const { index, segment } of graphemes.segment(text)) {
    used += stringWidth(segment);
    if (used >= width) return text.slice(0, index) + "…";
  }
  return text;
}

function pathList(paths: readonly string[]) {
  const visible = paths.slice(0, 3).map(progressText);
  if (paths.length > visible.length)
    visible.push(`+${paths.length - visible.length} more`);
  return visible.join(" · ");
}

function describeActivity(activity: Activity, scope?: DependencyProgressScope) {
  const paths = [
    ...new Set([...(scope?.files ?? []), ...(scope?.directories ?? [])]),
  ];
  const where = scope?.upstream
    ? progressText(scope.upstream)
    : paths.length === 1 && paths[0] === "."
      ? "checkout"
      : pathList(paths);
  const symbol = scope?.symbol ? ` · ${progressText(scope.symbol)}` : "";
  return activities[activity] + (where ? ` · ${where}` : "") + symbol;
}

function elapsed(ms: number) {
  const seconds = Math.floor(Math.max(0, ms) / 1000);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

export function createDependencyProgress({
  output,
  file,
  now,
  interactive,
  color,
}: {
  output: {
    write(text: string, callback?: () => void): unknown;
    columns?: number;
    on?(event: "error", listener: (error: Error) => void): unknown;
    off?(event: "error", listener: (error: Error) => void): unknown;
  };
  file?: string;
  now: () => number;
  interactive: boolean;
  color: boolean;
}) {
  const started = now();
  const pending = new Map<number, string>();
  const shown = new Set<string>();
  let nextActivity = 0;
  let status = "";
  let frame = 0;
  let timer: NodeJS.Timeout | undefined;
  let liveLine = false;
  let fileDescriptor: number | undefined;
  const onOutputError = () => {};
  output.on?.("error", onOutputError);

  function write(text: string) {
    try {
      output.write(text);
    } catch {
      // Progress is best-effort and cannot change the assessment outcome.
    }
  }

  function colorize(code: number, text: string) {
    return color ? `\x1b[${code}m${text}\x1b[0m` : text;
  }

  function rowPrefix(ms: number, marker: string) {
    return `${marker} ${colorize(2, elapsed(ms).padStart(6))}  `;
  }

  function styledPrefix(ms: number, style: keyof typeof rowStyles) {
    const { marker, tone } = rowStyles[style];
    return rowPrefix(ms, colorize(tone, marker));
  }

  function availableWidth(prefix: string) {
    return Math.max(1, (output.columns ?? 100) - stringWidth(prefix) - 1);
  }

  function live() {
    const active = [...pending.values()].at(-1);
    const action = active ?? status;
    if (!action) {
      clear();
      return;
    }
    const marker = colorize(36, spinner[frame++ % spinner.length]!);
    const prefix = rowPrefix(now() - started, marker);
    const detail = pending.size > 1 ? ` · ${pending.size} active checks` : "";
    liveLine = true;
    write(
      `${CLEAR_LINE}${prefix}${colorize(36, fit(action + detail, availableWidth(prefix)))}`,
    );
  }

  function clear() {
    if (!liveLine) return;
    write(CLEAR_LINE);
    liveLine = false;
  }

  function line(text: string) {
    clear();
    write(`${text}\n`);
    if (interactive) live();
  }

  function row(
    ms: number,
    style: keyof typeof rowStyles,
    text: string,
    label?: string,
  ) {
    const prefix =
      styledPrefix(ms, style) +
      (label ? colorize(2, `${label.padEnd(9)}  `) : "");
    line(prefix + fit(text, availableWidth(prefix)));
  }

  function closeFile() {
    if (fileDescriptor === undefined) return;
    const fd = fileDescriptor;
    fileDescriptor = undefined;
    try {
      closeSync(fd);
    } catch (error) {
      row(
        now() - started,
        "warning",
        `Progress file: ${progressText(errorMessage(error))}`,
      );
    }
  }

  if (file !== undefined) {
    try {
      fileDescriptor = openSync(file, "wx", 0o600);
    } catch (error) {
      row(
        now() - started,
        "warning",
        `Could not create progress file: ${progressText(errorMessage(error))}`,
      );
    }
  }

  function emit(event: DependencyProgressEvent) {
    const elapsedMs = Math.max(0, now() - started);
    if (fileDescriptor !== undefined) {
      try {
        writeFileSync(
          fileDescriptor,
          JSON.stringify({
            schemaVersion: 1,
            elapsedMs,
            ...event,
          }) + "\n",
        );
      } catch (error) {
        closeFile();
        row(
          elapsedMs,
          "warning",
          `Could not write progress file: ${progressText(errorMessage(error))}`,
        );
      }
    }

    try {
      render(event, elapsedMs);
    } catch {
      // Progress formatting cannot alter the investigation.
    }
  }

  function render(event: DependencyProgressEvent, elapsedMs: number) {
    switch (event.type) {
      case "started":
        line(
          `\n  ${colorize(1, "Exploitability")} · ${progressText(event.checkout)} · ${colorize(2, progressText(event.subject))}\n`,
        );
        status = "Preparing the checkout";
        row(elapsedMs, "active", status);
        if (interactive) {
          timer = setInterval(live, 120);
          timer.unref();
        }
        break;
      case "stage":
        status = stages[event.stage];
        row(elapsedMs, "active", status);
        if (event.stage === "investigate") {
          shown.clear();
          status = "Investigating source call paths";
        }
        break;
      case "advisories_loaded":
        row(
          elapsedMs,
          "complete",
          `Loaded ${event.count} advisory ${event.count === 1 ? "record" : "records"}`,
        );
        break;
      case "access_program":
        if (
          event.program === "daybreak_blue" ||
          event.program === "daybreak_red"
        ) {
          row(
            elapsedMs,
            "detail",
            event.program === "daybreak_blue"
              ? "Daybreak Blue"
              : "Daybreak Red",
            "Access",
          );
        } else {
          const prefix = styledPrefix(elapsedMs, "warning");
          const heading =
            event.program === "standard"
              ? "WARNING: DAYBREAK IS NOT ACTIVE"
              : "WARNING: DAYBREAK ACCESS NOT CONFIRMED";
          const first =
            event.program === "standard"
              ? "Codex selected Standard access."
              : "Codex did not select a Daybreak access program for this turn.";
          const indent = " ".repeat(stringWidth(prefix));
          line(
            `\n${prefix}${colorize(33, heading)}\n${indent}${first}\n${indent}Daybreak requires a supported model and an eligible OpenAI account.\n`,
          );
        }
        break;
      case "advisory_summary":
        row(elapsedMs, "detail", progressText(event.summary), "Advisory");
        break;
      case "proposed_sink": {
        const origin = {
          supplied: "supplied boundary",
          advisory_record: "named by advisory",
          advisory: "advisory-derived",
          discovered: "discovered",
        }[event.origin];
        const source =
          event.path === undefined
            ? ""
            : ` · ${progressText(event.path)}${event.line === undefined ? "" : `:${event.line}`}`;
        row(
          elapsedMs,
          "detail",
          `${progressText(event.function)} · ${origin}${source}`,
          "Sink",
        );
        break;
      }
      case "activity_started": {
        const action = describeActivity(event.activity, event.scope);
        pending.set(event.id, action);
        if (!shown.has(action)) {
          shown.add(action);
          row(elapsedMs, "active", action);
        }
        break;
      }
      case "activity_finished":
        pending.delete(event.id);
        if (event.searchedPaths?.length) {
          const paths = pathList(event.searchedPaths);
          const partial = event.outcome === "partial";
          const label = partial ? "Partial search" : "Searched";
          const key = `${label} ${paths}`;
          if (!shown.has(key)) {
            shown.add(key);
            row(elapsedMs, partial ? "warning" : "complete", paths, label);
          }
        }
        if (
          event.outcome === "partial" &&
          event.activity === "profiles" &&
          !shown.has("partial_profiles")
        ) {
          shown.add("partial_profiles");
          row(
            elapsedMs,
            "warning",
            "Runtime stacks returned with incomplete coverage",
          );
        }
        break;
      case "reviewed":
      case "reviewed_group": {
        const label = verdictLabels[event.verdict].toUpperCase();
        const tone = verdictTones[event.verdict];
        const correction =
          event.type === "reviewed" && event.previousVerdict
            ? ` · was ${verdictLabels[event.previousVerdict].toLowerCase()}`
            : "";
        const groupScope =
          event.type === "reviewed_group" &&
          event.assessments !== event.callsites
            ? `, ${event.assessments} assessments`
            : "";
        const detail =
          event.type === "reviewed_group"
            ? event.callsites === 0
              ? `No current reviewed calls for this proof · ${event.location}`
              : `${event.callsites} reviewed ${event.callsites === 1 ? "call" : "calls"} share this proof${groupScope} · e.g. ${event.location}`
            : [
                event.location,
                event.locationKind === "sink" && "caller unresolved",
                event.scope,
                event.version && `${event.component} ${event.version}`,
              ]
                .filter(Boolean)
                .join(" · ");
        const prefix = rowPrefix(elapsedMs, colorize(tone, "◆"));
        const verdictPrefix = `${prefix}${colorize(tone, label)}  `;
        const location = fit(
          detail,
          Math.max(1, availableWidth(verdictPrefix) - stringWidth(correction)),
        );
        const reasonPrefix = " ".repeat(stringWidth(prefix)) + "  ";
        status = "Investigating remaining calls";
        line(
          `\n${verdictPrefix}${location}${correction}` +
            (event.type === "reviewed"
              ? `\n${reasonPrefix}${fit(event.reason, availableWidth(reasonPrefix))}`
              : ""),
        );
        break;
      }
      case "assessment_finished":
        pending.clear();
        status = "";
        clear();
        break;
      case "report_ready": {
        pending.clear();
        status = "";
        const uses = Object.values(event.verdicts).reduce(
          (sum, n) => sum + n,
          0,
        );
        const counts = verdictOrder.flatMap((verdict) => {
          const count = event.verdicts[verdict];
          return count > 0
            ? [
                colorize(
                  verdictTones[verdict],
                  `${count} ${verdictLabels[verdict].toLowerCase()}`,
                ),
              ]
            : [];
        });
        const prefix = styledPrefix(elapsedMs, "complete");
        const indent = " ".repeat(stringWidth(prefix));
        line(
          `\n${prefix}${colorize(1, "Investigation summary")} · ${uses} reviewed ${uses === 1 ? "use" : "uses"}`,
        );
        if (counts.length) line(indent + counts.join("  ·  "));
        if (event.limitations > 0)
          line(
            `${indent}${event.limitations} ${event.limitations === 1 ? "limitation" : "limitations"} in the report`,
          );
        if (event.path !== undefined) {
          line(
            `${indent}${colorize(2, "Report saved")}  ${formatSecurityPolicyText(event.path)}`,
          );
        }
        break;
      }
      case "finished":
        pending.clear();
        status = "";
        clear();
        if (event.outcome === "blocked" || event.outcome === "interrupted")
          row(elapsedMs, "warning", `Investigation ${event.outcome}`);
        break;
    }
  }

  return {
    emit,
    begin(
      subject: string,
      activity: Activity,
      scope?: DependencyProgressScope,
    ) {
      const id = ++nextActivity;
      const context = { subject, id, activity, ...(scope && { scope }) };
      emit({ type: "activity_started", ...context });
      return (
        outcome: "returned" | "partial" | "failed",
        searchedPaths?: string[],
      ) =>
        emit({
          type: "activity_finished",
          ...context,
          outcome,
          ...(searchedPaths && { searchedPaths }),
        });
    },
    clear,
    close() {
      if (timer) clearInterval(timer);
      clear();
      closeFile();
      // Allow asynchronous stream errors from the final write to arrive.
      if (output.off) {
        try {
          output.write("", () => output.off?.("error", onOutputError));
        } catch {
          output.off("error", onOutputError);
        }
      }
    },
  };
}

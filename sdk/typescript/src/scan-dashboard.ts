import { basename, isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";
import { stripVTControlCharacters } from "node:util";
import type { ScanModelConfiguration } from "./config.js";
import { formatUsd, type ScanCost, type ScanSessionEvent } from "./cost.js";
import type { ScanActivity } from "./scan-activity.js";
import type { ScanMode } from "./targets.js";
import type { ScanProgress } from "./worker-progress.js";

const HIDE_CURSOR = "\u001B[?25l";
const SHOW_CURSOR = "\u001B[?25h";
const ENTER_ALTERNATE_SCREEN = "\u001B[?1049h";
const EXIT_ALTERNATE_SCREEN = "\u001B[?1049l";
const ENABLE_ALTERNATE_SCROLL = "\u001B[?1007h";
const DISABLE_ALTERNATE_SCROLL = "\u001B[?1007l";
const CURSOR_HOME = "\u001B[H";
const ERASE_LINE = "\u001B[2K";
const MAX_HISTORY_ENTRIES = 2_000;
const FIXED_SCREEN_ROWS = 8;

interface DashboardStream {
  write(chunk: string, callback?: (error?: Error | null) => void): unknown;
  on?(event: "error", listener: (error: Error) => void): unknown;
  off?(event: "error", listener: (error: Error) => void): unknown;
  readonly columns?: number;
  readonly rows?: number;
}

interface DashboardClock {
  now(): number;
  setInterval(callback: () => void, milliseconds: number): NodeJS.Timeout;
  clearInterval(timer: NodeJS.Timeout): void;
}

interface DashboardInput {
  readonly isTTY?: boolean;
  readonly isRaw?: boolean;
  setRawMode?(mode: boolean): unknown;
  on(event: "data", listener: (chunk: string | Uint8Array) => void): unknown;
  off(event: "data", listener: (chunk: string | Uint8Array) => void): unknown;
  resume?(): unknown;
  pause?(): unknown;
}

interface ScanDashboardOptions {
  repository: string;
  presentation?: "scan" | "publication" | "verification";
  mode?: ScanMode;
  model?: ScanModelConfiguration;
  maxCostUsd?: number;
  clock: DashboardClock;
  color?: boolean;
  sanitize?: (value: string) => string;
  input?: DashboardInput;
  onInterrupt?: () => void;
}

interface TimedScanActivity extends ScanActivity {
  recordedAt: number;
}

type DashboardActivityKind = ScanActivity["kind"] | "status" | "warning";

interface DashboardActivityLine {
  text: string;
  kind: DashboardActivityKind | "path" | "code";
  links?: readonly DashboardActivityLink[];
  code?: readonly string[];
  bold?: readonly string[];
}

interface DashboardActivityLink {
  label: string;
  target: string;
}

const ACTIVITY_MARKERS: Record<DashboardActivityKind, string> = {
  command: "✓",
  tool: "✓",
  message: "●",
  reasoning: "◦",
  status: "◆",
  warning: "▲",
};

const LINE_STYLES: Record<DashboardActivityLine["kind"] | "title", string> = {
  title: "1",
  message: "36",
  reasoning: "35",
  tool: "36",
  command: "2",
  path: "2",
  code: "2",
  status: "32",
  warning: "33",
};

export class ScanDashboard {
  readonly #stream: DashboardStream;
  readonly #options: ScanDashboardOptions;
  readonly #startedAt: number;
  readonly #activities: TimedScanActivity[] = [];
  readonly #details: (ScanSessionEvent & { recordedAt: number })[] = [];
  #detailsCache: {
    width: number;
    source: "all" | "main" | number;
    count: number;
    lines: DashboardActivityLine[];
    summaries: Map<string, Set<string>>;
  } | null = null;
  #stage = "Preparing scan";
  #files: ScanProgress | null = null;
  #publicationProgress: { completed: number; total: number } | null = null;
  #cost: Readonly<ScanCost> | null = null;
  #timer: NodeJS.Timeout | null = null;
  #scrollOffset = 0;
  #view: "activity" | "details" = "activity";
  #source: "all" | "main" | number = "all";
  #inputWasRaw = false;
  #noteCount = 0;
  #observingStreamErrors = false;
  readonly #onStreamError = (): void => {};
  readonly #onInput = (chunk: string | Uint8Array): void => {
    const input =
      typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    let lines = 0;
    for (const key of input.match(
      /[\u0003\u0004\u0015dam1-9]|\u001B\[(?:[ABHF]|[1456]~)/gu,
    ) ?? []) {
      if (key === "\u0003") {
        if (lines !== 0) this.scroll(lines);
        this.#options.onInterrupt?.();
        lines = 0;
      } else if (/^[dam1-9]$/u.test(key)) {
        if (
          this.#options.presentation !== undefined &&
          this.#options.presentation !== "scan"
        )
          continue;
        if (key !== "d" && this.#view !== "details") continue;
        if (lines !== 0) this.scroll(lines);
        if (key === "d") {
          this.#view = this.#view === "activity" ? "details" : "activity";
        } else {
          this.#source =
            key === "a" ? "all" : key === "m" ? "main" : Number(key);
        }
        this.#scrollOffset = 0;
        this.#refresh();
        lines = 0;
      } else if (key === "\u001B[A") {
        lines += 1;
      } else if (key === "\u001B[B") {
        lines -= 1;
      } else if (key === "\u0015") {
        lines += Math.max(1, Math.floor(this.#activityRows() / 2));
      } else if (key === "\u0004") {
        lines -= Math.max(1, Math.floor(this.#activityRows() / 2));
      } else if (key === "\u001B[5~") {
        lines += this.#activityRows();
      } else if (key === "\u001B[6~") {
        lines -= this.#activityRows();
      } else {
        if (lines !== 0) this.scroll(lines);
        this.scroll(
          key === "\u001B[H" || key === "\u001B[1~"
            ? Number.MAX_SAFE_INTEGER
            : -Number.MAX_SAFE_INTEGER,
        );
        lines = 0;
      }
    }
    if (lines !== 0) this.scroll(lines);
  };

  public constructor(stream: DashboardStream, options: ScanDashboardOptions) {
    this.#stream = stream;
    this.#options = options;
    this.#startedAt = options.clock.now();
  }

  public start(): void {
    if (this.#timer !== null) return;
    const input = this.#options.input;
    if (input?.isTTY === true) {
      this.#inputWasRaw = input.isRaw === true;
    }
    this.#timer = this.#options.clock.setInterval(() => this.#refresh(), 1_000);
    try {
      if (!this.#observingStreamErrors && this.#stream.on !== undefined) {
        this.#stream.on("error", this.#onStreamError);
        this.#observingStreamErrors = true;
      }
      this.#stream.write(`${ENTER_ALTERNATE_SCREEN}${HIDE_CURSOR}`);
      if (input?.isTTY === true) {
        input.setRawMode?.(true);
        input.resume?.();
        input.on("data", this.#onInput);
        this.#stream.write(ENABLE_ALTERNATE_SCROLL);
      }
      this.#render();
    } catch (error) {
      try {
        this.stop();
      } catch {
        try {
          this.#stream.write(
            `${DISABLE_ALTERNATE_SCROLL}${SHOW_CURSOR}${EXIT_ALTERNATE_SCREEN}`,
          );
        } catch {}
      }
      throw error;
    }
  }

  public stop(): void {
    if (this.#timer === null) return;
    this.#options.clock.clearInterval(this.#timer);
    this.#timer = null;
    const input = this.#options.input;
    try {
      if (input?.isTTY === true) {
        input.off("data", this.#onInput);
        input.setRawMode?.(this.#inputWasRaw);
        input.pause?.();
      }
      this.#stream.write(
        `${input?.isTTY === true ? DISABLE_ALTERNATE_SCROLL : ""}${SHOW_CURSOR}${EXIT_ALTERNATE_SCREEN}`,
      );
    } finally {
      if (this.#observingStreamErrors) {
        try {
          this.#stream.write("", () => {
            queueMicrotask(() => {
              if (this.#timer === null && this.#observingStreamErrors) {
                this.#stream.off?.("error", this.#onStreamError);
                this.#observingStreamErrors = false;
              }
            });
          });
        } catch {
          this.#stream.off?.("error", this.#onStreamError);
          this.#observingStreamErrors = false;
        }
      }
    }
  }

  public setStage(stage: string): void {
    this.#stage = stage;
    this.#refresh();
  }

  public setFiles(files: ScanProgress): void {
    this.#files = files;
    this.#refresh();
  }

  public setPublicationProgress(completed: number, total: number): void {
    this.#publicationProgress = { completed, total };
    this.#refresh();
  }

  public setCost(cost: Readonly<ScanCost>): void {
    this.#cost = cost;
    this.#refresh();
  }

  public note(description: string): void {
    this.record({
      id: `scan-note-${++this.#noteCount}`,
      kind: "command",
      status: "completed",
      description,
      paths: [],
    });
  }

  public record(activity: ScanActivity): void {
    const existing = this.#activities.findIndex(
      (entry) =>
        entry.id === activity.id ||
        (entry.worker === activity.worker &&
          isFileInventory(entry) &&
          isFileInventory(activity)),
    );
    const previousRows =
      this.#scrollOffset === 0 ? 0 : this.#activityLines(this.#width()).length;
    const recordedAt =
      existing < 0
        ? this.#options.clock.now()
        : this.#activities[existing]!.recordedAt;
    const entry = { ...activity, recordedAt };
    if (existing < 0) {
      this.#activities.push(entry);
    } else {
      this.#activities[existing] = entry;
    }
    if (this.#activities.length > MAX_HISTORY_ENTRIES) {
      this.#activities.splice(0, this.#activities.length - MAX_HISTORY_ENTRIES);
    }
    if (this.#scrollOffset !== 0) {
      this.#scrollOffset += Math.max(
        0,
        this.#activityLines(this.#width()).length - previousRows,
      );
    }
    this.#refresh();
  }

  public recordDetails(session: ScanSessionEvent): void {
    const previousRows =
      this.#view === "details" && this.#scrollOffset !== 0
        ? this.#activityLines(this.#width()).length
        : 0;
    const timestamp = session.event["timestamp"];
    const recordedAt =
      typeof timestamp === "string" ? Date.parse(timestamp) : NaN;
    const entry = {
      ...session,
      recordedAt: Number.isNaN(recordedAt)
        ? this.#options.clock.now()
        : recordedAt,
    };
    const index = this.#details.findLastIndex(
      (event) => event.recordedAt <= entry.recordedAt,
    );
    this.#details.splice(index + 1, 0, entry);
    if (index + 1 < (this.#detailsCache?.count ?? 0)) {
      this.#detailsCache = null;
    }
    if (this.#view === "details") {
      if (this.#scrollOffset !== 0) {
        this.#scrollOffset += Math.max(
          0,
          this.#activityLines(this.#width()).length - previousRows,
        );
      }
      this.#refresh();
    }
  }

  public scroll(lines: number): void {
    const maximum = Math.max(
      0,
      this.#activityLines(this.#width()).length - this.#activityRows(),
    );
    this.#scrollOffset = Math.max(
      0,
      Math.min(maximum, this.#scrollOffset + lines),
    );
    this.#refresh();
  }

  #refresh(): void {
    if (this.#timer === null) return;
    try {
      this.#render();
    } catch {}
  }

  #render(): void {
    const publication = this.#options.presentation === "publication";
    const verification = this.#options.presentation === "verification";
    const findingProgress = publication || verification;
    const width = this.#width();
    const activityRows = this.#activityRows();
    const divider = `  ${"─".repeat(Math.max(0, width - 4))}`;
    const elapsed = Math.max(
      0,
      Math.floor((this.#options.clock.now() - this.#startedAt) / 1_000),
    );
    const time = formatElapsed(elapsed);
    const files =
      this.#files === null
        ? "waiting for inventory"
        : `${formatCount(this.#files.filesCompleted)} / ${formatCount(this.#files.filesTotal)} reviewed`;
    const tokens =
      this.#cost === null
        ? "waiting for usage"
        : `${formatCount(this.#cost.inputTokens)} in · ${formatCount(this.#cost.cachedInputTokens)} cached · ${formatCount(this.#cost.outputTokens)} out`;
    const cost =
      this.#cost === null
        ? this.#options.maxCostUsd === undefined
          ? "waiting for usage"
          : `— / ${formatUsd(this.#options.maxCostUsd)}`
        : `${formatUsd(this.#cost.estimatedUsd)}${this.#options.maxCostUsd === undefined ? "" : ` / ${formatUsd(this.#options.maxCostUsd)} · ${budgetBar(this.#cost.estimatedUsd, this.#options.maxCostUsd)}`}`;

    const history = this.#activityLines(width);
    const maximumOffset = Math.max(0, history.length - activityRows);
    this.#scrollOffset = Math.min(this.#scrollOffset, maximumOffset);
    const first = Math.max(
      0,
      history.length - activityRows - this.#scrollOffset,
    );
    const activity = history.slice(first, first + activityRows);
    if (activity.length === 0) {
      activity.push({
        text: `  [${formatLocalTime(this.#options.clock.now())}] · Waiting for ${this.#view === "details" ? "session events" : publication ? "publication activity" : verification ? "verification activity" : "scan activity"}…`,
        kind: "path",
      });
    }
    while (activity.length < activityRows) {
      activity.push({ text: "", kind: "path" });
    }
    let scrollStatus =
      this.#scrollOffset === 0
        ? "Ctrl+C to exit"
        : `${formatCount(this.#scrollOffset)} ${this.#scrollOffset === 1 ? "line" : "lines"} above live · Ctrl+C to exit`;
    if (!findingProgress && this.#options.input?.isTTY === true) {
      scrollStatus =
        this.#view === "details"
          ? `d activity · a/m/1-9 source · ${scrollStatus}`
          : `d details · ${scrollStatus}`;
    }
    const model = this.#options.model;

    const lines = [
      `  CODEX SECURITY  ·  ${publication ? "PUBLISH  ·  " : verification ? "VERIFY-FIX  ·  " : ""}${basename(this.#options.repository)}${model === undefined ? "" : `  ·  ${model.model} (${model.reasoningEffort})`}${this.#view === "details" ? `  ·  DETAILS${this.#source === "all" ? "" : ` · ${typeof this.#source === "number" ? `worker ${this.#source}` : this.#source}`}` : ""}`,
      divider,
      ...activity,
      divider,
      ...(findingProgress
        ? [
            `  STAGE     ${this.#stage}`,
            `  FINDINGS  ${this.#publicationProgress === null ? "waiting for findings" : `${formatCount(this.#publicationProgress.completed)} / ${formatCount(this.#publicationProgress.total)} processed`}`,
          ]
        : [
            ...(this.#options.mode === "deep"
              ? []
              : [`  STAGE    ${this.#stage}`, `  FILES    ${files}`]),
            `  TOKENS   ${tokens}`,
            `  COST     ${cost}`,
          ]),
      `  TIME     ${time}  ·  ${scrollStatus}`,
    ];

    this.#stream.write(
      CURSOR_HOME +
        lines
          .map((line, index) => {
            const text = typeof line === "string" ? line : line.text;
            const clean = fitLine(
              typeof line !== "string" && this.#view === "details"
                ? text
                : this.#options.sanitize?.(text) ?? text,
              width,
            );
            const colored =
              this.#options.color === true
                ? styleLine(
                    clean,
                    typeof line === "string"
                      ? index === 0
                        ? "title"
                        : undefined
                      : line.kind,
                    typeof line !== "string" && this.#view === "details",
                  )
                : clean;
            const formatted =
              typeof line === "string"
                ? colored
                : linkActivity(
                    this.#options.color === true
                      ? styleInlineCode(colored, line)
                      : colored,
                    line.links,
                    this.#options.sanitize,
                  );
            return `${ERASE_LINE}${formatted}`;
          })
          .join("\n"),
    );
  }

  #width(): number {
    return Math.max(1, Math.min(this.#stream.columns ?? 88, 160));
  }

  #activityRows(): number {
    return Math.max(
      1,
      (this.#stream.rows ?? 24) -
        FIXED_SCREEN_ROWS +
        (this.#options.presentation === "publication"
          ? 2
          : this.#options.mode === "deep"
            ? 2
            : 0),
    );
  }

  #activityLines(width: number): DashboardActivityLine[] {
    if (this.#view === "details") {
      let cache = this.#detailsCache;
      if (
        cache === null ||
        cache.width !== width ||
        cache.source !== this.#source
      ) {
        this.#detailsCache = cache = {
          width,
          source: this.#source,
          count: 0,
          lines: [],
          summaries: new Map(),
        };
      }
      if (cache.count === this.#details.length) return cache.lines;
      const events = this.#details.slice(cache.count);
      cache.count = this.#details.length;
      for (const { threadId, worker, event, recordedAt } of events) {
        if (this.#source !== "all" && this.#source !== (worker ?? "main")) {
          continue;
        }
        let description = detailsDescription(event);
        if (description === undefined) continue;

        const payload = isRecord(event["payload"]) ? event["payload"] : {};
        const itemType = payload["type"];
        const prose =
          typeof itemType === "string" &&
          /^(?:message|agent_message|reasoning|agent_reasoning.*)$/u.test(
            itemType,
          );
        if (prose) {
          const seen = cache.summaries.get(threadId) ?? new Set<string>();
          cache.summaries.set(threadId, seen);
          if (itemType === "reasoning" && Array.isArray(payload["summary"])) {
            const summary = payload["summary"].filter(
              (part) => !isRecord(part) || !seen.has(String(part["text"])),
            );
            if (summary.length === 0) continue;
            for (const part of summary) {
              if (isRecord(part) && typeof part["text"] === "string") {
                seen.add(part["text"]);
              }
            }
            description = detailsDescription({
              ...event,
              payload: { ...payload, summary },
            });
          }
          if (description === undefined || seen.has(description)) continue;
          seen.add(description);
          if (itemType === "agent_reasoning") {
            seen.add(detailsText(payload["text"]));
          }
        } else {
          cache.summaries.delete(threadId);
        }

        const source = worker === undefined ? "main" : `worker ${worker}`;
        const prefix = `  [${formatLocalTime(recordedAt)}] ${source} · `;
        const code: string[] = [];
        const bold: string[] = [];
        if (prose) {
          description = description.replaceAll(
            /`([^`\r\n]+)`|\*\*([^*\r\n]+)\*\*/gu,
            (_match: string, inline: string, strong: string) => {
              const text = inline ?? strong;
              (inline === undefined ? bold : code).push(text);
              return text;
            },
          );
        }
        const paragraphs = description.split(/\r?\n/u);
        const lines =
          paragraphs.length === 1
            ? wrapActivity(prefix, description, width)
            : paragraphs.flatMap((line, index) =>
                wrapCode(
                  index === 0 ? prefix : " ".repeat(prefix.length),
                  line,
                  width,
                ),
              );
        for (const text of lines) {
          cache.lines.push({ text, kind: "path", code, bold });
        }
      }
      return cache.lines;
    }
    const elapsed = Math.max(
      0,
      Math.floor((this.#options.clock.now() - this.#startedAt) / 1_000),
    );
    const runningIcon = ["◐", "◓", "◑", "◒"][elapsed % 4];
    const lines: DashboardActivityLine[] = [];
    const append = (
      prefix: string,
      value: string,
      kind: DashboardActivityLine["kind"],
    ): void => {
      value = this.#options.sanitize?.(value) ?? value;
      if (kind !== "message" && kind !== "reasoning") {
        for (const text of wrapActivity(prefix, value, width)) {
          lines.push({ text, kind });
        }
        return;
      }

      const continuation = " ".repeat(prefix.length);
      let started = false;
      let fenced = false;
      for (const source of value.split(/\r?\n/u)) {
        if (/^\s*```/u.test(source)) {
          fenced = !fenced;
          continue;
        }
        const links: DashboardActivityLink[] = [];
        const code: string[] = [];
        const description = fenced
          ? source
          : source.replaceAll(
              /`([^`\r\n]+)`|\[([^\]\r\n]+)\]\(([^)\r\n]+)\)/gu,
              (
                _match: string,
                inline: string,
                label: string,
                target: string,
              ) => {
                if (inline !== undefined) {
                  code.push(inline);
                  return inline;
                }
                links.push({ label, target });
                return label;
              },
            );
        const wrapped = fenced
          ? wrapCode(started ? continuation : prefix, description, width)
          : wrapActivity(started ? continuation : prefix, description, width);
        for (const text of wrapped) {
          lines.push({ text, kind: fenced ? "code" : kind, links, code });
          started = true;
        }
      }
    };
    for (const entry of this.#activities) {
      const kind: DashboardActivityKind = entry.id.startsWith("scan-note-")
        ? /\b(?:warning|unavailable|interrupted|retrying)\b|could not be confirmed|capacity changed/iu.test(
            entry.description,
          )
          ? "warning"
          : "status"
        : entry.kind;
      const icon =
        entry.status === "failed"
          ? "×"
          : entry.status === "running"
            ? runningIcon
            : ACTIVITY_MARKERS[kind];
      const timestamp = `[${formatLocalTime(entry.recordedAt)}]`;
      const worker =
        entry.worker === undefined ? "" : `worker ${entry.worker} · `;
      const prefix = `  ${timestamp} ${icon} `;
      append(prefix, `${worker}${entry.description}`, kind);
      for (const path of entry.paths) {
        append(" ".repeat(prefix.length), path, "path");
      }
    }
    return lines;
  }
}

function detailsDescription(
  event: Record<string, unknown>,
): string | undefined {
  const type = typeof event["type"] === "string" ? event["type"] : "event";
  const payload = event["payload"];
  if (!isRecord(payload)) return type.replaceAll("_", " ");

  if (type === "session_meta") {
    const instructions = payload["base_instructions"];
    const text = isRecord(instructions) ? instructions["text"] : instructions;
    return typeof text === "string" ? `system: ${text}` : "session started";
  }
  if (type === "turn_context") {
    const details = [
      "model",
      "effort",
      "cwd",
      "summary",
      "developer_instructions",
      "user_instructions",
    ]
      .map((field) => payload[field])
      .filter((detail) => typeof detail === "string" && detail !== "");
    return `context${details.length === 0 ? "" : `: ${details.join(" · ")}`}`;
  }
  const itemType = typeof payload["type"] === "string" ? payload["type"] : type;
  if (itemType === "token_count") return undefined;
  if (itemType === "message" || itemType === "agent_message") {
    const role =
      typeof payload["role"] === "string" ? payload["role"] : "assistant";
    return `${role}: ${detailsText(payload["content"] ?? payload["message"])}`;
  }
  if (itemType === "reasoning" || itemType.startsWith("agent_reasoning")) {
    const text = detailsText(
      payload["summary"] ?? payload["text"] ?? payload["delta"],
    );
    return text.trim() === "" ? undefined : `reasoning: ${text}`;
  }
  if (itemType.endsWith("_call_output")) {
    return `result${payload["status"] === "failed" ? " failed" : ""}: ${detailsText(payload["output"])}`;
  }
  if (itemType.endsWith("_call")) {
    const name =
      typeof payload["name"] === "string" ? payload["name"] : "shell";
    const arguments_ = payload["arguments"] ?? payload["input"];
    const text =
      typeof arguments_ === "string"
        ? arguments_
        : arguments_ === undefined
          ? ""
          : JSON.stringify(arguments_);
    return `tool ${name}${text === "" ? "" : `: ${text}`}`;
  }
  return itemType.replaceAll("_", " ");
}

function detailsText(value: unknown): string {
  if (typeof value === "string") return value;
  if (!Array.isArray(value)) return "";
  return value
    .flatMap((item) =>
      isRecord(item) && typeof item["text"] === "string" ? [item["text"]] : [],
    )
    .join("\n");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function styleInlineCode(value: string, line: DashboardActivityLine): string {
  for (const text of line.bold ?? []) {
    value = value.replace(text, `\u001B[1m${text}\u001B[22m`);
  }
  for (const text of line.code ?? []) {
    value = value.replace(
      text,
      `\u001B[2m${text}\u001B[22m${line.kind === "message" ? "\u001B[1m" : ""}`,
    );
  }
  return value;
}

function linkActivity(
  value: string,
  links: readonly DashboardActivityLink[] | undefined,
  sanitize: ((value: string) => string) | undefined,
): string {
  for (const { label, target } of links ?? []) {
    const safe = safeHyperlinkTarget(sanitize?.(target) ?? target);
    if (safe !== undefined) {
      value = value.replace(
        label,
        `\u001B]8;;${safe}\u0007${label}\u001B]8;;\u0007`,
      );
    }
  }
  return value;
}

function safeHyperlinkTarget(value: string): string | undefined {
  if (/[\u0000-\u001F\u007F]/u.test(value)) return undefined;
  if (isAbsolute(value)) return pathToFileURL(value).href;
  if (!URL.canParse(value)) return undefined;
  const url = new URL(value);
  return url.protocol === "https:" || url.protocol === "http:"
    ? url.href
    : undefined;
}

function isFileInventory(activity: ScanActivity): boolean {
  return (
    activity.kind === "command" &&
    activity.paths.length === 0 &&
    /\brg\s+--files\b|\bgit\s+ls-files\b/u.test(activity.description)
  );
}

function formatElapsed(seconds: number): string {
  return `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
}

function formatLocalTime(timestamp: number): string {
  const date = new Date(timestamp);
  return [date.getHours(), date.getMinutes(), date.getSeconds()]
    .map((part) => String(part).padStart(2, "0"))
    .join(":");
}

function wrapActivity(prefix: string, value: string, width: number): string[] {
  const available = Math.max(1, width - prefix.length);
  const continuation = " ".repeat(prefix.length);
  const lines: string[] = [];
  const append = (text: string): void => {
    lines.push(`${lines.length === 0 ? prefix : continuation}${text}`);
  };
  let current = "";
  let separator = "";
  for (const word of value.split(/(\s+)/u)) {
    if (/^\s+$/u.test(word)) {
      separator = word;
      continue;
    }
    const characters = Array.from(word);
    if (characters.length > available) {
      if (current !== "") {
        append(current);
        current = "";
      }
      for (let start = 0; start < characters.length; start += available) {
        const part = characters.slice(start, start + available).join("");
        if (start + available < characters.length) {
          append(part);
        } else {
          current = part;
        }
      }
    } else if (
      current !== "" &&
      Array.from(current).length +
        Array.from(separator).length +
        characters.length >
        available
    ) {
      append(current);
      current = word;
    } else {
      current = current === "" ? word : `${current}${separator}${word}`;
    }
    separator = "";
  }
  if (current !== "") append(current);
  return lines;
}

function wrapCode(prefix: string, value: string, width: number): string[] {
  const characters = Array.from(value);
  const available = Math.max(1, width - prefix.length);
  return Array.from(
    { length: Math.max(1, Math.ceil(characters.length / available)) },
    (_, index) =>
      `${index === 0 ? prefix : " ".repeat(prefix.length)}${characters
        .slice(index * available, (index + 1) * available)
        .join("")}`,
  );
}

function styleLine(
  value: string,
  kind: DashboardActivityLine["kind"] | "title" | undefined,
  details = false,
): string {
  if (details) {
    return value
      .replace(
        /^(\s*)(\[\d{2}:\d{2}:\d{2}\])(\s+)(main|worker \d+)/u,
        "$1\u001B[2m$2\u001B[22m$3\u001B[36m$4\u001B[39m",
      )
      .replace(
        /^(.*\u001B\[39m · )((reasoning|assistant|user|system|context|result(?: failed)?|tool(?: [^:]+)?):)/u,
        (_match: string, prefix: string, label: string, type: string) => {
          const color =
            type === "reasoning"
              ? "35"
              : type === "result"
                ? "32"
                : /^(?:result failed|system|context)$/u.test(type)
                  ? "33"
                  : "36";
          return `${prefix}\u001B[${color}m${label}\u001B[39m`;
        },
      );
  }
  if (kind === undefined) return value;
  const style = LINE_STYLES[kind];
  if (
    kind === "message" ||
    kind === "reasoning" ||
    kind === "tool" ||
    kind === "status" ||
    kind === "warning"
  ) {
    const activity = value.match(
      /^(\s*)(\[\d{2}:\d{2}:\d{2}\])(\s+)(\S+)(\s+)(worker \d+ · )?(.*)$/u,
    );
    if (activity === null) {
      return kind === "message" || kind === "status" || kind === "warning"
        ? `\u001B[${kind === "message" ? "1" : style}m${value}\u001B[0m`
        : value;
    }
    const [, padding, timestamp, gap, marker, separator, worker, description] =
      activity;
    const prefix = `${padding}\u001B[2m${timestamp}\u001B[22m${gap}`;
    if (kind === "status" || kind === "warning") {
      return `${prefix}\u001B[${style}m${marker}${separator}${description}\u001B[0m`;
    }
    const workerLabel =
      worker === undefined ? "" : `\u001B[36m${worker}\u001B[39m`;
    const prose =
      kind === "message" ? `\u001B[1m${description}\u001B[22m` : description;
    return `${prefix}\u001B[${style}m${marker}\u001B[39m${separator}${workerLabel}${prose}`;
  }
  return `\u001B[${style}m${value}\u001B[0m`;
}

function formatCount(value: number): string {
  return value.toLocaleString("en-US");
}

function budgetBar(cost: number, limit: number): string {
  const proportion = Math.min(1, Math.max(0, cost / limit));
  const filled = Math.round(proportion * 12);
  return `[${"█".repeat(filled)}${"░".repeat(12 - filled)}] ${Math.round(proportion * 100)}%`;
}

function fitLine(value: string, width: number): string {
  const clean = stripVTControlCharacters(value).replaceAll(
    /[\u0000-\u001F\u007F]/gu,
    " ",
  );
  const characters = Array.from(clean);
  return characters.length <= width
    ? clean
    : `${characters.slice(0, Math.max(0, width - 1)).join("")}…`;
}

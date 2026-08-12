import { basename, isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";
import { stripVTControlCharacters } from "node:util";
import type { ScanModelConfiguration } from "./config.js";
import { formatUsd, type ScanCost } from "./cost.js";
import type { ScanActivity } from "./scan-activity.js";
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
  write(chunk: string): unknown;
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
  #stage = "Preparing scan";
  #files: ScanProgress | null = null;
  #cost: Readonly<ScanCost> | null = null;
  #timer: NodeJS.Timeout | null = null;
  #scrollOffset = 0;
  #inputWasRaw = false;
  #noteCount = 0;
  readonly #onInput = (chunk: string | Uint8Array): void => {
    const input =
      typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    let lines = 0;
    for (const key of input.match(
      /[\u0003\u0004\u0015]|\u001B\[(?:[ABHF]|[1456]~)/gu,
    ) ?? []) {
      if (key === "\u0003") {
        if (lines !== 0) this.scroll(lines);
        this.#options.onInterrupt?.();
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
    this.#stream.write(`${ENTER_ALTERNATE_SCREEN}${HIDE_CURSOR}`);
    const input = this.#options.input;
    if (input?.isTTY === true) {
      this.#inputWasRaw = input.isRaw === true;
      input.setRawMode?.(true);
      input.resume?.();
      input.on("data", this.#onInput);
      this.#stream.write(ENABLE_ALTERNATE_SCROLL);
    }
    this.#render();
    this.#timer = this.#options.clock.setInterval(() => this.#render(), 1_000);
  }

  public stop(): void {
    if (this.#timer === null) return;
    this.#options.clock.clearInterval(this.#timer);
    this.#timer = null;
    const input = this.#options.input;
    if (input?.isTTY === true) {
      input.off("data", this.#onInput);
      input.setRawMode?.(this.#inputWasRaw);
      input.pause?.();
    }
    this.#stream.write(
      `${input?.isTTY === true ? DISABLE_ALTERNATE_SCROLL : ""}${SHOW_CURSOR}${EXIT_ALTERNATE_SCREEN}`,
    );
  }

  public setStage(stage: string): void {
    this.#stage = stage;
    this.#refresh();
  }

  public setFiles(files: ScanProgress): void {
    this.#files = files;
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
    if (this.#timer !== null) this.#render();
  }

  #render(): void {
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
        text: `  [${formatLocalTime(this.#options.clock.now())}] · Waiting for scan activity…`,
        kind: "path",
      });
    }
    while (activity.length < activityRows) {
      activity.push({ text: "", kind: "path" });
    }
    const scrollStatus =
      this.#scrollOffset === 0
        ? "Ctrl+C to exit"
        : `${formatCount(this.#scrollOffset)} ${this.#scrollOffset === 1 ? "line" : "lines"} above live · Ctrl+C to exit`;
    const model = this.#options.model;

    const lines = [
      `  CODEX SECURITY  ·  ${basename(this.#options.repository)}${model === undefined ? "" : `  ·  ${model.model} (${model.reasoningEffort})`}`,
      divider,
      ...activity,
      divider,
      `  STAGE    ${this.#stage}`,
      `  FILES    ${files}`,
      `  TOKENS   ${tokens}`,
      `  COST     ${cost}`,
      `  TIME     ${time}  ·  ${scrollStatus}`,
    ];

    this.#stream.write(
      CURSOR_HOME +
        lines
          .map((line, index) => {
            const text = typeof line === "string" ? line : line.text;
            const clean = fitLine(
              this.#options.sanitize?.(text) ?? text,
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
                  )
                : clean;
            const formatted =
              typeof line === "string"
                ? colored
                : linkActivity(
                    this.#options.color === true
                      ? styleInlineCode(colored, line.code, line.kind)
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
    return Math.max(1, (this.#stream.rows ?? 24) - FIXED_SCREEN_ROWS);
  }

  #activityLines(width: number): DashboardActivityLine[] {
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

function styleInlineCode(
  value: string,
  code: readonly string[] | undefined,
  kind: DashboardActivityLine["kind"],
): string {
  for (const text of code ?? []) {
    value = value.replace(
      text,
      `\u001B[2m${text}\u001B[22m${kind === "message" ? "\u001B[1m" : ""}`,
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
): string {
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

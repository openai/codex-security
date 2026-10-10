import { basename, isAbsolute } from "node:path";
import { emitKeypressEvents } from "node:readline";
import { PassThrough } from "node:stream";
import { pathToFileURL } from "node:url";
import stripAnsi from "strip-ansi";
import stringWidth from "string-width";
import { isRecord } from "./record.js";
import type { ScanBudget } from "./api.js";
import type { ScanModelConfiguration } from "./config.js";
import type {
  ComponentReceipt,
  ComponentScanEvent,
  ComponentScanResult,
} from "./component-scan.js";
import { formatUsd, type ScanCost, type ScanSessionEvent } from "./cost.js";
import {
  estimateScanCost,
  formatScanCost,
  formatScanCosts,
  formatScanCostTokens,
  formatTokenUsage,
  type ScanTokenUsage,
} from "./cost-model.js";
import type { ScanActivity } from "./scan-activity.js";
import type { ScanMode } from "./targets.js";
import { scanPhaseLabel, type ScanProgress } from "./worker-progress.js";

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
  queueMicrotask?(callback: () => void): void;
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
  presentation?: "scan" | "publication" | "verification" | "components";
  componentName?: string;
  mode?: ScanMode;
  model?: ScanModelConfiguration;
  maxCostUsd?: number;
  showCost?: boolean;
  clock: DashboardClock;
  color?: boolean;
  input?: DashboardInput;
  onInterrupt?: () => void;
}

interface TimedScanActivity extends ScanActivity {
  recordedAt: number;
}

interface ComponentView {
  receipt: ComponentReceipt;
  dashboard: ScanDashboard;
}

type DashboardActivityKind = ScanActivity["kind"] | "status" | "warning";

interface DashboardActivityLine {
  text: string;
  kind: DashboardActivityKind | "path" | "code";
  contentStart?: number;
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
  #startedAt: number;
  #finishedAt: number | null = null;
  #components: ComponentView[] = [];
  #selectedComponent = 0;
  #showComponent = false;
  #componentResult: ComponentScanResult | null = null;
  readonly #activities: TimedScanActivity[] = [];
  readonly #activityCache = new WeakMap<
    TimedScanActivity,
    { width: number; icon: string | undefined; lines: DashboardActivityLine[] }
  >();
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
  #tokens: string | null = null;
  #budget: {
    request: ScanBudget;
    input: string;
    error: string;
    finish: (limit?: number, preserveInput?: boolean) => void;
  } | null = null;
  #timer: NodeJS.Timeout | null = null;
  #refreshPending = false;
  #scrollOffset = 0;
  #view: "activity" | "details" = "activity";
  #source: "all" | "main" | number = "all";
  #inputWasRaw = false;
  #noteCount = 0;
  #observingStreamErrors = false;
  readonly #onStreamError = (): void => {};
  #keyInput: PassThrough | null = null;
  #ss3Parameters = false;
  #inputKeys: {
    keys: string[];
    continued: boolean;
    replay: boolean | string;
    text: string;
  } | null = null;
  readonly #onInput = (chunk: string | Uint8Array): void => {
    const batch = {
      keys: [] as string[],
      continued: false,
      replay: false as boolean | string,
      text: "",
    };
    let current = chunk;
    do {
      batch.replay = false;
      this.#inputKeys = batch;
      try {
        this.#keyInput?.write(current);
      } finally {
        this.#inputKeys = null;
      }
      if (typeof batch.replay === "string") current = batch.replay;
    } while (batch.replay);
    this.#handleKeys(batch.keys);
  };

  #setKeyInput(input: PassThrough | null): void {
    const previous = this.#keyInput;
    if (previous !== null) {
      previous.removeAllListeners("keypress");
      previous.on("keypress", () => {});
      // Readline clears its Escape timer on input, after the active keypress returns.
      queueMicrotask(() => {
        previous.write(" ");
        previous.removeAllListeners();
        previous.destroy();
      });
    }
    this.#keyInput = input;
    if (input === null) return;
    let pending = 0;
    this.#ss3Parameters = false;
    input.setEncoding("utf8");
    input.on("data", (text: string) => {
      if (this.#inputKeys !== null) {
        this.#inputKeys.continued = pending > 0;
        this.#inputKeys.text = text;
      }
      pending += text.length;
    });
    emitKeypressEvents(input);
    input.on(
      "keypress",
      (
        _text: unknown,
        key: { sequence: string; meta?: boolean; code?: string },
      ) => {
        pending -= key.sequence.length;
        if (this.#ss3Parameters) {
          if (/^[ -?]+$/u.test(key.sequence)) return;
          this.#ss3Parameters = false;
          if (/^[@-~]$/u.test(key.sequence)) return;
        }
        const escapes =
          key.code === undefined
            ? undefined
            : key.sequence.match(/^\u001B+(?=\u001B)/u)?.[0];
        // Readline ends modified SS3 keys at the parameter separator.
        const modifiedSs3 =
          key.code !== undefined &&
          /^\u001BO[0-?]+$/u.test(key.sequence.slice(escapes?.length ?? 0));
        if (modifiedSs3) this.#ss3Parameters = true;
        const keys = modifiedSs3
          ? [...(escapes ?? ""), key.sequence.slice(escapes?.length ?? 0)]
          : key.code !== undefined && key.sequence.endsWith("\u001B")
            ? ["\u001B"]
            : (key.meta && key.code === undefined) ||
                key.sequence.includes("\u0003")
              ? Array.from(key.sequence)
              : escapes !== undefined
                ? [...escapes, key.sequence.slice(escapes.length)]
                : [key.sequence];
        const batch = this.#inputKeys;
        const continued = batch?.continued === true;
        if (batch !== null) batch.continued = false;
        if (batch === null) this.#handleKeys(keys);
        else if (
          this.#budget !== null &&
          batch.keys.length === 0 &&
          keys.length > 1 &&
          keys[0] === "\u001B" &&
          continued
        ) {
          // The buffered Escape belongs to the prior chunk's budget dismissal.
          // Replay the complete remaining key, including a prefix from prior chunks.
          this.#handleKeys(["\u001B"]);
          this.#setKeyInput(new PassThrough());
          batch.replay =
            key.sequence.slice(1) + (pending ? batch.text.slice(-pending) : "");
        } else if (keys.length > 1 && keys.every((key) => key === "\u001B")) {
          // Readline can consume a following key's Escape as a repeated Escape.
          // Keep that introducer with the remaining decoded text for replay.
          const remaining =
            key.sequence + (pending ? batch.text.slice(-pending) : "");
          const prefix = remaining.match(/^\u001B+/u)![0];
          for (const escape of prefix.slice(0, -1)) batch.keys.push(escape);
          this.#setKeyInput(new PassThrough());
          batch.replay = remaining.slice(prefix.length - 1);
        } else batch.keys.push(...keys);
      },
    );
  }

  #handleKeys(keys: string[]): void {
    if (this.#budget !== null) {
      for (const key of keys) {
        const budget = this.#budget;
        if (budget === null) break;
        if (key === "\u0003" || key === "\u0004") {
          budget.finish();
          this.#options.onInterrupt?.();
        } else if (key === "\u001B") {
          budget.finish(undefined, true);
        } else if (key === "\r" || key === "\n") {
          const value = budget.input.trim();
          const limit = Number(value);
          const minimum = Math.max(
            budget.request.maxCostUsd,
            this.#cost?.estimatedUsd ?? budget.request.cost.estimatedUsd,
          );
          if (value === "") budget.finish();
          else if (Number.isFinite(limit) && limit > minimum)
            budget.finish(limit);
          else
            budget.error = `Enter a finite total above ${formatUsd(minimum)}.`;
        } else if (key === "\u007F" || key === "\b") {
          budget.input = budget.input.slice(0, -1);
        } else if (key === "\u0015") {
          budget.input = "";
        } else if (!key.startsWith("\u001B") && key >= " ") {
          budget.input += key;
        }
      }
      this.#refresh();
      return;
    }
    if (this.#options.presentation === "components") {
      this.#componentInput(keys);
      return;
    }
    let lines = 0;
    for (const key of keys) {
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
      } else if (
        ["\u001B[H", "\u001B[F", "\u001B[1~", "\u001B[4~"].includes(key)
      ) {
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
  }

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
        this.#setKeyInput(new PassThrough());
        input.setRawMode?.(true);
        input.resume?.();
        input.on("data", this.#onInput);
        this.#stream.write(ENABLE_ALTERNATE_SCROLL);
      }
      this.#stream.write(this.#frame());
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
    if (this.#refreshPending) this.#refresh();
    this.#options.clock.clearInterval(this.#timer);
    this.#timer = null;
    this.#budget?.finish();
    const input = this.#options.input;
    try {
      if (input?.isTTY === true) {
        input.off("data", this.#onInput);
        this.#setKeyInput(null);
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

  public setComponents(receipts: readonly ComponentReceipt[]): void {
    this.#components = receipts.map((receipt) => {
      const dashboard = new ScanDashboard(this.#stream, {
        ...this.#options,
        presentation: "scan",
        mode: "standard",
        componentName: receipt.name,
      });
      dashboard.setStage("Queued");
      dashboard.note(`Scope: ${receipt.paths.join(", ")}`);
      return { receipt: { ...receipt }, dashboard };
    });
    this.showComponents("Scanning components");
  }

  public updateComponent(receipt: ComponentReceipt): void {
    const component = this.#components.find(
      ({ receipt: current }) => current.id === receipt.id,
    );
    if (component === undefined) return;
    const { dashboard } = component;
    if (receipt.status !== component.receipt.status) {
      if (receipt.status === "started") {
        dashboard.#startedAt = this.#options.clock.now();
        dashboard.setStage("Preparing scan");
      } else if (receipt.status !== "pending") {
        dashboard.#finishedAt = this.#options.clock.now();
        dashboard.setStage(componentStatus(receipt));
        dashboard.note(
          receipt.error ??
            `${componentStatus(receipt)} · ${receipt.findingCount ?? 0} findings before deduplication`,
        );
      }
    }
    if (receipt.cost !== undefined) dashboard.setCost(receipt.cost);
    component.receipt = { ...receipt };
    this.#refresh();
  }

  public recordComponentEvent(event: ComponentScanEvent): void {
    const dashboard = this.#components.find(
      ({ receipt }) => receipt.id === event.componentId,
    )?.dashboard;
    if (dashboard === undefined) return;
    switch (event.type) {
      case "progress":
        dashboard.setFiles(event.value);
        dashboard.setStage(scanPhaseLabel(event.value.phase));
        break;
      case "activity":
        dashboard.record(event.value);
        break;
      case "session":
        dashboard.recordDetails(event.value);
        break;
      case "cost":
        dashboard.setCost(event.value);
        break;
      case "usage":
        dashboard.setUsage(event.value);
        break;
      case "workers":
        if (event.value.kind === "dispatch")
          dashboard.setStage(scanPhaseLabel(event.value.phase));
        break;
      case "warning":
        dashboard.note(event.value);
        break;
    }
    this.#scheduleRefresh();
  }

  public showComponents(stage: string): void {
    this.#showComponent = false;
    this.setStage(stage);
  }

  public finishComponents(result: ComponentScanResult): void {
    this.#componentResult = result;
    this.showComponents(
      result.failed ||
        result.incomplete ||
        result.deduplication?.status === "incomplete"
        ? "Finished with partial results"
        : "Complete",
    );
  }

  public setFiles(files: ScanProgress): void {
    this.#files = files;
    this.#refresh();
  }

  public setPublicationProgress(completed: number, total: number): void {
    this.#publicationProgress = { completed, total };
    this.#refresh();
  }

  public setCost(
    cost: Readonly<ScanCost>,
    maxCostUsd = this.#options.maxCostUsd,
  ): void {
    this.#cost = cost;
    this.#tokens = formatScanCostTokens(cost);
    this.#options.maxCostUsd = maxCostUsd;
    this.#refresh();
  }

  public setUsage(usage: Readonly<ScanTokenUsage>): void {
    this.#tokens = formatTokenUsage(usage);
    this.#refresh();
  }

  public requestBudgetIncrease(
    request: ScanBudget,
  ): Promise<number | undefined> {
    if (
      request.signal.aborted ||
      this.#timer === null ||
      this.#options.input?.isTTY !== true ||
      this.#budget !== null
    ) {
      return Promise.resolve(undefined);
    }
    this.#setKeyInput(new PassThrough());
    return new Promise((resolve) => {
      const abort = () => finish();
      const finish = (limit?: number, preserveInput = false) => {
        request.signal.removeEventListener("abort", abort);
        this.#budget = null;
        if (this.#timer !== null && !preserveInput)
          this.#setKeyInput(new PassThrough());
        this.#refresh();
        resolve(limit);
      };
      this.#budget = { request, input: "", error: "", finish };
      request.signal.addEventListener("abort", abort, { once: true });
      this.#refresh();
    });
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
    this.#scheduleRefresh();
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
      this.#scheduleRefresh();
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
      this.#stream.write(this.#frame());
    } catch {}
  }

  #scheduleRefresh(): void {
    if (this.#timer === null || this.#refreshPending) return;
    this.#refreshPending = true;
    (this.#options.clock.queueMicrotask ?? queueMicrotask)(() => {
      this.#refreshPending = false;
      this.#refresh();
    });
  }

  #frame(): string {
    if (this.#options.presentation === "components") {
      return this.#showComponent
        ? this.#components[this.#selectedComponent]!.dashboard.#frame()
        : this.#componentFrame();
    }
    const publication = this.#options.presentation === "publication";
    const verification = this.#options.presentation === "verification";
    const findingProgress = publication || verification;
    const width = this.#width();
    const activityRows = this.#activityRows();
    const divider = `  ${"─".repeat(Math.max(0, width - 4))}`;
    const elapsed = Math.max(
      0,
      Math.floor(
        ((this.#finishedAt ?? this.#options.clock.now()) - this.#startedAt) /
          1_000,
      ),
    );
    const time = formatElapsed(elapsed);
    const files =
      this.#files === null
        ? "waiting for inventory"
        : this.#files.filesCompleted > 0
          ? `${formatCount(this.#files.filesCompleted)} / ${formatCount(this.#files.filesTotal)} reviewed`
          : `${formatCount(this.#files.filesTotal)} in scope`;
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
    if (this.#options.componentName !== undefined)
      scrollStatus = `Esc components · ${scrollStatus}`;
    const model = this.#options.model;

    return this.#formatFrame([
      `  CODEX SECURITY  ·  ${publication ? "PUBLISH  ·  " : verification ? "VERIFY-FIX  ·  " : ""}${basename(this.#options.repository)}${this.#options.componentName === undefined ? "" : `  ·  ${this.#options.componentName}`}${model === undefined ? "" : `  ·  ${model.model} (${model.reasoningEffort})`}${this.#view === "details" ? `  ·  DETAILS${this.#source === "all" ? "" : ` · ${typeof this.#source === "number" ? `worker ${this.#source}` : this.#source}`}` : ""}`,
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
            ...this.#tokenLines(),
            ...this.#costLines(),
            ...(this.#budget === null
              ? []
              : [
                  `  BUDGET   Raise total USD limit: ${this.#budget.input}_`,
                  `           ${this.#budget.error || "Scan running. Enter blank/Esc keeps limit."}`,
                ]),
          ]),
      `  TIME     ${time}  ·  ${this.#budget === null ? scrollStatus : "Enter to apply · Ctrl+C to exit"}`,
    ]);
  }

  #formatFrame(lines: (string | DashboardActivityLine)[]): string {
    const width = this.#width();
    return (
      CURSOR_HOME +
      lines
        .map((line, index) => {
          const text = typeof line === "string" ? line : line.text;
          const clean = fitLine(text, width);
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
                  line.contentStart,
                );
          return `${ERASE_LINE}${formatted}`;
        })
        .join("\n")
    );
  }

  #componentInput(keys: readonly string[]): void {
    for (const key of keys) {
      if (key === "\u0003") {
        this.#options.onInterrupt?.();
      } else if (this.#showComponent) {
        if (key === "\u001B" || key === "b") this.#showComponent = false;
        else
          this.#components[this.#selectedComponent]!.dashboard.#handleKeys([
            key,
          ]);
      } else if (
        (key === "\r" || key === "\n") &&
        this.#components.length > 0
      ) {
        this.#showComponent = true;
      } else {
        const change =
          key === "\u001B[A"
            ? -1
            : key === "\u001B[B"
              ? 1
              : key === "\u001B[5~"
                ? -this.#componentRows()
                : key === "\u001B[6~"
                  ? this.#componentRows()
                  : 0;
        this.#selectedComponent = Math.max(
          0,
          Math.min(
            this.#components.length - 1,
            this.#selectedComponent + change,
          ),
        );
        if (key === "\u001B[H" || key === "\u001B[1~")
          this.#selectedComponent = 0;
        if (key === "\u001B[F" || key === "\u001B[4~")
          this.#selectedComponent = Math.max(0, this.#components.length - 1);
      }
    }
    this.#refresh();
  }

  #componentRows(): number {
    return Math.max(
      1,
      (this.#stream.rows ?? 24) - 10 - this.#componentCostLines().length,
    );
  }

  #componentFrame(): string {
    const width = this.#width();
    const rows = this.#componentRows();
    const first = Math.max(
      0,
      Math.min(
        this.#selectedComponent - Math.floor(rows / 2),
        this.#components.length - rows,
      ),
    );
    const costWidth = Math.max(
      8,
      ...this.#components.map(({ dashboard }) =>
        dashboard.#cost === null ? 1 : formatScanCost(dashboard.#cost).length,
      ),
    );
    const nameWidth = Math.max(
      10,
      width - 52 - (this.#showCost ? costWidth + 1 : 0),
    );
    const cell = (value: string, width: number): string => {
      const text = fitLine(value, width);
      return text + " ".repeat(width - stringWidth(text));
    };
    const row = (
      marker: string,
      name: string,
      status: string,
      files: string,
      findings: string,
      cost: string,
    ): string =>
      `  ${marker} ${cell(name, nameWidth)} ${cell(status, 24)} ${files.padStart(11)} ${findings.padStart(8)}${this.#showCost ? ` ${cost.padStart(8)}` : ""}`;
    const table = this.#components
      .slice(first, first + rows)
      .map(({ receipt, dashboard }, index) => {
        const files = dashboard.#files;
        return row(
          first + index === this.#selectedComponent ? "›" : " ",
          receipt.name,
          receipt.status === "started"
            ? dashboard.#stage
            : componentStatus(receipt),
          files === null
            ? "—"
            : `${formatCount(files.filesCompleted)}/${formatCount(files.filesTotal)}`,
          receipt.findingCount === undefined
            ? "—"
            : formatCount(receipt.findingCount),
          dashboard.#cost === null ? "—" : formatScanCost(dashboard.#cost),
        );
      });
    if (table.length === 0) table.push(`  ${this.#stage}…`);
    while (table.length < rows) table.push("");
    const count = (status: ComponentReceipt["status"]) =>
      this.#components.filter(({ receipt }) => receipt.status === status)
        .length;
    const selected = this.#components[this.#selectedComponent]?.receipt;
    const rawFindings = this.#components.reduce(
      (sum, { receipt }) => sum + (receipt.findingCount ?? 0),
      0,
    );
    const findings =
      this.#componentResult === null
        ? `${rawFindings} findings before deduplication`
        : `${this.#componentResult.sourceFindingCount} findings → ${this.#componentResult.findingCount} groups${this.#componentResult.deduplication?.status === "incomplete" ? " · matching incomplete" : ""}`;
    const divider = `  ${"─".repeat(Math.max(0, width - 4))}`;
    return this.#formatFrame([
      `  CODEX SECURITY  ·  COMPONENTS  ·  ${basename(this.#options.repository)}`,
      divider,
      `  ${count("completed")} complete · ${count("started")} running · ${count("pending")} queued · ${count("incomplete")} incomplete · ${count("failed")} failed`,
      "",
      row(" ", "Component", "Status", "Files", "Findings", "Cost"),
      ...table,
      divider,
      `  SCOPE    ${selected?.paths.join(", ") ?? "waiting for component plan"}`,
      `  STATUS   ${selected?.error ?? findings}`,
      ...this.#componentCostLines(),
      `  STAGE    ${this.#stage}`,
      `  TIME     ${formatElapsed(Math.max(0, Math.floor((this.#options.clock.now() - this.#startedAt) / 1_000)))} · ↑↓ select · Enter activity · Ctrl+C cancel`,
    ]);
  }

  get #showCost(): boolean {
    return (
      this.#options.showCost === true || this.#options.maxCostUsd !== undefined
    );
  }

  #componentCostLines(): string[] {
    if (!this.#showCost) return [];
    const costs = this.#components.flatMap(({ dashboard }) =>
      dashboard.#cost === null ? [] : [dashboard.#cost],
    );
    return wrapActivity(
      "  COST     ",
      `${costs.length === 0 ? "waiting for usage" : formatScanCosts(costs)} · component scans only`,
      this.#width(),
    );
  }

  #width(): number {
    return Math.max(1, Math.min(this.#stream.columns ?? 88, 160));
  }

  #activityRows(): number {
    return Math.max(
      1,
      (this.#stream.rows ?? 24) -
        FIXED_SCREEN_ROWS -
        (this.#budget === null ? 0 : 2) -
        (this.#options.presentation === "publication" ||
        this.#options.presentation === "verification"
          ? 0
          : this.#tokenLines().length - 1 + this.#costLines().length - 1) +
        (this.#options.presentation === "publication" ||
        this.#options.presentation === "verification"
          ? 2
          : this.#options.mode === "deep"
            ? 2
            : 0),
    );
  }

  #tokenLines(): string[] {
    const tokens = this.#tokens ?? "waiting for usage";
    return wrapActivity("  TOKENS   ", tokens, this.#width());
  }

  #costLines(): string[] {
    if (!this.#showCost) return [];
    if (
      this.#cost === null &&
      this.#options.maxCostUsd === undefined &&
      estimateScanCost(this.#options.model?.model, {
        input_tokens: 0,
        output_tokens: 0,
      }) === null
    ) {
      return [];
    }
    const cost =
      this.#cost === null
        ? this.#options.maxCostUsd === undefined
          ? "waiting for usage"
          : `— / ${formatUsd(this.#options.maxCostUsd)}`
        : `${formatScanCost(this.#cost)}${this.#options.maxCostUsd === undefined ? "" : `; short-context budget baseline: ${formatUsd(this.#cost.estimatedUsd)} / ${formatUsd(this.#options.maxCostUsd)} · ${budgetBar(this.#cost.estimatedUsd, this.#options.maxCostUsd)}`}`;
    return wrapActivity("  COST     ", cost, this.#width());
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
        const prefix = fitActivityPrefix(
          `  [${formatLocalTime(recordedAt)}] ${source} · `,
          width,
        );
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
          cache.lines.push({
            text,
            kind: "path",
            code,
            bold,
            contentStart: prefix.length,
          });
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
      generatedPrefix = "",
    ): void => {
      prefix = fitActivityPrefix(prefix, width);
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
          lines.push({
            text,
            kind: fenced ? "code" : kind,
            links,
            code,
            contentStart: prefix.length + generatedPrefix.length,
          });
          generatedPrefix = generatedPrefix
            .slice(text.length - prefix.length)
            .trimStart();
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
      const cached = this.#activityCache.get(entry);
      if (cached?.width === width && cached.icon === icon) {
        for (const line of cached.lines) lines.push(line);
        continue;
      }
      const first = lines.length;
      const timestamp = `[${formatLocalTime(entry.recordedAt)}]`;
      const worker =
        entry.worker === undefined ? "" : `worker ${entry.worker} · `;
      const prefix = `  ${timestamp} ${icon} `;
      append(prefix, `${worker}${entry.description}`, kind, worker);
      for (const path of entry.paths) {
        append(" ".repeat(prefix.length), path, "path");
      }
      this.#activityCache.set(entry, {
        width,
        icon,
        lines: lines.slice(first),
      });
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
    return `${typeof payload["role"] === "string" ? payload["role"] : "assistant"}: ${detailsText(payload["content"] ?? payload["message"])}`;
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

function replaceVisibleText(
  value: string,
  search: string,
  replacement: string,
  contentStart = 0,
): string {
  let replaced = false;
  let offset = 0;
  return value
    .split(/(\u001B\[[0-?]*[ -/]*[@-~]|\u001B\][\s\S]*?(?:\u0007|\u001B\\))/gu)
    .map((part, index) => {
      if (index % 2 === 1) return part;
      const start = Math.max(0, contentStart - offset);
      offset += part.length;
      if (replaced || start >= part.length) return part;
      return (
        part.slice(0, start) +
        part.slice(start).replace(search, () => {
          replaced = true;
          return replacement;
        })
      );
    })
    .join("");
}

function styleInlineCode(value: string, line: DashboardActivityLine): string {
  for (const text of line.bold ?? []) {
    value = replaceVisibleText(
      value,
      text,
      `\u001B[1m${text}\u001B[22m`,
      line.contentStart,
    );
  }
  for (const text of line.code ?? []) {
    value = replaceVisibleText(
      value,
      text,
      `\u001B[2m${text}\u001B[22m${line.kind === "message" ? "\u001B[1m" : ""}`,
      line.contentStart,
    );
  }
  return value;
}

function linkActivity(
  value: string,
  links: readonly DashboardActivityLink[] | undefined,
  contentStart?: number,
): string {
  for (const { label, target } of links ?? []) {
    const safe = safeHyperlinkTarget(target);
    if (safe !== undefined) {
      value = replaceVisibleText(
        value,
        label,
        `\u001B]8;;${safe}\u0007${label}\u001B]8;;\u0007`,
        contentStart,
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

function componentStatus(receipt: ComponentReceipt): string {
  return {
    pending: "Queued",
    started: "Running",
    completed: "Complete",
    incomplete: "Incomplete",
    failed: "Failed",
  }[receipt.status];
}

function formatLocalTime(timestamp: number): string {
  const date = new Date(timestamp);
  return [date.getHours(), date.getMinutes(), date.getSeconds()]
    .map((part) => String(part).padStart(2, "0"))
    .join(":");
}

function fitActivityPrefix(prefix: string, width: number): string {
  return width <= 2 ? "" : fitLine(prefix, width - 2);
}

function wrapActivity(prefix: string, value: string, width: number): string[] {
  prefix = fitActivityPrefix(prefix, width);
  const available = Math.max(1, width - stringWidth(prefix));
  const continuation = " ".repeat(prefix.length);
  const lines: string[] = [];
  const append = (text: string): void => {
    lines.push(`${lines.length === 0 ? prefix : continuation}${text}`);
  };
  let current = "";
  let separator = "";
  let currentWidth = 0;
  const widths = new Map<string, number>();
  const wrappedWords = new Map<string, ReturnType<typeof columnChunks>>();
  const text = terminalText(value);
  const segments = graphemes.segment(text);
  let offset = 0;
  for (const word of text.split(/(\s+)/u)) {
    const start = offset;
    offset += word.length;
    if (/^\s+$/u.test(word)) {
      separator = word;
      continue;
    }
    const ascii = /^[\u0020-\u007E]*$/u.test(word);
    let parts = ascii ? undefined : wrappedWords.get(word);
    if (!ascii && parts === undefined) {
      parts = columnChunks(word, available, widths, segments, start);
      wrappedWords.set(word, parts);
    }
    const wordWidth = ascii
      ? word.length
      : parts!.length > 1
        ? available + 1
        : parts![0]!.columns;
    if (wordWidth > available) {
      if (current !== "") {
        append(current);
        current = "";
      }
      const chunks =
        parts ?? columnChunks(word, available, widths, segments, start);
      const last = chunks.at(-1)!;
      current = last.text;
      currentWidth = last.columns;
      for (let index = 0; index < chunks.length - 1; index++)
        append(chunks[index]!.text);
    } else if (
      current !== "" &&
      currentWidth + stringWidth(separator) + wordWidth > available
    ) {
      append(current);
      current = word;
      currentWidth = wordWidth;
    } else {
      currentWidth += (current === "" ? 0 : stringWidth(separator)) + wordWidth;
      current = current === "" ? word : `${current}${separator}${word}`;
    }
    separator = "";
  }
  if (current !== "") append(current);
  return lines;
}

const graphemes = new Intl.Segmenter();

function columnChunks(
  value: string,
  width: number,
  widths = new Map<string, number>(),
  segments = graphemes.segment(value),
  offset = 0,
): { text: string; columns: number }[] {
  const parts: { text: string; columns: number }[] = [];
  let current = "";
  let columns = 0;
  const append = (text: string, size: number): void => {
    if (current !== "" && columns + size > width) {
      parts.push({ text: current, columns });
      current = "";
      columns = 0;
    }
    current += text;
    columns += size;
  };
  const appendGraphemes = (start: number, end: number): void => {
    while (start < end) {
      const next = segments.containing(offset + start)!;
      const boundary = Math.min(end, next.index + next.segment.length - offset);
      const segment = value.slice(start, boundary);
      let size = widths.get(segment);
      if (size === undefined) {
        size = stringWidth(segment);
        widths.set(segment, size);
      }
      append(segment, size);
      start = boundary;
    }
  };
  let cursor = 0;
  for (const match of value.matchAll(/[\u0020-\u007E]{2,}/gu)) {
    // Keep edge characters with Unicode that can attach to their grapheme.
    appendGraphemes(cursor, match.index + 1);
    let start = match.index + 1;
    const end = match.index + match[0].length - 1;
    while (start < end) {
      if (columns >= width) {
        parts.push({ text: current, columns });
        current = "";
        columns = 0;
      }
      const size = Math.min(width - columns, end - start);
      append(value.slice(start, start + size), size);
      start += size;
    }
    cursor = end;
  }
  appendGraphemes(cursor, value.length);
  if (current !== "" || parts.length === 0)
    parts.push({ text: current, columns });
  return parts;
}

function wrapCode(prefix: string, value: string, width: number): string[] {
  prefix = fitActivityPrefix(prefix, width);
  const prefixWidth = stringWidth(prefix);
  const continuation = " ".repeat(prefixWidth);
  return columnChunks(
    terminalText(value),
    Math.max(1, width - prefixWidth),
  ).map((part, index) => `${index === 0 ? prefix : continuation}${part.text}`);
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
    return `${prefix}\u001B[${style}m${marker}\u001B[39m${separator}${worker === undefined ? "" : `\u001B[36m${worker}\u001B[39m`}${kind === "message" ? `\u001B[1m${description}\u001B[22m` : description}`;
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

function terminalText(value: string): string {
  return stripAnsi(value).replaceAll(/[\u0000-\u001F\u007F]/gu, " ");
}

function fitLine(value: string, width: number): string {
  const clean = terminalText(value);
  if (stringWidth(clean) <= width) return clean;
  let clipped = "";
  let columns = 0;
  for (const { segment } of graphemes.segment(clean)) {
    columns += stringWidth(segment);
    if (columns > width - 1) break;
    clipped += segment;
  }
  return `${clipped}…`;
}

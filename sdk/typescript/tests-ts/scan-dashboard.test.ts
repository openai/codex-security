import { EventEmitter } from "node:events";
import { Writable } from "node:stream";
import { stripVTControlCharacters } from "node:util";
import { describe, expect, test } from "bun:test";
import type { ComponentReceipt } from "../src/component-scan.js";
import { ScanDashboard } from "../src/scan-dashboard.js";
import { capture, fakeResult } from "./cli-fixtures.js";

const STARTED_AT = new Date(2026, 6, 29, 9, 41, 0).getTime();

function fakeClock(now: () => number = () => STARTED_AT) {
  return {
    now,
    setInterval: () => ({}) as NodeJS.Timeout,
    clearInterval: () => {},
  };
}

function lastFrame(stderr: ReturnType<typeof capture>): string {
  return stripVTControlCharacters(stderr.text())
    .split("CODEX SECURITY  ·  juice-shop")
    .at(-1)!;
}

class DashboardTestInput extends EventEmitter {
  readonly isTTY = true;
  isRaw = false;

  setRawMode(value: boolean): this {
    this.isRaw = value;
    return this;
  }

  resume(): this {
    return this;
  }

  pause(): this {
    return this;
  }
}

describe("live scan dashboard", () => {
  test("edits a higher total budget while continuing to show live cost", async () => {
    const stderr = capture(true);
    const input = new DashboardTestInput();
    const dashboard = new ScanDashboard(stderr.stream, {
      repository: "/synthetic/repository",
      maxCostUsd: 20,
      clock: fakeClock(),
      input,
    });
    const controller = new AbortController();
    const cost = {
      ...fakeResult([], "complete", { input_tokens: 100, output_tokens: 1 })
        .cost!,
      estimatedUsd: 16,
    };
    dashboard.start();
    dashboard.setCost(cost);
    const answer = dashboard.requestBudgetIncrease({
      maxCostUsd: 20,
      cost,
      signal: controller.signal,
    });
    input.emit("data", "-30\r");
    expect(stderr.text()).toContain("Enter a finite total above");
    input.emit("data", "\u00150\r");
    input.emit("data", "\u0015Infinity\r");
    input.emit("data", "\u001520\r");
    dashboard.setCost({ ...cost, estimatedUsd: 21 });
    input.emit("data", "\u001520.5\r");
    expect(stderr.text()).toContain("above $21.00");
    expect(stderr.text()).toContain("$21.00 / $20.00");
    input.emit("data", "\u0015300\u007F\r");
    await expect(answer).resolves.toBe(30);
    dashboard.setCost({ ...cost, estimatedUsd: 21 }, 30);
    expect(stderr.text()).toContain("$21.00 / $30.00");
    dashboard.stop();
    expect(input.isRaw).toBe(false);
    expect(input.listenerCount("data")).toBe(0);
  });

  test.each(["enter", "escape", "abort", "stop", "interrupt", "eof"] as const)(
    "dismisses a budget prompt without increasing the limit on %s",
    async (action) => {
      const stderr = capture(true);
      const input = new DashboardTestInput();
      let interrupted = false;
      const dashboard = new ScanDashboard(stderr.stream, {
        repository: "/synthetic/repository",
        maxCostUsd: 20,
        clock: fakeClock(),
        input,
        onInterrupt: () => {
          interrupted = true;
        },
      });
      const controller = new AbortController();
      dashboard.start();
      const answer = dashboard.requestBudgetIncrease({
        maxCostUsd: 20,
        cost: {
          ...fakeResult([], "complete", { input_tokens: 100, output_tokens: 1 })
            .cost!,
          estimatedUsd: 16,
        },
        signal: controller.signal,
      });
      if (action === "abort") controller.abort();
      else if (action === "stop") dashboard.stop();
      else
        input.emit(
          "data",
          { enter: "\r", escape: "\u001B", interrupt: "\u0003", eof: "\u0004" }[
            action
          ],
        );
      await expect(answer).resolves.toBeUndefined();
      expect(interrupted).toBe(action === "interrupt" || action === "eof");
      input.emit("data", "30\r");
      dashboard.stop();
      expect(input.isRaw).toBe(false);
      expect(input.listenerCount("data")).toBe(0);
    },
  );

  test("shows concurrent components and keeps their activity and costs separate", () => {
    const stderr = capture(true);
    const input = new DashboardTestInput();
    let timers = 0;
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 110, rows: 20 },
      {
        repository: "/synthetic/project",
        presentation: "components",
        input,
        clock: {
          ...fakeClock(),
          setInterval: () => {
            timers++;
            return {} as NodeJS.Timeout;
          },
          clearInterval: () => {
            timers--;
          },
        },
      },
    );
    const receipts: ComponentReceipt[] = ["API", "Web", "Shared"].map(
      (name, index) => ({
        id: `component-${index + 1}`,
        name,
        paths: [`src/${name.toLowerCase()}`],
        status: "pending",
        outputDir: `/synthetic/results/${index + 1}`,
      }),
    );
    const frame = () =>
      stripVTControlCharacters(stderr.text().split("\u001B[H").at(-1)!);
    dashboard.start();
    dashboard.setComponents(receipts);
    for (const receipt of receipts.slice(0, 2))
      dashboard.updateComponent({ ...receipt, status: "started" });
    const cost = fakeResult([], "complete", {
      input_tokens: 100,
      output_tokens: 10,
    }).cost!;
    for (const [index, receipt] of receipts.slice(0, 2).entries()) {
      dashboard.recordComponentEvent({
        componentId: receipt.id,
        type: "progress",
        value: {
          phase: index === 0 ? "validation" : "discovery",
          filesCompleted: index + 1,
          filesTotal: 10,
        },
      });
      dashboard.recordComponentEvent({
        componentId: receipt.id,
        type: "cost",
        value: { ...cost, estimatedUsd: index + 1 },
      });
      dashboard.recordComponentEvent({
        componentId: receipt.id,
        type: "activity",
        value: {
          id: "same-activity-id",
          kind: "message",
          status: "completed",
          description: `${receipt.name} only activity`,
          paths: [],
        },
      });
      dashboard.recordComponentEvent({
        componentId: receipt.id,
        type: "session",
        value: {
          threadId: receipt.id,
          parentThreadId: null,
          event: {
            type: "event_msg",
            payload: {
              type: "agent_message",
              message: `${receipt.name} session detail`,
            },
          },
        },
      });
    }
    expect(frame()).toContain("2 running · 1 queued");
    expect(frame()).toContain("validating findings");
    expect(frame()).toContain("1/10");
    expect(frame()).toContain("2/10");
    expect(frame()).toContain("$3.00 · component scans only");
    expect(frame()).toContain("before deduplication");
    expect(frame().split("\n")).toHaveLength(20);
    input.emit("data", "\r");
    expect(frame()).toContain("API only activity");
    expect(frame()).not.toContain("Web only activity");
    expect(frame()).toContain("$1.00");
    input.emit("data", "d");
    expect(frame()).toContain("API session detail");
    expect(frame()).not.toContain("Web session detail");
    input.emit("data", "\u001B");
    input.emit("data", "\u001B[B\r");
    expect(frame()).toContain("Web only activity");
    expect(frame()).not.toContain("API only activity");
    dashboard.updateComponent({
      ...receipts[0]!,
      status: "completed",
      findingCount: 3,
      scanId: "scan-api",
    });
    dashboard.showComponents("Combining duplicate findings");
    expect(frame()).toContain("1 complete · 1 running · 1 queued");
    expect(frame()).toContain("3 findings before deduplication");
    dashboard.finishComponents({
      total: 3,
      completed: 1,
      incomplete: 1,
      failed: 1,
      planPath: "/synthetic/plan.json",
      sourceFindingCount: 3,
      findingCount: 2,
      deduplication: {
        status: "incomplete",
        confirmedGroups: 1,
        uncertainPairs: 0,
      },
    });
    expect(frame()).toContain("3 findings → 2 groups · matching incomplete");
    expect(frame()).toContain("partial results");
    expect(timers).toBe(1);
    dashboard.stop();
    expect(timers).toBe(0);
    expect(input.isRaw).toBe(false);
    expect(input.listenerCount("data")).toBe(0);
    expect(stderr.text().split("\u001B[?1049h")).toHaveLength(2);
  });

  test("navigates a long component list and shows sanitized failure details", () => {
    const stderr = capture(true);
    const input = new DashboardTestInput();
    let interrupted = false;
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 80, rows: 14 },
      {
        repository: "/synthetic/project",
        presentation: "components",
        input,
        clock: fakeClock(),
        sanitize: (value) => value.replaceAll("synthetic-secret", "[redacted]"),
        onInterrupt: () => {
          interrupted = true;
        },
      },
    );
    const receipts: ComponentReceipt[] = Array.from(
      { length: 20 },
      (_, index) => ({
        id: `c${index}`,
        name: `Component ${index}`,
        paths: [`src/${index}`],
        status: "pending",
        outputDir: `/synthetic/${index}`,
      }),
    );
    const frame = () =>
      stripVTControlCharacters(stderr.text().split("\u001B[H").at(-1)!);
    dashboard.start();
    dashboard.setComponents(receipts);
    dashboard.updateComponent({
      ...receipts[19]!,
      status: "failed",
      error: "synthetic-secret unavailable",
    });
    input.emit("data", "\u001B[F");
    expect(frame()).toContain("Component 19");
    expect(frame()).not.toContain("Component 0 ");
    expect(frame()).toContain("[redacted] unavailable");
    expect(
      frame()
        .split("\n")
        .every((line) => line.length <= 80),
    ).toBe(true);
    input.emit("data", "\r\u0003");
    expect(interrupted).toBe(true);
    dashboard.stop();
  });

  test("renders publication progress without scan-only inventory and cost fields", () => {
    const stderr = capture(true);
    const input = new DashboardTestInput();
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 100, rows: 18 },
      {
        repository: "/synthetic/payments-api",
        presentation: "publication",
        input,
        color: false,
        clock: fakeClock(),
      },
    );

    dashboard.setStage("Connecting to Linear");
    dashboard.start();
    input.emit("data", "d");
    let text = stripVTControlCharacters(stderr.text());
    expect(text).toContain("CODEX SECURITY  ·  PUBLISH  ·  payments-api");
    expect(text).toContain("Waiting for publication activity");
    expect(text).toContain("FINDINGS  waiting for findings");
    expect(text).not.toContain("FILES");
    expect(text).not.toContain("TOKENS");
    expect(text).not.toContain("COST");
    expect(text).not.toContain("DETAILS");
    expect(text).not.toContain("d details");

    dashboard.setPublicationProgress(2, 5);
    dashboard.setStage("Publishing findings · 2/5");
    dashboard.record({
      id: "publication-reasoning",
      kind: "reasoning",
      status: "completed",
      description: "Preparing the next Linear issue.",
      paths: [],
    });
    text = stripVTControlCharacters(stderr.text());
    expect(text).toContain("FINDINGS  2 / 5 processed");
    expect(text).toContain("Publishing findings · 2/5");
    expect(text).toContain("Preparing the next Linear issue.");
    dashboard.stop();
    expect(stderr.text()).toContain("\u001B[?25h\u001B[?1049l");
  });

  test("restores terminal state when dashboard initialization fails", () => {
    const input = new DashboardTestInput();
    const output: string[] = [];
    let timerCleared = false;
    const dashboard = new ScanDashboard(
      {
        write(chunk: string): boolean {
          output.push(chunk);
          if (chunk.includes("\u001B[H")) {
            throw new Error("Dashboard rendering failed.");
          }
          return true;
        },
      },
      {
        repository: "/synthetic/repository",
        input,
        clock: {
          ...fakeClock(),
          clearInterval: () => {
            timerCleared = true;
          },
        },
      },
    );

    expect(() => dashboard.start()).toThrow("Dashboard rendering failed.");
    expect(timerCleared).toBe(true);
    expect(input.isRaw).toBe(false);
    expect(input.listenerCount("data")).toBe(0);
    expect(output.join("")).toContain("\u001B[?25h\u001B[?1049l");
    dashboard.stop();
  });

  test("restores the screen when raw mode setup and cleanup both fail", () => {
    const stderr = capture(true);
    const input = new DashboardTestInput();
    input.setRawMode = (enabled) => {
      throw new Error(
        enabled
          ? "Raw mode initialization failed."
          : "Raw mode cleanup failed.",
      );
    };
    const dashboard = new ScanDashboard(stderr.stream, {
      repository: "/synthetic/repository",
      input,
      clock: fakeClock(),
    });

    expect(() => dashboard.start()).toThrow("Raw mode initialization failed.");
    expect(stderr.text()).toContain("\u001B[?25h\u001B[?1049l");
    expect(input.listenerCount("data")).toBe(0);
  });

  test("disables alternate scrolling when dashboard rollback fails", () => {
    const input = new DashboardTestInput();
    const output: string[] = [];
    input.setRawMode = (enabled) => {
      if (!enabled) throw new Error("Raw mode cleanup failed.");
      input.isRaw = enabled;
      return input;
    };
    const dashboard = new ScanDashboard(
      {
        write(chunk: string): boolean {
          output.push(chunk);
          if (chunk.includes("\u001B[H")) {
            throw new Error("Dashboard rendering failed.");
          }
          return true;
        },
      },
      { repository: "/synthetic/repository", input, clock: fakeClock() },
    );

    expect(() => dashboard.start()).toThrow("Dashboard rendering failed.");
    expect(output.join("")).toContain("\u001B[?1007h");
    expect(output.join("")).toContain("\u001B[?1007l\u001B[?25h\u001B[?1049l");
  });

  test("keeps later dashboard redraw failures from stopping the scan", () => {
    let redraw: (() => void) | undefined;
    let failRedraw = false;
    const dashboard = new ScanDashboard(
      {
        write(chunk: string): boolean {
          if (failRedraw && chunk.includes("\u001B[H")) {
            throw new Error("Dashboard redraw failed.");
          }
          return true;
        },
      },
      {
        repository: "/synthetic/repository",
        clock: {
          ...fakeClock(),
          setInterval: (callback) => {
            redraw = callback;
            return {} as NodeJS.Timeout;
          },
        },
      },
    );

    dashboard.start();
    failRedraw = true;

    expect(() => redraw?.()).not.toThrow();
    expect(() => dashboard.setStage("reviewing files")).not.toThrow();

    failRedraw = false;
    dashboard.stop();
  });

  test("handles asynchronous dashboard stream failures while a scan is active", async () => {
    let redraw: (() => void) | undefined;
    let failRedraw = false;
    const stream = new Writable({
      autoDestroy: false,
      write(_chunk, _encoding, callback) {
        if (failRedraw) {
          queueMicrotask(() => callback(new Error("Dashboard output failed.")));
        } else {
          callback();
        }
      },
    });
    const dashboard = new ScanDashboard(stream, {
      repository: "/synthetic/repository",
      clock: {
        ...fakeClock(),
        setInterval: (callback) => {
          redraw = callback;
          return {} as NodeJS.Timeout;
        },
      },
    });

    dashboard.start();
    expect(stream.listenerCount("error")).toBe(1);
    const failure = new Promise<Error>((resolve) =>
      stream.once("error", resolve),
    );
    failRedraw = true;
    redraw?.();
    dashboard.stop();
    expect(stream.listenerCount("error")).toBe(2);

    await expect(failure).resolves.toMatchObject({
      message: "Dashboard output failed.",
    });
    await new Promise<void>((resolve) => queueMicrotask(resolve));
    expect(stream.listenerCount("error")).toBe(0);
  });

  test("redraws real scan activity and metrics in place", () => {
    const stderr = capture(true);
    const timers: NodeJS.Timeout[] = [];
    const dashboard = new ScanDashboard(stderr.stream, {
      repository: "/code/juice-shop",
      maxCostUsd: 2,
      clock: {
        now: () => STARTED_AT + 19_000,
        setInterval: () => {
          const timer = {} as NodeJS.Timeout;
          timers.push(timer);
          return timer;
        },
        clearInterval: (timer) => {
          timers.splice(timers.indexOf(timer), 1);
        },
      },
    });

    dashboard.start();
    dashboard.setStage("reviewing files");
    dashboard.setFiles({
      phase: "discovery",
      filesCompleted: 0,
      filesTotal: 1_258,
    });
    dashboard.record({
      id: "read-1",
      kind: "command",
      status: "running",
      description: 'nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
      paths: ["routes/login.ts"],
    });
    dashboard.setCost(
      fakeResult([], "complete", {
        input_tokens: 17_985,
        cached_input_tokens: 10_496,
        output_tokens: 236,
      }).cost!,
    );
    dashboard.stop();

    const text = stripVTControlCharacters(stderr.text());
    expect(text).toContain("CODEX SECURITY  ·  juice-shop");
    expect(text).not.toContain("ACTIVITY");
    expect(text).not.toContain("events · live");
    expect(text).not.toContain("WORKERS");
    expect(text).toContain("STAGE");
    expect(text).toContain("FILES");
    expect(text).toContain(
      '[09:41:19] ◐ nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
    );
    expect(text).toContain("               routes/login.ts");
    expect(text).not.toContain("[09:41:19]   routes/login.ts");
    expect(text).toContain("routes/login.ts");
    expect(text).toContain("0 / 1,258 reviewed");
    expect(text).not.toContain("opened");
    expect(text).not.toContain("3 / 6 active");
    expect(text).toContain("17,985 in · 10,496 cached · 236 out");
    expect(text).toContain("/ $2.00");
    expect(stderr.text()).toContain("\u001B[?1049h");
    expect(stderr.text()).toContain("\u001B[?1049l");
    expect(stderr.text()).toContain("\u001B[H");
    expect(stderr.text()).toContain("\u001B[?25l");
    expect(stderr.text()).toContain("\u001B[?25h");
    expect(timers).toEqual([]);
  });

  test("hides stage and file counts during Deep scans without wasting screen rows", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 80, rows: 12 },
      {
        repository: "/code/juice-shop",
        mode: "deep",
        clock: fakeClock(),
      },
    );

    dashboard.start();
    dashboard.setStage("inspecting repository files");
    dashboard.setFiles({
      phase: "preflight",
      filesCompleted: 0,
      filesTotal: 1_258,
    });
    for (let index = 1; index <= 6; index += 1) {
      dashboard.record({
        id: `worker-1:read-${index}`,
        kind: "command",
        status: "completed",
        description: `Reviewed source file ${index}`,
        paths: [],
        worker: 1,
      });
    }
    dashboard.setCost(
      fakeResult([], "complete", {
        input_tokens: 1_250,
        cached_input_tokens: 200,
        output_tokens: 30,
      }).cost!,
    );

    const frame = lastFrame(stderr);
    dashboard.stop();

    expect(frame).not.toContain("STAGE");
    expect(frame).not.toContain("FILES");
    expect(frame).not.toContain("inspecting repository files");
    expect(frame).not.toContain("0 / 1,258 reviewed");
    expect(frame).toContain("worker 1 · Reviewed source file 1");
    expect(frame).toContain("worker 1 · Reviewed source file 6");
    expect(frame).toContain("TOKENS");
    expect(frame).toContain("COST");
    expect(frame).toContain("TIME");
  });

  test("updates the same activity when a command completes", () => {
    const stderr = capture(true);
    let now = STARTED_AT;
    const dashboard = new ScanDashboard(stderr.stream, {
      repository: "/code/juice-shop",
      clock: fakeClock(() => now),
    });

    dashboard.start();
    now = STARTED_AT + 19_000;
    dashboard.record({
      id: "read-1",
      kind: "command",
      status: "running",
      description: 'nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
      paths: ["routes/login.ts"],
    });
    now = STARTED_AT + 24_000;
    dashboard.record({
      id: "read-1",
      kind: "command",
      status: "completed",
      description: 'nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
      paths: ["routes/login.ts"],
    });
    dashboard.stop();

    const frame = lastFrame(stderr);
    expect(frame).toContain(
      '[09:41:19] ✓ nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
    );
    expect(frame).toContain("               routes/login.ts");
    expect(frame).toContain("00:24  ·  Ctrl+C to exit");
    expect(frame.match(/\n {15}routes\/login\.ts/gu)).toHaveLength(1);
  });

  test("shows repeated file inventory commands as one activity", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(stderr.stream, {
      repository: "/code/juice-shop",
      clock: fakeClock(),
    });

    dashboard.start();
    for (const [id, description] of [
      ["inventory-1", "rg --files --hidden"],
      ["inventory-2", "git ls-files"],
    ] as const) {
      dashboard.record({
        id,
        kind: "command",
        status: "completed",
        description,
        paths: [],
      });
    }
    dashboard.stop();

    const frame = lastFrame(stderr);
    expect(frame).toContain("[09:41:00] ✓ git ls-files");
    expect(frame).not.toContain("rg --files --hidden");
    expect(frame).not.toContain("Building the file inventory");
  });

  test("labels actual delegated worker activity", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(stderr.stream, {
      repository: "/code/juice-shop",
      clock: fakeClock(),
    });

    dashboard.start();
    dashboard.record({
      id: "worker-thread:search-1",
      kind: "command",
      status: "running",
      description: 'rg -n "password" routes/login.ts',
      paths: ["routes/login.ts"],
      worker: 2,
    });
    dashboard.stop();

    expect(stripVTControlCharacters(stderr.text())).toContain(
      '[09:41:00] ◐ worker 2 · rg -n "password" routes/login.ts',
    );
  });

  test("keeps parent and worker file inventories distinct", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(stderr.stream, {
      repository: "/code/juice-shop",
      clock: fakeClock(),
    });

    dashboard.start();
    for (const activity of [
      { id: "parent-inventory" },
      { id: "worker-inventory", worker: 1 },
    ]) {
      dashboard.record({
        ...activity,
        kind: "command",
        status: "completed",
        description: "rg --files --hidden",
        paths: [],
      });
    }
    dashboard.stop();

    const frame = lastFrame(stderr);
    expect(frame).toContain("[09:41:00] ✓ rg --files --hidden");
    expect(frame).toContain("[09:41:00] ✓ worker 1 · rg --files --hidden");
  });

  test("scrolls through history while keeping terminal text selectable", () => {
    const stderr = capture(true);
    const input = new DashboardTestInput();
    let interrupted = false;
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 80, rows: 14 },
      {
        repository: "/code/juice-shop",
        input,
        onInterrupt: () => {
          interrupted = true;
        },
        clock: fakeClock(),
      },
    );

    dashboard.start();
    expect(input.isRaw).toBe(true);
    for (let index = 1; index <= 20; index += 1) {
      dashboard.record({
        id: `action-${index}`,
        kind: "command",
        status: "completed",
        description: `rg -n finding-${index} routes.ts`,
        paths: [],
      });
    }

    let frame = lastFrame(stderr);
    expect(frame).toContain("finding-16");
    expect(frame).toContain("finding-20");
    expect(frame.indexOf("finding-16")).toBeLessThan(
      frame.indexOf("finding-20"),
    );

    input.emit("data", "\u001B[A");
    frame = lastFrame(stderr);
    expect(frame).toContain("finding-15");
    expect(frame).not.toContain("finding-20");

    input.emit("data", "\u001B[B");
    input.emit("data", "\u001B[A");
    frame = lastFrame(stderr);
    expect(frame).toContain("finding-15");
    expect(frame).not.toContain("finding-20");
    expect(frame).toContain("1 line above live");

    input.emit("data", "\u001B[H");
    frame = lastFrame(stderr);
    expect(frame).toContain("finding-1");
    expect(frame).not.toContain("finding-20");

    input.emit("data", "\u001B[F");
    frame = lastFrame(stderr);
    expect(frame).toContain("finding-20");
    expect(frame).not.toContain("events · live");
    expect(frame).not.toContain("ACTIVITY");

    input.emit("data", "\u0003");
    expect(interrupted).toBe(true);
    dashboard.stop();
    expect(input.isRaw).toBe(false);
    expect(input.listenerCount("data")).toBe(0);
    expect(stderr.text()).toContain("\u001B[?1007h");
    expect(stderr.text()).toContain("\u001B[?1007l");
    expect(stderr.text()).not.toContain("\u001B[?1000h");
    expect(stderr.text()).not.toContain("\u001B[?1006h");
  });

  test("batches trackpad scroll events without dropping movement", () => {
    const stderr = capture(true);
    const input = new DashboardTestInput();
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 80, rows: 14 },
      { repository: "/code/juice-shop", input, clock: fakeClock() },
    );

    dashboard.start();
    for (let index = 1; index <= 30; index += 1) {
      dashboard.record({
        id: `action-${index}`,
        kind: "command",
        status: "completed",
        description: `rg -n finding-${index} routes.ts`,
        paths: [],
      });
    }

    const framesBefore = stderr.text().match(/\u001B\[H/gu)?.length ?? 0;
    input.emit("data", Buffer.from("\u001B[A".repeat(6)));

    let frame = lastFrame(stderr);
    expect(frame).toContain("6 lines above live");
    expect(frame).toContain("finding-19");
    expect(frame).not.toContain("finding-30");
    expect(stderr.text().match(/\u001B\[H/gu)?.length).toBe(framesBefore + 1);

    input.emit("data", "\u001B[B".repeat(4));
    frame = lastFrame(stderr);
    expect(frame).toContain("2 lines above live");
    expect(frame).toContain("finding-28");
    expect(frame).not.toContain("finding-30");
    expect(stderr.text().match(/\u001B\[H/gu)?.length).toBe(framesBefore + 2);
    dashboard.stop();
  });

  test("scrolls half a page with Mac-friendly Ctrl+U and Ctrl+D", () => {
    const stderr = capture(true);
    const input = new DashboardTestInput();
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 80, rows: 14 },
      { repository: "/code/juice-shop", input, clock: fakeClock() },
    );

    dashboard.start();
    for (let index = 1; index <= 20; index += 1) {
      dashboard.record({
        id: `action-${index}`,
        kind: "command",
        status: "completed",
        description: `rg -n finding-${index} routes.ts`,
        paths: [],
      });
    }

    input.emit("data", "\u0015");
    let frame = lastFrame(stderr);
    expect(frame).toContain("3 lines above live");
    expect(frame).toContain("finding-13");
    expect(frame).not.toContain("finding-20");
    expect(frame).toContain("Ctrl+C to exit");
    expect(frame).not.toContain("Ctrl+U/Ctrl+D");
    expect(frame).not.toContain("PgUp/PgDn");

    input.emit("data", "\u0004");
    frame = lastFrame(stderr);
    expect(frame).toContain("finding-20");
    expect(frame).not.toContain("above live");

    input.emit("data", "\u001B[5~");
    expect(lastFrame(stderr)).toContain("6 lines above live");
    input.emit("data", "\u001B[6~");
    expect(lastFrame(stderr)).not.toContain("above live");
    dashboard.stop();
  });

  test("shows unredacted, chronological session events and keeps the activity view safe", () => {
    const stderr = capture(true);
    const input = new DashboardTestInput();
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 140, rows: 24 },
      {
        repository: "/code/juice-shop",
        input,
        color: true,
        clock: fakeClock(),
        sanitize: (value) => value.replaceAll("synthetic-secret", "[redacted]"),
      },
    );

    dashboard.start();
    dashboard.record({
      id: "activity-1",
      kind: "command",
      status: "completed",
      description: "rg -n synthetic-secret routes/login.ts",
      paths: [],
    });
    for (const [seconds, type, payload] of [
      [
        2,
        "turn_context",
        { model: "gpt-5.6-sol", developer_instructions: "Check boundaries." },
      ],
      [0, "session_meta", { base_instructions: { text: "Inspect safely." } }],
      [1, "message", { role: "user", content: [{ text: "Find bugs." }] }],
      [
        3,
        "function_call",
        {
          name: "exec_command",
          arguments:
            "synthetic-secret `literal` **glob** \u001B[31mspoofed\u001B[0m\u0007",
        },
      ],
      [
        4,
        "function_call_output",
        {
          output: [
            {
              text: "result\nfunction inspect() {\n  if (input) {\n    return input;\n  }\n\n  return null;\n}",
            },
          ],
        },
      ],
      [5, "agent_reasoning", { text: "Inspect **critical** `db.raw(input)`." }],
      [
        5,
        "reasoning",
        {
          summary: [
            { text: "Inspect **critical** `db.raw(input)`." },
            { text: "New final detail." },
          ],
          encrypted_content: "never-display-encrypted-reasoning",
        },
      ],
      [6, "agent_message", { message: "Confirmed." }],
      [6, "message", { role: "assistant", content: [{ text: "Confirmed." }] }],
      [7, "token_count", {}],
      [8, "reasoning", { summary: [] }],
      [9, "agent_reasoning", { text: "   " }],
    ] as [number, string, Record<string, unknown>][]) {
      dashboard.recordDetails({
        threadId: "scan-thread",
        parentThreadId: null,
        event: {
          type: ["session_meta", "turn_context"].includes(type)
            ? type
            : type.startsWith("agent_") || type === "token_count"
              ? "event_msg"
              : "response_item",
          payload: { type, ...payload },
          timestamp: new Date(STARTED_AT + seconds * 1_000).toISOString(),
        },
      });
    }

    let frame = lastFrame(stderr);
    expect(frame).toContain("rg -n [redacted] routes/login.ts");
    expect(frame).toContain("d details");

    input.emit("data", "d");
    frame = lastFrame(stderr);
    for (const line of [
      "main · system: Inspect safely.",
      "main · user: Find bugs.",
      "main · context: gpt-5.6-sol · Check boundaries.",
      "main · tool exec_command: synthetic-secret `literal` **glob** spoofed",
      "main · result: result",
      "main · reasoning: Inspect critical db.raw(input).",
      "main · reasoning: New final detail.",
      "main · assistant: Confirmed.",
    ]) {
      expect(frame).toContain(line);
    }
    expect(frame.indexOf("main · system:")).toBeLessThan(
      frame.indexOf("main · context:"),
    );
    const continuation = " ".repeat("  [09:41:04] main · ".length);
    expect(frame).toContain(`${continuation}  if (input) {`);
    expect(frame).toContain(`\n${continuation}\n${continuation}  return null;`);
    expect(frame).not.toContain("main · token count");
    expect(frame.match(/main · reasoning:/gu)).toHaveLength(2);
    expect(frame.match(/Inspect critical db\.raw\(input\)\./gu)).toHaveLength(
      1,
    );
    expect(frame.match(/Confirmed\./gu)).toHaveLength(1);
    for (const sequence of [
      "\u001B[2m[09:41:05]\u001B[22m",
      "\u001B[36mmain\u001B[39m",
      "\u001B[35mreasoning:\u001B[39m",
      "\u001B[36mtool exec_command:\u001B[39m",
      "\u001B[32mresult:\u001B[39m",
      "\u001B[36massistant:\u001B[39m",
      "\u001B[1mcritical\u001B[22m",
      "\u001B[2mdb.raw(input)\u001B[22m",
    ]) {
      expect(stderr.text()).toContain(sequence);
    }
    expect(frame).toContain("TOKENS");
    expect(stderr.text()).not.toContain("never-display-encrypted-reasoning");
    expect(stderr.text()).not.toContain("\u001B[31m");
    expect(stderr.text()).not.toContain("\u0007");

    input.emit("data", "d");
    frame = lastFrame(stderr);
    expect(frame).toContain("rg -n [redacted] routes/login.ts");
    expect(frame).not.toContain("synthetic-secret");
    dashboard.stop();
  });

  test("filters workers and scrolls the details separately from scan activity", () => {
    const stderr = capture(true);
    const input = new DashboardTestInput();
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 120, rows: 14 },
      { repository: "/code/juice-shop", input, clock: fakeClock() },
    );
    let payloadReads = 0;
    const event = (threadId: string, text: string, worker?: number) => {
      dashboard.recordDetails({
        threadId,
        parentThreadId: null,
        worker,
        event: {
          type: "event_msg",
          get payload() {
            payloadReads += 1;
            return { type: "agent_message", message: text };
          },
        },
      });
    };

    dashboard.start();
    event("worker-one", "Worker one inspected routes.", 1);
    event("scan-thread", "Main scan started.");
    event("worker-two", "Independent worker inspected models.", 2);
    for (let index = 1; index <= 10; index += 1) {
      event("scan-thread", `trace ${index}`);
    }

    input.emit("data", "d");
    for (const [source, included, excluded] of [
      ["m", "trace 10", "Worker one"],
      ["1", "Worker one", "Independent worker"],
      ["2", "Independent worker", "Worker one"],
    ] as const) {
      input.emit("data", source);
      const frame = lastFrame(stderr);
      expect(frame).toContain(
        `DETAILS · ${source === "m" ? "main" : `worker ${source}`}`,
      );
      expect(frame).toContain(included);
      expect(frame).not.toContain(excluded);
    }

    input.emit("data", "a");
    input.emit("data", "\u001B[H");
    let frame = lastFrame(stderr);
    expect(frame).toContain("worker 1 · assistant: Worker one");
    expect(frame).toContain("main · assistant: Main scan started.");
    expect(frame).not.toContain("trace 10");
    expect(frame).toContain("above live");

    const readsBeforeScroll = payloadReads;
    input.emit("data", "\u001B[B");
    input.emit("data", "\u001B[A");
    expect(payloadReads).toBe(readsBeforeScroll);

    event("scan-thread", "live result\nsecond line");
    frame = lastFrame(stderr);
    expect(frame).toContain("Worker one inspected routes.");
    expect(frame).not.toContain("live result");
    expect(payloadReads).toBe(readsBeforeScroll + 3);

    dashboard.record({
      id: "background-activity",
      kind: "command",
      status: "completed",
      description: "Background activity must not move the details.",
      paths: [],
    });
    frame = lastFrame(stderr);
    expect(frame).toContain("Worker one inspected routes.");
    expect(frame).not.toContain("trace 10");

    input.emit("data", "d");
    frame = lastFrame(stderr);
    expect(frame).toContain("Background activity must not move the details.");
    expect(frame).not.toContain("above live");
    expect(stderr.text()).not.toMatch(/\u001B\[[\d;]*m/u);
    dashboard.stop();
  });

  test("wraps real reasoning and assistant prose into chronological history", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 55, rows: 18 },
      {
        repository: "/code/juice-shop",
        clock: fakeClock(),
      },
    );

    dashboard.start();
    dashboard.record({
      id: "thinking-1",
      kind: "reasoning",
      status: "completed",
      description:
        "Checking whether the authentication route reaches a SQL query without validating the user input.",
      paths: [],
      worker: 1,
    });
    dashboard.record({
      id: "message-1",
      kind: "message",
      status: "completed",
      description: "The login route passes the request body to the query.",
      paths: [],
      worker: 1,
    });

    const frame = lastFrame(stderr);
    expect(frame).toContain("◦ worker 1 · Checking whether");
    expect(frame).toContain("● worker 1 · The login route");
    expect(frame).toContain("without validating the user");
    expect(frame).not.toContain("thinking ·");
    expect(frame).not.toContain("said ·");
    expect(frame.match(/\[09:41:00\]/gu)).toHaveLength(2);
    expect(frame).toMatch(/\n {15}\S/u);
    expect(frame.indexOf("◦ worker 1")).toBeLessThan(
      frame.indexOf("● worker 1"),
    );
    dashboard.stop();
  });

  test("shows streamed worker reasoning fully expanded and updates it in place", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 72, rows: 45 },
      {
        repository: "/code/juice-shop",
        color: true,
        clock: fakeClock(),
      },
    );
    const details = `${"The login route crosses an organization authorization boundary. ".repeat(18)}Final tenant-isolation check.`;

    dashboard.start();
    dashboard.record({
      id: "worker-thread:reasoning-1",
      kind: "reasoning",
      status: "running",
      description: "The login route crosses",
      paths: [],
      worker: 2,
    });
    dashboard.record({
      id: "worker-thread:reasoning-1",
      kind: "reasoning",
      status: "completed",
      description: details,
      paths: [],
      worker: 2,
    });

    const frame = lastFrame(stderr);
    expect(frame).toContain("[09:41:00] ◦ worker 2 · The login route");
    expect(frame).toMatch(/Final\s+tenant-isolation check\./u);
    expect(frame).not.toContain("…");
    expect(frame.match(/\[09:41:00\]/gu)).toHaveLength(1);
    expect(stderr.text()).toContain("\u001B[35m◦\u001B[39m");
    dashboard.stop();
  });

  test("renders compact clickable local Markdown links without repeating timestamps", () => {
    const stderr = capture(true);
    const target =
      "/private/tmp/codex security/scans/promptfoo-cloud/artifacts/02_discovery/raw_candidates_02.jsonl";
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 55, rows: 18 },
      { repository: "/code/juice-shop", clock: fakeClock() },
    );

    dashboard.start();
    dashboard.record({
      id: "message-link",
      kind: "message",
      status: "completed",
      description: `Inspecting [raw_candidates_02.jsonl](${target}) before final validation.`,
      paths: [],
      worker: 2,
    });

    const frame = lastFrame(stderr);
    expect(frame).toContain("raw_candidates_02.jsonl");
    expect(frame).not.toContain("/private/tmp/");
    expect(frame.match(/\[09:41:00\]/gu)).toHaveLength(1);
    expect(stderr.text()).toContain(
      `\u001B]8;;file:///private/tmp/codex%20security/scans/promptfoo-cloud/artifacts/02_discovery/raw_candidates_02.jsonl\u0007raw_candidates_02.jsonl\u001B]8;;\u0007`,
    );
    dashboard.stop();
  });

  test("renders fenced Markdown code with exact indentation and one timestamp", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 90, rows: 18 },
      { repository: "/code/juice-shop", color: true, clock: fakeClock() },
    );

    dashboard.start();
    dashboard.record({
      id: "message-code",
      kind: "message",
      status: "completed",
      description:
        "Found the vulnerable query:\n```ts\n  const query = db.raw(input);\n    return query;\n```\nCheck its caller.",
      paths: [],
    });

    const frame = lastFrame(stderr);
    expect(frame).toContain("Found the vulnerable query:");
    expect(frame).toContain("                 const query = db.raw(input);");
    expect(frame).toContain("                   return query;");
    expect(frame).toContain("               Check its caller.");
    expect(frame).not.toContain("```ts");
    expect(frame.match(/\[09:41:00\]/gu)).toHaveLength(1);
    expect(stderr.text()).toContain(
      "\u001B[2m                 const query = db.raw(input);\u001B[0m",
    );

    dashboard.record({
      id: "message-wrapped-code",
      kind: "message",
      status: "completed",
      description: `\`\`\`sh\nrg -n ${"password ".repeat(12)}routes/login.ts\n\`\`\``,
      paths: [],
    });
    expect(lastFrame(stderr).match(/\[09:41:00\]/gu)).toHaveLength(2);
    dashboard.stop();
  });

  test("renders inline code while preserving clickable links and exact commands", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 120, rows: 18 },
      { repository: "/code/juice-shop", color: true, clock: fakeClock() },
    );

    dashboard.start();
    dashboard.record({
      id: "message-inline-code",
      kind: "message",
      status: "completed",
      description:
        "Inspect `db.raw(  input  )` and `[literal](/tmp/example.md)` in [report](/tmp/report.md).",
      paths: [],
    });

    const frame = lastFrame(stderr);
    expect(frame).toContain(
      "Inspect db.raw(  input  ) and [literal](/tmp/example.md) in report.",
    );
    expect(frame).not.toContain("`db.raw(  input  )`");
    expect(stderr.text()).toContain("\u001B[2mdb.raw(  input  )\u001B[22m");
    expect(stderr.text()).toContain(
      "\u001B]8;;file:///tmp/report.md\u0007report\u001B]8;;\u0007",
    );
    expect(stderr.text()).not.toContain("\u001B]8;;file:///tmp/example.md");

    dashboard.record({
      id: "command-inline-code",
      kind: "command",
      status: "completed",
      description: "printf '`db.raw(input)`'",
      paths: [],
    });
    expect(lastFrame(stderr)).toContain("printf '`db.raw(input)`'");
    dashboard.stop();
  });

  test("redacts external Markdown link targets and rejects unsafe links", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 120, rows: 18 },
      {
        repository: "/code/juice-shop",
        color: false,
        clock: fakeClock(),
        sanitize: (value) => value.replaceAll("secret-token", "[redacted]"),
      },
    );

    dashboard.start();
    dashboard.record({
      id: "message-links",
      kind: "message",
      status: "completed",
      description:
        "See [report](https://example.com/report?token=secret-token), [unsafe](javascript:alert), and [control](/tmp/\u001B]2;spoof\u0007).",
      paths: [],
    });

    const frame = lastFrame(stderr);
    expect(frame).toContain("See report, unsafe, and control.");
    expect(stderr.text()).toContain(
      "\u001B]8;;https://example.com/report?token=[redacted]\u0007report\u001B]8;;\u0007",
    );
    expect(stderr.text()).not.toContain("secret-token");
    expect(stderr.text()).not.toContain("javascript:");
    expect(stderr.text()).not.toContain("spoof");
    expect(stderr.text()).not.toContain("\u001B]8;;javascript:");

    dashboard.record({
      id: "command-link",
      kind: "command",
      status: "completed",
      description: "printf '[report](/tmp/report.md)'",
      paths: [],
    });
    expect(lastFrame(stderr)).toContain("printf '[report](/tmp/report.md)'");
    expect(stderr.text()).not.toContain("\u001B]8;;file:///tmp/report.md");
    dashboard.stop();
  });

  test("sanitizes complete activity descriptions before line wrapping", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(
      { ...stderr.stream, columns: 50, rows: 18 },
      {
        repository: "/code/juice-shop",
        color: false,
        clock: fakeClock(),
        sanitize: (value) =>
          value.includes("client_secret=") ? "[redacted]" : value,
      },
    );

    dashboard.start();
    dashboard.record({
      id: "wrapped-secret",
      kind: "command",
      status: "completed",
      description:
        "Checking request configuration client_secret= SYNTHETIC_SECRET_VALUE",
      paths: [],
    });

    expect(lastFrame(stderr)).toContain("[redacted]");
    expect(stderr.text()).not.toContain("SYNTHETIC_SECRET_VALUE");
    dashboard.stop();
  });

  test("colors important activity while keeping prose readable across terminal themes", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(stderr.stream, {
      repository: "/code/juice-shop",
      color: true,
      clock: fakeClock(),
    });

    dashboard.start();
    dashboard.record({
      id: "command-1",
      kind: "command",
      status: "completed",
      description: "rg -n password routes/login.ts",
      paths: [],
    });
    dashboard.record({
      id: "tool-1",
      kind: "tool",
      status: "completed",
      description: "read routes/login.ts",
      paths: [],
    });
    dashboard.record({
      id: "reasoning-1",
      kind: "reasoning",
      status: "completed",
      description: "Tracing the login query.",
      paths: [],
      worker: 1,
    });
    dashboard.record({
      id: "message-1",
      kind: "message",
      status: "completed",
      description: "The login query accepts unvalidated input.",
      paths: [],
      worker: 1,
    });

    const raw = stderr.text();
    expect(raw).toContain("\u001B[1m  CODEX SECURITY  ·  juice-shop\u001B[0m");
    expect(raw).toContain(
      "\u001B[2m  [09:41:00] ✓ rg -n password routes/login.ts\u001B[0m",
    );
    expect(raw).toContain("\u001B[2m[09:41:00]\u001B[22m");
    expect(raw).toContain("\u001B[36m✓\u001B[39m read routes/login.ts");
    expect(raw).toContain(
      "\u001B[35m◦\u001B[39m \u001B[36mworker 1 · \u001B[39mTracing the login query.",
    );
    expect(raw).toContain(
      "\u001B[36m●\u001B[39m \u001B[36mworker 1 · \u001B[39m\u001B[1mThe login query accepts unvalidated input.\u001B[22m",
    );
    expect(raw).not.toContain("\u001B[1;37m");
    expect(raw).not.toContain("\u001B[1;36m");
    dashboard.stop();
  });

  test("colors successful scan milestones and warnings distinctly", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(stderr.stream, {
      repository: "/code/juice-shop",
      color: true,
      clock: fakeClock(),
    });

    dashboard.start();
    for (const status of [
      "Started preflight",
      "Started reviewing files",
      "Preflight: worker delegation supported (up to 6 worker slots).",
      "Scan phase: reviewing files (6 workers).",
    ]) {
      dashboard.note(status);
      expect(stderr.text()).toContain(
        `\u001B[2m[09:41:00]\u001B[22m \u001B[32m◆ ${status}\u001B[0m`,
      );
    }

    dashboard.note("Preflight: worker delegation unavailable.");
    expect(stderr.text()).toContain(
      "\u001B[2m[09:41:00]\u001B[22m \u001B[33m▲ Preflight: worker delegation unavailable.\u001B[0m",
    );
    dashboard.stop();
  });

  test("leaves activity uncolored when colors are disabled", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(stderr.stream, {
      repository: "/code/juice-shop",
      color: false,
      clock: fakeClock(),
    });

    dashboard.start();
    dashboard.record({
      id: "message-1",
      kind: "message",
      status: "completed",
      description: "The login query accepts unvalidated input.",
      paths: [],
      worker: 1,
    });
    dashboard.note("Started reviewing files");
    dashboard.note("Preflight: worker delegation unavailable.");

    expect(stderr.text()).not.toMatch(/\u001B\[[\d;]*m/u);
    expect(lastFrame(stderr)).toContain(
      "[09:41:00] ● worker 1 · The login query accepts unvalidated input.",
    );
    expect(lastFrame(stderr)).toContain("◆ Started reviewing files");
    expect(lastFrame(stderr)).toContain(
      "▲ Preflight: worker delegation unavailable.",
    );
    dashboard.stop();
  });

  test("removes terminal escape sequences from repository-controlled paths", () => {
    const stderr = capture(true);
    const dashboard = new ScanDashboard(stderr.stream, {
      repository: "/code/juice-shop",
      clock: fakeClock(() => 0),
    });

    dashboard.start();
    dashboard.record({
      id: "read-1",
      kind: "command",
      status: "running",
      description: 'cat "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
      paths: ["routes/\u001B[31mspoofed.ts"],
    });
    dashboard.stop();

    expect(stderr.text()).not.toContain("\u001B[31m");
    expect(stripVTControlCharacters(stderr.text())).toContain(
      "routes/spoofed.ts",
    );
  });
});

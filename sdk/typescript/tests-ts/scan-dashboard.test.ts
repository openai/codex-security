import { EventEmitter } from "node:events";
import { stripVTControlCharacters } from "node:util";
import { describe, expect, test } from "bun:test";
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

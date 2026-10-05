import { describe, expect, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import {
  FakeSignals,
  capture,
  dependencies,
  fakeResult,
  fakeSecurity,
} from "./cli-fixtures.js";
import { throwing } from "./support/errors.js";
import { createCliTest, runCapturedCli } from "./support/cli-run.js";

describe("CLI signals", () => {
  test("maps Ctrl-C and SIGTERM to conventional exits and preserves partial output", async () => {
    for (const [signal, expectedExit, phrase] of [
      ["SIGINT", 130, "Scan canceled by Ctrl-C."],
      ["SIGTERM", 143, "Scan terminated by SIGTERM."],
    ] as const) {
      const { stdout, stderr, runCli } = createCliTest(main);

      const signals = new FakeSignals();
      const onInterrupt = mock();
      const exit = await runCli(
        ["scan", "."],
        dependencies({
          signals,
          onRun: () => signals.emit(signal),
          onInterrupt,
        }),
      );
      expect(exit).toBe(expectedExit);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(phrase);
      expect(stderr.text()).toContain("Partial output was kept at /tmp/scan.");
      expect(onInterrupt).toHaveBeenCalled();
      expect(signals.listeners.get(signal)?.size).toBe(0);
    }
  });

  test("cancels runtime preparation when a signal arrives", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const signals = new FakeSignals();
    const deps = dependencies({ signals });
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        signals.emit("SIGINT");
        const signal = (options as { signal?: AbortSignal }).signal;
        expect(signal?.aborted).toBe(true);
        throw new DOMException("aborted", "AbortError");
      });
    expect(await runCli(["scan", "."], deps)).toBe(130);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Scan canceled by Ctrl-C.");
    expect(stderr.text()).toContain("No partial output was kept.");
  });

  test("preserves signals received during client cleanup", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const signals = new FakeSignals();
    const exit = await runCli(
      ["scan", "."],
      dependencies({
        signals,
        onClose: () => signals.emit("SIGTERM"),
      }),
    );
    expect(exit).toBe(143);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Scan terminated by SIGTERM.");
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  });

  test("lets a later repeated signal escape cleanup while suppressing delivery duplicates", async () => {
    const { stderr, runCli } = createCliTest(main, { stderr: true });

    const signals = new FakeSignals();
    const forced: string[] = [];
    const synchronousWrites: string[] = [];
    let now = 0;
    const deps = dependencies({ signals });
    deps.now = () => now;
    deps.writeSynchronously = (_stream, value) => synchronousWrites.push(value);
    deps.forceExit = (signal) => forced.push(signal);
    deps.createSecurity = () =>
      fakeSecurity(async () => {
        signals.emit("SIGINT");
        signals.emit("SIGINT");
        expect(forced).toEqual([]);
        now = 1_000;
        signals.emit("SIGINT");
        return fakeResult();
      });

    expect(await runCli(["scan", "."], deps)).toBe(130);
    expect(forced).toEqual(["SIGINT"]);
    expect(synchronousWrites).toEqual(["\u001B[?25h"]);
    expect(stderr.text()).toContain("\u001B[?25h");
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
  });

  test("does not debounce a different termination signal", async () => {
    const signals = new FakeSignals();
    const forced: string[] = [];
    let now = 0;
    const deps = dependencies({ signals });
    deps.now = () => now;
    deps.forceExit = (signal) => forced.push(signal);
    deps.createSecurity = () =>
      fakeSecurity(async () => {
        signals.emit("SIGINT");
        now = 100;
        signals.emit("SIGTERM");
        return fakeResult();
      });

    await runCapturedCli(main, ["scan", "."], deps);
    expect(forced).toEqual(["SIGTERM"]);
  });

  test("forces exit when synchronous terminal restoration fails", async () => {
    const signals = new FakeSignals();
    const forced: string[] = [];
    let now = 0;
    const deps = dependencies({ signals });
    deps.now = () => now;
    deps.writeSynchronously = throwing("terminal unavailable");
    deps.forceExit = (signal) => forced.push(signal);
    deps.createSecurity = () =>
      fakeSecurity(async () => {
        signals.emit("SIGINT");
        now = 1_000;
        signals.emit("SIGINT");
        return fakeResult();
      });

    await main(["scan", "."], capture().stream, capture(true).stream, deps);
    expect(forced).toEqual(["SIGINT"]);
  });
});

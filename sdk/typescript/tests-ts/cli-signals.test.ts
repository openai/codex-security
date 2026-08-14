import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  FakeSignals,
  capture,
  dependencies,
  fakePreflight,
  fakeResult,
} from "./cli-fixtures.js";

describe("CLI signals", () => {
  test("maps Ctrl-C and SIGTERM to conventional exits and preserves partial output", async () => {
    for (const [signal, expectedExit, phrase] of [
      ["SIGINT", 130, "Scan canceled by Ctrl-C."],
      ["SIGTERM", 143, "Scan terminated by SIGTERM."],
    ] as const) {
      const stdout = capture();
      const stderr = capture();
      const signals = new FakeSignals();
      let interrupted = false;
      const exit = await main(
        ["scan", "."],
        stdout.stream,
        stderr.stream,
        dependencies({
          signals,
          onRun: () => signals.emit(signal),
          onInterrupt: () => {
            interrupted = true;
          },
        }),
      );
      expect(exit).toBe(expectedExit);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(phrase);
      expect(stderr.text()).toContain("Partial output was kept at /tmp/scan.");
      expect(interrupted).toBe(true);
      expect(signals.listeners.get(signal)?.size).toBe(0);
    }
  });

  test("cancels runtime preparation when a signal arrives", async () => {
    const stdout = capture();
    const stderr = capture();
    const signals = new FakeSignals();
    const deps = dependencies({ signals });
    deps.createSecurity = () => ({
      run: async (_repository, options) => {
        signals.emit("SIGINT");
        const signal = (options as { signal?: AbortSignal }).signal;
        expect(signal?.aborted).toBe(true);
        throw new DOMException("aborted", "AbortError");
      },
      close: async () => {},
      preflight: async () => fakePreflight(),
    });
    expect(await main(["scan", "."], stdout.stream, stderr.stream, deps)).toBe(
      130,
    );
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Scan canceled by Ctrl-C.");
    expect(stderr.text()).toContain("No partial output was kept.");
  });

  test("preserves signals received during client cleanup", async () => {
    const stdout = capture();
    const stderr = capture();
    const signals = new FakeSignals();
    const exit = await main(
      ["scan", "."],
      stdout.stream,
      stderr.stream,
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
    const stdout = capture();
    const stderr = capture(true);
    const signals = new FakeSignals();
    const forced: string[] = [];
    const synchronousWrites: string[] = [];
    let now = 0;
    const deps = dependencies({ signals });
    deps.now = () => now;
    deps.writeSynchronously = (_stream, value) => synchronousWrites.push(value);
    deps.forceExit = (signal) => forced.push(signal);
    deps.createSecurity = () => ({
      run: async () => {
        signals.emit("SIGINT");
        signals.emit("SIGINT");
        expect(forced).toEqual([]);
        now = 1_000;
        signals.emit("SIGINT");
        return fakeResult();
      },
      close: async () => {},
      preflight: async () => fakePreflight(),
    });

    expect(await main(["scan", "."], stdout.stream, stderr.stream, deps)).toBe(
      130,
    );
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
    deps.createSecurity = () => ({
      run: async () => {
        signals.emit("SIGINT");
        now = 100;
        signals.emit("SIGTERM");
        return fakeResult();
      },
      close: async () => {},
      preflight: async () => fakePreflight(),
    });

    await main(["scan", "."], capture().stream, capture().stream, deps);
    expect(forced).toEqual(["SIGTERM"]);
  });

  test("forces exit when synchronous terminal restoration fails", async () => {
    const signals = new FakeSignals();
    const forced: string[] = [];
    let now = 0;
    const deps = dependencies({ signals });
    deps.now = () => now;
    deps.writeSynchronously = () => {
      throw new Error("terminal unavailable");
    };
    deps.forceExit = (signal) => forced.push(signal);
    deps.createSecurity = () => ({
      run: async () => {
        signals.emit("SIGINT");
        now = 1_000;
        signals.emit("SIGINT");
        return fakeResult();
      },
      close: async () => {},
      preflight: async () => fakePreflight(),
    });

    await main(["scan", "."], capture().stream, capture(true).stream, deps);
    expect(forced).toEqual(["SIGINT"]);
  });
});

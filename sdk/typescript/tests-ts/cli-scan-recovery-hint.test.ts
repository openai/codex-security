import { expect, spyOn, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";

for (const [requestedSignal, exitCode] of [
  [null, 2],
  ["SIGINT", 130],
  ["SIGTERM", 143],
] as const) {
  test.each(["list-scans", "get-cli-scan-resume"])(
    `a stalled %s hint preserves the ${requestedSignal ?? "failure"} exit`,
    async (blockedCommand) => {
      const deadline = new AbortController();
      const timeout = spyOn(AbortSignal, "timeout").mockImplementation(
        () => deadline.signal,
      );
      const signals = new FakeSignals();
      const stderr = capture();
      const observed: Array<AbortSignal | undefined> = [];
      const deps = dependencies({
        signals,
        onTurn: (_repository, options) => {
          (
            options as { onOutputDirReady?: (path: string) => void }
          ).onOutputDirReady?.("/tmp/synthetic-scan");
        },
        onRun: () => {
          if (requestedSignal !== null) signals.emit(requestedSignal);
          throw new Error("Synthetic scan failure");
        },
      });
      deps.runWorkbench = async (args, _input, signal) => {
        observed.push(signal);
        if (args[0] === blockedCommand) {
          // An unbounded call fails the assertion without hanging this test.
          if (signal === undefined) throw new Error("Missing deadline");
          await new Promise<void>((_resolve, reject) => {
            signal.addEventListener("abort", () => reject(signal.reason), {
              once: true,
            });
            deadline.abort(new Error("Synthetic locked workbench"));
          });
        }
        return {
          scans: [{ scanId: "synthetic-scan", scanDir: "/tmp/synthetic-scan" }],
        };
      };
      try {
        expect(
          await main(["scan", "."], capture().stream, stderr.stream, deps),
        ).toBe(exitCode);
        expect(observed.length).toBe(blockedCommand === "list-scans" ? 1 : 2);
        expect(observed.every((signal) => signal === deadline.signal)).toBe(
          true,
        );
        expect(timeout).toHaveBeenCalled();
        expect(stderr.text()).toContain(
          "Partial output was kept at /tmp/synthetic-scan.",
        );
        expect(stderr.text()).not.toContain("Synthetic locked workbench");
        if (requestedSignal === null)
          expect(stderr.text()).toContain("Synthetic scan failure");
      } finally {
        timeout.mockRestore();
      }
    },
  );
}

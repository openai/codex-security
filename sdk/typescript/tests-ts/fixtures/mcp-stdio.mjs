import { setImmediate } from "node:timers/promises";
import { z } from "incur";
import { serveScanMcp } from "../../src/cli-mcp.ts";

const write = process.stdout.write;
process.stdout.write = function (...args) {
  const ready = Reflect.apply(write, this, args);
  if (!ready && process.argv[2] !== "flowing")
    process.send({ event: "backpressure" });
  return ready;
};

async function main() {
  const exitCode = await serveScanMcp({
    input: process.stdin,
    output: process.stdout,
    dependencies: {
      addSignalListener: (signal, listener) => process.on(signal, listener),
      removeSignalListener: (signal, listener) => process.off(signal, listener),
      now: Date.now,
      forceExit: (signal) => process.kill(process.pid, signal),
    },
    scanInputSchema: z.object({ waitForAbort: z.boolean().optional() }),
    infoInputSchema: z.object({}),
    infoOutputSchema: z.object({}),
    readInfo: async () => ({}),
    runScan: async ({ waitForAbort }, signal) => {
      if (!waitForAbort)
        return { exitCode: 0, data: { payload: "x".repeat(1024 * 1024) } };
      process.send({ event: "scan-started" });
      await new Promise((resolve) =>
        signal.addEventListener("abort", resolve, { once: true }),
      );
      process.send({
        event: "cleanup-started",
        outputDestroyed: process.stdout.destroyed,
      });
      await new Promise((resolve) => process.once("message", resolve));
      await setImmediate();
      await new Promise((resolve) =>
        process.send({ event: "cleanup-finished" }, resolve),
      );
      return { exitCode: 130 };
    },
  });
  process.exitCode = exitCode;
  process.send({ event: "returned", exitCode }, () => process.disconnect());
}

void main();

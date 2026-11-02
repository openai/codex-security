import { writeSync } from "node:fs";
import { main } from "../../src/cli.js";
import type { Finding } from "../../src/index.js";

const signal = process.argv[2] === "SIGTERM" ? "SIGTERM" : "SIGINT";
const evidence = "x".repeat(525_000);
const findings = [1, 2, 3].map(
  (index) =>
    ({
      findingId: `csf_${index}`,
      occurrenceId: `occ_${index}`,
      title: `Finding ${index}`,
      severity: "high",
      description: "Synthetic verification finding",
      codeEvidence: [{ path: `src/finding-${index}.ts`, code: evidence }],
    }) as unknown as Finding,
);
let workers = 0;

const dependencies = {
  environment: { TERM: "xterm-256color" },
  currentDirectory: () => "/tmp/verify-fix-signal-gap",
  now: Date.now,
  setInterval,
  clearInterval,
  addSignalListener: (name: NodeJS.Signals, listener: () => void) =>
    process.on(name, listener),
  removeSignalListener: (name: NodeJS.Signals, listener: () => void) =>
    process.off(name, listener),
  writeSynchronously: (
    stream: NodeJS.WritableStream & { fd?: number },
    value: string,
  ) => writeSync(stream.fd!, value),
  forceExit: (name: NodeJS.Signals) => process.kill(process.pid, name),
  checkForUpdate: async () => undefined,
  runWorkbench: async () => ({
    scan: {
      scanId: "scan-signal-gap",
      targetPath: "/tmp/verify-fix-signal-gap",
      findings,
    },
  }),
  readSavedFindings: async () => findings,
  runCodex: async (
    _arguments: readonly string[],
    output: {
      appServer?: { prompt: string };
      stdout: NodeJS.WritableStream;
    },
  ) => {
    workers += 1;
    process.stderr.write(`PTY_WORKER_${workers}\n`);
    const supplied = JSON.parse(
      output.appServer!.prompt.split("\n").at(-1)!,
    ) as Finding[];
    output.stdout.write(
      JSON.stringify({
        results: supplied.map(({ occurrenceId }) => ({
          id: occurrenceId,
          status: "fixed",
          evidence: "Synthetic verification passed.",
        })),
      }),
    );
    if (workers === 1) {
      setImmediate(() => {
        process.stderr.write("PTY_SIGNAL_BETWEEN_BATCHES\n");
        process.kill(process.pid, signal);
      });
    }
    return 0;
  },
  matchFindings: async () => ({ matches: [], uncertain: [] }),
  exportFindings: async () => undefined,
} as unknown as NonNullable<Parameters<typeof main>[3]>;

const exitCode = await main(
  ["verify-fix", "--scan", "scan-signal-gap", "--json"],
  process.stdout,
  process.stderr,
  dependencies,
);
process.stderr.write(`PTY_EXIT_${exitCode}\n`);
process.exitCode = exitCode;

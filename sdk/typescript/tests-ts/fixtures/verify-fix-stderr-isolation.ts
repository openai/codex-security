import { throws } from "node:assert/strict";
import { spawn } from "node:child_process";
import { closeSync, createWriteStream } from "node:fs";
import { createInterface } from "node:readline";
import { Writable } from "node:stream";
import { main, runCodexSkillCommand } from "../../src/cli.js";
import { dependencies, fakeResult } from "../cli-fixtures.js";
import type { JsonObject } from "../../src/index.js";

const scenario = process.argv[2] ?? "quiet-success";
if (
  scenario.startsWith("pty-") ||
  scenario === "single-saved-progress-interactive"
)
  void process.stderr.columns;
const sync = createWriteStream("", {
  fd: Number(process.env["VERIFY_FIX_SYNC_FD"] ?? "3"),
  autoClose: false,
});
const controls = createInterface({ input: process.stdin });
const pendingControls: Array<() => void> = [];
const queuedControls: string[] = [];

controls.on("line", (line) => {
  const pending = pendingControls.shift();
  if (pending === undefined) queuedControls.push(line);
  else pending();
});

function nextControl(): Promise<void> {
  if (queuedControls.length > 0) {
    queuedControls.shift();
    return Promise.resolve();
  }
  return new Promise((resolve) => pendingControls.push(resolve));
}

async function notify(value: JsonObject): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    sync.write(`${JSON.stringify(value)}\n`, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

const result = fakeResult(["high", "high", "high"]);
let singleRequest = scenario.startsWith("single-saved-progress");
const largeEvidence = '"quoted"\n'.repeat(60_000);
result.findings.findings.forEach((finding, index) => {
  Object.assign(finding, {
    occurrenceId: `occ_${index}`,
    findingId: `csf_${index}`,
    codeEvidence: [
      {
        path: "src/check.ts",
        code: singleRequest ? "compact evidence" : largeEvidence,
      },
    ],
  });
});

function setSingleRequest(value: boolean): void {
  singleRequest = value;
  for (const finding of result.findings.findings) {
    finding.codeEvidence![0]!.code = value ? "compact evidence" : largeEvidence;
  }
}

if (scenario === "pty-oversized") {
  result.findings.findings[0]!.codeEvidence![0]!.code = largeEvidence.repeat(2);
}

const publishWorkerPid = `
const { writeFileSync, renameSync } = require("node:fs");
const statePath = process.env.VERIFY_FIX_WORKER_STATE;
writeFileSync(statePath + ".tmp", JSON.stringify({ pid: process.pid }));
renameSync(statePath + ".tmp", statePath);
`;

let invocationWorker = 0;
const base = dependencies({
  environment: {
    ...process.env,
    CI: scenario.endsWith("-ci") ? "1" : undefined,
    CODEX_SECURITY_NO_UPDATE_NOTICE: undefined,
    NO_UPDATE_NOTIFIER: undefined,
    TERM: "xterm-256color",
  },
  result,
  onUpdateCheck: async () => {
    if (scenario !== "pty-text-update") return undefined;
    await notify({ event: "update-checked" });
    return {
      currentVersion: "1.0.0",
      latestVersion: "2.0.0",
      command: "update",
    };
  },
  onWorkbench: async () => {
    if (scenario === "pty-oversized") {
      process.once(
        "SIGWINCH",
        () => void notify({ event: "selection-resized" }),
      );
      await notify({ event: "selecting" });
      await nextControl();
    }
    return {
      scan: {
        scanId: "scan",
        targetPath: process.cwd(),
        findings: result.findings.findings as unknown as JsonObject[],
      },
    };
  },
  onCodex: async (_args, output) => {
    invocationWorker += 1;
    const batchWorker = invocationWorker;
    await notify({
      event: "worker-started",
      worker: batchWorker,
      pid: process.pid,
    });
    if (singleRequest) {
      await notify({
        event: "single-request-progress",
        hasOnEvent: output?.appServer?.onEvent !== undefined,
      });
      output?.appServer?.onEvent?.({
        method: "item/started",
        params: {
          item: {
            id: "single-command",
            type: "commandExecution",
            command: "rg authorization src/guard.ts",
          },
        },
      });
      output?.stdout.write(
        JSON.stringify({
          results: ["occ_0", "occ_1", "occ_2"].map((id) => ({
            id,
            status: "fixed",
            evidence: `Verified ${id} against source.`,
          })),
        }),
      );
      return 0;
    }
    if (
      batchWorker === 2 &&
      scenario !== "repeated-main" &&
      scenario !== "pty-oversized"
    )
      await nextControl();

    const id = `occ_${batchWorker - 1}`;
    if (batchWorker === 2 && scenario === "progress-success") {
      output?.appServer?.onEvent?.({
        method: "item/started",
        params: {
          item: {
            id: "command-2",
            type: "commandExecution",
            command: "rg authorization src/guard.ts",
          },
        },
      });
    }
    if (batchWorker === 2 && scenario.startsWith("pty-backpressure-")) {
      for (let index = 0; index < 5_000; index += 1) {
        output?.appServer?.onEvent?.({
          method: "item/started",
          params: {
            item: {
              id: `command-${index}`,
              type: "commandExecution",
              command: `rg authorization ${"nested/".repeat(20)}src/guard-${index}.ts`,
            },
          },
        });
      }
      await notify({ event: "progress-queued", worker: batchWorker });
      if (scenario === "pty-backpressure-worker-failure") {
        const state = process.env["VERIFY_FIX_WORKER_STATE"];
        if (state === undefined) throw new Error("Missing worker state path.");
        const child = spawn(
          process.execPath,
          [
            "-e",
            `
${publishWorkerPid}
process.stderr.write("Second worker original diagnostic.\\n", () => process.exit(7));
`,
          ],
          {
            env: { VERIFY_FIX_WORKER_STATE: state },
            stdio: ["ignore", "ignore", "pipe"],
          },
        );
        let diagnostic = "";
        child.stderr.setEncoding("utf8").on("data", (chunk: string) => {
          diagnostic += chunk;
        });
        const status = await new Promise<number>((resolve, reject) => {
          child.once("error", reject);
          child.once("close", (code) => resolve(code ?? 1));
        });
        output?.stderr.write(diagnostic);
        return status;
      }
      if (scenario !== "pty-backpressure-success") {
        const state = process.env["VERIFY_FIX_WORKER_STATE"];
        if (state === undefined) throw new Error("Missing worker state path.");
        let signalHandlers = "";
        if (scenario.includes("mixed")) {
          // The child acknowledges the first forwarded signal before the harness sends the second.
          process.once(
            "SIGUSR2",
            () => void notify({ event: "worker-signaled" }),
          );
          const first = scenario.includes("mixed-sigint-")
            ? "SIGINT"
            : "SIGTERM";
          signalHandlers = `
process.on("SIGINT", () => {});
process.on("SIGTERM", () => {});
process.once("${first}", () => process.kill(process.ppid, "SIGUSR2"));
`;
        }
        const source = `
${signalHandlers}
${publishWorkerPid}
setInterval(() => {}, 1_000);
`;
        return runCodexSkillCommand(
          ["-e", source, "--"],
          { ...output!, auth: undefined },
          { command: process.execPath },
          {
            VERIFY_FIX_WORKER_STATE: state,
            CODEX_SECURITY_STATE_DIR: `${state}.state`,
          },
        );
      }
    }
    if (batchWorker === 2 && scenario === "worker-failure") {
      output?.stderr.write("Second worker original diagnostic.\n");
      return 1;
    }
    if (batchWorker === 2 && scenario === "unrelated-stderr-error") {
      const error = Object.assign(new Error("Synthetic unrelated error."), {
        code: "EBADF",
      });
      throws(
        () => process.stderr.emit("error", error),
        (caught) => caught === error,
      );
      const observed = new Promise<Error>((resolve) =>
        process.stderr.once("error", resolve),
      );
      process.nextTick(() => process.stderr.emit("error", error));
      await notify({
        event: "stderr-error-observed",
        message: (await observed).message,
      });
    }
    output?.stdout.write(
      JSON.stringify({
        results: [
          {
            id,
            status: "fixed",
            evidence: `Verified ${id} against source.`,
          },
        ],
      }),
    );
    return 0;
  },
});

const liveSignals = {
  ...base,
  addSignalListener(signal: "SIGINT" | "SIGTERM", listener: () => void) {
    process.on(signal, listener);
  },
  removeSignalListener(signal: "SIGINT" | "SIGTERM", listener: () => void) {
    process.off(signal, listener);
  },
};

const arguments_ = [
  "verify-fix",
  "--scan",
  "scan",
  "--severity",
  "high",
  ...(scenario === "pty-text-update" ? [] : ["--json"]),
];
const discardedOutput = new Writable({
  write(_chunk, _encoding, done) {
    done();
  },
});
const runVerification = (
  output: Parameters<typeof main>[1] = process.stdout,
) => {
  invocationWorker = 0;
  return main(arguments_, output, process.stderr, liveSignals);
};

try {
  let exitCode: number;
  if (scenario === "pty-cleanup-sigwinch") {
    exitCode = await runVerification(discardedOutput);
    await notify({
      event: "invocation-complete",
      invocation: 1,
      exitCode,
      stderrErrorListeners: process.stderr.listenerCount("error"),
    });
    setSingleRequest(true);
    exitCode = await runVerification(discardedOutput);
    await notify({
      event: "invocation-complete",
      invocation: 2,
      exitCode,
      stderrErrorListeners: process.stderr.listenerCount("error"),
    });
    setSingleRequest(false);
    exitCode = await runVerification();
    await notify({
      event: "invocation-complete",
      invocation: 3,
      exitCode,
      stderrErrorListeners: process.stderr.listenerCount("error"),
    });
  } else {
    exitCode = await runVerification();
  }
  if (scenario === "repeated-main") {
    await notify({
      event: "invocation-complete",
      invocation: 1,
      exitCode,
      stderrErrorListeners: process.stderr.listenerCount("error"),
    });
    exitCode = await runVerification();
  }
  await new Promise<void>((resolve) => setImmediate(resolve));
  await notify({
    event: "complete",
    exitCode,
    sigintListeners: process.listenerCount("SIGINT"),
    sigtermListeners: process.listenerCount("SIGTERM"),
    stderrErrorListeners: process.stderr.listenerCount("error"),
  });
  if (scenario === "pty-cleanup-sigwinch") {
    process.once("SIGWINCH", () => {
      void notify({ event: "post-cleanup-sigwinch" });
    });
    await notify({ event: "cleanup-ready" });
    await nextControl();
  }
  if (
    ["pty-quiet-success", "pty-oversized", "pty-cleanup-sigwinch"].includes(
      scenario,
    )
  ) {
    // The harness has hung up this PTY. Close it after all CLI observations so
    // older Node releases do not abort restoring it during native shutdown.
    process.once("exit", () => closeSync(2));
  }
  controls.close();
  sync.end();
  process.exitCode = exitCode;
} catch (error) {
  await new Promise<void>((resolve) => setImmediate(resolve));
  await notify({
    event: "rejected",
    message: error instanceof Error ? error.message : String(error),
    sigintListeners: process.listenerCount("SIGINT"),
    sigtermListeners: process.listenerCount("SIGTERM"),
    stderrErrorListeners: process.stderr.listenerCount("error"),
  });
  controls.close();
  sync.end();
  process.stderr.write(
    `fixture: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 2;
}

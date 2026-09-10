import {
  spawn,
  type ChildProcessWithoutNullStreams,
  type SpawnOptionsWithoutStdio,
} from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { configuredCodexHome, readCodexHomeConfig } from "./auth.js";
import { CodexSecurityError } from "./errors.js";
import {
  codexSecurityCredentialHome,
  executablePathForSpawn,
  resolveCodexCommand,
} from "./runtime.js";
import { readSavedScanLogs, type ScanLogSource } from "./scan-logs.js";
import {
  BUNDLED_PLUGIN_VERSION,
  CODEX_EXECUTABLE_VERSION,
  CODEX_SDK_VERSION,
  VERSION,
} from "./version.js";

interface FeedbackOptions {
  reason: string;
  includeLogs: boolean;
  scan?: ScanLogSource;
  environment: NodeJS.ProcessEnv;
  workingDirectory: string;
  signal?: AbortSignal;
}

type StartCodex = (
  command: string,
  args: readonly string[],
  options: SpawnOptionsWithoutStdio & { stdio: ["pipe", "pipe", "pipe"] },
) => ChildProcessWithoutNullStreams;

export async function sendFeedback(
  options: FeedbackOptions,
  startCodex: StartCodex = spawn,
) {
  const { scan, environment, includeLogs } = options;
  options.signal?.throwIfAborted();
  const codexHome = codexSecurityCredentialHome(environment);
  const config = await readCodexHomeConfig(environment);
  const feedback = config["feedback"] as { enabled?: boolean } | undefined;
  if (feedback?.enabled === false) {
    throw new CodexSecurityError(
      "Sending feedback is disabled by configuration.",
    );
  }

  let directory: string | undefined;
  try {
    const extraLogFiles: string[] = [];
    if (includeLogs && scan !== undefined) {
      try {
        const logs = await readSavedScanLogs(
          scan,
          [codexHome, configuredCodexHome(environment)],
          { allowMissingRoot: true },
        );
        if (logs.sessions.length > 0) {
          directory = await mkdtemp(join(tmpdir(), "codex-security-feedback-"));
          const path = join(directory, "scan-logs.json");
          await writeFile(path, JSON.stringify(logs), { mode: 0o600 });
          extraLogFiles.push(path);
        }
      } catch {
        options.signal?.throwIfAborted();
        console.warn(
          "Codex Security could not attach saved scan logs; sending feedback with available Codex logs.",
        );
      }
    }

    options.signal?.throwIfAborted();
    const command = resolveCodexCommand(environment);
    const child = startCodex(
      executablePathForSpawn(command.command),
      ["app-server", "--stdio"],
      {
        cwd: options.workingDirectory,
        env: { ...environment, CODEX_HOME: codexHome },
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
        signal: options.signal,
      },
    );
    const uploaded = Promise.withResolvers<string>();
    const closed = new Promise<void>((resolve) => {
      child.once("close", () => {
        uploaded.reject(
          new CodexSecurityError("Codex exited before feedback was uploaded."),
        );
        resolve();
      });
    });
    child.once("error", uploaded.reject);
    child.stdin.on("error", uploaded.reject);
    child.stderr.resume();
    const send = (message: object) =>
      child.stdin.write(`${JSON.stringify(message)}\n`);
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    lines.on("line", (line) => {
      try {
        const message = JSON.parse(line) as {
          id?: number;
          method?: string;
          error?: { message: string };
          result?: { threadId?: string };
        };
        if (message.method !== undefined || message.id === undefined) return;
        if (message.error) throw new CodexSecurityError(message.error.message);
        if (message.id === 1) {
          send({ method: "initialized" });
          send({
            id: 2,
            method: "feedback/upload",
            params: {
              classification: "bug",
              reason: options.reason,
              threadId: scan?.continuationThreadId,
              includeLogs,
              extraLogFiles,
              tags: {
                codex_security_version: VERSION,
                codex_security_plugin_version: BUNDLED_PLUGIN_VERSION,
                codex_security_codex_version: CODEX_EXECUTABLE_VERSION,
                codex_security_sdk_version: CODEX_SDK_VERSION,
                ...(scan === undefined
                  ? {}
                  : { codex_security_scan_id: scan.scanId }),
              },
            },
          });
        } else if (message.id === 2) {
          const feedbackId = message.result?.threadId;
          if (!feedbackId)
            throw new CodexSecurityError("Codex did not return a feedback ID.");
          uploaded.resolve(feedbackId);
        }
      } catch (error) {
        uploaded.reject(error);
      }
    });
    try {
      send({
        id: 1,
        method: "initialize",
        params: { clientInfo: { name: "codex-security", version: VERSION } },
      });
      return {
        feedbackId: await uploaded.promise,
        scanId: scan?.scanId ?? null,
        includedLogs: includeLogs,
      };
    } finally {
      lines.close();
      child.stdin.end();
      child.kill();
      const timer = setTimeout(() => child.kill("SIGKILL"), 1_000);
      try {
        await closed;
      } finally {
        clearTimeout(timer);
      }
    }
  } finally {
    if (directory !== undefined)
      await rm(directory, { recursive: true, force: true });
  }
}

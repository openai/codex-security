import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import type { CodexOptions } from "@openai/codex-sdk";
import { bundledCodexSdkEnvironment } from "./codex-sdk-environment.js";
import { CodexSecurityError } from "./errors.js";
import { executablePathForSpawn, type CodexCommand } from "./runtime.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";
import { withCodexPreflightLock } from "./provider-profile.js";

/** Older custom plugins retain their existing prompt-driven launch path. */
export async function supportsDirectDeepScan(
  pluginRoot: string,
): Promise<boolean> {
  // The native parent keeps the plugin's configured Node selection under Bun.
  if (process.versions["bun"]) return false;
  const manifest = JSON.parse(
    await readFile(join(pluginRoot, ".codex-plugin", "plugin.json"), "utf8"),
  );
  return manifest.codexSecurity?.directDeepScanEngine === 1;
}

export interface DirectDeepScanOptions {
  codexOptions: CodexOptions & { nativeProfile?: string };
  preflightCommand: CodexCommand;
  pluginRoot: string;
  repository: string;
  scanDir: string;
  scanId: string;
  prompt: string;
  signal: AbortSignal;
}

/** Run the same coordinator as the plugin, without a parent model turn. */
export async function* runDeepScan(
  options: DirectDeepScanOptions,
): AsyncGenerator<{
  type: string;
  [key: string]: unknown;
}> {
  const native = await import(
    pathToFileURL(
      join(options.pluginRoot, "mcp", "permission-profile-preflight.mjs"),
    ).href
  );
  const profile = await import(
    pathToFileURL(join(options.pluginRoot, "scripts", "codex_profile.mjs")).href
  );
  const configured = options.codexOptions;
  const command = options.preflightCommand;
  const environment = bundledCodexSdkEnvironment(command.command, {
    ...configured.env,
    ...(configured.apiKey === undefined
      ? {}
      : { CODEX_API_KEY: configured.apiKey }),
  });
  const session = (await withCodexPreflightLock(
    environment,
    options.signal,
    () =>
      native.prepareCliDeepScanSession({
        codexPath: command.command,
        commandArgs: command.args,
        cwd: options.scanDir,
        env: environment,
        configOverrides: [
          ...profile.profileConfigOverrides(configured.config ?? {}),
          ...(configured.configOverrides ?? []),
          // This session only records native context; workers keep their own snapshot.
          "features.plugins=false",
        ],
        signal: options.signal,
        prompt:
          options.prompt +
          "\n\nThe host runs this Deep Scan coordinator directly and owns finalization. This saved request supplies context for later follow-up; do not start a replacement scan.",
      }),
  )) as {
    threadId: string;
    model: string;
    reasoningEffort?: string;
    permissionProfile: unknown;
  };
  yield { type: "thread.started", thread_id: session.threadId };
  options.signal.throwIfAborted();
  const node = process.versions["bun"]
    ? await resolveTrustedExecutable("node", environment, [options.repository])
    : undefined;
  if (node === null)
    throw new CodexSecurityError("Node.js is not available on PATH.");
  const output = await runEngine(
    node?.executable ?? process.execPath,
    [join(options.pluginRoot, "mcp", "server.mjs"), "--deep-scan-engine"],
    node?.environment ?? environment,
    JSON.stringify({ scanId: options.scanId, ...session }),
    options.signal,
  );
  const completed = JSON.parse(output);
  if (
    completed.scanId !== options.scanId ||
    completed.manifestPath !== join(options.scanDir, "scan-manifest.json")
  ) {
    throw new CodexSecurityError(
      "Deep Scan engine returned results for a different scan.",
    );
  }
  // The control session makes no model calls. Worker usage is read by the
  // existing scan tracker from the native sessions below this scan directory.
  yield {
    type: "turn.completed",
    usage: {
      input_tokens: 0,
      cached_input_tokens: 0,
      cache_write_input_tokens: 0,
      output_tokens: 0,
    },
  };
}

function runEngine(
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  request: string,
  signal: AbortSignal,
): Promise<string> {
  signal.throwIfAborted();
  const child = spawn(executablePathForSpawn(command), args, {
    env,
    windowsHide: true,
  });
  // EOF requests graceful coordinator/worker cleanup on Windows as well as Unix.
  // Keep the control pipe open until completion or explicit cancellation.
  const cancel = () => child.stdin.end();
  let stdout = "";
  let stderr = "";
  let processError: Error | undefined;
  child.stdout.setEncoding("utf8").on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.setEncoding("utf8").on("data", (chunk) => {
    stderr += chunk;
  });
  child.once("error", (error) => {
    processError = error;
  });
  child.stdin.on("error", (error: NodeJS.ErrnoException) => {
    if (
      !["EPIPE", "ECONNRESET", "EOF", "ERR_STREAM_DESTROYED"].includes(
        error.code ?? "",
      )
    )
      processError = error;
  });
  const result = new Promise<string>((resolve, reject) => {
    child.once("close", (code) => {
      signal.removeEventListener("abort", cancel);
      if (signal.aborted) reject(signal.reason);
      else if (processError) reject(processError);
      else if (code !== 0)
        reject(
          new CodexSecurityError(
            stderr.trim() || `Deep Scan engine exited with code ${code}.`,
          ),
        );
      else resolve(stdout);
    });
  });
  child.stdin.write(request + "\n");
  signal.addEventListener("abort", cancel, { once: true });
  if (signal.aborted) cancel();
  return result;
}

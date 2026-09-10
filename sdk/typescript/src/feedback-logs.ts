import {
  spawn,
  type ChildProcess,
  type SpawnOptions,
} from "node:child_process";
import { open } from "node:fs/promises";
import { join } from "node:path";
import { CodexSecurityError } from "./errors.js";
import {
  bundledPluginRoot,
  codexSecurityCredentialHome,
  codexSecurityStateDirectory,
  executablePathForSpawn,
  pluginHelperEnvironment,
  resolvePluginPython,
} from "./runtime.js";

interface FeedbackLogOptions {
  scanId: string;
  path: string;
  environment: NodeJS.ProcessEnv;
  workingDirectory: string;
  signal?: AbortSignal;
}

type StartCollector = (
  command: string,
  args: readonly string[],
  options: SpawnOptions & { stdio: ["pipe", number, "pipe"] },
) => ChildProcess;

export async function collectFeedbackLogs(
  options: FeedbackLogOptions,
  startCollector: StartCollector = spawn,
): Promise<boolean> {
  options.signal?.throwIfAborted();
  const [pluginRoot, python] = await Promise.all([
    bundledPluginRoot(),
    resolvePluginPython({
      environment: options.environment,
      protectedRoot: options.workingDirectory,
      signal: options.signal,
    }),
  ]);
  options.signal?.throwIfAborted();
  const output = await open(options.path, "w", 0o600);
  try {
    const child = startCollector(
      executablePathForSpawn(python),
      [join(pluginRoot, "scripts", "collect_feedback.py")],
      {
        cwd: options.workingDirectory,
        env: {
          ...pluginHelperEnvironment(options.environment),
          CODEX_HOME: codexSecurityCredentialHome(options.environment),
          CODEX_SECURITY_STATE_DIR: codexSecurityStateDirectory(
            options.environment,
          ),
        },
        stdio: ["pipe", output.fd, "pipe"],
        windowsHide: true,
        signal: options.signal,
      },
    );
    let failure: Error | undefined;
    const fail = (error: Error) => {
      failure ??= error;
      child.kill("SIGKILL");
    };
    const closed = new Promise<number | null>((resolve) => {
      child.once("close", resolve);
    });
    child.once("error", fail);
    child.stdin!.on("error", fail);
    child.stderr!.resume();
    child.stdin!.end(`${JSON.stringify({ scanIds: [options.scanId] })}\n`);
    const code = await closed;
    options.signal?.throwIfAborted();
    if (failure !== undefined) throw failure;
    if (code !== 0) {
      throw new CodexSecurityError(
        `The feedback log collector exited with code ${code}.`,
      );
    }
    return (await output.stat()).size !== 0;
  } finally {
    await output.close();
  }
}

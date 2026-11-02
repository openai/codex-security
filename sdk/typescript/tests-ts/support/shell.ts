export { gitText } from "../../../../plugins/codex-security/mcp-app/scripts/git.mjs";
import { execFile, execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export function bashCommand(): string {
  if (process.platform !== "win32") return "bash";
  const git = Bun.which("git");
  if (git === null) return "bash";
  const parent = dirname(dirname(git));
  const nestedGit =
    /[\\/](?:mingw32|mingw64|ucrt64|clangarm64)[\\/]bin[\\/]git\.exe$/iu;
  const roots = nestedGit.test(git) ? [parent, dirname(parent)] : [parent];
  for (const root of roots) {
    const gitBash = join(root, "bin", "bash.exe");
    if (existsSync(gitBash)) return gitBash;
  }
  return "bash";
}

export function workflowBashCommand(): string {
  return process.platform === "win32"
    ? join(
        process.env["ProgramFiles"] ?? "C:/Program Files",
        "Git/bin/bash.exe",
      )
    : "bash";
}

export function runCommand(
  command: string,
  args: string[],
  {
    input,
    timeout = 10_000,
    ...options
  }: {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    input?: string;
    timeout?: number;
    windowsHide?: boolean;
  } = {},
): Promise<{
  status: number | null;
  stdout: string;
  stderr: string;
  signal: NodeJS.Signals | null;
  error: Error | null;
}> {
  // Avoid Bun's premature synchronous timeouts while keeping pipe reads bounded.
  return new Promise((resolve, reject) => {
    const child = execFile(
      command,
      args,
      { ...options, timeout, encoding: "utf8" },
      (error, stdout, stderr) => {
        resolve({
          status: child.exitCode,
          stdout,
          stderr,
          signal: child.signalCode,
          error,
        });
      },
    );
    child.stdin?.on("error", reject);
    child.stdin?.end(input);
  });
}

export { pythonExecutable } from "./python.js";

export function writeSource(
  repository: string,
  path: string,
  content: string | Buffer,
): void {
  const destination = join(repository, path);
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, content);
}

export function nodeCommand() {
  return {
    command: execFileSync("node", ["-p", "process.execPath"], {
      encoding: "utf8",
    }).trim(),
  };
}

export async function readSubprocess(
  child: Bun.Subprocess<Bun.Spawn.Writable, "pipe" | "ignore", "pipe">,
) {
  const [status, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  return { status, stdout, stderr };
}

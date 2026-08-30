import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";

export function bashCommand(): string {
  if (process.platform !== "win32") return "bash";
  const git = Bun.which("git");
  if (git === null) return "bash";
  const gitBash = join(dirname(dirname(git)), "bin", "bash.exe");
  return existsSync(gitBash) ? gitBash : "bash";
}

export function runCommand(
  command: string,
  args: string[],
  {
    input,
    ...options
  }: {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    input?: string;
    timeout: number;
  },
): Promise<{ status: number | null; stdout: string; stderr: string }> {
  // Avoid Bun's premature synchronous timeouts while keeping pipe reads bounded.
  return new Promise((resolve, reject) => {
    const child = execFile(
      command,
      args,
      { ...options, encoding: "utf8" },
      (_error, stdout, stderr) => {
        resolve({ status: child.exitCode, stdout, stderr });
      },
    );
    child.stdin?.on("error", reject);
    child.stdin?.end(input);
  });
}

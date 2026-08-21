import { existsSync } from "node:fs";
import { dirname, join } from "node:path";

export function bashCommand(): string {
  if (process.platform !== "win32") return "bash";
  const git = Bun.which("git");
  if (git === null) return "bash";
  const gitBash = join(dirname(dirname(git)), "bin", "bash.exe");
  return existsSync(gitBash) ? gitBash : "bash";
}

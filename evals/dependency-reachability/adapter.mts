import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** A local candidate command receives the same case question and answer contract as the skill. */
export function runAdapter(
  command: string[],
  cwd: string,
  prompt: string,
  signal: AbortSignal,
) {
  return new Promise<{ answer: unknown; usage: null }>((resolve, reject) => {
    const child = spawn(command[0], command.slice(1), {
      cwd,
      signal,
      stdio: ["pipe", "pipe", "inherit"],
    });
    let output = "";
    let failure: Error | undefined;
    child.stdout.setEncoding("utf8").on("data", (data: string) => {
      output += data;
    });
    child.on("error", (error) => {
      failure = error;
    });
    child.stdin.on("error", (error) => {
      failure ??= error;
    });
    child.on("close", (code, killedBy) => {
      if (failure) return reject(failure);
      if (code !== 0)
        return reject(new Error(`Adapter exited with ${killedBy ?? code}`));
      try {
        resolve({ answer: JSON.parse(output), usage: null });
      } catch (error) {
        reject(new Error(`Invalid adapter JSON: ${output}`, { cause: error }));
      }
    });
    child.stdin.end(prompt);
  });
}

/** Wait for the adapter to exit before removing its working directory. */
export async function withAdapter(
  command: string[],
  execute: (state: {
    root: string;
    signal: AbortSignal;
    run(repo: string, prompt: string): ReturnType<typeof runAdapter>;
  }) => Promise<void>,
) {
  const root = await mkdtemp(join(tmpdir(), "reachability-"));
  const controller = new AbortController();
  const interrupt = () => controller.abort();
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", interrupt);
  try {
    await execute({
      root,
      signal: controller.signal,
      run: (repo, prompt) =>
        runAdapter(command, repo, prompt, controller.signal),
    });
  } finally {
    process.off("SIGINT", interrupt);
    process.off("SIGTERM", interrupt);
    await rm(root, { recursive: true, force: true });
  }
}

import { spawn } from "node:child_process";

/** A local candidate command receives the same case question and answer contract as the skill. */
export function runAdapter(command, cwd, prompt, signal) {
  return new Promise((resolve, reject) => {
    const child = spawn(command[0], command.slice(1), {
      cwd,
      signal,
      stdio: ["pipe", "pipe", "inherit"],
    });
    let output = "";
    let failure;
    child.stdout.setEncoding("utf8").on("data", (data) => {
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

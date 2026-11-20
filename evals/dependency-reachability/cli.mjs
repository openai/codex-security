import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

export async function invokeCli(
  cli,
  repo,
  args,
  { input, signal, stateDirectory } = {},
) {
  const child = spawn(process.execPath, [cli, "exploitability", ...args], {
    cwd: repo,
    env: {
      ...process.env,
      CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY: "1",
      ...(stateDirectory && { CODEX_SECURITY_STATE_DIR: stateDirectory }),
    },
    signal,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stdout = [];
  let stderr = "";
  child.stdout.on("data", (chunk) => stdout.push(chunk));
  child.stderr.setEncoding("utf8").on("data", (s) => {
    stderr += s;
  });
  const done = new Promise((accept, reject) => {
    child.on("error", reject);
    child.stdin.on("error", (error) => {
      if (error.code !== "EPIPE") reject(error);
    });
    child.on("close", (code, signal) =>
      accept({ code, signal, stdout: Buffer.concat(stdout), stderr }),
    );
  });
  child.stdin.end(input === undefined ? undefined : JSON.stringify(input));
  return done;
}

export async function writeCliLogs(dir, { code, stdout, stderr }) {
  await writeFile(join(dir, "stderr.log"), stderr, { mode: 0o600 });
  if (code !== 0) {
    await writeFile(join(dir, "stdout.log"), stdout, { mode: 0o600 });
  }
}

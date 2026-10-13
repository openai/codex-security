import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import {
  executablePathForSpawn,
  resolveCodexCommand,
} from "../../src/runtime.js";

export async function nativeRequest(
  environment: Record<string, string>,
  cwd: string,
  args: string[],
  method: string,
  params: unknown,
  command = resolveCodexCommand({}),
) {
  const child = spawn(
    executablePathForSpawn(command.command),
    [...args, "app-server", "--stdio"],
    {
      cwd,
      env: { PATH: process.env["PATH"], ...environment },
      windowsHide: true,
    },
  );
  const closed = once(child, "close");
  const lines = createInterface({ input: child.stdout });
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk));
  const timer = setTimeout(() => child.kill(), 15_000);
  const send = (message: unknown) =>
    child.stdin.write(JSON.stringify(message) + "\n");
  try {
    send({
      id: 1,
      method: "initialize",
      params: {
        clientInfo: { name: "synthetic_provider_test", version: "1" },
        capabilities: { experimentalApi: true },
      },
    });
    for await (const line of lines) {
      const response = JSON.parse(line);
      if (response.error) throw new Error(JSON.stringify(response.error));
      if (response.id === 1) {
        send({ method: "initialized", params: {} });
        send({ id: 2, method, params });
      }
      if (response.id === 2) return response.result;
    }
    throw new Error(`Native ${method} probe did not finish: ${stderr}`);
  } finally {
    clearTimeout(timer);
    lines.close();
    child.kill();
    await closed;
  }
}

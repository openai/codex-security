import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import type { CodexOptions } from "@openai/codex-sdk";
import type { CodexCommand } from "./runtime.js";
import { CODEX_SDK_VERSION } from "./version.js";

export interface DesktopSessionOptions {
  command: CodexCommand;
  environment: Record<string, string>;
  config: NonNullable<CodexOptions["config"]>;
  workingDirectory: string;
  title: string;
  signal: AbortSignal;
}

export async function prepareDesktopSession(
  options: DesktopSessionOptions,
): Promise<string> {
  const child = spawn(options.command.command, ["app-server"], {
    env: options.environment,
    signal: options.signal,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stderr.resume();
  const closed = once(child, "close");
  void closed.catch(() => undefined);
  const responses = createInterface({ input: child.stdout });
  const lines = responses[Symbol.asyncIterator]();

  const request = async (
    id: number,
    method: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>> => {
    child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
    while (true) {
      const line = await lines.next();
      if (line.done) throw new Error("Codex app server closed unexpectedly.");
      const response = JSON.parse(line.value) as {
        id?: number;
        result: Record<string, unknown>;
        error?: { message: string };
      };
      if (response.id !== id) continue;
      if (response.error !== undefined) throw new Error(response.error.message);
      return response.result;
    }
  };

  try {
    await request(0, "initialize", {
      clientInfo: {
        name: "codex-security",
        title: "Codex Security",
        version: CODEX_SDK_VERSION,
      },
      capabilities: { experimentalApi: true },
    });
    child.stdin.write(`${JSON.stringify({ method: "initialized" })}\n`);
    const result = await request(1, "thread/start", {
      cwd: options.workingDirectory,
      approvalPolicy: "never",
      config: options.config,
    });
    const threadId = (result["thread"] as { id: string }).id;
    await request(2, "thread/name/set", {
      threadId,
      name: options.title,
    });
    child.stdin.end();
    await closed;
    return threadId;
  } finally {
    responses.close();
    child.stdin.end();
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await closed.catch(() => undefined);
  }
}

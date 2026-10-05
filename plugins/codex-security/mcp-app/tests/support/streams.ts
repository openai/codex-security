import type { ChildProcessWithoutNullStreams } from "node:child_process";
import type { Readable } from "node:stream";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

export function consumeStreamLines(
  stream: Readable,
  consume: (line: string) => void,
) {
  let buffer = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    buffer += chunk;
    const lines = buffer.split("\n");
    buffer = lines.pop()!;
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed) consume(trimmed);
    }
  });
}

export function startServer(
  serverPath: string,
  env: NodeJS.ProcessEnv,
  {
    cwd,
    component,
    timeoutMessage,
  }: {
    cwd: string;
    component: string;
    timeoutMessage: (id: number) => string;
  },
) {
  const child = spawn(process.execPath, [serverPath, "--stdio"], {
    cwd,
    env,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const responses = new Map<number, ReturnType<typeof JSON.parse>>();
  const waiters = new Map<
    number,
    (response: ReturnType<typeof JSON.parse>) => void
  >();
  const stderrEvents: ReturnType<typeof JSON.parse>[] = [];
  const stderrLines: string[] = [];
  consumeStreamLines(child.stdout, (line) => {
    const response = JSON.parse(line);
    responses.set(response.id, response);
    waiters.get(response.id)?.(response);
    waiters.delete(response.id);
  });
  consumeStreamLines(child.stderr, (line) => {
    stderrLines.push(line);
    try {
      const event = JSON.parse(line);
      if (event.component === component) stderrEvents.push(event);
    } catch {
      // Non-structured diagnostics remain available through stderrText.
    }
  });
  return {
    pid: child.pid,
    notify(method: string, params = {}) {
      writeMessage(child, { jsonrpc: "2.0", method, params });
    },
    sendRequest(id: number, method: string, params = {}) {
      writeMessage(child, { jsonrpc: "2.0", id, method, params });
    },
    request(id: number, method: string, params = {}) {
      this.sendRequest(id, method, params);
      return this.waitForResponse(id);
    },
    async waitForResponse(id: number, timeoutMs = 15_000) {
      const existing = responses.get(id);
      if (existing) return existing;
      const { promise, resolve, reject } =
        Promise.withResolvers<ReturnType<typeof JSON.parse>>();
      waiters.set(id, resolve);
      const timer = setTimeout(
        () => reject(new Error(timeoutMessage(id))),
        timeoutMs,
      );
      return promise.finally(() => clearTimeout(timer));
    },
    stderrEvents() {
      return [...stderrEvents];
    },
    stderrText() {
      return stderrLines.join("\n");
    },
    response(id: number) {
      return responses.get(id);
    },
    async stop() {
      if (child.exitCode !== null || child.signalCode !== null) return;
      const exited = new Promise((resolve) => child.once("exit", resolve));
      child.stdin.end();
      await Promise.race([exited, delay(2_000)]);
      child.kill("SIGKILL");
      await exited;
    },
  };
}

export function writeMessage(
  child: Pick<ChildProcessWithoutNullStreams, "stdin">,
  message: unknown,
) {
  child.stdin.write(`${JSON.stringify(message)}\n`);
}

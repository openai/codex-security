import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";

function consumeStreamLines(stream, consume) {
  let buffer = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    buffer += chunk;
    const lines = buffer.split("\n");
    buffer = lines.pop();
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed) consume(trimmed);
    }
  });
}

export function startServer(
  serverPath,
  env,
  { cwd, component, withTimeout, responseLabel, stderrLines, checkSignalCode },
) {
  const child = spawn(process.execPath, [serverPath, "--stdio"], {
    cwd,
    env,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const responses = new Map();
  const waiters = new Map();
  const stderrEvents = [];
  consumeStreamLines(child.stdout, (line) => {
    const response = JSON.parse(line);
    responses.set(response.id, response);
    waiters.get(response.id)?.(response);
    waiters.delete(response.id);
  });
  consumeStreamLines(child.stderr, (line) => {
    stderrLines?.push(line);
    try {
      const event = JSON.parse(line);
      if (event.component === component) stderrEvents.push(event);
    } catch {
      // Callers choose whether to retain non-structured diagnostics.
    }
  });
  return {
    pid: child.pid,
    notify(method, params = {}) {
      writeMessage(child, { jsonrpc: "2.0", method, params });
    },
    sendRequest(id, method, params = {}) {
      writeMessage(child, { jsonrpc: "2.0", id, method, params });
    },
    request(id, method, params = {}) {
      this.sendRequest(id, method, params);
      return this.waitForResponse(id);
    },
    waitForResponse(id, timeoutMs = 15_000) {
      const existing = responses.get(id);
      if (existing) return Promise.resolve(existing);
      return withTimeout(
        new Promise((resolve) => waiters.set(id, resolve)),
        timeoutMs,
        `${responseLabel} ${id}`,
      );
    },
    stderrEvents() {
      return [...stderrEvents];
    },
    stderrText() {
      return stderrLines.join("\n");
    },
    response(id) {
      return responses.get(id);
    },
    async stop() {
      if (
        child.exitCode !== null ||
        (checkSignalCode && child.signalCode !== null)
      )
        return;
      child.stdin.end();
      const exited = new Promise((resolve) => child.once("exit", resolve));
      await Promise.race([exited, delay(2_000)]);
      if (child.exitCode === null && child.signalCode === null)
        child.kill("SIGKILL");
      await exited;
    },
  };
}

export function writeMessage(child, message) {
  child.stdin.write(`${JSON.stringify(message)}\n`);
}

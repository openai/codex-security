import { spawn } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { consumeStreamLines, writeMessage } from "./streams.ts";

export function startRpcServer(
  parameters: {
    command: string;
    args?: string[];
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    stderr?: "pipe" | "inherit";
  },
  options: {
    component?: string;
    timeoutMs?: number;
    terminateOnStop?: boolean;
  } = {},
) {
  const child = spawn(parameters.command, parameters.args ?? [], {
    cwd: parameters.cwd,
    env: parameters.env,
    stdio: ["pipe", "pipe", parameters.stderr ?? "pipe"],
  });
  const events = new EventEmitter();
  const messages: ReturnType<typeof JSON.parse>[] = [];
  const stderrLines: string[] = [];
  const stderrEvents: ReturnType<typeof JSON.parse>[] = [];
  let failure: Error | undefined;
  const fail = (error: Error) => {
    failure ??= error;
    events.emit("message");
  };
  child.on("error", fail);
  child.stdin!.on("error", fail);
  child.on("close", (code, signal) =>
    fail(
      new Error(
        `MCP server exited with ${signal ?? code} while waiting for a response.`,
      ),
    ),
  );
  consumeStreamLines(child.stdout!, (line) => {
    messages.push(JSON.parse(line));
    events.emit("message");
  });
  if (child.stderr)
    consumeStreamLines(child.stderr, (line) => {
      stderrLines.push(line);
      try {
        const event = JSON.parse(line);
        if (event.component === options.component) stderrEvents.push(event);
      } catch {}
    });
  const send = (message: object) =>
    writeMessage({ stdin: child.stdin! }, { jsonrpc: "2.0", ...message });
  const response = (id: number) =>
    messages.find(
      (message) => message.id === id && message.method === undefined,
    );
  const waitForMessage = async (
    predicate: (message: ReturnType<typeof JSON.parse>) => boolean,
    description = "matching JSON-RPC message",
    timeoutMs = options.timeoutMs ?? 30_000,
  ) => {
    const signal = AbortSignal.timeout(timeoutMs);
    while (true) {
      const message = messages.find(predicate);
      if (message) return message;
      if (failure) throw failure;
      try {
        await once(events, "message", { signal });
      } catch (error) {
        throw new Error(`Timed out waiting for ${description}`, {
          cause: error,
        });
      }
    }
  };
  const waitForResponse = (id: number, timeoutMs?: number) =>
    waitForMessage(
      (message) => message.id === id && message.method === undefined,
      `JSON-RPC response ${id}`,
      timeoutMs,
    );
  const request = (id: number, method: string, params = {}) => {
    send({ id, method, params });
    return waitForResponse(id);
  };
  return {
    pid: child.pid,
    notify: (method: string, params = {}) => send({ method, params }),
    sendRequest: (id: number, method: string, params = {}) =>
      send({ id, method, params }),
    sendResponse: (id: string, result: unknown) => send({ id, result }),
    sendError: (id: string, code: number, message: string) =>
      send({ id, error: { code, message } }),
    request,
    waitForMessage,
    waitForResponse,
    response,
    initialize(name: string, capabilities: Record<string, unknown> = {}) {
      return request(1, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities,
        clientInfo: { name, version: "0.1.0" },
      });
    },
    callTool: (id: number, params: Record<string, unknown>) =>
      request(id, "tools/call", params),
    stderrEvents: () => [...stderrEvents],
    stderrText: () => stderrLines.join("\n"),
    async stop() {
      if (child.exitCode !== null || child.signalCode !== null) return;
      const exited = new Promise((resolve) =>
        child.once(options.terminateOnStop ? "close" : "exit", resolve),
      );
      child.stdin!.end();
      if (options.terminateOnStop) child.kill();
      else {
        await Promise.race([exited, delay(2_000)]);
        child.kill("SIGKILL");
      }
      await exited;
    },
  };
}

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";

// This client deliberately uses only Node builtins. Detached plugin tests must
// not resolve an MCP client or SDK from the checkout's node_modules.
export async function startRpc(command, args, options) {
  const { requestTimeoutMs = 30_000, ...spawnOptions } = options;
  const child = spawn(command, args, {
    ...spawnOptions,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  let sequence = 0;
  let stderr = "";
  const pending = new Map();
  child.stderr.setEncoding("utf8").on("data", (chunk) => {
    stderr += chunk;
  });
  createInterface({ input: child.stdout }).on("line", (line) => {
    const response = JSON.parse(line);
    const waiter = pending.get(response.id);
    if (!waiter) return;
    pending.delete(response.id);
    clearTimeout(waiter.timer);
    if (response.error)
      waiter.reject(new Error(JSON.stringify(response.error)));
    else waiter.resolve(response.result);
  });
  const exited = once(child, "exit");
  child.on("exit", (code, signal) => {
    for (const waiter of pending.values()) {
      clearTimeout(waiter.timer);
      waiter.reject(
        new Error(`Fixture RPC exited (${code}, ${signal}): ${stderr}`),
      );
    }
    pending.clear();
  });
  const client = {
    child,
    request(method, params = {}) {
      return new Promise((resolve, reject) => {
        const id = ++sequence;
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`Fixture RPC timed out: ${method}\n${stderr}`));
        }, requestTimeoutMs);
        pending.set(id, { resolve, reject, timer });
        child.stdin.write(
          `${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`,
        );
      });
    },
    async call(name, args, meta) {
      const result = await this.request("tools/call", {
        name,
        arguments: args,
        ...(meta ? { _meta: meta } : {}),
      });
      assert.notEqual(result.isError, true, JSON.stringify(result));
      return result.structuredContent ?? JSON.parse(result.content[0].text);
    },
    async close() {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.stdin.end();
      const timeout = setTimeout(() => child.kill("SIGKILL"), 5_000);
      try {
        await exited;
      } finally {
        clearTimeout(timeout);
      }
    },
  };
  try {
    await client.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "installed-deep-fixture", version: "1.0.0" },
    });
    child.stdin.write(
      `${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`,
    );
    return client;
  } catch (error) {
    await client.close();
    throw error;
  }
}

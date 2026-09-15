#!/usr/bin/env node
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { appendFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { createInterface } from "node:readline";
import { startRpc } from "./package-rpc.mjs";

try {
  await run();
  process.exit(0);
} catch (error) {
  await trace({ phase: "fixture-error", error: error.stack });
  console.error(error);
  process.exit(1);
}

async function trace(event) {
  await appendFile(
    process.env.PACKAGE_DEEP_TRACE,
    `${JSON.stringify(event)}\n`,
  );
}

async function run() {
  const args = process.argv.slice(2);
  if (args.includes("app-server")) {
    await trace({ phase: "preflight", args });
    for await (const line of createInterface({ input: process.stdin })) {
      const message = JSON.parse(line);
      if (message.id === undefined) continue;
      let result;
      switch (message.method) {
        case "initialize":
          result = { userAgent: "package-fixture" };
          break;
        case "config/read":
          result = {
            config: {
              default_permissions: "codex_security_deep_scan_worker",
              permissions: {
                codex_security_deep_scan_worker: {
                  extends: ":read-only",
                  filesystem: { ":root": "read" },
                  network: { enabled: false },
                },
              },
            },
            origins: {},
            layers: null,
          };
          break;
        case "permissionProfile/list":
          result = {
            data: [
              {
                id: "codex_security_deep_scan_worker",
                description: null,
                allowed: true,
              },
            ],
            nextCursor: null,
          };
          break;
        case "account/read":
          result = { account: null, requiresOpenaiAuth: true };
          break;
        default:
          throw new Error(`Unexpected preflight method: ${message.method}`);
      }
      console.log(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }));
    }
    return;
  }
  let prompt = "";
  for await (const chunk of process.stdin) prompt += chunk;
  const config = {};
  for (let index = 0; index < args.length; index++) {
    if (args[index] !== "-c" && args[index] !== "--config") continue;
    const setting = args[++index];
    const equals = setting.indexOf("=");
    config[setting.slice(0, equals)] = setting.slice(equals + 1);
  }
  const prefix = "mcp_servers.cs_artifacts.";
  const env = Object.fromEntries(
    Object.entries(config)
      .filter(([name]) => name.startsWith(`${prefix}env.`))
      .map(([name, value]) => [
        name.slice(`${prefix}env.`.length),
        JSON.parse(value),
      ]),
  );
  const root = env.CODEX_SECURITY_ARTIFACT_ROOT;
  assert.ok(root, "The real worker must supply its bound artifact root.");
  assert.equal(config["mcp_servers.codex-security.enabled"], "false");
  const layout = env.CODEX_SECURITY_ARTIFACT_LAYOUT;
  const threadId = `package-${layout}-${basename(root)}-${basename(join(root, ".."))}`;
  console.log(JSON.stringify({ type: "thread.started", thread_id: threadId }));
  if (
    layout === "worker" &&
    basename(join(root, "..")) === "discovery-0002" &&
    process.env.PACKAGE_DEEP_HOLD &&
    existsSync(process.env.PACKAGE_DEEP_HOLD)
  ) {
    await trace({ phase: "held", scanId: env.CODEX_SECURITY_SCAN_ID });
    await new Promise(() => setInterval(() => {}, 1_000));
  }
  const server = await startRpc(
    JSON.parse(config[`${prefix}command`]),
    JSON.parse(config[`${prefix}args`]),
    { cwd: root, env: { ...process.env, ...env } },
  );
  let complete = true;
  try {
    if (layout === "worker") {
      const draft = {
        scanId: env.CODEX_SECURITY_SCAN_ID,
        findings: [],
        coverage: {
          completeness: "complete",
          surfaces: [],
          explicitExclusions: [],
          deferred: [],
        },
      };
      const marker = process.env.PACKAGE_DEEP_EMPTY_ONCE;
      if (marker && !existsSync(marker)) {
        await writeFile(marker, "process completed without a final artifact");
        complete = false;
      } else {
        await server.call("record_codex_security_scan_draft", {
          ...draft,
          complete: false,
        });
        await server.call("record_codex_security_scan_draft", {
          ...draft,
          complete: true,
        });
      }
    } else {
      assert.equal(layout, "reducer");
      const inputs = await server.call(
        "get_codex_security_deep_reducer_inputs",
        {},
      );
      assert.ok(inputs.discoveries.length > 0);
      await server.call("record_codex_security_deep_reduction", {
        scanId: env.CODEX_SECURITY_SCAN_ID,
        findings: [],
      });
    }
    await trace({
      phase: layout,
      complete,
      resumed: args.includes("resume"),
      scanId: env.CODEX_SECURITY_SCAN_ID,
      home: process.env.CODEX_HOME,
      hasApiKey: process.env.CODEX_API_KEY === "synthetic-package-deep-key",
      root,
      args,
    });
    console.log(
      JSON.stringify({
        type: "turn.completed",
        usage: {
          input_tokens: 1,
          cached_input_tokens: 0,
          output_tokens: 1,
        },
      }),
    );
  } finally {
    await server.close();
  }
}

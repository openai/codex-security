#!/usr/bin/env node
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { appendFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { createInterface } from "node:readline";
import { startRpc } from "./package-rpc.mjs";
import { parse } from "./package-toml.cjs";

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
    `${JSON.stringify({ ...event, python: process.env.PYTHON })}\n`,
  );
}

async function run() {
  const args = process.argv.slice(2);
  if (args.includes("app-server")) {
    await trace({ phase: "preflight", args });
    const threadId = "package-sdk-owner";
    const sessionPath = join(process.env.CODEX_HOME, `${threadId}.jsonl`);
    for await (const line of createInterface({ input: process.stdin })) {
      const message = JSON.parse(line);
      if (message.id === undefined) continue;
      let result;
      switch (message.method) {
        case "initialize":
          result = { userAgent: "package-fixture" };
          break;
        case "thread/start":
          assert.equal(message.params.threadSource, "security_scan");
          assert.equal(message.params.ephemeral, false);
          result = {
            thread: { id: threadId, path: sessionPath },
            model: "gpt-5.5",
            reasoningEffort: "high",
          };
          break;
        case "thread/inject_items":
          assert.equal(message.params.threadId, threadId);
          assert.equal(message.params.items[0].role, "user");
          await writeFile(
            sessionPath,
            `${JSON.stringify({
              type: "turn_context",
              payload: {
                permission_profile: {
                  type: "managed",
                  file_system: {
                    type: "restricted",
                    entries: [
                      {
                        path: { type: "special", value: { kind: "root" } },
                        access: "read",
                      },
                    ],
                  },
                  network: "restricted",
                },
              },
            })}\n`,
          );
          result = {};
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
  const overrides = [];
  for (let index = 0; index < args.length; index++) {
    if (args[index] === "-c" || args[index] === "--config")
      overrides.push(args[++index]);
  }
  const config = parse(overrides.join("\n"));
  const artifacts = config.mcp_servers.cs_artifacts;
  const env = artifacts.env;
  const root = env.CODEX_SECURITY_ARTIFACT_ROOT;
  assert.ok(root, "The real worker must supply its bound artifact root.");
  assert.equal(config.mcp_servers["codex-security"].enabled, false);
  assert.notEqual(artifacts.enabled, false);
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
  const server = await startRpc(artifacts.command, artifacts.args, {
    cwd: root,
    env: { ...process.env, ...env },
  });
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
      let cursor;
      let json = "";
      do {
        const page = await server.call(
          "get_codex_security_deep_reducer_inputs",
          {
            maxBytes: 64_000,
            ...(cursor === undefined ? {} : { cursor }),
          },
        );
        json += page.json;
        cursor = page.nextCursor;
      } while (cursor !== undefined);
      const inputs = JSON.parse(json);
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

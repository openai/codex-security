import { send, completeTurn } from "./app-server-messages.mjs";
import assert from "node:assert/strict";
import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { parse as parseToml } from "smol-toml";
import { createInterface } from "node:readline";

let loggedIn = false;
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  appendFileSync(process.env.SYNTHETIC_REQUEST_LOG, `${line}\n`);
  if (request.method === "initialize") {
    if (process.env.SYNTHETIC_CHECK_STARTUP_LOCK) {
      assert.equal(
        existsSync(join(process.env.CODEX_HOME, ".codex-security-scan.lock")),
        true,
      );
    }
    send({ id: request.id, result: {} });
  } else if (request.method === "account/login/start") {
    assert.deepEqual(request.params, {
      type: "apiKey",
      apiKey: process.env.SYNTHETIC_EXPECTED_KEY,
    });
    assert.ok(process.argv.includes('cli_auth_credentials_store="ephemeral"'));
    if (process.env.SYNTHETIC_LOGIN_FAILURE) {
      send({
        id: request.id,
        error: { code: -32000, message: "Unauthorized" },
      });
    } else {
      loggedIn = true;
      send({ id: request.id, result: { type: "apiKey" } });
    }
  } else if (request.method === "config/read") {
    send({ id: request.id, result: { config: {} } });
  } else if (request.method === "experimentalFeature/list") {
    assert.deepEqual(request.params, { threadId: "synthetic-thread" });
    send({
      id: request.id,
      result: {
        data: [
          { name: "cli_daybreak", enabled: true },
          { name: "api_key_cyber_access_programs", enabled: true },
        ],
        nextCursor: null,
      },
    });
  } else if (request.method === "thread/start") {
    if (process.env.SYNTHETIC_CHECK_STARTUP_LOCK) {
      assert.equal(
        existsSync(join(process.env.CODEX_HOME, ".codex-security-scan.lock")),
        true,
      );
    }
    if (process.env.SYNTHETIC_EXPECTED_PROVIDER !== undefined) {
      const config = parseToml(
        readFileSync(join(process.env.CODEX_HOME, "config.toml"), "utf8"),
      );
      assert.equal(
        config.model_provider,
        process.env.SYNTHETIC_EXPECTED_PROVIDER || undefined,
      );
      assert.equal(config.profile, undefined);
      assert.equal(config.model_providers?.stale, undefined);
      if (config.model_provider === "synthetic")
        assert.equal(
          config.model_providers.synthetic.requires_openai_auth,
          true,
        );
    }
    assert.equal(loggedIn, Boolean(process.env.SYNTHETIC_EXPECTED_KEY));
    assert.equal(process.env.CODEX_HOME, process.env.SYNTHETIC_EXPECTED_HOME);
    assert.equal(process.env.CODEX_API_KEY, process.env.SYNTHETIC_EXPECTED_KEY);
    assert.deepEqual(
      Object.keys(process.env).filter((key) =>
        ["OPENAI_API_KEY", "CODEX_API_KEY"].includes(key.toUpperCase()),
      ),
      process.env.SYNTHETIC_EXPECTED_CUSTOM_KEY
        ? ["OPENAI_API_KEY"]
        : process.env.SYNTHETIC_EXPECTED_KEY
          ? ["CODEX_API_KEY"]
          : [],
    );
    assert.equal(
      process.env.OPENAI_API_KEY,
      process.env.SYNTHETIC_EXPECTED_CUSTOM_KEY,
    );
    if (process.env.SYNTHETIC_LOGIN_FAILURE) {
      send({
        id: request.id,
        error: { code: -32000, message: "Unauthorized" },
      });
    } else {
      send({
        id: request.id,
        result: {
          thread: { id: "synthetic-thread" },
          sandbox: { type: "workspaceWrite" },
        },
      });
    }
  } else if (request.method === "command/exec") {
    if (process.env.SYNTHETIC_CHECK_STARTUP_LOCK) {
      assert.equal(
        existsSync(join(process.env.CODEX_HOME, ".codex-security-scan.lock")),
        false,
      );
    }
    assert.equal(request.params.sandboxPolicy.type, "workspaceWrite");
    assert.deepEqual(request.params.command, [process.execPath, "-e", ""]);
    send({ id: request.id, result: { exitCode: 0 } });
  } else if (request.method === "turn/start") {
    if (process.env.SYNTHETIC_CHECK_STARTUP_LOCK) {
      assert.equal(
        existsSync(join(process.env.CODEX_HOME, ".codex-security-scan.lock")),
        false,
      );
    }
    completeTurn(request, () => "Synthetic patch complete", "synthetic-thread");
  }
}

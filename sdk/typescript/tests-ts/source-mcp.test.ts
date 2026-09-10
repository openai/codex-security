import { createServer } from "node:http";
import { Codex } from "@openai/codex-sdk";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { stringify } from "smol-toml";
import type { JsonObject } from "../src/config.js";
import {
  resolveSourceMcp,
  sourceMcpConfig,
} from "../src/deduplication/source-mcp.js";
import { createApiTestFixtures } from "./support/api-events.js";
import { resolveCodexCommand } from "../src/runtime.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);

async function sourceForTest(
  name: string,
  config: JsonObject,
  environment: NodeJS.ProcessEnv,
) {
  await writeFile(
    join(environment["CODEX_HOME"]!, "config.toml"),
    stringify(config),
  );
  return resolveSourceMcp(name, environment);
}

test("native Codex stops before model generation when the required source MCP cannot start", async () => {
  const home = await temporaryDirectory();
  let modelRequests = 0;
  let authenticatedSourceRequests = 0;
  const server = createServer((request, response) => {
    if (request.url?.startsWith("/mcp")) {
      if (request.headers.authorization === "token synthetic-source-auth")
        authenticatedSourceRequests++;
      response.writeHead(503).end("Synthetic source server unavailable");
    } else {
      if (request.url?.includes("responses")) modelRequests++;
      response
        .writeHead(200, { "Content-Type": "application/json" })
        .end('{"data":[]}');
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as { port: number };
  const url = `http://127.0.0.1:${address.port}`;
  try {
    const source = await sourceForTest(
      "source",
      {
        mcp_servers: {
          source: {
            url: `${url}/mcp`,
            startup_timeout_sec: 2,
            env_http_headers: { Authorization: "SOURCE_AUTH" },
          },
        },
      },
      { CODEX_HOME: home, SOURCE_AUTH: "token synthetic-source-auth" },
    );
    const codex = new Codex({
      codexPathOverride: resolveCodexCommand({}).command,
      env: {
        PATH: process.env["PATH"] ?? "",
        CODEX_HOME: home,
        ...source.environment,
      },
      config: {
        ...sourceMcpConfig(source, {}),
        features: { plugins: false },
        model_provider: "fixture",
        model_providers: {
          fixture: {
            name: "Fixture",
            wire_api: "responses",
            base_url: `${url}/v1`,
            request_max_retries: 0,
          },
        },
      },
    });
    await expect(
      codex
        .startThread({ workingDirectory: home, skipGitRepoCheck: true })
        .run("Read source using the required MCP server.", {
          signal: AbortSignal.timeout(15_000),
        }),
    ).rejects.toThrow(/required.*source|source.*required/i);
    expect(authenticatedSourceRequests).toBeGreaterThan(0);
    expect(modelRequests).toBe(0);
  } finally {
    const closed = new Promise<void>((resolve) =>
      server.close(() => resolve()),
    );
    server.closeAllConnections();
    await closed;
  }
});

test("dedupe source MCP resolves the selected server and keeps credentials out of config", async () => {
  const home = await temporaryDirectory();
  const source = await sourceForTest(
    "sourcegraph",
    {
      mcp_servers: {
        sourcegraph: {
          url: "https://source.example.com/.api/mcp",
          http_headers: { Authorization: "token synthetic-source-credential" },
          default_tools_approval_mode: "approve",
          tools: { read_source: { approval_mode: "approve" } },
        },
        unrelated: { command: "unrelated-command" },
      },
    },
    { CODEX_HOME: home },
  );
  const config = sourceMcpConfig(source, {
    shell_environment_policy: { exclude: ["CODEX_HOME"] },
  });
  expect(config["mcp_servers"]).toEqual({
    sourcegraph: {
      url: "https://source.example.com/.api/mcp",
      env_http_headers: { Authorization: "CODEX_SECURITY_SOURCE_HEADER_0" },
      enabled: true,
      required: true,
      default_tools_approval_mode: "prompt",
      tools: { read_source: { approval_mode: "prompt" } },
    },
  });
  expect(JSON.stringify(config)).not.toContain("synthetic-source-credential");
  expect(source.environment).toEqual({
    CODEX_SECURITY_SOURCE_HEADER_0: "token synthetic-source-credential",
  });
  expect(config["shell_environment_policy"]).toEqual({
    exclude: ["CODEX_HOME", "CODEX_SECURITY_SOURCE_HEADER_0"],
  });
  await expect(
    resolveSourceMcp("missing", { CODEX_HOME: home }),
  ).rejects.toThrow("not configured");
  await expect(
    sourceForTest(
      "sourcegraph",
      { mcp_servers: { sourcegraph: { enabled: false } } },
      { CODEX_HOME: home },
    ),
  ).rejects.toThrow("disabled");
  await expect(
    sourceForTest(
      "sourcegraph",
      {
        mcp_servers: {
          sourcegraph: {
            url: "https://source.example.com/.api/mcp",
            env_http_headers: { Authorization: "MISSING_SOURCE_AUTH" },
          },
        },
      },
      { CODEX_HOME: home },
    ),
  ).rejects.toThrow("MISSING_SOURCE_AUTH");
});

test.skipIf(process.platform !== "win32")(
  "source credentials exclude inherited Windows environment aliases",
  async () => {
    const home = await temporaryDirectory();
    const source = await sourceForTest(
      "source",
      {
        mcp_servers: {
          source: {
            url: "https://source.example.com/mcp",
            env_http_headers: { Authorization: "SOURCE_AUTH" },
          },
        },
      },
      { CODEX_HOME: home, source_auth: "token synthetic-source-auth" },
    );
    expect(sourceMcpConfig(source, {})["shell_environment_policy"]).toEqual({
      exclude: ["SOURCE_AUTH", "source_auth"],
    });
  },
);

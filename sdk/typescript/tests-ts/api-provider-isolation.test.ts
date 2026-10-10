import { afterEach, expect, test } from "bun:test";
import { stringify as stringifyToml } from "smol-toml";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { executablePathForSpawn, resolveCodexCommand } from "../src/runtime.js";
import { profileConfigOverrides } from "../../../plugins/codex-security/scripts/codex_profile.mjs";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

async function nativeRequest(
  environment: Record<string, string>,
  cwd: string,
  args: string[],
  method: string,
  params: unknown,
) {
  const child = spawn(
    executablePathForSpawn(resolveCodexCommand({}).command),
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

test("native override tables retain inherited features and MCP servers", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  await mkdir(home, { mode: 0o700 });
  const original = stringifyToml({
    features: { shell_tool: false, view_image: false },
    mcp_servers: {
      "inherited.server": { command: "node", args: ["inherited-argument"] },
      "codex-security": { command: "node", enabled: true },
    },
  });
  await writeFile(join(home, "config.toml"), original);
  const { config } = await nativeRequest(
    { CODEX_HOME: home },
    root,
    profileConfigOverrides({
      features: { api_key_model_discovery: false },
      mcp_servers: { "codex-security": { command: "node", enabled: false } },
    }).flatMap((value) => ["--config", value]),
    "config/read",
    { cwd: root, includeLayers: false },
  );
  expect(config.features).toMatchObject({
    shell_tool: false,
    view_image: false,
    api_key_model_discovery: false,
  });
  expect(config.mcp_servers["inherited.server"]).toMatchObject({
    command: "node",
    args: ["inherited-argument"],
    enabled: true,
  });
  expect(config.mcp_servers["codex-security"].enabled).toBe(false);
  expect(await readFile(join(home, "config.toml"), "utf8")).toBe(original);
});

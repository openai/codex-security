import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, expect, spyOn, test } from "bun:test";
import { parse } from "smol-toml";
import * as runtime from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { nodeCommand } from "./support/shell.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-api-login-",
);
afterEach(cleanup);

test.each(["loginChatGPT", "loginChatGPTDeviceCode"] as const)(
  "%s does not start a child when closed during provider command preparation",
  async (method) => {
    const root = await temporaryDirectory();
    const marker = join(root, "child-started");
    const script = join(root, "synthetic-native.mjs");
    await writeFile(
      script,
      `import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(marker)}, "synthetic child started");
console.error("Open https://auth.example.test/device");
console.error("User code: ABCD-EFGH");
process.exit(1);
`,
    );
    let closing: Promise<void> | undefined;
    const client = new TestClient(
      {},
      {
        environment: {
          ...process.env,
          CODEX_SECURITY_STATE_DIR: root,
          NODE_OPTIONS: `--import=${pathToFileURL(script).href}`,
        },
        resolveCodexCommand: () => {
          closing = Promise.resolve().then(() => client.close());
          return nodeCommand();
        },
      },
    );
    try {
      await expect(client[method]()).rejects.toThrow("CodexSecurity is closed");
      await closing;
      expect(existsSync(marker)).toBe(false);
    } finally {
      await client.close();
    }
  },
);

test("close cancels a login queued behind another credential-home owner", async () => {
  const root = await temporaryDirectory();
  const environment = {
    CODEX_HOME: root,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const home = await runtime.prepareCodexSecurityCredentialHome(environment);
  const acquire = runtime.acquireCodexSecurityCredentialHomeLock;
  const release = await acquire(home);
  const queued = Promise.withResolvers<void>();
  const observer = spyOn(
    runtime,
    "acquireCodexSecurityCredentialHomeLock",
  ).mockImplementation((...args) => {
    queued.resolve();
    return acquire(...args);
  });
  const client = new TestClient(
    {},
    { environment, resolveCodexCommand: nodeCommand },
  );
  try {
    const login = client.loginChatGPT();
    await queued.promise;
    const closed = client.close();
    await expect(login).rejects.toMatchObject({ name: "AbortError" });
    await closed;
  } finally {
    observer.mockRestore();
    await release();
    await client.close();
  }
});

test("SDK sign-in honors the ambient login restriction and explicit overrides", async () => {
  const root = await temporaryDirectory();
  const ambient = join(root, "ambient");
  await mkdir(ambient, { mode: 0o700 });
  const environment = {
    PATH: process.env["PATH"],
    HOME: root,
    USERPROFILE: root,
    CODEX_HOME: ambient,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const home = await runtime.prepareCodexSecurityCredentialHome(environment);
  await writeFile(
    join(home, "config.toml"),
    'cli_auth_credentials_store = "ephemeral"\n',
  );
  await writeFile(
    join(ambient, "config.toml"),
    'forced_login_method = "chatgpt"\ncli_auth_credentials_store = "file"\n',
  );
  await using restricted = TestClient.withDependencies({ environment });
  await expect(restricted.loginApiKey("synthetic-sdk-key")).rejects.toThrow(
    "API key login is disabled",
  );
  expect(existsSync(join(home, "auth.json"))).toBe(false);

  await using allowed = new TestClient(
    { codexOverrides: { forced_login_method: "api" } },
    { environment },
  );
  await allowed.loginApiKey("synthetic-sdk-key");
  expect(
    JSON.parse(await readFile(join(home, "auth.json"), "utf8")).OPENAI_API_KEY,
  ).toBe("synthetic-sdk-key");
  expect((await allowed.account()).authenticated).toBe(true);
  await allowed.logout();
  expect(existsSync(join(home, "auth.json"))).toBe(false);
}, 30_000);

test.each(["loginChatGPT", "loginChatGPTDeviceCode"] as const)(
  "%s launches native sign-in with the requested storage and workspace",
  async (method) => {
    const root = await temporaryDirectory();
    const ambient = join(root, "ambient");
    await mkdir(ambient, { mode: 0o700 });
    await writeFile(
      join(ambient, "config.toml"),
      'cli_auth_credentials_store = "file"\n',
    );
    const script = join(root, "native-login.mjs");
    const observed = join(root, "config-at-login.toml");
    await writeFile(
      script,
      `
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
if (process.argv.includes("logout")) process.exit(0);
if (process.argv.includes("status")) process.exit(1);
writeFileSync(${JSON.stringify(observed)}, readFileSync(join(process.env.CODEX_HOME, "config.toml")));
console.error("Open https://auth.example.test/device");
console.error("User code: ABCD-EFGH");
setInterval(() => {}, 1000);
`,
    );
    await using client = new TestClient(
      {
        codexOverrides: { forced_chatgpt_workspace_id: "synthetic-workspace" },
      },
      {
        environment: {
          PATH: process.env["PATH"],
          CODEX_HOME: ambient,
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
        },
        resolveCodexCommand: () => ({ ...nodeCommand(), args: [script] }),
      },
    );
    const login = await client[method]();
    const lock = join(root, "state", "codex-home", ".codex-security-scan.lock");
    expect(existsSync(lock)).toBe(true);
    expect(parse(await readFile(observed, "utf8"))).toMatchObject({
      cli_auth_credentials_store: "file",
      forced_chatgpt_workspace_id: "synthetic-workspace",
    });
    const logout = client.logout();
    login.cancel();
    expect((await login.wait()).success).toBe(false);
    await logout;
    expect(existsSync(lock)).toBe(false);
  },
);

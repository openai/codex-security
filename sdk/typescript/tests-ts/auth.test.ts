import { nodeCommand } from "./support/shell.js";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, test, mock } from "bun:test";
import {
  accountStatus,
  CodexLoginHandle,
  loginApiKey,
  logout,
} from "../src/auth.js";
import { PluginBootstrapError } from "../src/index.js";
import { runCodexCommand } from "../src/runtime.js";
import type { CodexCommand } from "../src/index.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-auth-",
  false,
);

afterEach(cleanup);

async function fakeCodex(): Promise<{
  command: CodexCommand;
  environment: NodeJS.ProcessEnv;
}> {
  const root = await temporaryDirectory();
  const script = join(root, "codex.mjs");
  await writeFile(
    script,
    `
import { basename } from "node:path";

const args = [basename(process.argv[1]), ...process.argv.slice(2)];
if (args.join(" ") === "login --with-api-key") {
  const input = await process.stdin.reduce((text, chunk) => text + chunk, "");
  if (input.trim() !== "secret-key") {
    console.error("wrong key");
    process.exitCode = 2;
  }
} else if (args.join(" ") === "login status") {
  console.log("Logged in using ChatGPT");
} else if (args[0] === "login") {
  console.error("Listening on http://localhost:1455.");
  console.error("Listening on http://localhost.:1455.");
  console.error("Listening on http://callback.localhost:1455.");
  console.error("Listening on http://127.0.0.2:1455.");
  console.error("Listening on http://2130706433:1455.");
  console.error("Listening on http://0x7f000001:1455.");
  console.error("Listening on http://0.0.0.0:1455.");
  console.error("Listening on http://[::1]:1455.");
  console.error("Listening on http://[::]:1455.");
  console.error("Listening on http://[::ffff:127.0.0.1]:1455.");
  console.error("Listening on http://[::ffff:0.0.0.0]:1455.");
  console.error("Listening on http://[::127.0.0.1]:1455.");
  console.error('Open "\\u001b[32mhttps://127.auth.example.test/device\\u001b[0m"');
  console.error("Enter this one-time code");
  console.error("\\u001b[36m8356-V2EGR\\u001b[0m");
} else if (args.join(" ") !== "logout") {
  console.error("unexpected args: " + args.join(" "));
  process.exitCode = 3;
}
process.exit(process.exitCode ?? 0);
`,
  );
  return {
    command: nodeCommand(),
    environment: {
      ...process.env,
      NODE_OPTIONS: `--import=${pathToFileURL(script).href}`,
    },
  };
}

describe("Codex authentication process boundary", () => {
  test("persists API keys through the exact public Codex executable", async () => {
    const { command, environment } = await fakeCodex();
    await expect(loginApiKey(command, environment, "")).rejects.toBeInstanceOf(
      PluginBootstrapError,
    );
    await expect(
      loginApiKey(command, environment, "secret-key"),
    ).resolves.toMatchObject({
      success: true,
      exitCode: 0,
    });
  });

  test("handles a child closing API-key stdin before the write completes", async () => {
    const root = await temporaryDirectory("codex-security-auth-epipe-");
    const script = join(root, "exit.mjs");
    await writeFile(script, "process.exit(1);\n");
    await expect(
      runCodexCommand(
        { command: process.execPath },
        [script],
        process.env,
        "x".repeat(16 * 1024 * 1024),
      ),
    ).resolves.toMatchObject({ success: false, exitCode: 1 });
  });

  test("retains large noninteractive authentication output", async () => {
    const root = await temporaryDirectory("codex-security-auth-output-");
    const output = "verbose authentication output ".repeat(3_000);
    for (const stream of ["stdout", "stderr"] as const) {
      const script = join(root, `${stream}.mjs`);
      await writeFile(
        script,
        `process.${stream}.write(${JSON.stringify(output)}, () => process.exit(0));\n`,
      );
      const result = await runCodexCommand(
        { command: process.execPath },
        [script],
        process.env,
      );
      expect(result.success).toBe(true);
      expect(result[stream]).toBe(output);
    }
  });

  test("reports account state and performs logout", async () => {
    const { command, environment } = await fakeCodex();
    await expect(accountStatus(command, environment)).resolves.toMatchObject({
      authenticated: true,
      details: "Logged in using ChatGPT",
    });
    await expect(logout(command, environment)).resolves.toBeUndefined();
  });

  test("captures quoted interactive login metadata and completion", async () => {
    const { command, environment } = await fakeCodex();
    const observeSucceeded = mock();
    const handle = new CodexLoginHandle(
      command,
      ["login", "--device-auth"],
      environment,
      observeSucceeded,
    );
    await expect(handle.wait()).resolves.toMatchObject({ success: true });
    expect(handle.loginId).toBeNull();
    expect(handle.verificationUrl).toBe("https://127.auth.example.test/device");
    expect(handle.userCode).toBe("8356-V2EGR");
    expect(observeSucceeded).toHaveBeenCalled();
  });

  test.each(["User code: RIGHT-CODE", "Code: RIGHT-CODE", "RIGHT-CODE"])(
    "ignores URL parameters when reading device instructions: %s",
    async (instruction) => {
      const root = await temporaryDirectory("codex-security-auth-code-");
      const script = join(root, "login.mjs");
      const url = "https://auth.example.test/device?code=WRONG-CODE";
      await writeFile(
        script,
        `process.stderr.write(${JSON.stringify(`Open ${url}\n${instruction}\n`)}, () => process.exit(0));\n`,
      );
      const handle = new CodexLoginHandle(
        nodeCommand(),
        [script],
        process.env,
        () => {},
      );

      await expect(handle.wait()).resolves.toMatchObject({ success: true });
      expect(handle.verificationUrl).toBe(url);
      expect(handle.userCode).toBe("RIGHT-CODE");
    },
  );

  test.each([
    ["HTTP-only output", "", null],
    [
      "HTTP followed by HTTPS",
      "Open https://auth.example.test/device\n",
      "https://auth.example.test/device",
    ],
  ] as const)(
    "ignores external plaintext HTTP authentication URLs: %s",
    async (_description, httpsOutput, verificationUrl) => {
      const root = await temporaryDirectory("codex-security-auth-http-");
      const script = join(root, "login.mjs");
      await writeFile(
        script,
        `process.stderr.write(${JSON.stringify(`Open http://auth.example.test/device\n${httpsOutput}User code: ABCD-EFGH\n`)}, () => process.exit(0));\n`,
      );
      const handle = new CodexLoginHandle(
        nodeCommand(),
        [script],
        process.env,
        () => {},
      );

      await expect(handle.wait()).resolves.toMatchObject({ success: true });
      expect(handle.verificationUrl).toBe(verificationUrl);
      expect(handle.userCode).toBe("ABCD-EFGH");
    },
  );

  test("retains large interactive output and login instructions", async () => {
    const root = await temporaryDirectory("codex-security-auth-output-");
    const script = join(root, "login.mjs");
    const output = "verbose authentication output ".repeat(3_000);
    await writeFile(
      script,
      `
console.error("Open https://auth.example.test/device");
console.error("User code: ABCD-EFGH");
setTimeout(() => {
  process.stderr.write(${JSON.stringify(output)}, () => process.exit(0));
}, 10);
`,
    );
    const observeSucceeded = mock();
    const handle = new CodexLoginHandle(
      { command: process.execPath },
      [script, "login", "--device-auth"],
      process.env,
      observeSucceeded,
    );

    await handle.waitForInstructions({ deviceCode: true });
    expect(handle.verificationUrl).toBe("https://auth.example.test/device");
    expect(handle.userCode).toBe("ABCD-EFGH");
    const result = await handle.wait();
    expect(result).toMatchObject({ success: true, exitCode: 0, stdout: "" });
    expect(result.stderr).toContain(output);
    expect(observeSucceeded).toHaveBeenCalled();
  });

  test("drains native login stderr before resolving authentication", async () => {
    const root = await temporaryDirectory("codex-security-auth-stderr-");
    const script = join(root, "login-stderr.mjs");
    const message = "network timeout while authenticating";
    await writeFile(
      script,
      `process.stderr.write(${JSON.stringify(`${message}\n`)}, (error) => process.exit(error ? 2 : 1));\n`,
    );

    const handle = new CodexLoginHandle(
      { command: process.execPath },
      [script, "login"],
      process.env,
      () => {},
    );
    await expect(handle.waitForInstructions()).rejects.toThrow(message);
    await expect(handle.wait()).resolves.toMatchObject({
      success: false,
      exitCode: 1,
      stderr: expect.stringContaining(message),
    });
  });

  test.skipIf(process.platform === "win32")(
    "drains inherited stderr before resolving interactive login",
    async () => {
      const root = await temporaryDirectory("codex-security-auth-drain-");
      const script = join(root, "inherited-stderr.mjs");
      const ready = join(root, "grandchild-ready");
      const release = join(root, "release-grandchild");
      const message = "network timeout while authenticating";
      const grandchildScript = `
import { existsSync, writeFileSync, writeSync } from "node:fs";

const ready = process.argv[1];
const release = process.argv[2];
const parentPid = Number(process.argv[3]);
const timeout = setTimeout(() => process.exit(1), 10_000);
const watcher = setInterval(() => {
  if (!existsSync(release)) return;
  try {
    process.kill(parentPid, 0);
    return;
  } catch (error) {
    if (error?.code !== "ESRCH") {
      clearInterval(watcher);
      clearTimeout(timeout);
      process.exit(1);
    }
  }
  clearInterval(watcher);
  clearTimeout(timeout);
  writeSync(2, ${JSON.stringify(`${message}\n`)});
  process.exit(0);
}, 25);
writeFileSync(ready, "ready");
`;
      await writeFile(
        script,
        `
import { spawn } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";

const ready = ${JSON.stringify(ready)};
const release = ${JSON.stringify(release)};
const grandchild = spawn(
  process.execPath,
  ["-e", ${JSON.stringify(grandchildScript)}, ready, release, String(process.pid)],
  { stdio: ["ignore", "ignore", "inherit"], windowsHide: true },
);
const readyTimeout = setTimeout(() => {
  clearInterval(readyWatcher);
  grandchild.kill();
  console.error("Timed out waiting for the login grandchild.");
  process.exit(1);
}, 10_000);
const readyWatcher = setInterval(() => {
  if (!existsSync(ready)) return;
  clearInterval(readyWatcher);
  clearTimeout(readyTimeout);
  writeFileSync(release, "released");
  process.exit(1);
}, 25);
grandchild.once("error", (error) => {
  clearInterval(readyWatcher);
  clearTimeout(readyTimeout);
  console.error(error.message);
  process.exit(1);
});
`,
      );

      const handle = new CodexLoginHandle(
        { command: process.execPath },
        [script, "login"],
        process.env,
        () => {},
      );
      await expect(handle.waitForInstructions()).rejects.toThrow(message);
      await expect(handle.wait()).resolves.toMatchObject({
        success: false,
        exitCode: 1,
        stderr: expect.stringContaining(message),
      });
    },
  );

  test("escalates cancellation when a login child ignores SIGTERM", async () => {
    const root = await temporaryDirectory("codex-security-auth-sigkill-");
    const script = join(root, "codex.mjs");
    await writeFile(
      script,
      `
console.error("Open https://auth.example.test/device");
console.error("User code: ABCD-EFGH");
process.on("SIGTERM", () => {});
setInterval(() => {}, 1000);
`,
    );
    const observeSucceeded = mock();
    const handle = new CodexLoginHandle(
      { command: process.execPath },
      [script, "login", "--device-auth"],
      process.env,
      observeSucceeded,
    );
    await handle.waitForInstructions({ deviceCode: true });
    handle.cancel();
    await expect(
      Promise.race([
        handle.wait(),
        delay(5_000).then(throwing("Login cancellation did not settle.")),
      ]),
    ).resolves.toMatchObject({ success: false });
    expect(observeSucceeded).not.toHaveBeenCalled();
  });

  test("does not report a canceled interactive login as successful", async () => {
    const root = await temporaryDirectory("codex-security-auth-cancel-");
    const script = join(root, "codex.mjs");
    await writeFile(
      script,
      `
console.error("Open https://auth.example.test/device");
console.error("User code: ABCD-EFGH");
process.on("SIGTERM", () => process.exit(0));
setInterval(() => {}, 1000);
`,
    );
    const observeSucceeded = mock();
    const handle = new CodexLoginHandle(
      { command: process.execPath },
      [script, "login", "--device-auth"],
      process.env,
      observeSucceeded,
    );
    await handle.waitForInstructions({ deviceCode: true });
    handle.cancel();
    await expect(handle.wait()).resolves.toMatchObject({ success: false });
    expect(observeSucceeded).not.toHaveBeenCalled();
  });
});

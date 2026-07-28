import { mkdtemp, readFile, rm, watch, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  accountStatus,
  CodexLoginHandle,
  loginApiKey,
  logout,
  runCodex,
} from "../src/auth.js";
import { PluginBootstrapError } from "../src/index.js";
import type { CodexCommand } from "../src/index.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function fakeCodex(): Promise<CodexCommand> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-auth-"));
  temporaryDirectories.push(root);
  const script = join(root, "codex.mjs");
  await writeFile(
    script,
    `
const args = process.argv.slice(2);
if (args.join(" ") === "login --with-api-key") {
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  if (input.trim() !== "secret-key") {
    console.error("wrong key");
    process.exitCode = 2;
  } else {
    console.log("API key stored");
  }
} else if (args.join(" ") === "login status") {
  console.log("Logged in using ChatGPT");
} else if (args.join(" ") === "logout") {
  console.log("Logged out");
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
  console.error("Open \\u001b[32mhttps://127.auth.example.test/device\\u001b[0m");
  console.error("Enter this one-time code");
  console.error("\\u001b[36m8356-V2EGR\\u001b[0m");
  process.exit(0);
} else {
  console.error("unexpected args: " + args.join(" "));
  process.exitCode = 3;
}
`,
  );
  return { command: process.execPath, prefixArgs: [script] };
}

describe("Codex authentication process boundary", () => {
  test("persists API keys through the exact public Codex executable", async () => {
    const command = await fakeCodex();
    await expect(loginApiKey(command, process.env, "")).rejects.toBeInstanceOf(
      PluginBootstrapError,
    );
    await expect(
      loginApiKey(command, process.env, "secret-key"),
    ).resolves.toMatchObject({
      success: true,
      exitCode: 0,
    });
  });

  test("handles a child closing API-key stdin before the write completes", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-epipe-"));
    temporaryDirectories.push(root);
    const script = join(root, "exit.mjs");
    await writeFile(script, "process.exit(1);\n");
    await expect(
      runCodex(
        { command: process.execPath, prefixArgs: [script] },
        [],
        process.env,
        "x".repeat(16 * 1024 * 1024),
      ),
    ).resolves.toMatchObject({ success: false, exitCode: 1 });
  });

  test("reports account state and performs logout", async () => {
    const command = await fakeCodex();
    await expect(accountStatus(command, process.env)).resolves.toMatchObject({
      authenticated: true,
      details: "Logged in using ChatGPT",
    });
    await expect(logout(command, process.env)).resolves.toBeUndefined();
  });

  test("captures interactive login metadata and completion", async () => {
    const command = await fakeCodex();
    let succeeded = false;
    const handle = new CodexLoginHandle(
      command,
      ["login", "--device-auth"],
      process.env,
      () => {
        succeeded = true;
      },
    );
    await expect(handle.wait()).resolves.toMatchObject({ success: true });
    expect(handle.loginId).toBeNull();
    expect(handle.verificationUrl).toBe("https://127.auth.example.test/device");
    expect(handle.userCode).toBe("8356-V2EGR");
    expect(succeeded).toBe(true);
  });

  test("drains inherited stderr before resolving interactive login", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-drain-"));
    temporaryDirectories.push(root);
    const script = join(root, "inherited-stderr.mjs");
    const message = "network timeout while authenticating";
    const grandchildScript = `
process.once("disconnect", () => {
  process.stderr.write(${JSON.stringify(`${message}\n`)});
});
process.send("ready");
`;
    await writeFile(
      script,
      `
import { spawn } from "node:child_process";

const grandchild = spawn(process.execPath, ["-e", ${JSON.stringify(grandchildScript)}], {
  stdio: ["ignore", "ignore", "inherit", "ipc"],
  windowsHide: true,
});
const readyTimeout = setTimeout(() => {
  grandchild.kill();
  console.error("Timed out waiting for the login grandchild.");
  process.exit(1);
}, 10_000);
grandchild.once("message", (message) => {
  if (message === "ready") {
    clearTimeout(readyTimeout);
    process.exit(1);
  }
});
grandchild.once("error", (error) => {
  clearTimeout(readyTimeout);
  console.error(error.message);
  process.exit(1);
});
`,
    );

    const handle = new CodexLoginHandle(
      { command: process.execPath, prefixArgs: [script] },
      ["login"],
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

  test
    .skipIf(process.platform !== "win32")
    .each([
      "releases inherited login pipes when the Windows fallback fires",
      "releases inherited login pipes after a native Windows process exits",
    ])("%s", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-pipes-"));
    temporaryDirectories.push(root);
    const ready = join(root, "grandchild-ready");
    const release = join(root, "release-grandchild");
    const done = join(root, "grandchild-done");
    const script = join(root, "inherited-pipes.mjs");
    const grandchildScript = `
import { existsSync, watch, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = process.argv[1];
const release = join(root, "release-grandchild");
const watcher = watch(root, () => {
  if (existsSync(release)) {
    watcher.close();
    writeFileSync(join(root, "grandchild-done"), "done");
    process.exit(0);
  }
});
writeFileSync(join(root, "grandchild-ready"), "ready");
process.send("ready");
if (existsSync(release)) {
  watcher.close();
  writeFileSync(join(root, "grandchild-done"), "done");
  process.exit(0);
}
`;
    await writeFile(
      script,
      `
import { spawn } from "node:child_process";

const grandchild = spawn(
  process.execPath,
  ["-e", ${JSON.stringify(grandchildScript)}, ${JSON.stringify(root)}],
  { stdio: ["ignore", "ignore", "inherit", "ipc"], windowsHide: true },
);
const readyTimeout = setTimeout(() => {
  grandchild.kill();
  console.error("Timed out waiting for the Windows login grandchild.");
  process.exit(1);
}, 10_000);
grandchild.once("message", (message) => {
  if (message === "ready") {
    clearTimeout(readyTimeout);
    process.exit(0);
  }
});
grandchild.once("error", (error) => {
  clearTimeout(readyTimeout);
  console.error(error.message);
  process.exit(1);
});
`,
    );

    const completionSignal = AbortSignal.timeout(20_000);
    const grandchildDone = (async () => {
      try {
        for await (const event of watch(root, {
          signal: completionSignal,
        })) {
          if (event.filename === "grandchild-done") {
            return await readFile(done, "utf8");
          }
        }
      } catch (error) {
        if (completionSignal.aborted) {
          throw new Error("The Windows login grandchild did not exit.", {
            cause: error,
          });
        }
        throw error;
      }
      throw new Error("The Windows login grandchild did not exit.");
    })();
    const handle = new CodexLoginHandle(
      { command: process.execPath, prefixArgs: [script] },
      ["login"],
      process.env,
      () => {},
    );
    try {
      await expect(handle.wait()).resolves.toMatchObject({
        success: true,
        exitCode: 0,
      });
      await expect(readFile(ready, "utf8")).resolves.toBe("ready");
    } finally {
      await writeFile(release, "released");
      await expect(grandchildDone).resolves.toBe("done");
    }
  });

  test("does not report a canceled interactive login as successful", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-cancel-"));
    temporaryDirectories.push(root);
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
    let succeeded = false;
    const handle = new CodexLoginHandle(
      { command: process.execPath, prefixArgs: [script] },
      ["login", "--device-auth"],
      process.env,
      () => {
        succeeded = true;
      },
    );
    await handle.waitForInstructions({ deviceCode: true });
    handle.cancel();
    await expect(handle.wait()).resolves.toMatchObject({ success: false });
    expect(succeeded).toBe(false);
  });
});

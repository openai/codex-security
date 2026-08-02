import { ChildProcess } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
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
  console.error("Listening on http://[::ffff:7f00:1]:1455.");
  console.error("Listening on http://[0:0:0:0:0:0:0:1]:1455.");
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

  test("rejects oversized noninteractive authentication output", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-output-"));
    temporaryDirectories.push(root);
    const secret = "sk-proj-SYNTHETIC_OVERSIZED_OUTPUT_SECRET";
    for (const stream of ["stdout", "stderr"] as const) {
      const script = join(root, `${stream}.mjs`);
      await writeFile(
        script,
        `process.${stream}.write(${JSON.stringify(secret)}.repeat(3_000), () => process.exit(0));\n`,
      );
      const failure = await runCodex(
        { command: process.execPath, prefixArgs: [script] },
        [],
        process.env,
      ).then(
        () => null,
        (error: unknown) => error,
      );
      expect(failure).toBeInstanceOf(PluginBootstrapError);
      expect(String(failure)).toContain("64 KiB safety limit");
      expect(String(failure)).not.toContain(secret);
    }
  });

  test("forces oversized noninteractive authentication to terminate", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-auth-command-kill-"),
    );
    temporaryDirectories.push(root);
    const script = join(root, "command.mjs");
    await writeFile(
      script,
      `
process.on("SIGTERM", () => {});
process.stderr.write("x".repeat(128 * 1024));
setInterval(() => {}, 1000);
`,
    );
    const timeout = AbortSignal.timeout(2_500);

    await expect(
      Promise.race([
        runCodex(
          { command: process.execPath, prefixArgs: [script] },
          [],
          process.env,
        ),
        new Promise<never>((_, reject) => {
          timeout.addEventListener(
            "abort",
            () => reject(new Error("Oversized authentication did not settle.")),
            { once: true },
          );
        }),
      ]),
    ).rejects.toThrow("64 KiB safety limit");
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

  test("bounds interactive output while retaining discovered instructions", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-output-"));
    temporaryDirectories.push(root);
    const script = join(root, "login.mjs");
    const secret = "sk-proj-SYNTHETIC_INTERACTIVE_OUTPUT_SECRET";
    await writeFile(
      script,
      `
console.error("Open https://auth.example.test/device");
console.error("User code: ABCD-EFGH");
setTimeout(() => {
  process.stderr.write(${JSON.stringify(secret)}.repeat(3_000), () => process.exit(0));
}, 10);
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
    expect(handle.verificationUrl).toBe("https://auth.example.test/device");
    expect(handle.userCode).toBe("ABCD-EFGH");
    const result = await handle.wait();
    expect(result).toMatchObject({
      success: false,
      stdout: "",
      stderr: "Codex login output exceeded the 64 KiB safety limit.",
    });
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(succeeded).toBe(false);
  });

  test("ignores authentication instructions hidden in a split terminal escape", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-escape-"));
    temporaryDirectories.push(root);
    const script = join(root, "login.mjs");
    await writeFile(
      script,
      `
process.stderr.write("\\u001b]0;" + "x".repeat(5 * 1024));
setTimeout(() => process.stderr.write("https://hidden.example.test/device"), 10);
setTimeout(() => {
  process.stderr.write("\\u0007\\nOpen https://auth.example.test/device\\nUser code: SAFE-1234\\n");
  setTimeout(() => process.exit(0), 10);
}, 20);
`,
    );
    const handle = new CodexLoginHandle(
      { command: process.execPath, prefixArgs: [script] },
      ["login", "--device-auth"],
      process.env,
      () => {},
    );

    await handle.waitForInstructions({ deviceCode: true });
    expect(handle.verificationUrl).toBe("https://auth.example.test/device");
    expect(handle.userCode).toBe("SAFE-1234");
    await expect(handle.wait()).resolves.toMatchObject({ success: true });
  });

  test("waits for complete login instructions split across output chunks", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-fragment-"));
    temporaryDirectories.push(root);
    const script = join(root, "login.mjs");
    await writeFile(
      script,
      `
process.stderr.write("Open https://auth.example");
setTimeout(() => process.stderr.write(".test/device\\nUser code: ABCD"), 10);
setTimeout(() => {
  process.stderr.write("-EFGH\\n");
  setTimeout(() => process.exit(0), 10);
}, 20);
`,
    );
    const handle = new CodexLoginHandle(
      { command: process.execPath, prefixArgs: [script] },
      ["login", "--device-auth"],
      process.env,
      () => {},
    );

    await handle.waitForInstructions({ deviceCode: true });
    expect(handle.verificationUrl).toBe("https://auth.example.test/device");
    expect(handle.userCode).toBe("ABCD-EFGH");
    await expect(handle.wait()).resolves.toMatchObject({ success: true });
  });

  test("recognizes carriage-return-separated interactive login instructions", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-carriage-"));
    temporaryDirectories.push(root);
    const script = join(root, "login.mjs");
    await writeFile(
      script,
      'process.stderr.write("Open https://auth.example.test/device\\rUser code: ABCD-EFGH\\r"); setTimeout(() => process.exit(0), 25);\n',
    );
    const handle = new CodexLoginHandle(
      { command: process.execPath, prefixArgs: [script] },
      ["login", "--device-auth"],
      process.env,
      () => {},
    );

    await handle.waitForInstructions({ deviceCode: true });
    expect(handle.verificationUrl).toBe("https://auth.example.test/device");
    expect(handle.userCode).toBe("ABCD-EFGH");
    await expect(handle.wait()).resolves.toMatchObject({ success: true });
  });

  test("rejects instruction waiters when an unfinished login exceeds its output bound", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-tail-"));
    temporaryDirectories.push(root);
    const script = join(root, "login.mjs");
    await writeFile(
      script,
      'process.stderr.write("Open https://auth.example.test/device"); setTimeout(() => process.stderr.write("x".repeat(128 * 1024)), 20);\n',
    );
    const handle = new CodexLoginHandle(
      { command: process.execPath, prefixArgs: [script] },
      ["login"],
      process.env,
      () => {},
    );

    await expect(handle.waitForInstructions()).rejects.toThrow(
      "64 KiB safety limit",
    );
    await expect(handle.wait()).resolves.toMatchObject({ success: false });
  });

  test("forces an oversized login to settle when it ignores termination", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-auth-output-kill-"),
    );
    temporaryDirectories.push(root);
    const script = join(root, "login.mjs");
    await writeFile(
      script,
      `
console.error("Open https://auth.example.test/device");
console.error("User code: ABCD-EFGH");
process.on("SIGTERM", () => {});
setTimeout(() => {
  process.stderr.write("x".repeat(128 * 1024));
  setInterval(() => {}, 1000);
}, 10);
`,
    );
    const handle = new CodexLoginHandle(
      { command: process.execPath, prefixArgs: [script] },
      ["login", "--device-auth"],
      process.env,
      () => {},
    );

    try {
      await handle.waitForInstructions({ deviceCode: true });
      const timeout = AbortSignal.timeout(2_500);
      const result = await Promise.race([
        handle.wait(),
        new Promise<never>((_, reject) => {
          timeout.addEventListener(
            "abort",
            () => reject(new Error("Oversized login did not settle.")),
            { once: true },
          );
        }),
      ]);
      expect(result).toMatchObject({
        success: false,
        stderr: "Codex login output exceeded the 64 KiB safety limit.",
      });
    } finally {
      handle.cancel();
      await handle.wait();
    }
  });

  test("drains native login stderr before resolving authentication", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-stderr-"));
    temporaryDirectories.push(root);
    const script = join(root, "login-stderr.mjs");
    const message = "network timeout while authenticating";
    await writeFile(
      script,
      `process.stderr.write(${JSON.stringify(`${message}\n`)}, (error) => process.exit(error ? 2 : 1));\n`,
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

  test.skipIf(process.platform === "win32")(
    "drains inherited stderr before resolving interactive login",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-auth-drain-"));
      temporaryDirectories.push(root);
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
    },
  );

  test("releases native login pipes when the cross-platform fallback fires", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-pipes-"));
    temporaryDirectories.push(root);
    const ready = join(root, "grandchild-ready");
    const release = join(root, "release-grandchild");
    const script = join(root, "login-pipes.mjs");
    const grandchildScript = `
import { existsSync, writeFileSync } from "node:fs";

const ready = process.argv[1];
const release = process.argv[2];
const timeout = setTimeout(() => process.exit(1), 10_000);
const watcher = setInterval(() => {
  if (!existsSync(release)) return;
  clearInterval(watcher);
  clearTimeout(timeout);
  process.exit(0);
}, 25);
writeFileSync(ready, String(process.pid));
`;
    await writeFile(
      script,
      `
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";

const grandchild = spawn(
  process.execPath,
  ["-e", ${JSON.stringify(grandchildScript)}, ${JSON.stringify(ready)}, ${JSON.stringify(release)}],
  {
    stdio: ["ignore", "inherit", "inherit"],
    windowsHide: true,
    detached: true,
  },
);
const readyTimeout = setTimeout(() => {
  clearInterval(readyWatcher);
  grandchild.kill();
  console.error("Timed out waiting for the Windows login grandchild.");
  process.exit(1);
}, 10_000);
const readyWatcher = setInterval(() => {
  if (!existsSync(${JSON.stringify(ready)})) return;
  clearInterval(readyWatcher);
  clearTimeout(readyTimeout);
  process.stdout.write("ready\\n", (error) => process.exit(error ? 1 : 0));
}, 25);
grandchild.once("error", (error) => {
  clearInterval(readyWatcher);
  clearTimeout(readyTimeout);
  console.error(error.message);
  process.exit(1);
});
`,
    );

    const originalOnce = ChildProcess.prototype.once;
    let loginChild: ChildProcess | undefined;
    const processObserver = spyOn(ChildProcess.prototype, "once");
    processObserver.mockImplementation(function (
      this: ChildProcess,
      event: string,
      listener: (...eventArguments: never[]) => void,
    ) {
      if (event === "exit") loginChild = this;
      return Reflect.apply(originalOnce, this, [event, listener]);
    });

    let handle: CodexLoginHandle;
    try {
      handle = new CodexLoginHandle(
        { command: process.execPath, prefixArgs: [script] },
        ["login"],
        process.env,
        () => {},
      );
    } finally {
      processObserver.mockRestore();
    }

    const readMarker = async (path: string): Promise<string> => {
      const deadline = Date.now() + 5_000;
      while (true) {
        try {
          return await readFile(path, "utf8");
        } catch (error) {
          if (
            !(error instanceof Error) ||
            !("code" in error) ||
            error.code !== "ENOENT" ||
            Date.now() >= deadline
          ) {
            throw error;
          }
          await delay(25);
        }
      }
    };

    let grandchildPid: number | undefined;
    try {
      const readyMarker = await readMarker(ready);
      expect(readyMarker).toMatch(/^\d+$/u);
      grandchildPid = Number(readyMarker);
      expect(Number.isSafeInteger(grandchildPid)).toBe(true);
      expect(grandchildPid).toBeGreaterThan(0);
      const timeout = AbortSignal.timeout(5_000);
      const completion = Promise.race([
        handle.wait(),
        new Promise<never>((_, reject) => {
          timeout.addEventListener(
            "abort",
            () => reject(new Error("The login fallback timed out.")),
            { once: true },
          );
        }),
      ]);
      await expect(completion).resolves.toMatchObject({
        success: true,
        exitCode: 0,
      });
      expect(loginChild?.stdout?.destroyed).toBe(true);
      expect(loginChild?.stderr?.destroyed).toBe(true);
    } finally {
      await writeFile(release, "released");
      if (grandchildPid !== undefined) {
        const deadline = Date.now() + 5_000;
        while (true) {
          try {
            process.kill(grandchildPid, 0);
          } catch (error) {
            if (
              error instanceof Error &&
              "code" in error &&
              error.code === "ESRCH"
            ) {
              break;
            }
            throw error;
          }
          if (Date.now() >= deadline) {
            throw new Error(
              "The login grandchild did not exit after pipe cleanup.",
            );
          }
          await delay(25);
        }
      }
    }
  });

  test("escalates cancellation when a login child ignores SIGTERM", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-auth-sigkill-"));
    temporaryDirectories.push(root);
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
    await expect(
      Promise.race([
        handle.wait(),
        delay(5_000).then(() => {
          throw new Error("Login cancellation did not settle.");
        }),
      ]),
    ).resolves.toMatchObject({ success: false });
    expect(succeeded).toBe(false);
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

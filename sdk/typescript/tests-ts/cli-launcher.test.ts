import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  copyFile,
  mkdir,
  readFile,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { VERSION } from "../src/index.js";
import { SYNTHETIC_CREDENTIALS } from "./cli-fixtures.js";
import { runCommand } from "./support/shell.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const packageRoot = join(import.meta.dir, "..");

describe("CLI launcher", () => {
  test("runs through an installed npm-style bin symlink", async () => {
    await using temp = await scopedTemporaryDirectory(
      "codex-security-cli-bin-",
    );
    const root = temp.path;
    const launcher = join(packageRoot, "src", "cli.ts");
    const bins =
      process.platform === "win32"
        ? [launcher]
        : ["codex-security", "cs"].map((name) => join(root, name));
    for (const bin of bins) {
      if (process.platform !== "win32") {
        await symlink(launcher, bin);
      }
      const { status, stdout, stderr } = await runCommand(
        process.execPath,
        [bin, "--version"],
        { timeout: 30_000 },
      );

      expect(status, stderr).toBe(0);
      expect(stderr).toBe("");
      expect(stdout).toBe(`${VERSION}\n`);
    }
  });

  test("maps unexpected source-entrypoint failures to exit 2", async () => {
    await using temp = await scopedTemporaryDirectory(
      "codex-security-cli-failure-",
    );
    const root = temp.path;
    const preload = join(root, "unavailable-cwd.mjs");
    await writeFile(
      preload,
      'Object.defineProperty(process, "cwd", { value() { throw new Error(process.env.TEST_DIAGNOSTIC); } });\n',
    );
    const { status, stdout, stderr } = await runCommand(
      process.execPath,
      ["--preload", preload, join(packageRoot, "src", "cli.ts"), "scan"],
      {
        env: {
          ...process.env,
          TEST_DIAGNOSTIC: `working directory is unavailable: ${SYNTHETIC_CREDENTIALS}`,
        },
        timeout: 30_000,
      },
    );

    expect(status, stderr).toBe(2);
    expect(stdout).toBe("");
    expect(stderr).toBe(
      `working directory is unavailable: ${SYNTHETIC_CREDENTIALS}\n`,
    );
  });

  test("preserves installed-launcher startup failures while escaping C1 controls", async () => {
    await using temp = await scopedTemporaryDirectory(
      "codex-security-cli-bin-failure-",
    );
    const root = temp.path;
    const controls = String.fromCharCode(
      ...Array.from({ length: 33 }, (_, index) => 0x7f + index),
    );
    const launcher = join(root, "bin", "codex-security.mjs");
    await mkdir(join(root, "bin"), { recursive: true });
    await mkdir(join(root, "dist"), { recursive: true });
    await copyFile(join(packageRoot, "bin", "codex-security.mjs"), launcher);
    await writeFile(
      join(root, "dist", "cli.js"),
      `throw new Error(${JSON.stringify(`failed ${SYNTHETIC_CREDENTIALS}${controls} details`)});\n`,
    );
    const child = await runCommand("node", [launcher], {
      env: { ...process.env, NODE_NO_WARNINGS: "1" },
      timeout: 30_000,
    });

    expect(child.status).toBe(2);
    expect(child.stdout).toBe("");
    expect(child.stderr).toBe(
      `codex-security: Failed to start Codex Security: failed ${SYNTHETIC_CREDENTIALS}${" ".repeat(controls.length)} details\n`,
    );
  });

  test.each(["import", "runCli", "missing", "success"])(
    "preserves installed-launcher %s results",
    async (scenario) => {
      await using temp = await scopedTemporaryDirectory(
        "codex-security-cli-bin-failure-",
      );
      const root = temp.path;
      const launcher = join(root, "bin", "codex-security.mjs");
      await mkdir(join(root, "bin"), { recursive: true });
      await mkdir(join(root, "dist"), { recursive: true });
      await copyFile(join(packageRoot, "bin", "codex-security.mjs"), launcher);
      const detail = `EACCES: failed ${SYNTHETIC_CREDENTIALS}\u001b[31m\rnext\nline café 🔒\u001b]52;c;U1lOVEhFVElD\u0007 C1 \u0080\u009b2J\u009bH\u009d52;c;U1lOVEhFVElD\u009c\u009f end`;
      const display = `EACCES: failed ${SYNTHETIC_CREDENTIALS} [31m next\nline café 🔒 ]52;c;U1lOVEhFVElD  C1   2J H 52;c;U1lOVEhFVElD   end`;
      if (scenario !== "missing")
        await writeFile(
          join(root, "dist", "cli.js"),
          scenario === "success"
            ? "export const runCli = () => 7;\n"
            : scenario === "runCli"
              ? "export const runCli = async () => { throw process.env.TEST_DIAGNOSTIC; };\n"
              : "throw new Error(process.env.TEST_DIAGNOSTIC);\n",
        );
      const child = await runCommand("node", [launcher], {
        env: {
          ...process.env,
          NODE_NO_WARNINGS: "1",
          TEST_DIAGNOSTIC: detail,
        },
        timeout: 30_000,
      });

      expect(child.status).toBe(scenario === "success" ? 7 : 2);
      expect(child.stdout).toBe("");
      if (scenario === "success") expect(child.stderr).toBe("");
      else if (scenario === "missing") {
        expect(child.stderr).toContain("Cannot find module");
        expect(child.stderr).toContain(join(root, "dist", "cli.js"));
      } else
        expect(child.stderr).toBe(
          `codex-security: Failed to start Codex Security: ${display}\n`,
        );
    },
  );

  test.skipIf(process.platform === "win32")(
    "exits after interrupting a native login with a full stderr pipe",
    async () => {
      await using temp = await scopedTemporaryDirectory("cli-login-signal-");
      const root = temp.path;
      const native = join(root, "native.cjs");
      const pid = join(root, "native.pid");
      await writeFile(
        native,
        `#!/usr/bin/env node
        require("node:fs").writeFileSync(${JSON.stringify(pid)}, String(process.pid));
        process.stderr.write("Open the sign-in URL.\\n");
        setInterval(() => {}, 30000);`,
        { mode: 0o700 },
      );
      const preload = join(root, "fill-stderr.mjs");
      await writeFile(
        preload,
        `import { writeSync } from "node:fs";
        const write = process.stderr.write.bind(process.stderr);
        const padding = Buffer.alloc(4096);
        try { while (true) writeSync(2, padding); }
        catch (error) { if (error.code !== "EAGAIN") throw error; }
        process.stderr.write = (...args) => {
          const result = write(...args);
          process.kill(process.pid, process.env.TEST_SIGNAL);
          return result;
        };`,
      );

      for (const [signal, status] of [
        ["SIGINT", 130],
        ["SIGTERM", 143],
      ] as const) {
        const child = spawn(
          process.execPath,
          ["--preload", preload, join(packageRoot, "src", "cli.ts"), "login"],
          {
            env: {
              PATH: process.env["PATH"],
              HOME: root,
              CODEX_SECURITY_STATE_DIR: join(root, "state"),
              CODEX_CLI_PATH: native,
              NO_UPDATE_NOTIFIER: "1",
              TEST_SIGNAL: signal,
            },
            stdio: ["ignore", "ignore", "pipe"],
            timeout: 8000,
            killSignal: "SIGKILL",
          },
        );
        const [code, exitSignal] = await once(child, "exit");
        child.stderr.destroy();
        const nativePid = Number(await readFile(pid, "utf8"));
        expect(nativePid).toBeGreaterThan(1);
        // Clean up a leaked native child if the launcher failed to reap it.
        expect(() => process.kill(nativePid, "SIGKILL")).toThrow(
          expect.objectContaining({ code: "ESRCH" }),
        );
        expect([code, exitSignal]).toEqual([status, null]);
      }
    },
  );
});

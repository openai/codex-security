import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";
import { VERSION } from "../src/index.js";
import { SYNTHETIC_CREDENTIALS } from "./cli-fixtures.js";
import { runCommand } from "./support/shell.js";

const packageRoot = join(import.meta.dir, "..");

describe("CLI launcher", () => {
  test("runs through an installed npm-style bin symlink", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-cli-bin-"));
    try {
      const launcher = join(packageRoot, "src", "cli.ts");
      const bin =
        process.platform === "win32" ? launcher : join(root, "codex-security");
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
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("maps unexpected source-entrypoint failures to exit 2", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-cli-failure-"));
    try {
      const preload = join(root, "unavailable-cwd.mjs");
      await writeFile(
        preload,
        `Object.defineProperty(process, "cwd", { value() { throw new Error(${JSON.stringify(`working directory is unavailable: ${SYNTHETIC_CREDENTIALS}`)}); } });\n`,
      );
      const { status, stdout, stderr } = await runCommand(
        process.execPath,
        ["--preload", preload, join(packageRoot, "src", "cli.ts"), "scan"],
        { timeout: 30_000 },
      );

      expect(status, stderr).toBe(2);
      expect(stdout).toBe("");
      expect(stderr).toBe(
        `working directory is unavailable: ${SYNTHETIC_CREDENTIALS}\n`,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("maps installed-launcher failures to a fixed startup error", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "codex-security-cli-bin-failure-"),
    );
    try {
      const launcher = join(root, "bin", "codex-security.mjs");
      await mkdir(join(root, "bin"), { recursive: true });
      await mkdir(join(root, "dist"), { recursive: true });
      await copyFile(join(packageRoot, "bin", "codex-security.mjs"), launcher);
      await writeFile(
        join(root, "dist", "cli.js"),
        `throw new Error(${JSON.stringify(`failed ${SYNTHETIC_CREDENTIALS}`)});\n`,
      );
      const child = await runCommand("node", [launcher], {
        env: { ...process.env, NODE_NO_WARNINGS: "1" },
        timeout: 30_000,
      });

      expect(child.status).toBe(2);
      expect(child.stdout).toBe("");
      expect(child.stderr).toBe(
        "codex-security: Failed to start Codex Security.\n",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("builds and runs emitted split TypeScript output from a clean installed npm-style bin when Node preserves main symlinks", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-cli-node-bin-"));
    try {
      const installed = join(root, "node_modules", "@openai", "codex-security");
      const dist = join(installed, "dist");
      const build = await runCommand(
        "node",
        [
          join(packageRoot, "node_modules", "typescript", "bin", "tsc"),
          "--project",
          join(packageRoot, "tsconfig.build.json"),
          "--outDir",
          dist,
        ],
        { cwd: packageRoot, timeout: 30_000 },
      );
      expect(build.status).toBe(0);
      expect(build.stderr).toBe("");

      expect(await readFile(join(dist, "cli.js"), "utf8")).toContain(
        'from "./api.js"',
      );

      const launcher = join(installed, "bin", "codex-security.mjs");
      await mkdir(join(installed, "bin"), { recursive: true });
      await copyFile(join(packageRoot, "bin", "codex-security.mjs"), launcher);
      await copyFile(
        join(packageRoot, "package.json"),
        join(installed, "package.json"),
      );
      await symlink(
        join(packageRoot, "node_modules"),
        join(installed, "node_modules"),
        process.platform === "win32" ? "junction" : "dir",
      );

      const binDirectory = join(root, "node_modules", ".bin");
      await mkdir(binDirectory, { recursive: true });
      const bin =
        process.platform === "win32"
          ? launcher
          : join(binDirectory, "codex-security");
      if (process.platform !== "win32") {
        await symlink(launcher, bin);
      }

      const launchEnvironment = {
        ...process.env,
        NODE_OPTIONS:
          "--preserve-symlinks-main --no-experimental-detect-module",
        NODE_USE_ENV_PROXY: undefined,
      };
      const child = await runCommand("node", [bin, "--version"], {
        env: launchEnvironment,
        timeout: 30_000,
      });

      expect(child.status).toBe(0);
      expect(child.stderr).toBe("");
      expect(child.stdout).toBe(`${VERSION}\n`);

      const preload = join(root, "unavailable-cwd.mjs");
      await writeFile(
        preload,
        [
          "const originalCwd = process.cwd;",
          'Object.defineProperty(process, "cwd", {',
          "  value() {",
          '    if (/[\\\\/]dist[\\\\/]cli\\.js:/u.test(new Error().stack ?? "")) {',
          '      throw new Error("working directory is unavailable");',
          "    }",
          "    return originalCwd.call(process);",
          "  },",
          "});\n",
        ].join("\n"),
      );
      const failed = await runCommand(
        "node",
        ["--import", pathToFileURL(preload).href, bin, "scan"],
        {
          env: launchEnvironment,
          timeout: 30_000,
        },
      );

      expect([failed.status, failed.stdout, failed.stderr]).toEqual([
        2,
        "",
        "working directory is unavailable\n",
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);
});

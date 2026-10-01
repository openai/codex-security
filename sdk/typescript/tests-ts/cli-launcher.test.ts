import {
  copyFile,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
});

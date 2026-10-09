import { copyFile, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { VERSION } from "../src/index.js";
import { SYNTHETIC_CREDENTIALS } from "./cli-fixtures.js";
import { runCommand } from "./support/shell.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

const packageRoot = join(import.meta.dir, "..");

describe("CLI launcher", () => {
  test("runs through an installed npm-style bin symlink", async () => {
    const root = await temporaryDirectory("codex-security-cli-bin-");
    try {
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
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("maps unexpected source-entrypoint failures to exit 2", async () => {
    const root = await temporaryDirectory("codex-security-cli-failure-");
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

  test.each(["import", "main", "missing", "success"])(
    "preserves installed-launcher %s results",
    async (scenario) => {
      const root = await temporaryDirectory("codex-security-cli-bin-failure-");
      try {
        const launcher = join(root, "bin", "codex-security.mjs");
        await mkdir(join(root, "bin"), { recursive: true });
        await mkdir(join(root, "dist"), { recursive: true });
        await copyFile(
          join(packageRoot, "bin", "codex-security.mjs"),
          launcher,
        );
        const detail = `EACCES: failed ${SYNTHETIC_CREDENTIALS}\u001b[31m\rnext\nline café 🔒\u001b]52;c;U1lOVEhFVElD\u0007 C1 \u0080\u009b2J\u009bH\u009d52;c;U1lOVEhFVElD\u009c\u009f end`;
        const display = `EACCES: failed ${SYNTHETIC_CREDENTIALS} [31m next\nline café 🔒 ]52;c;U1lOVEhFVElD  C1   2J H 52;c;U1lOVEhFVElD   end`;
        if (scenario !== "missing")
          await writeFile(
            join(root, "dist", "cli.js"),
            scenario === "success"
              ? "export const main = () => 7;\n"
              : scenario === "main"
                ? `export const main = async () => { throw ${JSON.stringify(detail)}; };\n`
                : `throw new Error(${JSON.stringify(detail)});\n`,
          );
        const child = await runCommand("node", [launcher], {
          env: { ...process.env, NODE_NO_WARNINGS: "1" },
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
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );
});

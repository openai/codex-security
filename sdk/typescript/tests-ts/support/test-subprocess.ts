import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect } from "bun:test";

export function testBash(): string {
  if (process.platform !== "win32") return "bash";
  const git = Bun.which("git");
  if (git === null) return "bash";
  const gitBash = join(dirname(dirname(git)), "bin", "bash.exe");
  return existsSync(gitBash) ? gitBash : "bash";
}

export function runTestInSubprocess(file: string, name: string): boolean {
  const identity = `${file}::${name}`;
  if (process.env["CODEX_SECURITY_ISOLATED_TEST"] === identity) return false;
  const pattern = `${name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}$`;

  const result = spawnSync(
    process.execPath,
    ["test", "--timeout", "30000", "--test-name-pattern", pattern, file],
    {
      cwd: fileURLToPath(new URL("../../", import.meta.url)),
      encoding: "utf8",
      env: { ...process.env, CODEX_SECURITY_ISOLATED_TEST: identity },
      windowsHide: true,
    },
  );
  expect(result.status, result.stderr || result.error?.message).toBe(0);
  return true;
}

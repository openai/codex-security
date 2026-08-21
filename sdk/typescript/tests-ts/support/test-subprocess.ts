import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect } from "bun:test";

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

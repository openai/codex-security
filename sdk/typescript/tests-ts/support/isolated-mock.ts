import { spawnSync } from "node:child_process";
import { expect } from "bun:test";

export function runMockInSubprocess(file: string, name: string): boolean {
  if (process.env["CODEX_SECURITY_ISOLATED_MOCK"] === "1") return false;

  const result = spawnSync(
    process.execPath,
    ["test", "--timeout", "30000", "--test-name-pattern", name, file],
    {
      encoding: "utf8",
      env: { ...process.env, CODEX_SECURITY_ISOLATED_MOCK: "1" },
      windowsHide: true,
    },
  );
  expect(result.status, result.stderr).toBe(0);
  return true;
}

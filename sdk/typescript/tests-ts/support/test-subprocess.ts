import { spawnSync } from "node:child_process";
import { writeSync } from "node:fs";
import { expect } from "bun:test";

export function runTestInSubprocess(file: string, name: string): boolean {
  const identity = `${file}::${name}`;
  if (process.env["CODEX_SECURITY_ISOLATED_TEST"] === identity) {
    writeSync(2, `[isolated test] child: ${identity}\n`);
    return false;
  }
  const timeout = process.env["CODEX_SECURITY_TEST_TIMEOUT_MS"] ?? "30000";
  const pattern = `${name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}$`;

  writeSync(2, `[isolated test] start: ${identity}\n`);
  const result = spawnSync(
    process.execPath,
    ["test", "--timeout", timeout, "--test-name-pattern", pattern, file],
    {
      cwd: new URL("../../", import.meta.url),
      encoding: "utf8",
      stdio: ["pipe", "pipe", "inherit"],
      env: { ...process.env, CODEX_SECURITY_ISOLATED_TEST: identity },
      windowsHide: true,
    },
  );
  writeSync(
    2,
    `[isolated test] end: ${identity} (status=${result.status}, signal=${result.signal})\n`,
  );
  expect(result.status, result.stderr || result.error?.message).toBe(0);
  return true;
}

import { join } from "node:path";
import { expect } from "bun:test";

export function shouldScheduleNativeSandboxTests(
  platform: NodeJS.Platform,
  environment: NodeJS.ProcessEnv,
): boolean {
  if (platform !== "win32") return true;
  const setting =
    environment["CODEX_SECURITY_TEST_WINDOWS_SANDBOX"]?.toLowerCase();
  if (setting === "1" || setting === "true") return true;
  if (setting === "0" || setting === "false") return false;
  return (
    environment["GITHUB_ACTIONS"] === "true" &&
    environment["RUNNER_ENVIRONMENT"] === "github-hosted"
  );
}

export async function waitForWindowsSandboxSetup() {
  if (process.platform !== "win32") return;

  // Codex applies read ACLs in a background worker shared across Codex homes.
  // Finish that work before deleting its fixture or creating another workspace.
  const result = Bun.spawnSync(
    [
      join(
        process.env["SystemRoot"] ?? "C:\\Windows",
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      ),
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `
$ErrorActionPreference = 'Stop'
try {
  $mutex = [System.Threading.Mutex]::OpenExisting('Local\\CodexSandboxReadAcl')
} catch [System.Threading.WaitHandleCannotBeOpenedException] {
  exit 0
}
try {
  if (-not $mutex.WaitOne(30000)) {
    throw 'Codex sandbox read ACL setup did not finish within 30 seconds'
  }
  $mutex.ReleaseMutex()
} finally {
  $mutex.Dispose()
}`,
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
}

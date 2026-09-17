export function packageSmokeTimeouts(platform = process.platform) {
  // Cold-cache npm installs can exceed three minutes on Windows CI.
  const commandTimeoutMs = platform === "win32" ? 300_000 : 120_000;

  return {
    commandTimeoutMs,
    // Installation and verification run sequentially; allow both plus cleanup.
    processTimeoutMs: commandTimeoutMs * 2 + 30_000,
  };
}

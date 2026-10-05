export function packageSmokeTimeouts(platform = process.platform) {
  const commandTimeoutMs = platform === "win32" ? 180_000 : 120_000;
  const installTimeoutMs = platform === "win32" ? 300_000 : commandTimeoutMs;

  return {
    commandTimeoutMs,
    installTimeoutMs,
    // Installation and verification run sequentially; allow both plus cleanup.
    processTimeoutMs: installTimeoutMs + commandTimeoutMs + 30_000,
  };
}

export function packageSmokeTimeouts(platform = process.platform) {
  const commandTimeoutMs = platform === "win32" ? 180_000 : 120_000;

  return {
    commandTimeoutMs,
    // Installation and verification run sequentially; allow both plus cleanup.
    processTimeoutMs: commandTimeoutMs * 2 + 30_000,
  };
}

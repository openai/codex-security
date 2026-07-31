export function packageSmokeTimeouts(platform = process.platform) {
  const commandTimeoutMs = platform === "win32" ? 180_000 : 120_000;

  return {
    commandTimeoutMs,
    processTimeoutMs: commandTimeoutMs + 30_000,
  };
}

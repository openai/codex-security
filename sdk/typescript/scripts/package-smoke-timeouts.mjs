export function packageSmokeTimeouts(platform = process.platform) {
  const commandTimeoutMs = platform === "win32" ? 180_000 : 120_000;
  const installTimeoutMs = platform === "win32" ? 600_000 : commandTimeoutMs;
  // The Deep Scan fixture deliberately retries a missing result. Its first
  // production backoff is 60 seconds with up to 30% jitter.
  const deepScanTimeoutMs = commandTimeoutMs + 78_000;

  return {
    commandTimeoutMs,
    installTimeoutMs,
    deepScanTimeoutMs,
    // Installation, ordinary checks, and the Deep Scan fixture run sequentially.
    processTimeoutMs:
      installTimeoutMs + commandTimeoutMs + deepScanTimeoutMs + 30_000,
  };
}

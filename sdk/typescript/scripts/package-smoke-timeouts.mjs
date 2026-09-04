export function packageSmokeTimeouts(platform = process.platform) {
  const commandTimeoutMs = platform === "win32" ? 180_000 : 120_000;

  return {
    commandTimeoutMs,
    // Windows npm installation can consume most of one command budget before
    // the installed-package, credential-lock, and worker checks start.
    processTimeoutMs:
      commandTimeoutMs * (platform === "win32" ? 2 : 1) + 30_000,
  };
}

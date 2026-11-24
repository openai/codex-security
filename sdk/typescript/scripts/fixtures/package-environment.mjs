export function packageEnvironment(home, extraKeys = []) {
  return {
    ...Object.fromEntries(
      [
        "PATH",
        "Path",
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATHEXT",
        "TMP",
        "TEMP",
        "TMPDIR",
        ...extraKeys,
      ]
        .filter((key) => process.env[key] !== undefined)
        .map((key) => [key, process.env[key]]),
    ),
    HOME: home,
    USERPROFILE: home,
    CODEX_HOME: home,
  };
}

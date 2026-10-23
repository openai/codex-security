export function patchSnapshotWindowsConfig(): string {
  if (process.platform !== "win32") return "";
  // Hosted Windows admins can provision the supported elevated backend without
  // UAC prompts. Keep local fixtures on their existing unelevated backend.
  const sandbox =
    process.env["GITHUB_ACTIONS"] === "true" &&
    process.env["RUNNER_ENVIRONMENT"] === "github-hosted"
      ? "elevated"
      : "unelevated";
  return `windows = { sandbox = "${sandbox}" }\n`;
}

// Native temporary-directory grants must stay inside the owning fixture.
export function patchSnapshotEnvironment(
  temporaryDirectory: string,
  environment: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  return {
    ...Object.fromEntries(
      Object.entries(environment).filter(
        ([name]) => !["TEMP", "TMP", "TMPDIR"].includes(name.toUpperCase()),
      ),
    ),
    TEMP: temporaryDirectory,
    TMP: temporaryDirectory,
    TMPDIR: temporaryDirectory,
  };
}

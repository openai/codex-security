import { fileURLToPath } from "node:url";

/** Use only the temporary checkout's Git configuration in Sonar import tests. */
export function sonarGitTestEnvironment(base: NodeJS.ProcessEnv = process.env) {
  return {
    ...Object.fromEntries(
      Object.entries(base).filter(
        ([name]) => !name.toUpperCase().startsWith("GIT_"),
      ),
    ),
    GIT_CONFIG_GLOBAL: fileURLToPath(
      new URL("./empty.gitconfig", import.meta.url),
    ),
    GIT_CONFIG_NOSYSTEM: "1",
  };
}

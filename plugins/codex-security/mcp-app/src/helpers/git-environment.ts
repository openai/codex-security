import { readFileSync } from "node:fs";

const gitSelector =
  /^(?:GIT_CONFIG_(?:GLOBAL|SYSTEM|NOSYSTEM|PARAMETERS|COUNT|(?:KEY|VALUE)_\d+)|GIT_ATTR_(?:SOURCE|NOSYSTEM)|GIT_NO_REPLACE_OBJECTS|GIT_REPLACE_REF_BASE|XDG_CONFIG_HOME)$/u;

export function gitConfigurationEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const canonical = (name: string) =>
    process.platform === "win32" ? name.toUpperCase() : name;
  const bridge = Object.keys(environment).find(
    (name) => canonical(name) === "CODEX_SECURITY_GIT_ENVIRONMENT_FILE",
  );
  const selected: Record<string, string> = {};
  for (const source of [
    bridge === undefined
      ? {}
      : (JSON.parse(readFileSync(environment[bridge]!, "utf8")) as Record<
          string,
          unknown
        >),
    environment,
  ])
    for (const [name, value] of Object.entries(source)) {
      const key = canonical(name);
      if (gitSelector.test(key) && typeof value === "string")
        selected[key] = value;
    }
  return selected;
}

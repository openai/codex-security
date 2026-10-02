import { promises as fs } from "node:fs";
import { expandHome } from "../../../../sdk/typescript/src/codex-home.js";
import {
  resolveTrustedExecutable,
  type TrustedExecutable,
} from "../../../../sdk/typescript/src/trusted-executable.js";

/** Use the configured executable or PATH, with the shared repository exclusion. */
export function resolveTrustedCodex(
  environment: NodeJS.ProcessEnv,
  protectedRoot: string | readonly string[],
): Promise<TrustedExecutable | null> {
  return resolveTrustedExecutable(
    expandHome(resolveCodexPath(environment), environment),
    environment,
    protectedRoot,
  );
}

export async function snapshotNativeEnvironment(): Promise<
  Record<string, string>
> {
  const environment = Object.fromEntries(
    Object.entries(process.env)
      .filter((entry): entry is [string, string] => entry[1] !== undefined)
      .map(([name, value]) => [
        process.platform === "win32" ? name.toUpperCase() : name,
        value,
      ]),
  );
  const codexHome = environment.CODEX_HOME;
  if (codexHome !== undefined && codexHome.length > 0 && !codexHome.trim()) {
    delete environment.CODEX_HOME;
  } else if (codexHome !== undefined && codexHome.length > 0) {
    // Resolve symlink/.. paths before consumers normalize them or change cwd.
    environment.CODEX_HOME = await fs.realpath(
      expandHome(codexHome.trim(), environment),
    );
  }
  return environment;
}

export function resolveCodexPath(
  environment: NodeJS.ProcessEnv = process.env,
): string {
  return environment.CODEX_CLI_PATH?.trim() || "codex";
}

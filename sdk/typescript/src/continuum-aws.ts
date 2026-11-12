import { readdir, readFile, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, dirname, isAbsolute, join, resolve } from "node:path";
import { environmentEntry } from "./auth.js";
import { bundledPluginRoot } from "./bundled-plugin.js";
import { CodexSecurityError } from "./errors.js";
import { localGitProtectionRoots } from "./local-git-metadata.js";
import {
  isWithin,
  resolveTrustedExecutable,
  trustedHostPathResolver,
} from "./trusted-executable.js";

const windows = process.platform === "win32";

function expandVariables(path: string, environment: NodeJS.ProcessEnv): string {
  // AWS uses Python's platform-specific expandvars for configuration paths.
  const variables = windows
    ? /'[^']*'?|%(%|[^%]*%?)|\$(\$|[-\w]+|\{[^}]*\}?)/gu
    : /\$(\w+|\{[^}]*\}?)/gu;
  return path.replace(variables, (match) => {
    if (match.startsWith("'")) return match;
    const token = match.slice(1);
    if (token === "%" || token === "$") return token;
    let name = token;
    if (match.startsWith("%")) {
      if (!token.endsWith("%")) return match;
      name = token.slice(0, -1);
    } else if (token.startsWith("{")) {
      if (!token.endsWith("}")) return match;
      name = token.slice(1, -1);
    }
    return environmentEntry(environment, name) ?? match;
  });
}

function expandedSetting(
  name: string,
  value: string,
  home: string,
  environment: NodeJS.ProcessEnv,
): string {
  const path = expandVariables(value, environment);
  if (
    path === "~" ||
    path.startsWith("~/") ||
    (windows && path.startsWith("~\\"))
  )
    return home + path.slice(1);
  if (path.startsWith("~"))
    throw new CodexSecurityError(`Use a fully expanded file path for ${name}.`);
  return path;
}

function pinSetting(
  name: string,
  path: string,
  environment: NodeJS.ProcessEnv,
): string {
  if (
    expandVariables(path, environment) !== path ||
    (name === "AWS_DATA_PATH" && path.includes(delimiter))
  )
    throw new CodexSecurityError(`Use a fully expanded file path for ${name}.`);
  return path;
}

function missingPath(error: NodeJS.ErrnoException) {
  if (error.code !== "ENOENT" && error.code !== "ENOTDIR") throw error;
}

async function checkModelPath(
  path: string,
  resolvePath: (path: string) => string | null,
  roots: readonly string[],
  signal: AbortSignal | undefined,
  levels = 3,
): Promise<string> {
  signal?.throwIfAborted();
  const safe = resolvePath(path);
  if (safe === null || roots.some((root) => isWithin(safe, root)))
    throw new CodexSecurityError(
      `Use an AWS model path separate from the selected checkout: ${path}`,
    );
  if (levels === 0) return safe;
  const entries = await readdir(safe).catch(missingPath);
  // AWS loads global models and service/version/*.json[.gz].
  for (const entry of entries ?? []) {
    const child = join(safe, entry);
    if (
      /\.json(?:\.gz)?$/iu.test(entry) ||
      (levels > 1 && (await stat(child).catch(missingPath))?.isDirectory())
    )
      await checkModelPath(child, resolvePath, roots, signal, levels - 1);
  }
  return safe;
}

export async function prepareContinuumAws(
  cwd: string,
  environment: NodeJS.ProcessEnv,
  signal?: AbortSignal,
) {
  const caller = await realpath(cwd);
  const roots = [
    ...new Set([
      resolve(cwd),
      caller,
      ...(await localGitProtectionRoots(cwd, environment, signal)),
    ]),
  ];
  const resolvePath = await trustedHostPathResolver(caller, roots);
  const settings = JSON.parse(
    await readFile(
      join(
        await bundledPluginRoot(),
        "skills/publish-findings/scripts/continuum_aws_settings.json",
      ),
      "utf8",
    ),
  ) as { accountDirectories: string[]; hostSettings: string[] };

  const name = windows ? "aws.exe" : "aws";
  const directories: string[] = [];
  for (let entry of (environmentEntry(environment, "PATH") ?? "").split(
    delimiter,
  )) {
    if (windows && entry.startsWith('"') && entry.endsWith('"'))
      entry = entry.slice(1, -1);
    if (!isAbsolute(entry)) continue;
    const path = resolvePath(entry);
    if (path === null || path.includes(delimiter)) continue;
    const candidate = resolvePath(join(path, name));
    if (candidate !== null && (!windows || /\.exe$/iu.test(candidate)))
      directories.push(path);
  }
  const aws = await resolveTrustedExecutable(
    name,
    { PATH: directories.join(delimiter) },
    roots,
  );
  const executable = aws ? resolvePath(aws.executable) : null;
  if (!aws || executable === null)
    throw new CodexSecurityError(
      "Could not find an installed AWS CLI outside the selected checkout.",
    );

  // Credential helpers can use any interpreter. Only forward AWS and host settings.
  const hostSettings = new Set([
    ...settings.accountDirectories,
    ...settings.hostSettings,
  ]);
  const child: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(environment)) {
    const key = windows ? name.toUpperCase() : name;
    if (
      value !== undefined &&
      (key.startsWith("AWS_") ||
        key.startsWith("LC_") ||
        hostSettings.has(key.toUpperCase()))
    )
      child[key] = value;
  }
  child["PATH"] = aws.environment["PATH"];

  function trustedSetting(path: string, label: string) {
    const safe = resolvePath(path);
    if (safe === null)
      throw new CodexSecurityError(
        `Use ${label} outside the selected checkout.`,
      );
    return safe;
  }

  for (const name of settings.accountDirectories) {
    const path = child[name];
    if (path)
      child[name] = trustedSetting(path, `an account ${name} directory`);
  }
  const configuredHome = windows
    ? (child["USERPROFILE"] ??
      (child["HOMEPATH"]
        ? (child["HOMEDRIVE"] ?? "") + child["HOMEPATH"]
        : undefined))
    : child["HOME"];
  const home = trustedSetting(
    configuredHome ?? homedir(),
    "an account home directory",
  );
  child[windows ? "USERPROFILE" : "HOME"] = home;

  // AWS can run credential helpers from profiles and commands from aliases.
  const awsDirectory = join(home, ".aws");
  for (const [name, filename] of [
    ["AWS_CONFIG_FILE", "config"],
    ["AWS_SHARED_CREDENTIALS_FILE", "credentials"],
  ] as const) {
    const value = child[name];
    const path =
      value === undefined
        ? join(awsDirectory, filename)
        : expandedSetting(name, value, home, environment);
    const safe = trustedSetting(path, `an ${name} file`);
    if (value !== undefined) child[name] = pinSetting(name, safe, child);
  }
  trustedSetting(join(awsDirectory, "cli", "alias"), "an AWS CLI alias file");
  await checkModelPath(
    join(awsDirectory, "models"),
    resolvePath,
    roots,
    signal,
  );
  if (child["AWS_DATA_PATH"] !== undefined) {
    const paths: string[] = [];
    for (const entry of child["AWS_DATA_PATH"].split(delimiter)) {
      const path = expandedSetting("AWS_DATA_PATH", entry, home, environment);
      if (!path) continue;
      const safe = await checkModelPath(path, resolvePath, roots, signal);
      paths.push(pinSetting("AWS_DATA_PATH", safe, child));
    }
    child["AWS_DATA_PATH"] = paths.join(delimiter);
  }

  // Windows may search the current directory for a bare credential helper name.
  return {
    executable,
    cwd: dirname(executable),
    environment: child,
  };
}

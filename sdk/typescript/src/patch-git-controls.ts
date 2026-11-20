import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  realpath,
  rm,
  stat,
  symlink,
} from "node:fs/promises";
import { homedir, tmpdir, userInfo } from "node:os";
import {
  basename,
  delimiter,
  dirname,
  isAbsolute,
  join,
  normalize,
  parse,
  relative,
  resolve,
  sep,
} from "node:path";
import {
  patchCredentialKind,
  gitSecretSetting,
  httpCredentialFile,
  proxyUserinfo,
  withoutUrlCredentials,
} from "./patch-publication-hooks.js";
import {
  awsAccountHome,
  awsProfileFiles,
  expandCredentialPath,
} from "./continuum-aws.js";
import { configuredCodexHome, environmentEntry } from "./auth.js";
import {
  codexSecurityCredentialHome,
  type ProcessEnvironment,
} from "./runtime.js";
import { gitAlternatePathBytes, gitMarkerRoot } from "./targets.js";

// Git hook entrypoints: https://git-scm.com/docs/githooks
const GIT_HOOKS = [
  "applypatch-msg",
  "pre-applypatch",
  "post-applypatch",
  "pre-commit",
  "pre-merge-commit",
  "prepare-commit-msg",
  "commit-msg",
  "post-commit",
  "pre-rebase",
  "post-checkout",
  "post-merge",
  "pre-push",
  "pre-receive",
  "update",
  "proc-receive",
  "post-receive",
  "post-update",
  "reference-transaction",
  "push-to-checkout",
  "pre-auto-gc",
  "post-rewrite",
  "sendemail-validate",
  "fsmonitor-watchman",
  "p4-changelist",
  "p4-prepare-changelist",
  "p4-post-changelist",
  "p4-pre-submit",
  "post-index-change",
].flatMap((hook) =>
  process.platform === "win32" ? [hook, `${hook}.exe`] : [hook],
);

export interface PatchGitCommandOptions {
  readonly encoding?: "base64";
  readonly nestedProbe?: boolean;
  readonly indexFile?: string;
  readonly hookMessagePath?: string;
  readonly input?: string | Uint8Array;
  readonly environment?: NodeJS.ProcessEnv;
}

type RunGit = (
  root: string,
  directory: string,
  args: string[],
  options?: PatchGitCommandOptions,
) => Promise<string>;

type RunIndexGit = (
  args: string[],
  options?: PatchGitCommandOptions,
) => Promise<string>;

export async function withPatchGitIndex<T>(
  run: RunIndexGit,
  inspect: (run: RunIndexGit, indexFile: string) => Promise<T>,
  files?: readonly string[] | { readonly treeKeys: readonly string[] },
  sourcePathspecs?: readonly string[],
): Promise<T> {
  const directory = await mkdtemp(
    join(await realpath(tmpdir()), "codex-security-patch-tree-"),
  );
  const indexFile = join(directory, "index");
  const indexed: RunIndexGit = (args, options) =>
    run(args, { ...options, indexFile });
  try {
    let head: string | undefined;
    try {
      head = (
        await indexed(["rev-parse", "--verify", "--quiet", "HEAD"])
      ).trim();
    } catch (error) {
      const failure = error as { code?: unknown; status?: unknown };
      if ((failure.code ?? failure.status) !== 1) throw error;
      // An unborn symbolic HEAD has no commit; malformed refs still fail.
      await indexed(["symbolic-ref", "--quiet", "HEAD"]);
    }
    await indexed(["read-tree", head ?? "--empty"]);
    let removals = "";
    if (head !== undefined && sourcePathspecs !== undefined) {
      // A staged rename can replace a HEAD spelling that still resolves on disk.
      // Index-info paths are root-relative, including when called from a subdirectory.
      const removed = await run(
        [
          "diff",
          "--cached",
          "--no-renames",
          "--no-relative",
          "--ignore-submodules=none",
          "--diff-filter=D",
          "--name-only",
          "-z",
          head,
          ...sourcePathspecs,
        ],
        { encoding: "base64" },
      );
      const zero = "0".repeat(head.length);
      for (const path of Buffer.from(removed, "base64")
        .toString("latin1")
        .split("\0"))
        if (path) removals += `0 ${zero}\t${path}\0`;
    }
    const entries = Buffer.from(
      await run(
        [
          ...(sourcePathspecs === undefined ? ["--literal-pathspecs"] : []),
          "ls-files",
          "--stage",
          "--full-name",
          "-z",
          ...(sourcePathspecs ??
            (files === undefined || "treeKeys" in files
              ? []
              : ["--", ...files])),
        ],
        {
          encoding: "base64",
        },
      ),
      "base64",
    ).toString("latin1");
    // ls-files accepts only text argv pathspecs. Filter whole-index records
    // by their original bytes when a requested path cannot round-trip as text.
    const selectedEntries =
      files && "treeKeys" in files
        ? entries
            .split("\0")
            .filter((entry) => {
              const path = entry.slice(entry.indexOf("\t") + 1);
              return files.treeKeys.some(
                (key) => path === key || path.startsWith(key + "/"),
              );
            })
            .map((entry) => entry + "\0")
            .join("")
        : entries;
    await indexed(
      ["-c", "core.ignorestat=false", "update-index", "-z", "--index-info"],
      {
        input: Buffer.from(
          removals +
            selectedEntries.replaceAll(
              /(^|\0)([0-7]+ [a-f\d]+) [123]\t/gu,
              "$1$2 0\t",
            ),
          "latin1",
        ),
      },
    );
    return await inspect(indexed, indexFile);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

export interface PatchGitControls {
  readonly publicationHooks: PatchPublicationHooks;
  readonly nestedCheckouts: readonly string[];
  readonly nestedConfigurationDigests: ReadonlySet<string>;
  readonly readOnlyPaths: readonly string[];
  readonly modelOnlyReadOnlyPaths: readonly string[];
  readonly unavailableFilters: readonly string[];
  readonly credentialStorePaths: readonly string[];
  protectShellCredentialFiles(
    ...settings: (Readonly<Record<string, unknown>> | undefined)[]
  ): Promise<readonly string[]>;
  readonly externalConfigPaths: readonly string[];
  readonly externalCachePaths: readonly string[];
  readonly snapshotStoragePaths: readonly string[];
  readonly snapshotConfig?: PatchSnapshotConfig;
  readonly hostRefreshFilters: readonly string[];
  hostFilterSettings(switchingBranch: boolean): Promise<readonly string[]>;
  validate(): Promise<void>;
}

export interface PatchPublicationHooks {
  readonly gitDirectory: string;
  readonly commonDirectory?: string;
  readonly events: Set<string>;
  readonly configured: Set<string>;
}

function recordConfiguredHook(
  hooks: Pick<PatchPublicationHooks, "events" | "configured">,
  key: string,
  event: string,
) {
  const name = /^hook\.(.+)\.event$/u.exec(key)?.[1];
  if (name !== undefined && GIT_HOOKS.includes(event)) {
    hooks.events.add(event);
    hooks.configured.add(name);
  }
}

async function hookIsAvailable(path: string): Promise<boolean> {
  const executable = await access(path, constants.X_OK).then(
    () => true,
    () => false,
  );
  if (!executable) return false;
  const metadata = await stat(path).catch(missing);
  return metadata !== undefined && !metadata.isDirectory();
}

async function readConfiguredHooks(
  hooks: Pick<PatchPublicationHooks, "events" | "configured">,
  run: (args: string[]) => Promise<string>,
) {
  let entries: string;
  try {
    entries = await run([
      "config",
      "--includes",
      "--null",
      "--get-regexp",
      "^hook\\..+\\.event$",
    ]);
  } catch (error) {
    const failure = error as { code?: unknown; status?: unknown };
    if ((failure.code ?? failure.status) === 1) return;
    throw error;
  }
  for (const entry of entries.split("\0")) {
    const separator = entry.indexOf("\n");
    if (separator !== -1)
      recordConfiguredHook(
        hooks,
        entry.slice(0, separator),
        entry.slice(separator + 1),
      );
  }
}

// These settings can hold authentication material in the file itself. A
// credential helper name or ordinary SSH command alone is not an inline secret.
function hasInlineGitAuthentication(key: string, value: string): boolean {
  if (value && gitSecretSetting.test(key)) return true;
  if (
    withoutUrlCredentials(key) !== key ||
    withoutUrlCredentials(value) !== value
  )
    return true;
  if (/^(?:http|remote)(?:\..*)?\.proxy$/iu.test(key))
    return proxyUserinfo.test(value);
  if (/^http(?:\..*)?\.extraheader$/iu.test(key)) {
    const header = /^([^:]+):\s*(\S.*)$/u.exec(value);
    return (
      !!header &&
      (/(?:^|-)(?:authorization|auth|token|api-?key|cookie|secret)(?:$|-)/iu.test(
        header[1]!.trim(),
      ) ||
        /^(?:basic|bearer|digest|negotiate)\s+\S+/iu.test(header[2]!))
    );
  }
  return (
    /^credential(?:\..*)?\.helper$/iu.test(key) &&
    value.startsWith("!") &&
    /(?:password|credential|oauth_refresh_token)=/iu.test(value)
  );
}

// Command parameters take precedence over config files and GIT_CONFIG_COUNT.
// Quote the entire key separately: a driver subsection may itself contain "=".
export function patchFilterParameters(
  keys: readonly string[],
  block: boolean,
  previous?: string,
): string {
  const quote = (text: string) => "'" + text.replaceAll("'", "'\\''") + "'";
  const settings = new Map<string, string>();
  for (const key of keys) {
    settings.set(
      key,
      block
        ? 'echo "Cannot run Git filter with an operator credential helper or askpass program whose backing store cannot be isolated." >&2; exit 1'
        : "",
    );
    settings.set(
      key.slice(0, key.lastIndexOf(".")) + ".required",
      String(block),
    );
  }
  return [
    previous,
    ...[...settings].map(([key, value]) => quote(key) + "=" + quote(value)),
  ]
    .filter(Boolean)
    .join(" ");
}

// A helper is a shell command. Only interpret an unambiguous literal file
// argument to Git's built-in store. Other helpers can use arbitrary backends.
function credentialStoreFile(helper: string): string | undefined {
  const match =
    /^store[ \t]+--file(?:=|[ \t]+)(?:'([^']+)'|"([^"$`\\]+)"|([\w/.:@%+=,-]+))$/u.exec(
      helper,
    );
  const path = match?.[1] ?? match?.[2] ?? match?.[3];
  if (!path || !isAbsolute(path)) return undefined;
  // Git for Windows' shell can translate POSIX paths and drive-relative paths.
  if (process.platform === "win32" && !/^[a-z]:\//iu.test(path))
    return undefined;
  return path;
}

function rejectCredentialedGitDelegate(): never {
  throw new Error(
    "Cannot run Git filters or hooks with inline authentication in an external Git configuration file. Select a Git configuration without inline credentials for patching.",
  );
}

// Resume has no model turn or private-index discovery. These queries only read configuration and paths.
export async function activePatchPublicationHooks(
  run: (args: string[]) => Promise<string>,
): Promise<PatchPublicationHooks> {
  const hooks = { events: new Set<string>(), configured: new Set<string>() };
  await readConfiguredHooks(hooks, run);
  const directory = dirname(
    (
      await run([
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "hooks/pre-push",
      ])
    ).replace(/\n$/u, ""),
  );
  for (const hook of GIT_HOOKS) {
    const path = join(directory, hook);
    if (await hookIsAvailable(path))
      hooks.events.add(hook.replace(/\.exe$/u, ""));
  }
  return {
    ...hooks,
    gitDirectory: (await run(["rev-parse", "--absolute-git-dir"])).replace(
      /\n$/u,
      "",
    ),
  };
}

export interface PatchSnapshotConfig {
  // Latin-1 maps each captured Git byte to one character. Git's NUL-delimited
  // records leave NUL available to mark the prefix of an included file.
  files: string[];
  global?: number;
  system?: number;
  commands: Record<string, number>;
}

// Embedded in the sandbox bridge, where each invocation has its own endpoints.
export function snapshotConfigBytes(files: string[], prefix: string): Buffer[] {
  // A blank line keeps the writer connected until Git finishes probing the
  // pipe's attributes or reading the otherwise empty configuration.
  return files.map((text) =>
    Buffer.from(text.replaceAll("\0", prefix) || "\n", "latin1"),
  );
}

const includeSetting = /^include(?:if\..*)?\.path$/u;

function parseConfigEntry(entry: string) {
  const split = entry.indexOf("\n");
  return split < 0
    ? { key: entry, value: undefined }
    : { key: entry.slice(0, split), value: entry.slice(split + 1) };
}

// Invert Git's NUL-delimited config output, retaining valueless keys and
// arbitrary bytes. Subsection names may themselves contain dots and quotes.
function serializeConfigEntry(key: string, value: string | undefined): string {
  const quote = (text: string) => '"' + text.replace(/["\\]/gu, "\\$&") + '"';
  const first = key.indexOf(".");
  const last = key.lastIndexOf(".");
  const section = key.slice(0, first);
  const subsection =
    first === last ? "" : " " + quote(key.slice(first + 1, last));
  const assignment =
    value === undefined ? "" : " = " + quote(value).replaceAll("\n", "\\n");
  return (
    "[" + section + subsection + "]\n" + key.slice(last + 1) + assignment + "\n"
  );
}

function hasErrorCode(error: unknown, ...codes: string[]): boolean {
  return codes.includes((error as NodeJS.ErrnoException).code ?? "");
}

const missing = (error: unknown): undefined => {
  if (hasErrorCode(error, "ENOENT", "ENOTDIR")) return undefined;
  throw error;
};

function inside(root: string, path: string): boolean {
  const difference = relative(root, path);
  return (
    difference !== ".." &&
    !difference.startsWith(`..${sep}`) &&
    !isAbsolute(difference)
  );
}

function controlPathText(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      bytes,
    );
  } catch (cause) {
    throw new Error(
      "Patch cannot safely use Git configuration or administration paths that are not valid UTF-8.",
      { cause },
    );
  }
}

const realControlPath = async (path: string) =>
  controlPathText(await realpath(path, { encoding: "buffer" }));

// Append before realpath so a link/.. path keeps the filesystem's meaning.
const relativeFile = (directory: string, path: string) =>
  isAbsolute(path)
    ? path
    : directory + (directory.endsWith(sep) ? "" : sep) + path;

function httpCredentialPath(directory: string, file: string): string {
  if (process.platform === "win32") {
    const drive = /^[a-z]:(?![\\/])/iu.exec(file)?.[0];
    if (drive) {
      const current = /^(?:\\\\[?.]\\)?([a-z]:)[\\/]/iu.exec(directory)?.[1];
      if (drive.toLowerCase() !== current?.toLowerCase())
        throw new Error(
          "Use a fully qualified path for a Git HTTP credential file on another Windows drive.",
        );
      return `${directory}${sep}${file.slice(2)}`;
    }
    if (/^[\\/](?![\\/])/u.test(file)) {
      const volume =
        /^\\\\[?.]\\UNC\\[^\\]+\\[^\\]+/iu.exec(directory)?.[0] ??
        parse(directory).root;
      return `${volume.replace(/[\\/]$/u, "")}${file}`;
    }
  }
  return relativeFile(directory, file);
}

// Windows Go clients accept quotes around path list entries containing ';'.
function goPathList(value: string): string[] {
  if (process.platform !== "win32") return value.split(delimiter);
  const files: string[] = [];
  let current = "";
  let quoted = false;
  for (const character of value) {
    if (character === '"') quoted = !quoted;
    else if (character === delimiter && !quoted) {
      files.push(current);
      current = "";
    } else current += character;
  }
  files.push(current);
  return files;
}

function accountHomeDirectory(): string | undefined {
  try {
    return userInfo().homedir;
  } catch {
    // An effective UID need not have an entry in the password database.
    return undefined;
  }
}

export const githubConfigFiles = ["config.yml", "hosts.yml"] as const;

export function githubConfigDirectory(environment: NodeJS.ProcessEnv) {
  const explicit = environmentEntry(environment, "GH_CONFIG_DIR");
  if (explicit) return explicit;
  const xdg = environmentEntry(environment, "XDG_CONFIG_HOME");
  if (xdg) return join(xdg, "gh");
  const windows = process.platform === "win32";
  const appData = windows && environmentEntry(environment, "AppData");
  if (appData) return join(appData, "GitHub CLI");
  const home = environmentEntry(environment, windows ? "USERPROFILE" : "HOME");
  return join(home ?? "", ".config", "gh");
}

function selectFilePaths(paths: Set<string>, directory: string, file: string) {
  // A delegate can use the literal path or a client's normalized spelling.
  paths.add(relativeFile(directory, file));
  paths.add(join(directory, file));
  if (process.platform === "win32" && /^[a-z]:$/iu.test(directory))
    paths.add(directory + file);
}

function credentialHomes(environment: NodeJS.ProcessEnv) {
  // A delegate can unset a client override or read the default file directly.
  // On Windows kubeconfig discovery also checks HOME and HOMEDRIVE/HOMEPATH.
  const homes = new Set([
    environmentEntry(environment, "HOME"),
    awsAccountHome(environment),
    accountHomeDirectory(),
  ]);

  if (process.platform === "win32") {
    const drive = environmentEntry(environment, "HOMEDRIVE");
    const path = environmentEntry(environment, "HOMEPATH");
    if (drive && path) homes.add(drive + path);
  }
  return homes;
}

function clientConfigRoots(
  environment: NodeJS.ProcessEnv,
  homes: Set<string | undefined>,
): Set<string> {
  // Include legacy homes and the platform's user and system config roots.
  const get = (name: string) => environmentEntry(environment, name);
  const windows = process.platform === "win32";
  // The XDG library used by glab defaults to / when Unix HOME is empty.
  if (!windows && !get("HOME")) homes = new Set([...homes, "/"]);
  const homePrefix = windows ? /^%USERPROFILE%/u : /^(?:~|\$HOME)/u;
  const roots = new Set<string>();
  const xdg = [
    get("XDG_CONFIG_HOME"),
    ...goPathList(get("XDG_CONFIG_DIRS") ?? ""),
  ];
  for (const dir of xdg) {
    if (!dir) continue;
    roots.add(dir);
    if (homePrefix.test(dir))
      for (const home of homes)
        if (home) roots.add(join(home, dir.replace(homePrefix, "")));
  }
  for (const home of homes) {
    if (!home) continue;
    selectFilePaths(roots, home, ".config");
    if (windows) {
      roots.add(relativeFile(home, join("AppData", "Local")));
      roots.add(relativeFile(home, join("AppData", "Roaming")));
    } else if (process.platform === "darwin") {
      roots.add(relativeFile(home, join("Library", "Application Support")));
      roots.add(relativeFile(home, join("Library", "Preferences")));
    }
  }
  if (windows) {
    for (const key of [
      "LOCALAPPDATA",
      "APPDATA",
      "PROGRAMDATA",
      "ALLUSERSPROFILE",
    ]) {
      const value = get(key);
      if (value) roots.add(value);
    }
    roots.add(join((get("SYSTEMDRIVE") ?? "C:") + sep, "ProgramData"));
  } else if (process.platform === "darwin") {
    roots.add("/Library/Application Support");
    roots.add("/Library/Preferences");
  } else roots.add("/etc/xdg");
  return roots;
}

export function defaultSshConfigs(
  executable: string,
  environment: NodeJS.ProcessEnv,
): Map<string, string | undefined> {
  const configs = new Map<string, string | undefined>();
  const windows = process.platform === "win32";
  // The pinned transport starts in its volume root. OpenSSH uses the account
  // database for the user config. Git for Windows also consults HOME, then
  // HOMEDRIVE/HOMEPATH and USERPROFILE through the MSYS account database.
  const cwd = parse(executable).root;
  const prefix = dirname(dirname(executable));
  const msys =
    basename(prefix).toLowerCase() === "usr" ? dirname(prefix) : prefix;
  const homes = windows
    ? credentialHomes(environment)
    : [accountHomeDirectory()];
  for (let home of homes) {
    if (home === undefined) continue;
    if (windows && /^\/(?!\/)/u.test(home)) {
      const drive = /^\/(?:cygdrive\/)?([a-z])(?:\/|$)/iu;
      home = drive.test(home) ? home.replace(drive, "$1:/") : msys + home;
    }
    configs.set(
      relativeFile(relativeFile(cwd, home), join(".ssh", "config")),
      undefined,
    );
  }

  // System Includes are relative to the compiled SSHDIR. Cover OS packages,
  // portable OpenSSH, Homebrew and the bundled Git for Windows client.
  const system = (dir: string) =>
    configs.set(relativeFile(dir, "ssh_config"), dir);
  if (windows) {
    const data = environmentEntry(environment, "ProgramData");
    if (data) system(relativeFile(relativeFile(cwd, data), "ssh"));
    system(join(msys, "etc", "ssh"));
  } else {
    system("/etc/ssh");
    system(join(prefix, "etc", "ssh"));
    system(join(prefix, "etc"));
    const cellar = /^(.*)\/Cellar\/openssh\//u.exec(executable);
    if (cellar) system(join(cellar[1]! || "/", "etc", "ssh"));
  }
  return configs;
}

const gitlabConfigFile = join("glab-cli", "config.yml");

// Bind logical candidates, including absent higher-priority files. glab versions
// differ on the order of legacy and XDG roots. An explicit directory wins in all.
export function gitlabConfigFiles(environment: NodeJS.ProcessEnv): string[] {
  const explicit = environmentEntry(environment, "GLAB_CONFIG_DIR");
  const paths = new Set<string>();
  if (explicit) selectFilePaths(paths, explicit, "config.yml");
  else
    for (const directory of clientConfigRoots(
      environment,
      credentialHomes(environment),
    ))
      selectFilePaths(paths, directory, gitlabConfigFile);
  return [...paths];
}

function selectStoreDirectory(paths: Set<string>, path: string) {
  paths.add(path);
  paths.add(normalize(path));
}

function credentialPointers() {
  return { files: new Set<string>(), directories: new Set<string>() };
}

const npmGlobal = join("etc", "npmrc");
const devpiFiles = ["auth.json", "current.json"];

function selectClientFiles(
  selected: Set<string>,
  environment: NodeJS.ProcessEnv,
  homes: Set<string | undefined>,
) {
  const nuget = "NuGet/NuGet.Config";
  const uvCredentials = "uv/credentials/credentials.toml";
  const keyringFiles = (dir: string) => [
    join(dir, "keyring_pass.cfg"),
    join(dir, "crypted_pass.cfg"),
  ];
  const nugetCache = "MicrosoftCredentialProvider/SessionTokenCache.dat";
  const maven = [
    "settings.xml",
    "settings-security.xml",
    "settings-security4.xml",
  ];
  const helm = ["registry/config.json", "repositories.yaml"];
  const helmConfig = helm.map((file) => join("helm", file));
  const podmanAuth = "containers/auth.json";
  const pnpm = (dir = "pnpm") =>
    ["rc", "auth.ini", "config.yaml"].map((file) => join(dir, file));
  const npmPrefix =
    process.platform === "win32"
      ? dirname(process.execPath)
      : dirname(dirname(process.execPath));
  selectFilePaths(selected, npmPrefix, npmGlobal);
  if (process.platform !== "win32" && environment["DESTDIR"])
    selectFilePaths(
      selected,
      join(environment["DESTDIR"], npmPrefix),
      npmGlobal,
    );
  // Client homes also contain executables and caches. Protect just these
  // files under each default and each directory selected by the operator.
  const clientStores: [string | null, string[], ...string[]][] = [
    [
      ".azure",
      ["AZURE_CONFIG_DIR"],
      "accessTokens.json",
      "msal_token_cache.json",
      "msal_token_cache.bin",
      "service_principal_entries.json",
      "service_principal_entries.bin",
    ],
    [".docker", ["DOCKER_CONFIG"], "config.json", "cert.pem", "key.pem"],
    [".", ["XDG_CONFIG_HOME"], ".bunfig.toml"],
    [null, ["PREFIX", "NPM_CONFIG_PREFIX"], npmGlobal],
    [null, ["DOCKER_CERT_PATH"], "cert.pem", "key.pem"],
    [".cargo", ["CARGO_HOME"], "credentials", "credentials.toml"],
    [null, ["POETRY_CONFIG_DIR"], "auth.toml", "config.toml"],
    [null, ["UV_CREDENTIALS_DIR"], "credentials.toml"],
    [".rye", ["RYE_HOME"], "credentials", "config.toml"],
    [".devpi/client", [], ...devpiFiles],
    [
      ".local/share",
      ["XDG_DATA_HOME"],
      uvCredentials,
      "gem/credentials",
      nugetCache,
      ...keyringFiles("python_keyring"),
    ],
    [".gradle", ["GRADLE_HOME", "GRADLE_USER_HOME"], "gradle.properties"],
    [".m2", [], ...maven],
    [null, ["MAVEN_HOME", "M2_HOME"], "conf/settings.xml"],
    [".anaconda", [], "keyring", "config.toml"],
    [".mamba", [], "auth/authentication.json"],
    [".rattler", [], "credentials.json"],
    [".bundle", ["BUNDLE_USER_HOME", "BUNDLE_APP_CONFIG"], "config"],
    [".", ["DOTNET_CLI_HOME"], join(".nuget", nuget)],
    [
      ".config",
      ["XDG_CONFIG_HOME"],
      nuget,
      "gem/gemrc",
      podmanAuth,
      ...helmConfig,
      ...pnpm(),
    ],
    [null, ["HELM_CONFIG_HOME"], ...helm],
    [null, ["XDG_RUNTIME_DIR"], podmanAuth],
  ];
  if (process.platform === "win32")
    clientStores.push(
      ["AppData/Local", ["LOCALAPPDATA"], nugetCache, ...pnpm("pnpm/config")],
      [
        "AppData/Roaming",
        ["APPDATA"],
        nuget,
        ...helmConfig,
        join("npm", npmGlobal),
        uvCredentials,
        "uv/data/credentials/credentials.toml",
      ],
      [
        "AppData/Local",
        ["LOCALAPPDATA", "PROGRAMDATA"],
        ...keyringFiles("Python Keyring"),
      ],
    );
  if (process.platform === "darwin")
    clientStores.push(
      ["Library/Preferences", [], ...helmConfig, ...pnpm()],
      ["Library/Application Support", [], nugetCache, uvCredentials],
    );
  const entries = Object.entries(environment);
  for (const [subdir, selectors, ...files] of clientStores) {
    for (const [name, dir] of entries) {
      if (!dir || !selectors.includes(name.toUpperCase())) continue;
      for (const file of files) selectFilePaths(selected, dir, normalize(file));
    }
    if (subdir === null) continue;
    for (const home of homes) {
      if (home === undefined) continue;
      for (const file of files)
        selectFilePaths(selected, home, join(subdir, file));
    }
  }
  for (const file of (environment["GEMRC"] ?? "").split(delimiter))
    if (file) selected.add(file);
  if (process.platform === "linux" && process.getuid) {
    const uid = String(process.getuid());
    selectFilePaths(selected, join("/run/containers", uid), "auth.json");
    selectFilePaths(selected, join("/run/user", uid), podmanAuth);
  }
}

async function collectCredentialPointers(
  paths: ReturnType<typeof credentialPointers>,
  checkout: string,
  inherited: Readonly<Record<string, unknown>>,
  settings?: Readonly<Record<string, unknown>>,
): Promise<void> {
  const environment: NodeJS.ProcessEnv = Object.create(null);
  const key = (name: string) =>
    process.platform === "win32" ? name.toUpperCase() : name;
  for (const source of [inherited, settings ?? {}])
    for (const [name, value] of Object.entries(source))
      if (typeof value === "string") environment[key(name)] = value;
  const selected = paths.files;
  const pipConfig = process.platform === "win32" ? "pip.ini" : "pip.conf";
  const binstarDirs = new Set<string>();
  const devpi = environment["DEVPI_CLIENTDIR"];
  const terraformHomes = new Set<string>();
  const selectFile = (directory: string, file: string, paths = selected) =>
    selectFilePaths(paths, directory, file);
  const selectComposer = (dir: string) => {
    // Platform::expandPath substitutes only a leading ~, $NAME or %NAME%.
    const expanded = dir.replace(
      /^(?:~(?=[\\/])|\$(\w+)|%(\w+)%)/u,
      (_match, dollar?: string, percent?: string) => {
        const name = dollar ?? percent;
        if (!name || (name === "HOME" && process.platform === "win32"))
          return environment["HOME"] || awsAccountHome(environment);
        return environment[key(name)] ?? "";
      },
    );
    for (const file of ["auth.json", "config.json"])
      selectFile(expanded || sep, file);
  };
  const selectGh = (directory: string) => {
    for (const file of githubConfigFiles) selectFile(directory, file);
  };
  const gcloudAdc = "application_default_credentials.json";
  const selectGcloud = (directory: string, prefix = "") => {
    selectFile(directory, join(prefix, gcloudAdc));
    for (const db of ["credentials.db", "access_tokens.db"])
      // SQLite can also keep credential rows in its journal or write-ahead log.
      for (const suffix of ["", "-journal", "-wal"])
        selectFile(directory, join(prefix, db + suffix));
    selectFile(
      directory,
      join(prefix, "legacy_credentials"),
      paths.directories,
    );
  };
  const awsCaches = new Set<string>();
  const selectPgDefaults = (home: string) => {
    selectFile(home, process.platform === "win32" ? "pgpass.conf" : ".pgpass");
    selectFile(home, ".pg_service.conf");
    const client =
      process.platform === "win32" ? home : relativeFile(home, ".postgresql");
    selectFile(client, "postgresql.key");
    selectFile(client, "postgresql.crt");
  };
  const homes = credentialHomes(environment);
  const selectFragments = async (
    dir: string,
    pattern: RegExp,
    optional = false,
  ) => {
    const entries = await readdir(httpCredentialPath(checkout, dir), {
      withFileTypes: true,
    }).catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT" || error.code === "ENOTDIR") return [];
      if (optional && hasErrorCode(error, "EACCES", "EPERM", "ELOOP"))
        return [];
      throw error;
    });
    for (const entry of entries)
      if (!entry.isDirectory() && pattern.test(entry.name))
        selectFile(
          dir,
          entry.name.replace(pattern, (suffix) => suffix.toLowerCase()),
        );
  };
  const profileDirs = new Set<string>();
  const protectCodexHome = (home: string, subdirectory = "") => {
    if (subdirectory) selectFile(home, subdirectory, profileDirs);
    else profileDirs.add(home);
    for (const file of ["auth.json", ".credentials.json", "config.toml"])
      selectFile(home, join(subdirectory, file));
  };
  protectCodexHome(configuredCodexHome(environment));
  protectCodexHome(codexSecurityCredentialHome(environment));
  for (const home of homes) {
    if (home === undefined) continue;
    terraformHomes.add(
      process.platform === "win32" ? join(home, "AppData", "Roaming") : home,
    );
    selectPgDefaults(
      process.platform === "win32"
        ? relativeFile(home, join("AppData", "Roaming", "postgresql"))
        : home,
    );
    if (devpi !== undefined) {
      const dir = expandCredentialPath("DEVPI_CLIENTDIR", devpi, home) || ".";
      for (const file of devpiFiles) selectFile(dir, file);
    }
    selectFile(home, join(".continuum", "anaconda-client"), binstarDirs);
    selectFile(home, ".gnupg", paths.directories);
    if (process.platform === "win32")
      selectFile(home, join("AppData", "Roaming", "gnupg"), paths.directories);
    protectCodexHome(home, ".codex");
    selectFile(home, join(".gcm", "store"), paths.directories);
    selectGcloud(home, join(".config", "gcloud"));
    for (const client of ["cli", "sso", "login"])
      selectFile(home, join(".aws", client, "cache"), awsCaches);
    const loginCache = environment["AWS_LOGIN_CACHE_DIRECTORY"];
    if (loginCache !== undefined)
      awsCaches.add(
        expandCredentialPath(
          "AWS_LOGIN_CACHE_DIRECTORY",
          loginCache,
          home,
          environment,
        ),
      );
    selectGh(join(home, ".config", "gh"));
    selectComposer(relativeFile(home, ".composer"));
    selectComposer(relativeFile(home, ".config/composer"));
    if (process.platform === "win32")
      selectComposer(relativeFile(home, "AppData/Roaming/Composer"));
    for (const file of [
      ".dockercfg",
      ".gemrc",
      join(".gem", "credentials"),
      join(".kube", "config"),
      ".npmrc",
      ".yarnrc",
      ".yarnrc.yml",
      ".condarc",
      ".pypirc",
      join(".gcm", "msal.cache"),
      join(".gcm", "msal", "app.cache"),
      join(".local", ".IdentityService", "msal.cache"),
      ".boto",
      join(process.platform === "win32" ? "pip" : ".pip", pipConfig),
    ])
      selectFile(home, file);
    for (const name of [
      "ANACONDA_AUTH_KEYRING_PATH",
      "ANACONDA_CLOUD_KEYRING_PATH",
      "ANACONDA_CONFIG_TOML",
      "BOTO_CONFIG",
      "AWS_CREDENTIAL_FILE",
      "PIP_CLIENT_CERT",
    ]) {
      const value = environment[name];
      if (value)
        selected.add(
          expandCredentialPath(
            name,
            value,
            home,
            name === "BOTO_CONFIG" || name.startsWith("ANACONDA_")
              ? environment
              : undefined,
          ),
        );
    }
    for (const { defaultPath, path } of awsProfileFiles(home, environment)) {
      selected.add(defaultPath);
      if (path) selected.add(path);
    }
  }
  selectClientFiles(selected, environment, homes);
  const entries = Object.entries(environment);
  if (environment["COMPOSER_HOME"])
    selectComposer(environment["COMPOSER_HOME"]);
  if (environment["XDG_CONFIG_HOME"]) {
    selectGh(join(environment["XDG_CONFIG_HOME"], "gh"));
    selectComposer(relativeFile(environment["XDG_CONFIG_HOME"], "composer"));
  }
  if (process.platform === "win32") {
    const appData = environment["APPDATA"];
    // Native GnuPG asks Windows for Roaming AppData and falls back to C:/gnupg.
    paths.directories.add("C:\\gnupg");
    for (const roaming of [appData, process.env["APPDATA"]])
      if (roaming) selectFile(roaming, "gnupg", paths.directories);
    if (appData) {
      terraformHomes.add(appData);
      selectGh(join(appData, "GitHub CLI"));
      selectComposer(relativeFile(appData, "Composer"));
      selectPgDefaults(relativeFile(appData, "postgresql"));
    }
    // google-auth treats an empty APPDATA as a relative directory.
    if (appData === "") selectFile(appData, join("gcloud", gcloudAdc));
    // The gcloud CLI falls back to the system drive for empty or absent APPDATA.
    selectGcloud(
      appData || (environment["SYSTEMDRIVE"] ?? "C:") + sep,
      "gcloud",
    );
  }
  selectGh(githubConfigDirectory(environment));
  // uv falls back to a relative state directory if home discovery fails.
  selected.add(join(".uv", "credentials", "credentials.toml"));
  const roots = clientConfigRoots(environment, homes);
  if (process.platform === "win32")
    for (const [name, dir] of entries)
      if (dir && /^WIN_PD_OVERRIDE_(?:(?:LOCAL|COMMON)_)?APPDATA$/u.test(name))
        roots.add(dir);
  for (const root of roots) {
    selectFile(root, join("pypoetry", "auth.toml"));
    selectFile(root, join("pypoetry", "config.toml"));
    selectFile(root, join("hatch", "config.toml"));
    selectFile(root, join("pdm", "config.toml"));
    if (process.platform === "win32")
      selectFile(root, join("pdm", "pdm", "config.toml"));
    selectFile(root, join("uv", "uv.toml"));
    selectFile(
      root,
      process.platform === "win32" ? join("ContinuumIO", "binstar") : "binstar",
      binstarDirs,
    );
    selectFile(root, gitlabConfigFile);
    selectFile(root, join("pip", pipConfig));
    selectFile(root, join("sops", "age", "keys.txt"));
    if (process.platform === "win32")
      selectFile(root, join(".IdentityService", "msal.cache"));
  }
  if (process.platform !== "win32") {
    selectFile("/etc", pipConfig);
    selectFile("/etc", join("uv", "uv.toml"));
    selectFile("/etc", "boto.cfg");
  }
  for (const prefix of [
    environment["VIRTUAL_ENV"],
    environment["CONDA_PREFIX"],
  ])
    if (prefix) selectFile(prefix, pipConfig);
  // Capture physical targets too when a profile is a link into a dotfile tree.
  for (const dir of awsCaches) {
    // An explicitly empty AWS_LOGIN_CACHE_DIRECTORY stores SHA-256 session files in cwd.
    const local = resolve(checkout, dir) === resolve(checkout);
    if (!local) paths.directories.add(dir);
    await selectFragments(
      dir || ".",
      local ? /^[0-9a-f]{64}\.json$/u : /\.json$/u,
      true,
    );
  }
  // The defaults are dedicated stores. An explicit override can instead
  // point to a shared data directory, including ./data in the checkout.
  for (const dir of binstarDirs) paths.directories.add(dir);
  const binstar = environment["BINSTAR_CONFIG_DIR"];
  if (binstar !== undefined) {
    const dir = binstar || ".";
    selectFile(dir, "data", binstarDirs);
    selectFile(dir, join("data", "config.yaml"));
    selectFile(dir, join("data", "tokens"), paths.directories);
  }
  for (const dir of binstarDirs) {
    await selectFragments(dir, /(?:\.token|^config\.yaml)$/u, true);
    await selectFragments(relativeFile(dir, "tokens"), /\.token$/u, true);
  }
  for (const dir of profileDirs)
    await selectFragments(dir, /\.config\.toml(?:\.tmp)?$/iu);
  for (const home of terraformHomes) {
    const windows = process.platform === "win32";
    selectFile(home, windows ? "terraform.rc" : ".terraformrc");
    const dir = join(home, windows ? "terraform.d" : ".terraform.d");
    selectFile(dir, "credentials.tfrc.json");
    await selectFragments(dir, /\.tfrc(?:\.json)?$/u);
  }
  const npmConfigPath = (value: string) => {
    // npm trims path settings and expands environment references before '~'.
    const expanded = value
      .trim()
      .replace(
        /(?<!\\)(\\*)\$\{([^$?{}]+)(\?)?\}/gu,
        (
          match,
          escapes: string,
          variable: string,
          optional: string | undefined,
        ) => {
          if (escapes.length % 2) return match.slice((escapes.length + 1) / 2);
          const replacement = environment[key(variable)];
          return (
            escapes.slice(escapes.length / 2) +
            (typeof replacement === "string"
              ? replacement
              : optional
                ? ""
                : "${" + variable + "}")
          );
        },
      );
    const homePrefix = process.platform === "win32" ? /^~[\\/]/u : /^~\//u;
    if (homePrefix.test(expanded)) {
      const home = environment[key("HOME")];
      return resolve(
        typeof home === "string" && home ? home : homedir(),
        expanded.slice(2),
      );
    }
    return expanded && normalize(expanded);
  };
  for (const [name, value] of entries) {
    if (typeof value !== "string" || !value) continue;
    const variable = name.toUpperCase();
    if (patchCredentialKind(variable) === "file") {
      selected.add(value);
      if (/^~[\\/]/u.test(value))
        for (const home of homes) if (home) selectFile(home, value.slice(2));
      const path = variable.startsWith("NPM_CONFIG_")
        ? npmConfigPath(value)
        : normalize(value);
      if (path) selected.add(path);
      continue;
    }
    switch (variable) {
      case "NPM_CONFIG_PREFIX":
        selectFile(npmConfigPath(value), npmGlobal);
        break;
      case "YARN_RC_FILENAME":
        for (const home of homes) if (home) selectFile(home, value);
        break;
      case "GNUPGHOME": {
        // GnuPG interprets C:name as C:\name on Windows.
        const dir =
          process.platform === "win32"
            ? value.replace(/^([a-z]:)(?![\\/])/iu, "$1\\")
            : value;
        selectStoreDirectory(paths.directories, dir);
        if (dir === "~" || dir.startsWith("~/"))
          for (const home of homes)
            if (home !== undefined) paths.directories.add(home + dir.slice(1));
        break;
      }
      case "KUBECONFIG":
        for (const path of goPathList(value)) if (path) selected.add(path);
        break;
      case "GCM_PLAINTEXT_STORE_PATH":
        selectStoreDirectory(paths.directories, value);
        break;
      case "GLAB_CONFIG_DIR":
        selectFile(value, "config.yml");
        break;
      case "CLOUDSDK_CONFIG":
        selectGcloud(value);
        break;
      case "PGSYSCONFDIR":
        selectFile(value, "pg_service.conf");
        break;
    }
  }
}

async function readGitMarker(
  marker: string | Buffer,
): Promise<Buffer | true | undefined> {
  const metadata = await stat(marker).catch(missing);
  if (metadata === undefined) return undefined;
  if (metadata.isDirectory()) return true;
  if (!metadata.isFile()) return undefined;
  const contents = await readFile(marker);
  return contents.subarray(0, 8).equals(Buffer.from("gitdir: "))
    ? contents
    : undefined;
}

export async function selectedGitFileReference(
  marker: string,
  gitDirectory: string,
): Promise<string | undefined> {
  const contents = await readGitMarker(marker);
  if (contents === undefined || contents === true) return undefined;
  const reference = relativeFile(
    dirname(marker),
    controlPathText(contents)
      .slice(8)
      .replace(/[\r\n]+$/u, ""),
  );
  return (await realControlPath(reference).catch(missing)) === gitDirectory
    ? reference
    : undefined;
}

function gitFatalDiagnostic(error: unknown): string | undefined {
  if (!(error instanceof Error)) return undefined;
  const failure = error as Error & {
    code?: unknown;
    status?: unknown;
    stderr?: unknown;
  };
  if (failure.code !== 128 && failure.status !== 128) return undefined;
  if (Buffer.isBuffer(failure.stderr)) return failure.stderr.toString("utf8");
  return typeof failure.stderr === "string" ? failure.stderr : undefined;
}

function hasNoWorktree(error: unknown): boolean {
  return /fatal: this operation must be run in a work tree\r?\n$/u.test(
    gitFatalDiagnostic(error) ?? "",
  );
}

async function readCommonDirectory(
  gitDirectory: string,
  rememberReference?: (path: string) => Promise<void>,
): Promise<string | undefined> {
  const commonBytes = await readFile(join(gitDirectory, "commondir")).catch(
    missing,
  );
  const common =
    commonBytes === undefined ? undefined : controlPathText(commonBytes);
  if (common === undefined) return undefined;
  const commonReference = relativeFile(
    gitDirectory,
    common.replace(/[\r\n]+$/u, ""),
  );
  const resolvedCommon = await realControlPath(commonReference);
  await rememberReference?.(commonReference);
  return resolvedCommon;
}

async function markerDirectories(
  directory: string,
  isGitDirectory: (path: string, contents?: Buffer | true) => Promise<boolean>,
  commonDirectory?: string,
  rememberReference?: (path: string) => Promise<void>,
): Promise<string[] | undefined> {
  const marker = join(directory, ".git");
  const contents = await readGitMarker(marker);
  if (contents === undefined) return undefined;
  if (!(await isGitDirectory(marker, contents))) return undefined;
  const reference =
    contents === true
      ? marker
      : relativeFile(
          directory,
          controlPathText(contents)
            .slice(8)
            .replace(/[\r\n]+$/u, ""),
        );
  const gitDirectory = await realControlPath(reference).catch(missing);
  if (gitDirectory === undefined) return undefined;
  if (!(await stat(gitDirectory)).isDirectory()) return undefined;
  await rememberReference?.(reference);
  if (commonDirectory !== undefined) return [gitDirectory, commonDirectory];
  const common = await readCommonDirectory(gitDirectory, rememberReference);
  return common === undefined ? [gitDirectory] : [gitDirectory, common];
}

async function isRegisteredLinkedWorktree(
  checkout: string,
  directories: string[],
): Promise<boolean> {
  const [gitDirectory, common] = directories;
  if (
    !gitDirectory ||
    !common ||
    relative(join(common, "worktrees"), dirname(gitDirectory)) !== ""
  )
    return false;
  // Git records the reciprocal checkout path in the common repository's
  // worktree registration. A gitfile in the selected checkout cannot supply it.
  const backlink = join(gitDirectory, "gitdir");
  if (!(await lstat(backlink).catch(missing))?.isFile()) return false;
  const registered = relativeFile(
    gitDirectory,
    controlPathText(await readFile(backlink)).replace(/[\r\n]+$/u, ""),
  );
  const marker = await realControlPath(registered).catch(missing);
  return (
    marker !== undefined && relative(join(checkout, ".git"), marker) === ""
  );
}

// Git permits include files and hook directories that do not exist yet.
async function canonicalPath(path: string): Promise<string> {
  // Match realpath's Windows separators when a path no longer exists.
  if (sep === "\\") path = path.replaceAll("/", sep);
  // Some realpath implementations collapse file/.. even when lookup fails.
  const canonical = await stat(path)
    .then(() => realControlPath(path))
    .catch(missing);
  if (canonical !== undefined) return canonical;
  const parent = dirname(path);
  if (parent === path) return path;
  // A missing intermediate component must not collapse into an existing file.
  return `${await canonicalPath(parent)}${path.slice(parent.length)}`;
}

async function directoryLinkEntry(
  path: string,
  identity: { dev: bigint; ino: bigint },
): Promise<string> {
  const parent = await canonicalPath(dirname(path));
  const spelling = basename(path);
  const names = await readdir(parent).catch((error: unknown) => {
    // Traversal can be permitted without directory-list access.
    if (hasErrorCode(error, "EACCES", "EPERM")) return undefined;
    throw error;
  });
  // Exact names remain distinct in case-sensitive directories.
  if (names !== undefined && !names.includes(spelling)) {
    for (const name of names) {
      if (name.toLowerCase() !== spelling.toLowerCase()) continue;
      const candidate = join(parent, name);
      const metadata = await lstat(candidate, { bigint: true }).catch(missing);
      if (metadata?.dev === identity.dev && metadata.ino === identity.ino)
        return candidate;
    }
    let match: string | undefined;
    for (const name of names) {
      if (name.toLowerCase() === spelling.toLowerCase()) continue;
      const candidate = join(parent, name);
      const metadata = await lstat(candidate, { bigint: true }).catch(missing);
      if (metadata?.dev !== identity.dev || metadata.ino !== identity.ino)
        continue;
      if (match !== undefined) return join(parent, spelling);
      match = candidate;
    }
    if (match !== undefined) return match;
  }
  return join(parent, spelling);
}

function trimDirectorySeparators(path: string): string {
  const rootLength = parse(path).root.length;
  return (
    path.slice(0, rootLength) +
    path.slice(rootLength).replace(sep === "\\" ? /[\\/]+$/u : /\/+$/u, "")
  );
}

async function directoryLinks(path: string): Promise<string[]> {
  const links = new Set<string>();
  const inspected = new Set<string>();
  const inspect = async (path: string): Promise<void> => {
    path = trimDirectorySeparators(path);
    if (inspected.has(path)) return;
    inspected.add(path);
    // Reject filesystem loops before tracing individual links.
    await canonicalPath(path);
    for (
      let entry = path;
      dirname(entry) !== entry;
      entry = trimDirectorySeparators(dirname(entry))
    ) {
      const metadata = await lstat(entry, { bigint: true }).catch(missing);
      if (!metadata?.isSymbolicLink()) continue;
      links.add(await directoryLinkEntry(entry, metadata));
      // Link targets can contain additional directory links.
      await inspect(relativeFile(dirname(entry), await readlink(entry)));
    }
  };
  await inspect(path);
  return [...links];
}

async function readableGitParent(
  checkout: string,
  path: Buffer,
  directory: boolean,
  gitlink: boolean,
  selectsGitDirectory: (
    directory: Buffer,
    markerContents: Buffer | true,
  ) => Promise<boolean>,
): Promise<{ path: string; exact: boolean } | undefined> {
  const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  if (path.at(-1) === 47) path = path.subarray(0, -1);
  if (!directory) path = path.subarray(0, Math.max(0, path.lastIndexOf(47)));
  let exact = true;
  while (path.length > 0) {
    try {
      return { path: utf8.decode(path), exact };
    } catch {
      // Check the actual byte path; never inspect its replacement-decoded alias.
    }
    // Ordinary symlink replacements are data, including raw-byte ancestors.
    let skippedSymlink = false;
    for (let offset = 0; offset < path.length;) {
      const separator = path.indexOf(47, offset);
      const end = separator < 0 ? path.length : separator;
      const prefix = path.subarray(0, end);
      if (
        (!gitlink ||
          !exact ||
          end !== path.length ||
          process.platform !== "win32") &&
        (
          await lstat(
            Buffer.concat([Buffer.from(`${checkout}${sep}`), prefix]),
          ).catch(missing)
        )?.isSymbolicLink()
      ) {
        path = prefix.subarray(0, Math.max(0, prefix.lastIndexOf(47)));
        exact = false;
        skippedSymlink = true;
        break;
      }
      offset = end + 1;
    }
    if (skippedSymlink) continue;
    const rawCheckout = Buffer.concat([Buffer.from(`${checkout}${sep}`), path]);
    const marker = Buffer.concat([rawCheckout, Buffer.from(`${sep}.git`)]);
    const markerContents = await readGitMarker(marker);
    if (
      markerContents !== undefined &&
      (await selectsGitDirectory(rawCheckout, markerContents))
    )
      throw new Error(
        "Patch cannot safely use Git administration whose checkout path is not valid UTF-8.",
      );
    path = path.subarray(0, Math.max(0, path.lastIndexOf(47)));
    exact = false;
  }
  return undefined;
}

// Older Git versions do not recognize GIT_NO_LAZY_FETCH. An empty protocol
// allowlist also prevents local object reads from contacting promisor remotes.
export const PATCH_LOCAL_GIT_ENVIRONMENT = {
  GIT_NO_LAZY_FETCH: "1",
  GIT_ALLOW_PROTOCOL: "",
} as const;

export type PatchGitControlMode = "sandbox" | "external" | "resumed-hook";

export async function capturePatchGitControls(
  directory: string,
  runGit: RunGit,
  {
    usesWorktreeMarker = true,
    usesCommonDirectoryMarker = true,
    selectedGitDirectory,
    environment = process.env,
    automaticPublication = false,
    mode = "sandbox",
    credentialStorePaths = new Set<string>(),
    shellSettings,
    onSnapshotConfig,
  }: {
    usesWorktreeMarker?: boolean;
    usesCommonDirectoryMarker?: boolean;
    selectedGitDirectory?: string;
    environment?: ProcessEnvironment;
    automaticPublication?: boolean;
    mode?: PatchGitControlMode;
    credentialStorePaths?: Set<string>;
    shellSettings?: Readonly<Record<string, unknown>>;
    onSnapshotConfig?: (config: PatchSnapshotConfig) => void;
  } = {},
): Promise<PatchGitControls | undefined> {
  const globalConfig = environmentEntry(environment, "GIT_CONFIG_GLOBAL");
  const systemConfig = environmentEntry(environment, "GIT_CONFIG_SYSTEM");
  const noSystem = environmentEntry(environment, "GIT_CONFIG_NOSYSTEM");
  const xdgConfigHome = environmentEntry(environment, "XDG_CONFIG_HOME");
  const objectDirectory = environmentEntry(environment, "GIT_OBJECT_DIRECTORY");
  const alternatePaths = environmentEntry(
    environment,
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  );
  const commandParameters = environmentEntry(
    environment,
    "GIT_CONFIG_PARAMETERS",
  );
  const userProfile = environmentEntry(environment, "USERPROFILE");
  let root = directory;
  const run = (
    checkout: string,
    args: string[],
    options?: PatchGitCommandOptions,
  ) =>
    runGit(root, checkout, args, {
      ...options,
      environment: {
        ...options?.environment,
        ...PATCH_LOCAL_GIT_ENVIRONMENT,
      },
    });
  const runBytes = async (
    checkout: string,
    args: string[],
    options?: PatchGitCommandOptions,
  ) =>
    Buffer.from(
      await run(checkout, args, { ...options, encoding: "base64" }),
      "base64",
    );
  const runControl = async (...args: Parameters<typeof run>) =>
    controlPathText(await runBytes(...args));
  // GIT_CONFIG selects a file only for git-config, not snapshot bookkeeping.
  const configOptions = { environment: { GIT_CONFIG: undefined } };
  const runConfig = (checkout: string, args: string[]) =>
    runControl(checkout, args, configOptions);
  // Config records contain unrelated keys too. Split bytes before decoding paths.
  const runConfigFields = async (
    checkout: string,
    args: string[],
    input?: Uint8Array,
  ) =>
    (await runBytes(checkout, args, { ...configOptions, input }))
      .toString("latin1")
      .split("\0");
  const controlPath = async (checkout: string, ...args: string[]) =>
    (await runControl(checkout, ["rev-parse", ...args])).replace(/\n$/u, "");
  const absolutePath = (checkout: string, ...args: string[]) =>
    controlPath(checkout, "--path-format=absolute", ...args);
  const configPath = (field: string) =>
    controlPathText(Buffer.from(field, "latin1"));
  if (mode === "resumed-hook") {
    // Use the saved push's working directory, including a bare repository.
    root = await realControlPath(directory);
  } else {
    try {
      const output = await runControl(directory, [
        "rev-parse",
        "--show-toplevel",
      ]);
      if (output.length === 0) return undefined;
      root = await realControlPath(output.replace(/\n$/u, ""));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (
        message.includes("not a git repository") ||
        message.toLowerCase() === "git is not available on a trusted path."
      )
        return undefined;
      throw error;
    }
  }
  const isGitDirectory = async (
    path: string,
    markerContents?: Buffer | true,
    nestedProbe = false,
  ): Promise<boolean> => {
    let administration: Buffer | undefined = Buffer.from(path);
    if (Buffer.isBuffer(markerContents)) {
      let target = markerContents.subarray(8);
      while (target.at(-1) === 10 || target.at(-1) === 13)
        target = target.subarray(0, -1);
      administration =
        target.length === 0
          ? undefined
          : isAbsolute(target.toString("latin1"))
            ? target
            : Buffer.concat([Buffer.from(`${dirname(path)}${sep}`), target]);
    }
    if (administration !== undefined) {
      for (const name of ["HEAD", "commondir"]) {
        const metadataPath = Buffer.concat([
          administration,
          Buffer.from(`${sep}${name}`),
        ]);
        const metadata = await stat(metadataPath).catch(missing);
        if (metadata && !metadata.isFile() && !metadata.isDirectory())
          throw new Error(
            `Patch cannot safely inspect non-regular Git metadata: ${metadataPath.toString("utf8")}`,
          );
      }
    }
    // Git's early gitfile reader finds relative targets using slash separators.
    const gitPath =
      process.platform === "win32" ? path.replaceAll("\\", "/") : path;
    try {
      // This early rev-parse mode only checks filesystem structure. It does not
      // select the candidate repository or load its configuration and hooks.
      await runBytes(root, ["rev-parse", "--resolve-git-dir", gitPath], {
        nestedProbe,
      });
      return true;
    } catch (error) {
      const diagnostic = gitFatalDiagnostic(error);
      if (diagnostic === undefined) throw error;
      const negatives = [
        `fatal: not a gitdir '${gitPath}'`,
        `fatal: gitfile does not point to a valid repository: ${gitPath}`,
        `fatal: no path in gitfile: ${gitPath}`,
      ];
      if (Buffer.isBuffer(markerContents)) {
        // This text is used only to recognize Git's diagnostic, never as a path
        // for filesystem access. Match the subprocess's UTF-8 error decoding.
        const configured = markerContents
          .subarray(8)
          .toString("utf8")
          .replace(/[\r\n]+$/u, "");
        const target = isAbsolute(configured)
          ? configured
          : `${gitPath.slice(0, gitPath.lastIndexOf("/") + 1)}${configured}`;
        negatives.push(`fatal: not a git repository: ${target}`);
      }
      if (
        negatives.some(
          (negative) =>
            diagnostic.endsWith(`${negative}\n`) ||
            diagnostic.endsWith(`${negative}\r\n`),
        )
      )
        return false;
      throw error;
    }
  };
  const rawCheckoutSelectsGit = async (
    checkout: Buffer,
    markerContents: Buffer | true,
  ): Promise<boolean> => {
    const temporary = await mkdtemp(
      join(tmpdir(), "codex-security-git-marker-"),
    );
    try {
      const alias = join(temporary, "checkout");
      // The symlink preserves byte names and relative gitfile resolution while
      // giving the native filesystem-only probe a representable argument.
      await symlink(checkout, alias);
      return await isGitDirectory(join(alias, ".git"), markerContents, true);
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  };
  const administrationRoots = new Map<string, { dev: bigint; ino: bigint }>();
  const administrationLinks = new Set<string>();
  const nestedDirectories = new Map<string, readonly string[]>();
  const nestedConfigurationDigests = new Set<string>();
  const rememberAdministrationReference = async (
    path: string,
  ): Promise<void> => {
    for (const link of await directoryLinks(path))
      administrationLinks.add(link);
  };
  const remember = async (path: string): Promise<void> => {
    const metadata = await stat(path, { bigint: true });
    // glab config set can save a token in the repository configuration.
    if (mode !== "external" && !administrationRoots.has(path))
      await protectStore(join(path, gitlabConfigFile));
    administrationRoots.set(path, { dev: metadata.dev, ino: metadata.ino });
  };
  const controlPaths = new Map<
    string,
    {
      canonical: string;
      identity: { dev: bigint; ino: bigint } | undefined;
      directory: boolean | undefined;
      readOnly: boolean;
      allowDirectoryChanges: boolean;
      allowDirectoryCreation: boolean;
      contents: Buffer | null | undefined;
    }
  >();
  const snapshotStoragePaths = new Set<string>();
  let snapshotConfig: PatchSnapshotConfig | undefined;
  let projectSnapshotConfig: (() => Promise<void>) | undefined;
  const credentialFileIds = new Set<string>();
  const configurationFiles = new Set<string>();
  const modelOnlyReadOnlyPaths = new Set<string>();
  const externalCachePaths = new Set<string>();
  const inaccessibleIncludes = new Set<string>();
  const unreadableConfigurations = new Set<string>();
  const inaccessibleHooks = new Set<string>();
  const hookContents = new Map<
    string,
    Buffer | { size: bigint; mtimeNs: bigint; ctimeNs: bigint }
  >();
  const hookDirectories = new Set<string>();
  const rememberControl = async (
    path: string,
    protectDirectory = true,
    addReadPermission = true,
    allowDirectoryCreation = false,
  ): Promise<void> => {
    const canonical = await canonicalPath(path);
    const metadata = await stat(canonical, { bigint: true }).catch(missing);
    const directory = metadata?.isDirectory();
    const previous = controlPaths.get(path);
    controlPaths.set(path, {
      canonical,
      contents: previous?.contents,
      identity: metadata && { dev: metadata.dev, ino: metadata.ino },
      directory,
      readOnly:
        previous?.readOnly === true ||
        (addReadPermission && (protectDirectory || !directory)),
      allowDirectoryChanges:
        !protectDirectory && previous?.allowDirectoryChanges !== false,
      allowDirectoryCreation:
        (allowDirectoryCreation || !protectDirectory) &&
        (previous === undefined ||
          previous.allowDirectoryCreation ||
          previous.allowDirectoryChanges),
    });
  };
  const rememberConfiguration = async (
    path: string,
    protectDirectory = true,
    optional = false,
  ): Promise<void> => {
    await rememberControl(path, protectDirectory);
    const control = controlPaths.get(path)!;
    if (control.contents !== undefined) return;
    if (!(await stat(control.canonical).catch(missing))?.isFile()) return;
    configurationFiles.add(control.canonical);
    try {
      control.contents = await readFile(control.canonical);
      unreadableConfigurations.delete(path);
    } catch (error) {
      if (optional && hasErrorCode(error, "EACCES", "EPERM")) {
        unreadableConfigurations.add(path);
        return;
      }
      throw error;
    }
  };
  const rememberSelectedConfiguration = async (
    path: string,
    optional = false,
  ): Promise<void> => {
    try {
      // Absent and empty regular inputs have no --show-origin records. Devices
      // such as /dev/null and unavailable optional inputs keep native behavior.
      const metadata = await stat(path).catch(missing);
      if (metadata === undefined) {
        await rememberControl(path, false);
        controlPaths.get(path)!.contents = null;
      } else if (metadata.isFile())
        await rememberConfiguration(path, true, optional);
    } catch (error) {
      if (optional && hasErrorCode(error, "EACCES", "EPERM")) return;
      throw error;
    }
  };
  const expandConfigurationPath = async (
    path: string,
    checkout = root,
    optional = true,
  ) => {
    try {
      return (
        await runConfig(checkout, [
          "-c",
          `codexsecurity.patchcontrolpath=${path}`,
          "config",
          "--null",
          "--type=path",
          "--get",
          "codexsecurity.patchcontrolpath",
        ])
      ).replace(/\0$/u, "");
    } catch (error) {
      // Per-user defaults and inactive includes can name an unavailable home.
      if (
        optional &&
        error instanceof Error &&
        error.message.includes("failed to expand user dir")
      )
        return undefined;
      throw error;
    }
  };
  // An untrusted delegate can select "store" itself, even when no helper was
  // configured. Deny the default stores as well as explicitly named files.
  let hostMayReadStore = false;
  let unisolatedCredentialHelper = false;
  const storeTarget = async (path: string): Promise<string> => {
    const physical = await realControlPath(path).catch(missing);
    if (physical !== undefined) return physical;
    // A dangling store symlink may acquire credentials after preflight. Deny
    // its physical target even when an ancestor or the final file is absent.
    const parent = dirname(path);
    if (parent === path) return path;
    if ((await lstat(path).catch(missing))?.isSymbolicLink())
      return storeTarget(relativeFile(parent, await readlink(path)));
    return relativeFile(await storeTarget(parent), basename(path));
  };
  const protectStore = async (path: string, includeDirectory = false) => {
    try {
      const metadata = await stat(path, { bigint: true }).catch(missing);
      if (metadata && !metadata.isFile() && !metadata.isDirectory()) {
        // Git can read credentials from a FIFO. Do not open it during capture
        // or assume that a regular-file sandbox rule isolates its producer.
        unisolatedCredentialHelper = true;
        return;
      }
      if (metadata?.isFile() || includeDirectory) hostMayReadStore = true;
      if (metadata?.isFile() && metadata.nlink > 1n)
        credentialFileIds.add(metadata.dev + ":" + metadata.ino);
      // Mounting a deny at a symlink itself fails on Linux. Git's file store
      // follows the link when locking and replacing its backing file.
      if (!metadata || metadata.isFile() || includeDirectory)
        credentialStorePaths.add(await storeTarget(path));
    } catch (error) {
      // Git cannot read an inaccessible store or a cyclic link. Preserve its
      // normal behavior without creating a mount at an unresolved alias.
      if (!hasErrorCode(error, "EACCES", "EPERM", "ELOOP")) throw error;
    }
  };
  const requestedDirectory =
    mode === "resumed-hook" ? root : await realControlPath(directory);
  const protectTransportFile = async (
    checkout: string,
    file: string,
    includeDirectory = false,
  ) => {
    const paths = new Set([httpCredentialPath(checkout, file)]);
    // Git can retain an external caller's cwd for transport.
    if (checkout === root && !inside(root, requestedDirectory))
      paths.add(httpCredentialPath(requestedDirectory, file));
    for (const path of paths) await protectStore(path, includeDirectory);
  };
  if (mode !== "external") {
    const legacy = await expandConfigurationPath("~/.git-credentials");
    if (legacy) await protectStore(relativeFile(root, legacy));
    const xdg = xdgConfigHome
      ? relativeFile(xdgConfigHome, "git/credentials")
      : await expandConfigurationPath("~/.config/git/credentials");
    if (xdg) await protectStore(relativeFile(root, xdg));
    // Git for Windows can initialize HOME from the drive and home path.
    // libcurl otherwise falls back to USERPROFILE or the Unix account home.
    const accountHome = accountHomeDirectory();
    const profile = process.platform === "win32" ? userProfile : undefined;
    const home = (await expandConfigurationPath("~")) || profile || accountHome;
    if (home) {
      await protectTransportFile(root, relativeFile(home, ".netrc"));
      await protectTransportFile(root, relativeFile(home, "_netrc"));
    }
    // OpenSSH locates account keys independently of Git's HOME override.
    // Checkout-selected hooks can otherwise copy a key into COMMIT_EDITMSG.
    for (const directory of new Set([home, profile, accountHome]))
      if (directory)
        await protectStore(
          relativeFile(root, relativeFile(directory, ".ssh")),
          true,
        );
  }
  const globalConfigurationPaths: string[] = [];
  let systemConfigurationPath: string | undefined;
  if (globalConfig !== undefined) {
    if (globalConfig !== "") globalConfigurationPaths.push(globalConfig);
  } else {
    for (const path of [
      xdgConfigHome
        ? `${xdgConfigHome}/git/config`
        : await expandConfigurationPath("~/.config/git/config"),
      await expandConfigurationPath("~/.gitconfig"),
    ])
      if (path !== undefined) globalConfigurationPaths.push(path);
  }
  if (systemConfig) {
    const disabled =
      noSystem === undefined
        ? "false"
        : (
            await runConfig(root, [
              "-c",
              `codexsecurity.patchnosystem=${noSystem}`,
              "config",
              "--type=bool",
              "--get",
              "codexsecurity.patchnosystem",
            ])
          ).trim();
    if (disabled === "false") systemConfigurationPath = systemConfig;
  }
  const insideSelectedRoots = (path: string): boolean =>
    inside(root, path) ||
    [...administrationRoots.keys()].some((administration) =>
      inside(administration, path),
    );
  // Global configuration can include a checkout-controlled file.
  const userSelectedConfig = async (
    scope: string | undefined,
    origin: string | undefined,
    checkout: string,
  ): Promise<boolean> =>
    (scope === "global" || scope === "system" || scope === "command") &&
    !(
      origin?.startsWith("file:") &&
      insideSelectedRoots(
        await canonicalPath(relativeFile(checkout, origin.slice(5))),
      )
    );
  const canPrepareStorage = async (path: string): Promise<boolean> => {
    for (const entry of await directoryLinks(path)) {
      if (administrationLinks.has(entry)) {
        await rememberControl(entry, true, false);
      } else if (insideSelectedRoots(dirname(entry))) {
        await rememberControl(entry, true, false);
        return false;
      }
    }
    return true;
  };
  const rememberHook = async (path: string): Promise<void> => {
    if (await hookIsAvailable(path)) {
      publicationHooks.events.add(basename(path).replace(/\.exe$/u, ""));
      await rememberControl(path, false);
      const canonical = controlPaths.get(path)!.canonical;
      const metadata = await stat(canonical, { bigint: true });
      if (metadata.isFile()) {
        try {
          hookContents.set(path, await readFile(canonical));
        } catch (error) {
          if (!hasErrorCode(error, "EACCES", "EPERM")) throw error;
          // Execute-only native hooks remain usable, but writable aliases must
          // not change them while the model controls the repository.
          hookContents.set(path, {
            size: metadata.size,
            mtimeNs: metadata.mtimeNs,
            ctimeNs: metadata.ctimeNs,
          });
        }
      }
    } else {
      // Git ignores inactive entries; reject their activation before bookkeeping.
      inaccessibleHooks.add(path);
    }
  };
  const publicationHooks = {
    events: new Set<string>(),
    configured: new Set<string>(),
  };
  const activeHostFilters = new Set<string>();
  const branchFilterSettings = new Set<string>();
  let hasConditionalFilters = false;
  const filterCheckouts = new Set<string>();
  let checkoutCleanFilter = false;
  const delegateFilters = new Set<string>();
  const nonemptyFilters = new Set<string>();
  const conditionalFilters = new Set<string>();
  const protectedFilterKeys = () => [...delegateFilters].map(configPath);
  let externalInlineAuthentication = false;
  const captureCredentialSource = async (
    checkout: string,
    key: string,
    value: string,
    origin: "file" | "command",
  ) => {
    if (mode === "external" || !value) return;
    // Delegates lose command-scope askpass settings, but Git can still read a
    // file-backed prompt and call it even when both askpass variables are unset.
    if (key === "core.askpass" && origin === "file") {
      unisolatedCredentialHelper = true;
      return;
    }
    if (httpCredentialFile.test(key)) {
      // The transport may create a cookie jar after capture. Keep host Git
      // from re-running a checkout filter even when the file is still absent.
      hostMayReadStore = true;
      // Git passes the proxy SSL key and certificate paths verbatim to libcurl.
      const file = /\.proxyssl(?:key|cert)$/iu.test(key)
        ? configPath(value)
        : await expandConfigurationPath(configPath(value));
      if (file) await protectTransportFile(checkout, file);
      return;
    }
    if (/^credential(?:\..*)?\.plaintextstorepath$/iu.test(key)) {
      const pointers = credentialPointers();
      selectStoreDirectory(pointers.directories, configPath(value));
      await protectPointers(checkout, pointers);
      return;
    }
    if (!/^credential(?:\..*)?\.helper$/iu.test(key)) return;
    if (value === "store") {
      hostMayReadStore = true;
      return;
    }
    const file = credentialStoreFile(value);
    if (file === undefined) unisolatedCredentialHelper = true;
    else {
      hostMayReadStore = true;
      await protectStore(configPath(file));
    }
  };
  const checkDelegateCredentials = (canRunOtherDelegate: boolean) => {
    if (externalInlineAuthentication) rejectCredentialedGitDelegate();
    if (unisolatedCredentialHelper && canRunOtherDelegate)
      throw new Error(
        "Cannot run Git filters or hooks with an operator credential helper or askpass program whose backing store cannot be isolated. Select a Git configuration without that credential source for patching.",
      );
  };
  const snapshotFilter = (key: string) =>
    /^filter\..*\.(?:clean|process)$/su.test(key) ||
    (automaticPublication && /^filter\..*\.smudge$/su.test(key));
  const activeCheckoutFilters = async (checkout: string): Promise<string[]> => {
    const entries = await runConfigFields(checkout, [
      "config",
      "--null",
      "--show-scope",
      "--show-origin",
      "--includes",
      "--get-regexp",
      "^filter\\..*\\.(clean|smudge|process)$",
    ]).catch((error: NodeJS.ErrnoException & { status?: number }) => {
      if (error.status === 1 || Number(error.code) === 1) return [];
      throw error;
    });
    const drivers = new Map<string, boolean>();
    for (let index = 0; index + 2 < entries.length; index += 3) {
      const setting = entries[index + 2]!;
      const separator = setting.indexOf("\n");
      const key = separator < 0 ? setting : setting.slice(0, separator);
      drivers.set(
        configPath(key),
        separator >= 0 &&
          separator + 1 < setting.length &&
          !(await userSelectedConfig(
            entries[index],
            configPath(entries[index + 1]!),
            checkout,
          )),
      );
    }
    return [...drivers]
      .filter(([, untrusted]) => untrusted)
      .map(([key]) => key);
  };
  const inheritedPointers = credentialPointers();
  if (mode !== "external") {
    await collectCredentialPointers(inheritedPointers, root, environment);
    if (shellSettings)
      await collectCredentialPointers(
        inheritedPointers,
        root,
        environment,
        shellSettings,
      );
  }
  const protectPointers = async (
    checkout: string,
    { files, directories }: ReturnType<typeof credentialPointers>,
  ) => {
    if (mode === "external") return;
    for (const file of [...files, ...directories]) {
      if (process.platform !== "win32" && file === "/dev/null") continue;
      hostMayReadStore = true;
      const includeDirectory = directories.has(file);
      // Like Git, GnuPG expands ~user through the Unix password database.
      if (
        includeDirectory &&
        process.platform !== "win32" &&
        /^~[^/]/u.test(file)
      ) {
        const expanded = await expandConfigurationPath(file);
        if (expanded) await protectStore(expanded, true);
      }
      await protectTransportFile(checkout, file, includeDirectory);
      // Commands may also inherit the original caller's subdirectory.
      if (checkout === root && directory !== root && !isAbsolute(file))
        await protectStore(
          httpCredentialPath(directory, file),
          includeDirectory,
        );
    }
  };
  const captureReferences = async (checkout: string): Promise<void> => {
    const projectConfig =
      checkout === root &&
      mode !== "external" &&
      (process.platform === "win32" || !!onSnapshotConfig);
    const expandedIncludes = new Map<string, string>();
    const parsedFiles = new Map<Buffer, string[] | undefined>();
    const readConfig = async (contents: Buffer) => {
      if (parsedFiles.has(contents)) return parsedFiles.get(contents);
      let entries: string[] | undefined;
      try {
        // Parse captured bytes without activating dormant includes or their errors.
        entries = await runConfigFields(
          checkout,
          ["config", "--file", "-", "--no-includes", "--null", "--list"],
          contents,
        );
      } catch (error) {
        if (!(
          error instanceof Error && error.message.includes("bad config line")
        ))
          throw error;
      }
      if (projectConfig) parsedFiles.set(contents, entries);
      return entries;
    };
    await protectPointers(checkout, inheritedPointers);
    filterCheckouts.add(checkout);
    const records = await runConfigFields(checkout, [
      "config",
      "--null",
      "--show-scope",
      "--show-origin",
      "--includes",
      "--list",
    ]);
    // Bind an active origin to the include edges from the same native Git read.
    const settings: {
      scope: string;
      origin: string;
      key: string;
      value: string;
    }[] = [];
    for (let index = 0; index + 2 < records.length; index += 3) {
      const { key, value = "" } = parseConfigEntry(records[index + 2]!);
      settings.push({
        scope: records[index]!,
        origin: records[index + 1]!,
        key,
        value,
      });
    }
    const activeConfigurations = new Set<string>();
    let sshSigning = settings.some(
      ({ key, value }) => key === "gpg.format" && value === "ssh",
    );
    const signingKeys = new Set<string>();
    if (
      mode !== "resumed-hook" &&
      settings.some(({ key }) => /^hook\..+\.event$/u.test(key))
    )
      await readConfiguredHooks(publicationHooks, (args) =>
        runConfig(checkout, args),
      );
    for (const [key, value] of new Map(
      settings
        .filter(({ key }) => snapshotFilter(key))
        .map(({ key, value }) => [key, value]),
    )) {
      if (value) delegateFilters.add(key);
    }
    for (const { scope, origin, key, value } of settings) {
      if (
        key === "user.signingkey" &&
        (await userSelectedConfig(scope, configPath(origin), checkout))
      )
        signingKeys.add(value);
      if (automaticPublication && value && snapshotFilter(key))
        nonemptyFilters.add(key);
      if (origin.startsWith("file:")) {
        const inline = hasInlineGitAuthentication(key, value);
        if (
          (inline ||
            key === "core.askpass" ||
            httpCredentialFile.test(key) ||
            /^credential(?:\..*)?\.(?:helper|plaintextstorepath)$/iu.test(
              key,
            )) &&
          (await userSelectedConfig(scope, configPath(origin), checkout))
        ) {
          externalInlineAuthentication ||= inline;
          await captureCredentialSource(checkout, key, value, "file");
        }
        const path = relativeFile(checkout, configPath(origin.slice(5)));
        activeConfigurations.add(path);
      } else if (scope === "command") {
        // Removing a command-scope setting does not prevent opening its file.
        await captureCredentialSource(checkout, key, value, "command");
      }
    }
    const captureHooks = async (configured?: string): Promise<void> => {
      let entry: string;
      try {
        entry = await runControl(checkout, [
          ...(configured === undefined
            ? []
            : ["-c", `core.hooksPath=${configured}`]),
          "rev-parse",
          "--git-path",
          "hooks/post-index-change",
        ]);
      } catch (error) {
        if (
          configured !== undefined &&
          error instanceof Error &&
          error.message.includes("failed to expand user dir")
        )
          return;
        throw error;
      }
      // A complete entry preserves Git's empty hooksPath semantics.
      const hooks = relativeFile(checkout, dirname(entry.replace(/\n$/u, "")));
      hookDirectories.add(hooks);
      // Bind absent entries too, while leaving ordinary directory contents editable.
      for (const hook of GIT_HOOKS)
        await rememberHook(relativeFile(hooks, hook));
    };
    const inspectedIncludes = new Set<string>();
    const captureInclude = async (
      relativeTo: string,
      value: string,
      optional: boolean,
      userSelected: boolean,
    ): Promise<void> => {
      const rawPath = configPath(value);
      if (rawPath.length === 0) return;
      const path = await expandConfigurationPath(rawPath, checkout, optional);
      if (path === undefined) return;
      const includePath = relativeFile(relativeTo, path);
      if (projectConfig) expandedIncludes.set(value, path);
      try {
        if (
          !insideSelectedRoots(await canonicalPath(includePath)) &&
          (!userSelected ||
            (await directoryLinks(includePath)).some((link) =>
              insideSelectedRoots(dirname(link)),
            ))
        )
          throw new Error(
            `Checkout requested ${optional ? "a conditional" : "an active"} include outside the selected Git roots: ${includePath}`,
          );
        await rememberConfiguration(includePath, !optional, optional);
      } catch (error) {
        // Active includes already passed Git's normal --includes read above.
        if (optional && hasErrorCode(error, "EACCES", "ELOOP")) {
          inaccessibleIncludes.add(includePath);
          return;
        }
        throw error;
      }
      if (!optional) return;
      const control = controlPaths.get(includePath)!;
      if (!Buffer.isBuffer(control.contents)) return;
      const origin = dirname(includePath);
      const identity = `${control.canonical}\0${await canonicalPath(origin)}`;
      if (inspectedIncludes.has(identity)) return;
      inspectedIncludes.add(identity);
      const entries = await readConfig(control.contents);
      if (!entries) return;
      for (const entry of entries) {
        const { key, value = "" } = parseConfigEntry(entry);
        if (automaticPublication && snapshotFilter(key)) {
          // Leaving a branch can remove an empty override and activate a
          // nonempty command that was present earlier in Git's config order.
          conditionalFilters.add(key);
          if (value) nonemptyFilters.add(key);
        }
        sshSigning ||= key === "gpg.format" && value === "ssh";
        if (!insideSelectedRoots(control.canonical)) {
          if (key === "user.signingkey") signingKeys.add(value);
          externalInlineAuthentication ||= hasInlineGitAuthentication(
            key,
            value,
          );
          await captureCredentialSource(checkout, key, value, "file");
        }
        recordConfiguredHook(
          publicationHooks,
          configPath(key),
          configPath(value),
        );
        if (
          automaticPublication &&
          value &&
          /^filter\..*\.(clean|smudge|process)$/su.test(key)
        ) {
          hasConditionalFilters = true;
          if (!userSelected || insideSelectedRoots(control.canonical))
            branchFilterSettings.add(configPath(key));
        }
        if (key === "core.hookspath" && mode !== "resumed-hook")
          await captureHooks(configPath(value));
        else if (includeSetting.test(key))
          await captureInclude(
            origin,
            value,
            true,
            userSelected && !insideSelectedRoots(control.canonical),
          );
      }
    };
    for (const { scope, origin, key, value } of settings) {
      if (!includeSetting.test(key)) continue;
      const relativeTo = origin.startsWith("file:")
        ? dirname(relativeFile(checkout, configPath(origin.slice(5))))
        : checkout;
      await captureInclude(
        relativeTo,
        value,
        key.startsWith("includeif."),
        await userSelectedConfig(scope, origin, checkout),
      );
    }
    // A branch switch can activate a conditional SSH format or key path.
    if (sshSigning && mode !== "external") {
      for (const key of signingKeys) {
        if (!key || key.startsWith("key::") || key.startsWith("ssh-")) continue;
        const file = await expandConfigurationPath(configPath(key), checkout);
        if (!file) continue;
        hostMayReadStore = true;
        await protectTransportFile(checkout, file);
        // ssh-keygen -Y sign strips the public key or certificate suffix.
        const privateKey = file.replace(/(.)(?:-cert)?\.pub$/su, "$1");
        if (privateKey !== file)
          await protectTransportFile(checkout, privateKey);
      }
    }
    if (mode === "resumed-hook" && !projectConfig) return;
    for (const path of activeConfigurations) await rememberConfiguration(path);
    if (
      automaticPublication &&
      settings.some(({ key }) =>
        /^filter\..*\.(clean|smudge|process)$/su.test(key),
      )
    ) {
      for (const key of await activeCheckoutFilters(checkout)) {
        activeHostFilters.add(key);
        if (!key.endsWith(".smudge")) checkoutCleanFilter = true;
      }
    }
    const globals = globalConfigurationPaths.map((path) =>
      relativeFile(checkout, path),
    );
    // The first system record belongs to the top-level file, including
    // when its first setting is itself an include.
    const systemOrigin = settings.find(
      ({ scope }) => scope === "system",
    )?.origin;
    const system =
      systemConfigurationPath ??
      (systemOrigin?.startsWith("file:")
        ? configPath(systemOrigin.slice(5))
        : undefined);
    const systems = system ? [relativeFile(checkout, system)] : [];
    for (const path of [...globals, ...systems])
      await rememberSelectedConfiguration(path, true);
    if (projectConfig)
      projectSnapshotConfig = async () => {
        // Windows shares its read-deny ACL across commands. Give snapshot Git
        // its own system/global files, leaving the originals denied. Keep the
        // include graph so Git evaluates conditions in each branch and repo.
        const files: string[] = [];
        const numbers = new Map<string, number>();
        const paths = new Map(
          [...controlPaths].map(([path, control]) => [
            normalize(path),
            control,
          ]),
        );
        const pathBytes = (path: string) =>
          Buffer.from(path.split(sep).join("/")).toString("latin1");
        const numberFor = async (path: string): Promise<number | undefined> => {
          const control = paths.get(normalize(path));
          if (
            !control ||
            !Buffer.isBuffer(control.contents) ||
            insideSelectedRoots(control.canonical) ||
            [...credentialStorePaths].some((store) =>
              inside(store, control.canonical),
            ) ||
            (control.identity &&
              credentialFileIds.has(
                control.identity.dev + ":" + control.identity.ino,
              ))
          )
            return;
          const id =
            control.canonical + "\0" + (await canonicalPath(dirname(path)));
          if (numbers.has(id)) return numbers.get(id);
          const entries = await readConfig(control.contents);
          if (!entries) return;
          const number = files.push("") - 1;
          numbers.set(id, number);
          let text = "";
          for (const record of entries) {
            if (!record) continue;
            let { key, value } = parseConfigEntry(record);
            if (hasInlineGitAuthentication(key, value ?? "")) continue;
            if (includeSetting.test(key)) {
              // Git resolves ./ conditions against the real file's directory,
              // treating the directory prefix literally. Relative include
              // destinations use the path through which Git opened that file.
              key = key.replace(
                /^(includeif\.(?:gitdir|worktree)(?:\/i)?:)\.[\\/]/u,
                (_match, prefix: string) =>
                  prefix +
                  pathBytes(dirname(control.canonical))
                    .replace(/[\\[*?]/gu, "\\$&")
                    .replace(/\/?$/u, "/"),
              );
              const expanded = value && expandedIncludes.get(value);
              if (expanded) {
                const target = relativeFile(dirname(path), expanded);
                const child = await numberFor(target);
                value = child === undefined ? pathBytes(target) : "\0" + child;
              }
            }
            text += serializeConfigEntry(key, value);
          }
          files[number] = text;
          return number;
        };
        const scope = async (roots: string[]) => {
          let projected: number | undefined;
          const parts: string[] = [];
          for (const path of roots) {
            if (!Buffer.isBuffer(paths.get(normalize(path))?.contents))
              continue;
            const id = await numberFor(path);
            if (id === undefined)
              parts.push(serializeConfigEntry("include.path", pathBytes(path)));
            else {
              projected = id;
              parts.push(files[id]!);
            }
          }
          // Combine projected XDG and home files at their original include depth.
          return projected !== undefined && parts.length > 1
            ? files.push(parts.join("")) - 1
            : projected;
        };
        const global = await scope(globals);
        const system = await scope(systems);
        const commands: Record<string, number> = Object.create(null);
        for (const { scope, origin, key, value } of settings) {
          if (
            scope !== "command" ||
            origin.startsWith("file:") ||
            !includeSetting.test(key)
          )
            continue;
          const path = expandedIncludes.get(value);
          if (path && isAbsolute(path)) {
            const number = await numberFor(path);
            if (number !== undefined) commands[configPath(value)] = number;
          }
        }
        if (!snapshotConfig && !files.length) return;
        // The launch context retains this object as shell policy can supply
        // additional credential paths before the native permissions resolve.
        snapshotConfig ??= { files, commands };
        Object.assign(snapshotConfig, { files, global, system, commands });
        onSnapshotConfig?.(snapshotConfig);
      };
    if (mode === "resumed-hook") return;
    const localConfig = await absolutePath(checkout, "--git-path", "config");
    const captureLocalConfig = async (path: string) => {
      await rememberSelectedConfiguration(path);
      // Absorbed submodules keep these files outside their worktrees. The
      // status inventory omits them even when they contain local credentials.
      const contents = controlPaths.get(path)?.contents;
      if (automaticPublication && checkout !== root && contents?.length)
        nestedConfigurationDigests.add(
          createHash("sha256").update(contents).digest("hex"),
        );
    };
    await captureLocalConfig(localConfig);
    let worktreeConfig = false;
    try {
      worktreeConfig =
        (
          await runConfig(checkout, [
            "config",
            "--local",
            "--no-includes",
            "--type=bool",
            "--get",
            "extensions.worktreeConfig",
          ])
        ).trim() === "true";
    } catch (error) {
      const failure = error as { code?: unknown; status?: unknown };
      if ((failure.code ?? failure.status) !== 1) throw error;
    }
    if (worktreeConfig) {
      const path = await absolutePath(
        checkout,
        "--git-path",
        "config.worktree",
      );
      await captureLocalConfig(path);
    }
    await captureHooks();
  };
  const selectedPaths: string[] = [];
  for (const argument of ["--absolute-git-dir", "--git-common-dir"])
    selectedPaths.push(await absolutePath(root, argument));
  const selectedDirectories = await Promise.all(
    selectedPaths.map(realControlPath),
  );
  if (mode === "resumed-hook") {
    // Resume has already found a hook. Inspect only its config graph, including
    // inactive includes it could open directly. No private index or working tree
    // walk is needed to publish the saved commit.
    for (const path of selectedDirectories) await remember(path);
    await captureReferences(root);
    checkDelegateCredentials(true);
    await projectSnapshotConfig?.();
    return undefined;
  }
  const gitDirectory = selectedDirectories[0]!;
  const commonDirectory = selectedDirectories[1]!;
  // A checkout's core.worktree can change Git's reported top-level directory.
  // Anchor implicit metadata to the checkout selected by the caller.
  const gitDirectorySelected =
    !usesWorktreeMarker ||
    (!usesCommonDirectoryMarker &&
      relative(gitDirectory, commonDirectory) === "");
  const commonDirectorySelected =
    !usesCommonDirectoryMarker ||
    (!usesWorktreeMarker && inside(gitDirectory, commonDirectory));
  let markerRoot =
    (gitDirectorySelected || inside(requestedDirectory, gitDirectory)) &&
    (commonDirectorySelected || inside(requestedDirectory, commonDirectory))
      ? null
      : await gitMarkerRoot(requestedDirectory, undefined, "nearest");
  // Git skips an empty .git directory when searching upward from a component.
  while (markerRoot !== null && markerRoot !== root) {
    const marker = join(markerRoot, ".git");
    const contents = await readGitMarker(marker);
    if (
      contents !== undefined &&
      (await isGitDirectory(marker, contents, true))
    )
      break;
    const parent = dirname(markerRoot);
    markerRoot =
      parent === markerRoot
        ? null
        : await gitMarkerRoot(parent, undefined, "nearest");
  }
  const checkout = usesWorktreeMarker
    ? (markerRoot ?? requestedDirectory)
    : requestedDirectory;
  const trustedGitDirectory =
    gitDirectorySelected || inside(checkout, gitDirectory);
  const trustedCommonDirectory =
    commonDirectorySelected || inside(checkout, commonDirectory);
  const validateRegistration = async () => {
    if (
      (!trustedGitDirectory || !trustedCommonDirectory) &&
      (markerRoot === null ||
        !(await isRegisteredLinkedWorktree(markerRoot, selectedDirectories)) ||
        (await selectedGitFileReference(
          join(markerRoot, ".git"),
          gitDirectory,
        )) === undefined)
    ) {
      throw new Error(
        "External Git administration requires an explicitly selected Git directory or a registered worktree. Set GIT_DIR or GIT_COMMON_DIR to the intended directory.",
      );
    }
  };
  await validateRegistration();
  for (const [index, path] of selectedDirectories.entries()) {
    await remember(path);
    for (const link of await directoryLinks(selectedPaths[index]!))
      administrationLinks.add(link);
  }
  const selectedCommonDirectory = usesCommonDirectoryMarker
    ? undefined
    : selectedDirectories[1];
  for (const argument of [
    ...(usesWorktreeMarker ? [] : ["--git-dir"]),
    ...(usesCommonDirectoryMarker ? [] : ["--git-common-dir"]),
  ]) {
    const path = relativeFile(root, await controlPath(root, argument));
    await rememberControl(path);
    for (const link of await directoryLinks(path))
      administrationLinks.add(link);
  }
  const selectedMarker = usesWorktreeMarker
    ? await markerDirectories(
        root,
        isGitDirectory,
        selectedCommonDirectory,
        rememberAdministrationReference,
      )
    : undefined;
  if (!usesWorktreeMarker && selectedGitDirectory !== undefined) {
    const reference = await selectedGitFileReference(
      selectedGitDirectory,
      selectedDirectories[0]!,
    );
    if (reference !== undefined)
      await rememberAdministrationReference(reference);
  }
  if (!usesWorktreeMarker && usesCommonDirectoryMarker)
    await readCommonDirectory(
      selectedDirectories[0]!,
      rememberAdministrationReference,
    );
  if (selectedMarker !== undefined)
    for (const link of await directoryLinks(join(root, ".git")))
      administrationLinks.add(link);
  const discover = async (capture: boolean): Promise<void> => {
    const pendingStoragePaths: { path: string; userSelected: boolean }[] = [];
    const protectedRoots = capture
      ? []
      : (
          await Promise.all(
            [...administrationRoots].map(async ([path, identity]) => {
              const metadata = await stat(path, { bigint: true }).catch(
                missing,
              );
              return metadata?.dev === identity.dev &&
                metadata.ino === identity.ino
                ? path
                : undefined;
            }),
          )
        ).filter((path): path is string => path !== undefined);
    if (!capture) {
      for (const path of inaccessibleHooks) {
        if (await hookIsAvailable(path))
          throw new Error(
            `Git hook became accessible during the patch: ${path}`,
          );
      }
      for (const path of inaccessibleIncludes) {
        try {
          const canonical = await canonicalPath(path);
          const metadata = await stat(canonical).catch(missing);
          if (metadata === undefined || metadata.isDirectory()) continue;
        } catch (error) {
          if (hasErrorCode(error, "EACCES", "ELOOP")) continue;
          throw error;
        }
        throw new Error(
          `Git conditional include became accessible during the patch: ${path}`,
        );
      }
      for (const [path, expected] of controlPaths) {
        const canonical = await canonicalPath(path);
        const metadata = await stat(canonical, { bigint: true }).catch(missing);
        // An absent entry or directory cannot supply hook/configuration bytes.
        // Keep file activation and overlapping configuration roles bound.
        if (
          expected.allowDirectoryChanges &&
          (expected.identity === undefined || expected.directory === true) &&
          (metadata === undefined || metadata.isDirectory())
        )
          continue;
        if (
          canonical === expected.canonical &&
          expected.allowDirectoryCreation &&
          expected.identity === undefined &&
          metadata?.isDirectory()
        ) {
          expected.identity = { dev: metadata.dev, ino: metadata.ino };
          expected.directory = true;
          expected.allowDirectoryCreation = false;
        }
        if (
          canonical !== expected.canonical ||
          (![...administrationRoots.keys()].some((root) =>
            inside(root, expected.canonical),
          ) &&
            (metadata?.dev !== expected.identity?.dev ||
              metadata?.ino !== expected.identity?.ino ||
              metadata?.isDirectory() !== expected.directory))
        )
          throw new Error(
            `Git configuration or hooks changed location during the patch: ${path}`,
          );
        const hook = hookContents.get(path);
        if (
          hook !== undefined &&
          (!metadata?.isFile() ||
            !(await hookIsAvailable(path)) ||
            (Buffer.isBuffer(hook)
              ? !(await readFile(canonical)).equals(hook)
              : metadata.size !== hook.size ||
                metadata.mtimeNs !== hook.mtimeNs ||
                metadata.ctimeNs !== hook.ctimeNs))
        )
          throw new Error(`Git hook changed during the patch: ${path}`);
        if (unreadableConfigurations.has(path)) {
          try {
            await readFile(canonical);
          } catch (error) {
            if (hasErrorCode(error, "EACCES", "EPERM")) continue;
            throw error;
          }
          throw new Error(
            `Git configuration became readable during the patch: ${path}`,
          );
        }
        if (
          expected.contents === null
            ? metadata !== undefined && !metadata.isDirectory()
            : expected.contents !== undefined &&
              (!metadata?.isFile() ||
                !(await readFile(canonical)).equals(expected.contents))
        )
          throw new Error(
            `Git configuration changed during the patch: ${path}`,
          );
      }
      const marker =
        selectedMarker === undefined
          ? undefined
          : await markerDirectories(
              root,
              isGitDirectory,
              selectedCommonDirectory,
            );
      if (
        selectedDirectories.some((path) => !protectedRoots.includes(path)) ||
        (selectedMarker !== undefined &&
          (marker === undefined ||
            marker.length !== selectedMarker.length ||
            marker.some((path, index) => path !== selectedMarker[index])))
      ) {
        throw new Error(
          "Selected Git administration changed during the patch. Inspect the checkout before retrying.",
        );
      }
      await validateRegistration();
    }
    const visited = new Set<string>();
    const visit = async (checkout: string): Promise<void> => {
      const canonical = await realControlPath(checkout);
      if (!inside(root, canonical))
        throw new Error(
          "Nested Git checkout resolves outside the selected repository.",
        );
      if (visited.has(canonical)) return;
      let naturalWorktree = true;
      let commonDirectory = selectedDirectories[1]!;
      if (canonical !== root) {
        const directories = await markerDirectories(
          checkout,
          (path, contents) => isGitDirectory(path, contents, true),
          undefined,
          capture ? rememberAdministrationReference : undefined,
        );
        if (directories === undefined) return;
        commonDirectory = directories.at(-1)!;
        const previous = nestedDirectories.get(canonical);
        if (
          !capture &&
          previous !== undefined &&
          (directories.length !== previous.length ||
            directories.some((path, index) => path !== previous[index]))
        )
          throw new Error(
            `Nested Git administration changed during the patch: ${checkout}`,
          );
        if (
          !capture &&
          directories.some(
            (path) => !protectedRoots.some((root) => inside(root, path)),
          )
        )
          throw new Error(
            `Patch selected Git metadata outside the pre-patch administration directories: ${checkout}`,
          );
        if (
          directories.some(
            (path) =>
              !inside(root, path) &&
              !selectedDirectories.some((selected) => inside(selected, path)),
          ) &&
          !(await isRegisteredLinkedWorktree(canonical, directories))
        )
          throw new Error(
            `Nested Git administration is outside the selected repository and its registered worktrees: ${checkout}`,
          );
        if (capture) {
          nestedDirectories.set(canonical, directories);
          for (const path of directories) await remember(path);
          for (const link of await directoryLinks(join(checkout, ".git")))
            administrationLinks.add(link);
        }
        const config = join(directories.at(-1)!, "config");
        if ((await stat(config).catch(missing))?.isFIFO())
          throw new Error(
            `Patch cannot safely inspect non-regular Git metadata: ${config}`,
          );
        let worktree: string | undefined;
        try {
          worktree = await realControlPath(
            await controlPath(checkout, "--show-toplevel"),
          );
        } catch (error) {
          if (!hasNoWorktree(error)) throw error;
          naturalWorktree = false;
        }
        if (worktree !== undefined && relative(canonical, worktree) !== "")
          throw new Error(
            "Git's worktree root does not match the selected checkout's .git marker. Select the intended checkout explicitly or fix its Git configuration.",
          );
      }
      if (canonical === root && objectDirectory !== undefined) {
        if (capture)
          await rememberControl(
            relativeFile(root, objectDirectory),
            true,
            false,
          );
      } else {
        const objects = await canonicalPath(join(commonDirectory, "objects"));
        if (
          !inside(commonDirectory, objects) &&
          !selectedDirectories.some((selected) => inside(selected, objects))
        )
          throw new Error(
            `Git object storage resolves outside the selected Git administration: ${checkout}`,
          );
      }
      if (capture) {
        await captureReferences(checkout);
        const [common, storage] = await Promise.all([
          absolutePath(checkout, "--git-common-dir"),
          // Git LFS reads the selected config with includes enabled.
          runControl(checkout, [
            "config",
            "--includes",
            "--null",
            "--show-scope",
            "--show-origin",
            "--default=",
            "--get",
            "lfs.storage",
          ]).catch((error: unknown) => {
            const failure = error as Error & {
              code?: unknown;
              status?: unknown;
              stderr?: unknown;
              signal?: unknown;
              killed?: boolean;
            };
            const status = failure.code ?? failure.status;
            const missingValue =
              status === 1 &&
              (failure.stderr === "" ||
                (Buffer.isBuffer(failure.stderr) &&
                  failure.stderr.length === 0));
            // Git LFS discards failed config reads, including partial output,
            // and uses the default cache after reporting its warning.
            if (
              error instanceof Error &&
              failure.name !== "AbortError" &&
              !failure.signal &&
              !failure.killed &&
              (missingValue || status === 128)
            )
              return "";
            throw error;
          }),
        ]);
        const [scope, origin, value] = storage.split("\0");
        const configured = value || "lfs";
        const absolute =
          isAbsolute(configured) &&
          (process.platform !== "win32" || parse(configured).root.length > 1);
        const lfs = absolute ? configured : join(common, configured);
        // Git reports a supplied default as command-line configuration. Only an
        // actual nonempty setting can authorize a cache outside this checkout.
        const userSelected =
          !!value && (await userSelectedConfig(scope, origin, checkout));
        pendingStoragePaths.push({ path: lfs, userSelected });
      }
      let tracked: Buffer;
      let untracked: Buffer;
      let deleted: Buffer;
      try {
        [tracked, untracked, deleted] = await withPatchGitIndex(
          (args, options) =>
            run(
              checkout,
              [
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "hook.post-index-change.enabled=false",
                ...[...publicationHooks.configured].flatMap((name) => [
                  "-c",
                  `hook.${name}.enabled=false`,
                ]),
                "-c",
                "core.fsmonitor=false",
                ...args,
              ],
              options,
            ),
          async (indexed) => {
            const outputs = await Promise.all([
              indexed(
                ["ls-files", "--cached", "--stage", "--full-name", "-z"],
                {
                  encoding: "base64",
                },
              ),
              indexed(
                [
                  "ls-files",
                  "--others",
                  "--exclude-standard",
                  "--full-name",
                  "-z",
                ],
                {
                  encoding: "base64",
                },
              ),
              indexed(["ls-files", "--deleted", "--full-name", "-z"], {
                encoding: "base64",
              }),
            ]);
            return outputs.map((output) => Buffer.from(output, "base64")) as [
              Buffer,
              Buffer,
              Buffer,
            ];
          },
        );
      } catch (error) {
        if (!naturalWorktree && hasNoWorktree(error)) return;
        throw error;
      }
      visited.add(canonical);
      const candidates = new Map<
        string,
        { gitlink: boolean; selected: boolean }
      >();
      const add = async (
        path: string,
        directory: boolean,
        gitlink: boolean,
        inspectAncestors = false,
      ): Promise<void> => {
        const readable = await readableGitParent(
          checkout,
          Buffer.from(path, "latin1"),
          directory,
          gitlink,
          rawCheckoutSelectsGit,
        );
        if (readable === undefined) return;
        let candidate = resolve(checkout, readable.path);
        gitlink &&= readable.exact;
        while (candidate !== checkout && inside(checkout, candidate)) {
          const previous = candidates.get(candidate);
          candidates.set(candidate, {
            gitlink: (previous?.gitlink ?? false) || gitlink,
            selected:
              (previous?.selected ?? false) ||
              readable.exact ||
              inspectAncestors,
          });
          gitlink = false;
          readable.exact = false;
          candidate = dirname(candidate);
        }
      };
      for (const entry of tracked
        .toString("latin1")
        .split("\0")
        .filter(Boolean)) {
        // A tracked file can become a directory without appearing as deleted.
        await add(
          entry.slice(entry.indexOf("\t") + 1),
          true,
          entry.startsWith("160000 "),
        );
      }
      // Git can replace a directory's deleted tracked files with a gitlink.
      for (const path of deleted.toString("latin1").split("\0").filter(Boolean))
        await add(path, false, false, true);
      for (const path of untracked
        .toString("latin1")
        .split("\0")
        .filter(Boolean))
        if (path.endsWith("/")) await add(path, true, false);
      const symlinkedAncestors: string[] = [];
      for (const [candidate, { gitlink, selected }] of [...candidates].sort(
        ([a], [b]) => a.length - b.length,
      )) {
        if (symlinkedAncestors.some((ancestor) => inside(ancestor, candidate)))
          continue;
        // Git for Windows follows directory junctions as directories.
        if (
          (!gitlink || process.platform !== "win32") &&
          (await lstat(candidate).catch(missing))?.isSymbolicLink()
        ) {
          symlinkedAncestors.push(candidate);
          continue;
        }
        if (
          [...visited].some(
            (path) =>
              path !== canonical &&
              inside(canonical, path) &&
              inside(path, candidate),
          )
        )
          continue;
        if (
          selected &&
          (await lstat(join(candidate, ".git")).catch(missing)) !== undefined
        )
          await visit(candidate);
      }
    };
    await visit(root);
    if (capture)
      for (const key of conditionalFilters)
        if (nonemptyFilters.has(key)) delegateFilters.add(key);
    if (mode === "sandbox" && capture) {
      const hookCanRun =
        publicationHooks.events.has("post-index-change") ||
        (automaticPublication &&
          [
            "post-checkout",
            "pre-commit",
            "prepare-commit-msg",
            "commit-msg",
            "post-commit",
            "pre-push",
            "reference-transaction",
            "pre-auto-gc",
          ].some((event) => publicationHooks.events.has(event)));
      if (delegateFilters.size || hookCanRun)
        checkDelegateCredentials(hookCanRun);
    }
    if (capture && checkoutCleanFilter) {
      // Inspect the original checkout before status or add can invoke a filter.
      const passive = [
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.ignoreStat=false",
        "-c",
        "core.trustctime=true",
        "-c",
        "core.checkStat=default",
      ];
      // Git can re-read any effective driver while checking for local edits,
      // including an external definition that executes code from the checkout.
      const passiveFilters =
        hostMayReadStore || unisolatedCredentialHelper
          ? protectedFilterKeys()
          : [...activeHostFilters];
      const passiveOptions = {
        environment: {
          GIT_CONFIG_PARAMETERS: patchFilterParameters(
            passiveFilters,
            false,
            commandParameters,
          ),
        },
      };
      for (const checkout of visited) {
        const inspect = (...args: string[]) =>
          runBytes(checkout, [...passive, ...args], passiveOptions);
        const local = await inspect(
          "ls-files",
          "--others",
          "--directory",
          "--no-empty-directory",
          "-z",
        );
        const error =
          "Cannot automatically publish from a checkout with local-only files or tracked edits and a checkout-selected Git filter. Run patch without --create-pr and review the changes before publishing.";
        if (local.length) throw new Error(error);
        // Git normally skips these paths when it compares the worktree to the index.
        const entries = await inspect("ls-files", "-v", "-z");
        if (/(?:^|\0)[a-zS] /u.test(entries.toString("latin1")))
          throw new Error(error);
        // The index may itself contain private edits. Check it separately even when
        // the worktree exactly matches those staged bytes. Visit gitlinks below
        // their own root rather than letting Git invoke a nested status command.
        for (const comparison of [["diff", "--cached"], ["diff-files"]]) {
          const changed = await inspect(
            ...comparison,
            "--name-only",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=dirty",
            "--",
          );
          if (changed.length) throw new Error(error);
        }
      }
    }
    for (const { path, userSelected } of pendingStoragePaths) {
      try {
        const children = [join(path, "objects"), join(path, "tmp")];
        const canonical = await canonicalPath(path);
        const protectsAdministration = [...administrationRoots.keys()].some(
          (administration) => inside(canonical, administration),
        );
        let prepare =
          !protectsAdministration &&
          (userSelected || insideSelectedRoots(canonical));
        for (const candidate of [path, ...children])
          if (!(await canPrepareStorage(candidate))) prepare = false;
        if (!prepare) {
          // A non-directory ancestor makes both cache children unavailable.
          let ancestor = canonical;
          let metadata = await stat(ancestor).catch(missing);
          while (metadata === undefined && dirname(ancestor) !== ancestor) {
            ancestor = dirname(ancestor);
            metadata = await stat(ancestor).catch(missing);
          }
          if (!metadata?.isDirectory()) continue;
          // Keep model write restrictions and let snapshots inherit host access.
          for (const child of children) {
            await rememberControl(child, true, false, true);
            const target = controlPaths.get(child)!.canonical;
            if (insideSelectedRoots(target)) modelOnlyReadOnlyPaths.add(target);
            else externalCachePaths.add(target);
          }
          continue;
        }
        // Git LFS renames from tmp into objects. Separate writable bindings
        // create distinct mounts on Linux and make that rename fail with EXDEV.
        // Keep both directories on the same binding, preserving narrower Git
        // control exclusions already captured within the cache.
        for (const child of children) {
          await mkdir(child, { recursive: true });
          await rememberControl(child, true, false);
          const target = controlPaths.get(child)!.canonical;
          modelOnlyReadOnlyPaths.add(target);
          if (!inside(canonical, target)) {
            if (!userSelected || insideSelectedRoots(canonical))
              throw new Error(
                `Git LFS storage left the selected cache: ${child}`,
              );
            await rememberControl(child);
            snapshotStoragePaths.add(target);
          }
        }
        await rememberControl(path);
        snapshotStoragePaths.add(canonical);
      } catch (error) {
        // Unavailable optional storage gets no extra snapshot permission.
        // Git/LFS reports the failure if a snapshot actually uses it.
        if (!hasErrorCode(error, "EACCES", "EPERM", "EROFS", "ENOTDIR"))
          throw error;
      }
    }
  };
  await discover(true);
  await projectSnapshotConfig?.();
  const snapshotControlPaths: string[] = [];
  for (const [path, control] of controlPaths) {
    if (!control.readOnly) continue;
    for (const link of await directoryLinks(path))
      if ([...snapshotStoragePaths].some((storage) => inside(storage, link)))
        snapshotControlPaths.push(link);
  }
  const snapshotControlLocation = async (path: string): Promise<string> => {
    let ancestor = path;
    for (;;) {
      try {
        const canonical = `${await canonicalPath(ancestor)}${path.slice(ancestor.length)}`;
        for (const link of await directoryLinks(ancestor))
          if (
            [...snapshotStoragePaths].some((storage) => inside(storage, link))
          )
            snapshotControlPaths.push(link);
        return canonical;
      } catch (error) {
        // Locate opaque control paths without resolving their entries. The
        // native sandbox must enforce the literal exclusions or reject them.
        if (!hasErrorCode(error, "EACCES", "ELOOP")) throw error;
        const parent = dirname(ancestor);
        if (parent === ancestor) throw error;
        ancestor = parent;
      }
    }
  };
  for (const path of inaccessibleIncludes) {
    const canonical = await snapshotControlLocation(path);
    if ([...snapshotStoragePaths].some((storage) => inside(storage, canonical)))
      snapshotControlPaths.push(canonical);
  }
  for (const directory of hookDirectories) {
    const canonical = await snapshotControlLocation(directory);
    if ([...snapshotStoragePaths].some((storage) => inside(storage, canonical)))
      for (const hook of GIT_HOOKS)
        snapshotControlPaths.push(relativeFile(canonical, hook));
  }
  const alternateObjectDirectories: string[] = [];
  for (let bytes of gitAlternatePathBytes(
    Buffer.from(alternatePaths ?? ""),
    delimiter,
  )) {
    const nul = bytes.indexOf(0);
    if (nul !== -1) bytes = bytes.subarray(0, nul);
    if (bytes.length === 0) continue;
    let selected: string;
    try {
      selected = new TextDecoder("utf-8", {
        fatal: true,
        ignoreBOM: true,
      }).decode(bytes);
    } catch {
      // Permission paths require UTF-8; keep the original Git binding unchanged.
      continue;
    }
    let resolved: Buffer;
    try {
      resolved = await runBytes(
        root,
        ["rev-parse", "--path-format=absolute", "--git-path", "objects"],
        { environment: { GIT_OBJECT_DIRECTORY: selected } },
      );
    } catch (error) {
      const failure = error as Error & { code?: unknown; status?: unknown };
      // An unavailable primary object directory fails repository discovery;
      // the original alternate binding still lets Git report or ignore it.
      if (
        (failure.code ?? failure.status) === 128 &&
        failure.message.includes("fatal: not a git repository")
      )
        continue;
      throw error;
    }
    let path: string;
    try {
      path = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
        .decode(resolved)
        .replace(/\n$/u, "");
    } catch {
      continue;
    }
    if ((await stat(path).catch(missing))?.isDirectory())
      alternateObjectDirectories.push(path);
  }
  return {
    publicationHooks: { ...publicationHooks, gitDirectory, commonDirectory },
    readOnlyPaths: [
      ...new Set([
        ...alternateObjectDirectories,
        ...administrationRoots.keys(),
        ...snapshotControlPaths,
        ...[...controlPaths.values()]
          .filter(
            ({ canonical, identity, readOnly }) =>
              readOnly &&
              (identity !== undefined ||
                [...snapshotStoragePaths].some((storage) =>
                  inside(storage, canonical),
                )),
          )
          .map(({ canonical }) => canonical),
      ]),
    ],
    nestedCheckouts: [...nestedDirectories.keys()],
    nestedConfigurationDigests,
    modelOnlyReadOnlyPaths: [...modelOnlyReadOnlyPaths],
    unavailableFilters: unisolatedCredentialHelper ? protectedFilterKeys() : [],
    credentialStorePaths: [...credentialStorePaths],
    async protectShellCredentialFiles(...settings) {
      const added = credentialPointers();
      for (const source of new Set(settings))
        if (source)
          await collectCredentialPointers(added, root, environment, source);
      for (const file of inheritedPointers.files) added.files.delete(file);
      for (const dir of inheritedPointers.directories)
        added.directories.delete(dir);
      const previouslyUnisolated = unisolatedCredentialHelper;
      for (const checkout of filterCheckouts)
        await protectPointers(checkout, added);
      if (added.files.size || added.directories.size)
        await projectSnapshotConfig?.();
      if (
        !previouslyUnisolated &&
        unisolatedCredentialHelper &&
        (delegateFilters.size || publicationHooks.events.size)
      )
        checkDelegateCredentials(true);
      return [...credentialStorePaths];
    },
    externalConfigPaths: [...configurationFiles].filter(
      (path) => !insideSelectedRoots(path),
    ),
    externalCachePaths: [...externalCachePaths],
    snapshotStoragePaths: [...snapshotStoragePaths],
    snapshotConfig,
    hostRefreshFilters:
      mode === "sandbox" && automaticPublication ? protectedFilterKeys() : [],
    async hostFilterSettings(switchingBranch) {
      // These overrides also reach delegated hooks. The host-only refresh
      // overrides above are removed when the dispatcher enters the sandbox.
      if (!hasConditionalFilters) return [...activeHostFilters];
      // Switching can activate a conditional config before Git calls post-checkout.
      if (switchingBranch)
        return [...new Set([...activeHostFilters, ...branchFilterSettings])];
      // Once HEAD is bound, use Git's actual config order so operator overrides survive.
      return [
        ...new Set(
          (
            await Promise.all([...filterCheckouts].map(activeCheckoutFilters))
          ).flat(),
        ),
      ];
    },
    validate: () => discover(false),
  };
}

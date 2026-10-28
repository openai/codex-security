import {
  environmentValue,
  isMissingPathError,
  resolvedPathText as canonical,
  readChunks,
} from "./helper-files";
import {
  spawn,
  type SpawnOptions,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { randomUUID } from "node:crypto";
import type { Writable } from "node:stream";
import {
  basename,
  dirname,
  delimiter,
  isAbsolute,
  resolve,
  sep,
} from "node:path";
import { createRequire } from "node:module";
import { constants } from "node:os";
import { spawnWindowsProcess } from "../../../native/windows-process.mjs";
import { nativeTarget } from "../../../native/platform.mjs";
import { decodePosixBytes, encodePosixPath } from "./posix-path";
import { decodeUtf8 } from "./utf8";
import {
  ancestors,
  append,
  executable,
  exists,
  inside,
  linkedParent,
  lstat,
  regular,
  sameFile,
  sourceMetadata,
  walk,
  windows,
} from "./inventory-paths";
import { createSourceSampler } from "./source-preview";
import { gitConfigurationEnvironment } from "./git-environment";

interface ToolResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: Buffer;
  stderr: string;
}

class GitFailure extends Error {
  constructor(readonly result: ToolResult) {
    super(
      result.stderr.trim() ||
        (result.signal
          ? `Git terminated by ${result.signal}`
          : `Git exited with status ${result.status}`),
    );
  }
}

const repositoryEnvironment = [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CEILING_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_DIR",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
  "GIT_INDEX_FILE",
  "GIT_NAMESPACE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_WORK_TREE",
];
const posixLoaderSetting = /^(?:LD|DYLD)_[A-Z0-9_]+$/u;

function rawToolValue(value: string): boolean {
  return (windows ? /[\ud800-\udfff]/u : /[\udc80-\udcff]/u).test(value);
}

function selectedBundledRipgrep(candidate: string): boolean {
  const codex = environmentValue("CODEX_CLI_PATH");
  if (!codex) return false;
  try {
    return sameFile(
      candidate,
      append(
        append(dirname(dirname(canonical(codex))), "codex-path"),
        "rg.exe",
      ),
    );
  } catch {
    return false;
  }
}

function trustedTool(
  name: "git" | "rg",
  target: string,
  rawWindowsLookup = false,
  environment: NodeJS.ProcessEnv = process.env,
): string | undefined {
  const value = (name: string) => {
    if (environment === process.env) return environmentValue(name);
    const key = windows
      ? Object.keys(environment)
          .sort()
          .find((key) => key.toUpperCase() === name)
      : name;
    return key === undefined ? undefined : environment[key];
  };
  let protectedRoot = canonical(target);
  for (const ancestor of ancestors(protectedRoot))
    if (exists(append(ancestor, ".git"))) protectedRoot = ancestor;
  const configured = name === "git" ? value("CODEX_SECURITY_GIT") : undefined;
  if (configured === "") return undefined;
  if (configured !== undefined && !isAbsolute(configured))
    throw new Error(
      "CODEX_SECURITY_GIT must name an absolute trusted executable.",
    );
  const searchPath = value("PATH") ?? (windows ? ".;C:\\bin" : "/usr/bin:/bin");
  const directories =
    windows && name === "rg"
      ? windowsToolPaths(searchPath)
      : searchPath.split(delimiter);
  const candidates =
    configured !== undefined
      ? [configured]
      : directories.flatMap((entry) => {
          const directory =
            windows && name === "git" ? entry.replace(/^"|"$/gu, "") : entry;
          let nativeWindowsLookup = rawWindowsLookup;
          if (windows && name === "rg") {
            try {
              nativeWindowsLookup ||= rawToolValue(
                canonical(resolve(target, directory)),
              );
            } catch {
              return [];
            }
          }
          const names = windows
            ? name === "rg" && !nativeWindowsLookup
              ? ["rg.com", "rg.exe"]
              : [`${name}.exe`, `${name}.com`]
            : [name];
          return names.map((name) => append(directory, name));
        });
  for (const selected of candidates) {
    const candidate =
      name === "rg" &&
      (!isAbsolute(selected) || (windows && /^[\\/](?![\\/])/u.test(selected)))
        ? windows
          ? resolve(target, selected)
          : append(target, selected)
        : selected;
    let invocation: string, resolved: string;
    try {
      invocation = append(canonical(dirname(candidate)), basename(candidate));
      resolved = canonical(candidate);
    } catch {
      continue;
    }
    if (
      !executable(resolved) ||
      (windows &&
        (!/\.(exe|com)$/iu.test(candidate) || /\.(bat|cmd)$/iu.test(resolved)))
    )
      continue;
    const inRepository = [resolve(candidate), invocation, resolved].some(
      (path) => {
        try {
          inside(protectedRoot, path);
          return true;
        } catch {
          return false;
        }
      },
    );
    if (inRepository && !(name === "rg" && selectedBundledRipgrep(resolved))) {
      if (configured !== undefined)
        throw new Error(
          "CODEX_SECURITY_GIT must stay outside the protected repository.",
        );
      continue;
    }
    return invocation;
  }
  return undefined;
}

export function trustedGitExecutable(
  repository: string,
  environment: NodeJS.ProcessEnv = process.env,
): string | undefined {
  return trustedTool("git", repository, false, environment);
}

function windowsToolPaths(searchPath: string): string[] {
  const paths: string[] = [];
  for (let start = 0; start < searchPath.length;) {
    let end = start;
    const quote = searchPath[start];
    if (quote === '"' || quote === "'") {
      end = searchPath.indexOf(quote, start + 1);
      if (end < 0) end = searchPath.length;
    }
    end = searchPath.indexOf(";", end);
    if (end < 0) end = searchPath.length;
    const entry = searchPath.slice(start, end).replace(/^["']|["']$/gu, "");
    if (entry) paths.push(entry);
    start = end + 1;
  }
  return paths;
}

function spawnTool(
  command: string,
  args: string[],
  options: SpawnOptions & {
    cwd?: string;
    stdio: ["ignore" | "pipe", "pipe", "pipe"];
  },
  inheritedEnvironment: Record<string, string>,
  inputFd: 0 | 3 = 0,
) {
  const stdio = [...options.stdio];
  if (inputFd === 3) stdio.push("pipe");
  const environment = Object.fromEntries(
    Object.entries(inheritedEnvironment).filter(
      ([name, value]) =>
        rawToolValue(value) || (!windows && posixLoaderSetting.test(name)),
    ),
  );
  const values = [
    command,
    ...args,
    ...(typeof options.cwd === "string" ? [options.cwd] : []),
    ...Object.values(environment),
  ];
  if (!values.some(rawToolValue)) {
    try {
      return {
        child: spawn(command, args, { ...options, stdio }),
        failureMarker: undefined,
      };
    } catch (error) {
      const failure = error as NodeJS.ErrnoException;
      // macOS Node exposes ENOEXEC numerically; use the shell's text-file fallback.
      if (
        windows ||
        (failure.code !== "ENOEXEC" &&
          failure.errno !== -constants.errno.ENOEXEC)
      )
        throw error;
    }
  }
  if (windows) {
    const binary = createRequire(import.meta.url).resolve(
      `./native/${nativeTarget}/windows.node`,
    );
    return {
      child: spawnWindowsProcess(binary, command, args, options, environment),
      failureMarker: undefined,
    };
  }
  // Node encodes argv/cwd as UTF-8. POSIX sh can reconstruct raw filename bytes
  // with its builtin printf; a sentinel preserves trailing newlines in each value.
  const assign = (value: string) => {
    if (value.includes("\0"))
      throw new TypeError("Process arguments must not contain NUL bytes");
    const octal = [...encodePosixPath(value)]
      .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
      .join("");
    return `value=$(printf '%b.' '${octal}'); value=\${value%.}`;
  };
  const failureMarker = `\0${randomUUID()}\0`;
  const reportFailure = `printf '${failureMarker.replaceAll("\0", "\\000")}' >&2`;
  const script = [
    "set --",
    ...Object.entries(environment).flatMap(([name, value]) => [
      assign(value),
      `${name}="$value"; export ${name}`,
    ]),
    ...[command, ...args].flatMap((value) => [
      assign(value),
      'set -- "$@" "$value"',
    ]),
    ...(typeof options.cwd === "string"
      ? [assign(options.cwd), 'cd -P -- "$value" || exit']
      : []),
    // Only a failed exec emits this launch-specific frame. A tool may itself
    // exit 126/127, and a separate status pipe can leak through shell redirects.
    'if [ -n "${BASH_VERSION:-}" ]; then shopt -s execfail; fi',
    `trap "${reportFailure}" 0`,
    'exec "$@"',
    // Bash 3.2 clears EXIT traps on failed exec; dash exits through the trap.
    "status=$?",
    "trap - 0",
    reportFailure,
    'exit "$status"',
  ].join("\n");
  // Loader settings belong to the tool: decoded raw values can fail at shell
  // startup, and macOS system shells also strip ordinary DYLD_* values.
  const env = { ...(options.env ?? process.env) };
  for (const name of Object.keys(environment)) delete env[name];
  // macOS ships dash; unlike its Bash 3.2 sh, failed exec retains ENOENT's 127.
  const shell = process.platform === "darwin" ? "/bin/dash" : "/bin/sh";
  const child = spawn(shell, ["-c", script], {
    ...options,
    env,
    cwd: undefined,
    stdio,
  });
  return { child, failureMarker };
}

function inheritedToolPaths(
  additional: string[] = [],
  environment: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const keys = Object.keys(environment).sort();
  const toolConfiguration = keys.filter((name) => {
    const key = windows ? name.toUpperCase() : name;
    return (
      [
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_ATTR_SOURCE",
        "GIT_REPLACE_REF_BASE",
      ].includes(key) ||
      /^GIT_CONFIG_(?:KEY|VALUE)_\d+$/u.test(key) ||
      // Restore loader settings before exec: the tool cannot repair them after
      // its dynamic loader has already tried to open libraries and preload files.
      (!windows && posixLoaderSetting.test(key))
    );
  });
  return Object.fromEntries(
    [
      "HOME",
      "PATH",
      "XDG_CONFIG_HOME",
      ...additional,
      ...toolConfiguration,
    ].flatMap((name) => {
      const key = windows
        ? (keys.find((key) => key.toUpperCase() === name.toUpperCase()) ?? name)
        : name;
      const value =
        environment === process.env ? environmentValue(key) : environment[key];
      return value === undefined ? [] : [[name, value]];
    }),
  );
}

type GitSetting = { key: string; value?: string };

function authenticationHeader(key: string): boolean {
  return /^http(?:\..*)?\.extraheader$/isu.test(key);
}

function commandSettings(output: Buffer): GitSetting[] {
  const fields = paths(output),
    settings: GitSetting[] = [];
  for (let index = 0; index < fields.length; index += 2) {
    if (fields[index] !== "command line:") continue;
    const record = fields[index + 1]!,
      separator = record.indexOf("\n");
    // Git rejects newlines in command-setting keys. File subsection keys can
    // contain them, so discard other scopes before decoding the record.
    settings.push(
      separator < 0
        ? { key: record }
        : {
            key: record.slice(0, separator),
            value: record.slice(separator + 1),
          },
    );
  }
  return settings;
}

export async function gitInspectionEnvironment(
  environment: NodeJS.ProcessEnv,
  gitExecutable: string | undefined,
  repository: string,
  signal?: AbortSignal,
): Promise<NodeJS.ProcessEnv> {
  const env = { ...environment, ...inheritedToolPaths([], environment) };
  const configuration = gitConfigurationEnvironment(env);
  if (windows)
    for (const name of Object.keys(env))
      if (Object.hasOwn(configuration, name.toUpperCase())) delete env[name];
  Object.assign(env, configuration);
  for (const name of Object.keys(env))
    if (/^CODEX_SECURITY_GIT_ENVIRONMENT(?:_FILE)?$/iu.test(name))
      delete env[name];
  if (gitExecutable === undefined) {
    for (const name of Object.keys(env))
      if (/^GIT_CONFIG_(?:COUNT|PARAMETERS|(?:KEY|VALUE)_\d+)$/u.test(name))
        delete env[name];
    return env;
  }
  const headerIndexes = Object.keys(env).flatMap((name) => {
    const match = /^GIT_CONFIG_KEY_(\d+)$/u.exec(name);
    return match && authenticationHeader(env[name]!) ? [match[1]!] : [];
  });
  if (!headerIndexes.length && !env.GIT_CONFIG_PARAMETERS) return env;

  const parserEnvironment = (
    source: NodeJS.ProcessEnv,
    parametersOnly = false,
  ) => {
    const result = { ...source };
    for (const name of Object.keys(result)) {
      const key = windows ? name.toUpperCase() : name;
      if (
        repositoryEnvironment.includes(key) ||
        key === "GIT_CONFIG" ||
        (parametersOnly &&
          /^GIT_CONFIG_(?:COUNT|(?:KEY|VALUE)_\d+)$/u.test(key))
      )
        delete result[name];
    }
    result.GIT_NO_LAZY_FETCH = "1";
    result.GIT_ALLOW_PROTOCOL = "";
    return result;
  };
  const run = async (args: string[], selected: NodeJS.ProcessEnv) => {
    const execution = spawnTool(
      gitExecutable,
      ["--no-pager", "-C", repository, ...args],
      { env: selected, stdio: ["ignore", "pipe", "pipe"], signal },
      inheritedToolPaths([], selected),
    );
    return requireSuccess(await collect(execution));
  };
  const parserArgs = [
    "config",
    "--null",
    "--list",
    "--show-origin",
    "--no-includes",
  ];
  // Validate with Git before removing a setting, preserving native diagnostics
  // for malformed counts, missing values, and malformed parameter quoting.
  const full = commandSettings(await run(parserArgs, parserEnvironment(env)));
  const parameters = commandSettings(
    await run(parserArgs, parserEnvironment(env, true)),
  );
  const count = full.length - parameters.length;
  const original = { ...env };
  for (const index of headerIndexes) {
    delete env[`GIT_CONFIG_KEY_${index}`];
    delete env[`GIT_CONFIG_VALUE_${index}`];
  }
  if (
    count > 0 &&
    full.slice(0, count).some((setting) => authenticationHeader(setting.key)) &&
    full
      .slice(0, count)
      .every(
        (_setting, index) =>
          original[`GIT_CONFIG_KEY_${index}`] !== undefined &&
          original[`GIT_CONFIG_VALUE_${index}`] !== undefined,
      )
  ) {
    const retained: { key: string; value: string }[] = [];
    for (let index = 0; index < count; index++) {
      const key = original[`GIT_CONFIG_KEY_${index}`]!,
        value = original[`GIT_CONFIG_VALUE_${index}`]!;
      delete env[`GIT_CONFIG_KEY_${index}`];
      delete env[`GIT_CONFIG_VALUE_${index}`];
      if (!authenticationHeader(key)) retained.push({ key, value });
    }
    env.GIT_CONFIG_COUNT = String(retained.length);
    retained.forEach(({ key, value }, index) => {
      env[`GIT_CONFIG_KEY_${index}`] = key;
      env[`GIT_CONFIG_VALUE_${index}`] = value;
    });
  }
  if (parameters.some((setting) => authenticationHeader(setting.key))) {
    const selected = parserEnvironment(env, true);
    delete selected.GIT_CONFIG_PARAMETERS;
    const quote = async (arguments_: string[]): Promise<string> => {
      try {
        return decodeGitPath(
          await run(["rev-parse", "--sq-quote", ...arguments_], selected),
        ).trim();
      } catch (error) {
        const failure = error as NodeJS.ErrnoException;
        // Native quoting can exceed argv space even when the original
        // single PARAMETERS environment value fits.
        if (
          (failure.code !== "E2BIG" &&
            failure.code !== "ENAMETOOLONG" &&
            !(
              failure.code === "WINDOWS_PROCESS_ERROR" && failure.errno === 206
            )) ||
          arguments_.length < 2
        )
          throw error;
        const middle = Math.floor(arguments_.length / 2);
        return `${await quote(arguments_.slice(0, middle))} ${await quote(arguments_.slice(middle))}`;
      }
    };
    const pieces: string[] = [],
      pending: string[] = [];
    for (const { key, value } of parameters) {
      if (authenticationHeader(key)) continue;
      // Keep legacy quoting for older Git. An '=' inside the key needs the
      // separate key/value form already accepted by the native parser.
      if (!key.includes("=")) {
        pending.push(value === undefined ? key : `${key}=${value}`);
        continue;
      }
      if (pending.length) {
        pieces.push(await quote(pending));
        pending.length = 0;
      }
      pieces.push(
        `${await quote([key])}=${value === undefined ? "" : await quote([value])}`,
      );
    }
    if (pending.length) pieces.push(await quote(pending));
    env.GIT_CONFIG_PARAMETERS = pieces.join(" ");
  }
  return env;
}

async function gitProcess(
  repo: string,
  args: string[],
  caseSensitivePathspecs = false,
  ignoreConfigFile = false,
) {
  const command = trustedTool("git", repo);
  if (!command) return undefined;
  const env = await gitInspectionEnvironment(process.env, command, repo);
  const inherited = inheritedToolPaths([], env);
  for (const name of Object.keys(env)) {
    const key = windows ? name.toUpperCase() : name;
    if (
      repositoryEnvironment.includes(key) ||
      (ignoreConfigFile && key === "GIT_CONFIG") ||
      (caseSensitivePathspecs && key === "GIT_ICASE_PATHSPECS") ||
      [
        "GIT_LITERAL_PATHSPECS",
        "GIT_NO_LAZY_FETCH",
        "GIT_ALLOW_PROTOCOL",
      ].includes(key)
    )
      delete env[name];
  }
  env.GIT_LITERAL_PATHSPECS = "1";
  // Local inspection must not fetch objects through a configured transport.
  env.GIT_NO_LAZY_FETCH = "1";
  env.GIT_ALLOW_PROTOCOL = "";
  if (caseSensitivePathspecs) env.GIT_ICASE_PATHSPECS = "0";
  return spawnTool(
    command,
    [
      "-c",
      "core.fsmonitor=false",
      "-c",
      "i18n.logOutputEncoding=UTF-8",
      "-C",
      repo,
      ...args,
    ],
    { env, stdio: ["pipe", "pipe", "pipe"] },
    inherited,
  );
}

export async function runRipgrep(
  args: string[],
  repo: string,
): Promise<ToolResult> {
  if (!windows) return runTool("rg", args, repo);
  const inherited = inheritedToolPaths([
    "RIPGREP_CONFIG_PATH",
    "CODEX_SECURITY_GIT",
  ]);
  const rawWindowsLookup = [repo, ...args, ...Object.values(inherited)].some(
    rawToolValue,
  );
  const command = trustedTool("rg", repo, rawWindowsLookup);
  if (!command)
    throw Object.assign(new Error("spawn rg ENOENT"), { code: "ENOENT" });
  return runTool(command, args, repo);
}

export async function runTool(
  command: string,
  args: string[],
  cwd?: string,
  input?: Buffer,
  inputFd: 0 | 3 = 0,
): Promise<ToolResult> {
  const execution = spawnTool(
    command,
    args,
    {
      cwd,
      stdio: [
        input === undefined || inputFd !== 0 ? "ignore" : "pipe",
        "pipe",
        "pipe",
      ],
    },
    inheritedToolPaths(["RIPGREP_CONFIG_PATH", "CODEX_SECURITY_GIT"]),
    inputFd,
  );
  const pipe = execution.child.stdio[inputFd] as Writable | null;
  pipe?.on("error", () => {});
  pipe?.end(input);
  return collect(execution);
}

async function collect({
  child,
  failureMarker,
}: ReturnType<typeof spawnTool>): Promise<ToolResult> {
  const stdout: Buffer[] = [],
    stderr: Buffer[] = [];
  child.stdout!.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr!.on("data", (chunk: Buffer) => stderr.push(chunk));
  await new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", () => resolve());
  });
  const diagnostic = Buffer.concat(stderr);
  const start = failureMarker ? diagnostic.indexOf(failureMarker) : -1;
  if (start >= 0)
    throw Object.assign(
      new Error(
        Buffer.concat([
          diagnostic.subarray(0, start),
          diagnostic.subarray(start + failureMarker!.length),
        ]).toString("utf8"),
      ),
      { code: child.exitCode === 127 ? "ENOENT" : "EACCES" },
    );
  return {
    status: child.exitCode,
    signal: child.signalCode,
    stdout: Buffer.concat(stdout),
    stderr: diagnostic.toString("utf8"),
  };
}

export async function git(
  repo: string,
  args: string[],
  caseSensitivePathspecs = false,
  ignoreConfigFile = false,
) {
  try {
    const execution = await gitProcess(
      repo,
      args,
      caseSensitivePathspecs,
      ignoreConfigFile,
    );
    if (execution) {
      execution.child.stdin!.end();
      return await collect(execution);
    }
  } catch (error) {
    if (error instanceof GitFailure)
      return { ...error.result, stdout: Buffer.alloc(0) };
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return { status: 127, signal: null, stdout: Buffer.alloc(0), stderr: "" };
}

export function decodeGitPath(data: Buffer): string {
  if (!windows) return decodePosixBytes(data);
  // Git index paths can contain UTF-8-encoded lone UTF-16 code units on Windows.
  return data
    .toString("latin1")
    .split(/(\xed[\xa0-\xbf][\x80-\xbf])/u)
    .map((part) =>
      /^\xed[\xa0-\xbf][\x80-\xbf]$/u.test(part)
        ? String.fromCharCode(
            0xd000 |
              ((part.charCodeAt(1) & 0x3f) << 6) |
              (part.charCodeAt(2) & 0x3f),
          )
        : decodeUtf8(Buffer.from(part, "latin1")),
    )
    .join("");
}

export function encodeGitPath(value: string): Buffer {
  if (!windows) return encodePosixPath(value);
  return Buffer.concat(
    value.split(/([\ud800-\udfff])/u).map((part) => {
      if (!/^[\ud800-\udfff]$/u.test(part)) return Buffer.from(part);
      const unit = part.charCodeAt(0);
      return Buffer.from([
        0xe0 | (unit >> 12),
        0x80 | ((unit >> 6) & 0x3f),
        0x80 | (unit & 0x3f),
      ]);
    }),
  );
}

function gitLine(data: Buffer): string {
  return decodeGitPath(data).replace(windows ? /\r?\n$/u : /\n$/u, "");
}

function paths(data: Buffer): string[] {
  return decodeGitPath(data).split("\0").filter(Boolean);
}
function requireSuccess(result: ToolResult): Buffer {
  if (result.status !== 0) throw new GitFailure(result);
  return result.stdout;
}

export async function directoryPaths(
  target: string,
): Promise<string[] | undefined> {
  const root = await git(target, ["rev-parse", "--show-toplevel"]);
  if (root.status !== 0 || !root.stdout.length) return undefined;
  const repository = canonical(gitLine(root.stdout));
  const prefix = decodeGitPath(
    requireSuccess(await git(target, ["rev-parse", "--show-prefix"])),
  )
    .replace(/\n$/u, "")
    .replace(/\/$/u, "");
  const scope = prefix ? append(repository, prefix) : repository;
  inside(repository, canonical(scope));
  if (!sameFile(scope, target))
    throw new Error("Scan target must stay inside its Git working tree.");
  const depth = prefix ? prefix.split("/").length : 0;
  // Git's ASCII case folding does not cover Unicode directory aliases.
  const unicodeCase = [...prefix].some(
    (character) =>
      character.charCodeAt(0) > 127 &&
      character.toLowerCase() !== character.toUpperCase(),
  );
  const listing = paths(
    requireSuccess(
      await git(repository, [
        ...(depth && !unicodeCase ? ["--no-literal-pathspecs"] : []),
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        depth && !unicodeCase ? `:(icase,literal)${prefix}` : ".",
      ]),
    ),
  );
  const found = new Set<string>(),
    matching = new Map<string, boolean>();
  for (const name of listing) {
    const parts = name.split("/");
    if (parts.some((part) => sourceMetadata.has(part))) continue;
    if (parts.length <= depth) continue;
    if (depth) {
      const indexedPrefix = append(repository, parts.slice(0, depth).join(sep));
      if (!matching.has(indexedPrefix))
        matching.set(indexedPrefix, sameFile(indexedPrefix, scope));
      if (!matching.get(indexedPrefix)) continue;
    }
    const path = append(target, parts.slice(depth).join(sep));
    let metadata;
    try {
      if (linkedParent(target, path)) continue;
      metadata = lstat(path);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") continue;
      throw error;
    }
    found.add(path);
    if (
      metadata.isDirectory() &&
      !("isNameSurrogate" in metadata && metadata.isNameSurrogate())
    ) {
      const nestedRoot = await git(path, ["rev-parse", "--show-toplevel"]);
      const nested =
        nestedRoot.status === 0 && sameFile(gitLine(nestedRoot.stdout), path)
          ? await directoryPaths(path)
          : undefined;
      for (const child of nested ?? walk(path, true, true)) found.add(child);
    }
  }
  return [...found];
}

export interface Change {
  path: string;
  status: string;
  sourcePath?: string;
}

async function gitPathsOutput(
  repo: string,
  args: string[],
  names: string[],
): Promise<Buffer> {
  if (!names.length) return Buffer.alloc(0);
  try {
    return requireSuccess(await git(repo, [...args, "--", ...names], true));
  } catch (error) {
    const failure = error as NodeJS.ErrnoException;
    // Retry only an actual native argument-length failure, without a path cap.
    if (
      (failure.code !== "E2BIG" &&
        failure.code !== "ENAMETOOLONG" &&
        !(failure.code === "WINDOWS_PROCESS_ERROR" && failure.errno === 206)) ||
      names.length < 2
    )
      throw error;
    const middle = Math.floor(names.length / 2);
    return Buffer.concat([
      await gitPathsOutput(repo, args, names.slice(0, middle)),
      await gitPathsOutput(repo, args, names.slice(middle)),
    ]);
  }
}

async function worktreeObjectHashes(
  repo: string,
  names: string[],
): Promise<Map<string, string>> {
  let output: Buffer;
  try {
    output = await gitPathsOutput(repo, ["hash-object"], names);
  } catch (error) {
    if (!(error instanceof GitFailure)) throw error;
    const readable: string[] = [];
    for (const path of names) {
      const absolute = append(repo, path);
      try {
        if (linkedParent(repo, absolute) || !regular(absolute)) continue;
        for (const _ of readChunks(absolute)) break;
      } catch {
        continue;
      }
      readable.push(path);
    }
    if (readable.length === names.length) throw error;
    return worktreeObjectHashes(repo, readable);
  }
  const hashes = gitLine(output).split(/\r?\n/u);
  return new Map(names.map((name, index) => [name, hashes[index]!]));
}

async function unchangedWorktreeFiles(
  repo: string,
  candidates: Map<string, string>,
): Promise<Set<string>> {
  if (!candidates.size) return new Set();
  const replacements = new Set(
    gitLine(
      requireSuccess(await git(repo, ["replace", "-l", "--format=short"])),
    )
      .toLowerCase()
      .split(/\r?\n/u),
  );
  const replaced = [...candidates.values()].some((oid) =>
    replacements.has(oid),
  );
  if (
    replaced &&
    !("GIT_NO_REPLACE_OBJECTS" in gitConfigurationEnvironment(process.env))
  ) {
    const enabled = await git(
      repo,
      ["config", "--bool", "--get", "core.useReplaceRefs"],
      false,
      true,
    );
    if (enabled.status !== 1) requireSuccess(enabled);
    if (enabled.status === 1 || gitLine(enabled.stdout) !== "false") {
      // Hashes and status compare index OIDs without replacement refs.
      // Preserve Git's selected change when its base uses a replacement.
      candidates = new Map(
        [...candidates].filter(([, oid]) => !replacements.has(oid)),
      );
    }
  }
  const hashes = await worktreeObjectHashes(repo, [...candidates.keys()]);
  const unchanged = new Set(
    [...candidates]
      .filter(([name, oid]) => !hashes.has(name) || hashes.get(name) === oid)
      .map(([name]) => name),
  );
  const remaining = [...candidates.keys()].filter(
    (name) => !unchanged.has(name),
  );
  const indexed = new Map<string, string>();
  for (const record of paths(
    await gitPathsOutput(repo, ["ls-files", "--stage", "-z"], remaining),
  )) {
    const separator = record.indexOf("\t"),
      fields = record.slice(0, separator).split(" ");
    if (fields[2] === "0") indexed.set(record.slice(separator + 1), fields[1]!);
  }
  const matching = remaining.filter(
    (name) => indexed.get(name) === candidates.get(name),
  );
  // Git's loaded index preserves automatic EOL rules; inspect only eligible
  // selected paths and leave the original index untouched.
  const status = await gitPathsOutput(
    repo,
    [
      "--no-optional-locks",
      "status",
      "--porcelain",
      "-z",
      "--untracked-files=no",
      "--ignore-submodules=all",
      "--no-renames",
    ],
    matching,
  );
  const dirty = new Set(paths(status).map((record) => record.slice(3)));
  for (const name of matching) if (!dirty.has(name)) unchanged.add(name);
  return unchanged;
}

async function changed(
  repo: string,
  args: string[],
  local = false,
): Promise<Change[]> {
  const fields = paths(
    requireSuccess(
      await git(
        repo,
        [
          // Raw inspection must not refresh the full index, including excluded metadata.
          ...(local ? ["-c", "diff.autoRefreshIndex=false"] : []),
          ...(local ? ["--no-literal-pathspecs"] : []),
          "diff",
          "--ignore-submodules=all",
          "--raw",
          "--no-abbrev",
          "-z",
          "--diff-filter=ACMRDT",
          ...args,
          "--",
          ...(local
            ? [":(top,glob,exclude)**/.svn", ":(top,glob,exclude)**/.svn/**"]
            : []),
        ],
        local,
      ),
    ),
  );
  const changes: Change[] = [];
  const candidates = new Map<string, string>();
  let index = 0;
  while (index < fields.length) {
    const metadata = fields[index++]!.split(" "),
      status = metadata.at(-1)![0]!;
    const sourcePath = status === "R" ? fields[index] : undefined;
    if (status === "C" || status === "R") index++;
    const path = fields[index++]!;
    if (
      local &&
      status === "M" &&
      metadata[0]!.slice(1) === metadata[1] &&
      /^0+$/u.test(metadata[3]!)
    ) {
      const absolute = append(repo, path);
      try {
        if (!linkedParent(repo, absolute) && regular(absolute)) {
          // Raw worktree records can reflect only stale index stat data.
          // Normalize eligible text without opening the older base blob or
          // making Git buffer files the inventory already excludes as binary.
          const sampler = createSourceSampler();
          try {
            for (const chunk of readChunks(absolute))
              if (!sampler.consume(chunk)) break;
          } catch {
            continue;
          }
          if (!sampler.finish()[1]) candidates.set(path, metadata[2]!);
        }
      } catch (error) {
        if (!isMissingPathError(error)) throw error;
      }
    }
    if (
      (status === "D" ? metadata[0]!.slice(1) : metadata[1]!).startsWith("100")
    )
      changes.push({
        path,
        status,
        ...(sourcePath === undefined ? {} : { sourcePath }),
      });
  }
  const unchanged = await unchangedWorktreeFiles(repo, candidates);
  return changes.filter((change) => !unchanged.has(change.path));
}
export async function changedPaths(
  repo: string,
  base: string,
  head: string,
  mode: string,
): Promise<Change[]> {
  if (mode === "revisions") return changed(repo, [`${base}..${head}`]);
  const unstaged = await changed(repo, [base], true),
    staged = await changed(repo, ["--cached", base], true);
  const result = new Map(staged.map((change) => [change.path, change]));
  for (const change of unstaged) result.set(change.path, change);
  for (const path of paths(
    requireSuccess(
      await git(repo, ["ls-files", "--others", "--exclude-standard", "-z"]),
    ),
  )) {
    if (path.endsWith("/")) continue;
    if (path.split("/").some((part) => sourceMetadata.has(part))) continue;
    const absolute = append(repo, path);
    try {
      if (!linkedParent(repo, absolute) && regular(absolute))
        result.set(path, { path, status: "A" });
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
    }
  }
  const changes = new Map<string, Change>();
  for (const change of result.values()) {
    const { path, status } = change;
    if (path.split("/").some((part) => sourceMetadata.has(part))) continue;
    if (status === "D") {
      changes.set(path, change);
      continue;
    }
    const absolute = append(repo, path);
    try {
      if (linkedParent(repo, absolute)) {
        // Git may report a modified file through a junction. Only its base blob is in scope.
        if (status === "M") changes.set(path, { path, status: "D" });
      } else if (regular(absolute)) {
        changes.set(path, change);
        continue;
      }
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
    }
    if (
      status === "R" &&
      change.sourcePath !== undefined &&
      !changes.has(change.sourcePath)
    )
      changes.set(change.sourcePath, { path: change.sourcePath, status: "D" });
  }
  return [...changes.values()];
}

/** Consume each complete blob while retaining at most the preview prefix. */
export async function blobSamples(
  repo: string,
  names: string[],
): Promise<([Buffer, boolean] | undefined)[]> {
  if (!names.length) return [];
  const nulInput = names.some((name) => /[\r\n]/u.test(name));
  const separator = nulInput ? "\0" : "\n";
  const child = (
    await gitProcess(repo, ["cat-file", "--batch", ...(nulInput ? ["-z"] : [])])
  )?.child as ChildProcessWithoutNullStreams | undefined;
  if (!child) return names.map(() => undefined);
  const completion = new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => resolve(code ?? 1));
  });
  child.stderr.resume();
  child.stdin.on("error", () => {});
  child.stdin.end(encodeGitPath(names.join(separator) + separator));
  const result: ([Buffer, boolean] | undefined)[] = [];
  let pending = Buffer.alloc(0),
    remaining: number | undefined,
    sampler = createSourceSampler();
  try {
    for await (const chunk of child.stdout) {
      pending = Buffer.concat([pending, chunk as Buffer]);
      while (pending.length) {
        if (remaining === undefined) {
          const end = pending.indexOf(0x0a);
          if (end < 0) break;
          const header = pending.subarray(0, end).toString("utf8").split(" ");
          pending = pending.subarray(end + 1);
          if (header.at(-2) !== "blob") {
            result.push(undefined);
            continue;
          }
          remaining = Number(header.at(-1));
          sampler = createSourceSampler();
        }
        if (remaining > 0) {
          const length = Math.min(remaining, pending.length),
            data = pending.subarray(0, length);
          sampler.consume(data);
          remaining -= length;
          pending = pending.subarray(length);
          if (remaining) break;
        }
        if (!pending.length) break;
        if (pending[0] !== 0x0a) throw new Error("Invalid Git blob framing");
        pending = pending.subarray(1);
        result.push(sampler.finish());
        remaining = undefined;
      }
    }
    if (
      (await completion) ||
      remaining !== undefined ||
      result.length !== names.length
    )
      return names.map(() => undefined);
    return result;
  } catch (error) {
    child.kill();
    await completion.catch(() => {});
    throw error;
  }
}

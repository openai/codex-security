import {
  environmentValue,
  isMissingPathError,
  readChunks,
  resolvedPathText as canonical,
} from "./helper-files";
import {
  spawn,
  spawnSync,
  type SpawnOptions,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { randomUUID } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import {
  lstatSync,
  mkdirSync,
  readdirSync,
  readlinkSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import type { Writable } from "node:stream";
import {
  basename,
  dirname,
  delimiter,
  isAbsolute,
  parse,
  resolve,
  sep,
} from "node:path";
import { createRequire } from "node:module";
import { constants, release, tmpdir } from "node:os";
import { spawnWindowsProcess } from "../../../native/windows-process.mjs";
import { nativeTarget } from "../../../native/platform.mjs";
import {
  decodePosixBytes,
  encodePosixPath,
  resolvePosixPath,
} from "./posix-path";
import { decodeUtf8 } from "./utf8";
import {
  ancestors,
  append,
  executable,
  exists,
  fsPath,
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
import { helperEnvironment } from "../helper-environment";

interface ToolResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: Buffer;
  stderr: string;
}

const repositoryEnvironment = [
  "GIT_ALLOW_PROTOCOL",
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CEILING_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_DIR",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
  "GIT_GLOB_PATHSPECS",
  "GIT_ICASE_PATHSPECS",
  "GIT_INDEX_FILE",
  "GIT_LITERAL_PATHSPECS",
  "GIT_NAMESPACE",
  "GIT_NO_LAZY_FETCH",
  "GIT_OBJECT_DIRECTORY",
  "GIT_WORK_TREE",
];
const posixLoaderSetting = /^(?:LD|DYLD)_[A-Z0-9_]+$/u;

function rawToolValue(value: string): boolean {
  return (windows ? /[\ud800-\udfff]/u : /[\udc80-\udcff]/u).test(value);
}

function selectedBundledRipgrep(
  candidate: string,
  protectedRoot: string,
): boolean {
  const codex = environmentValue("CODEX_CLI_PATH");
  if (!codex) return false;
  try {
    const binary = canonical(codex);
    if (!isRepositoryPath(protectedRoot, binary)) return false;
    return sameFile(
      candidate,
      append(
        append(dirname(dirname(binary)), "codex-path"),
        windows ? "rg.exe" : "rg",
      ),
    );
  } catch {
    return false;
  }
}

function protectedToolRoot(target: string): string {
  let root = canonical(target);
  for (const ancestor of ancestors(root))
    if (exists(append(ancestor, ".git"))) root = ancestor;
  return root;
}

function isRepositoryPath(root: string, path: string): boolean {
  try {
    inside(root, path);
    return true;
  } catch {
    return false;
  }
}

// The kernel can dispatch a shebang or the POSIX shell can interpret an
// executable text file after ENOEXEC. Only skip inspection for native images.
const nativeImageMagic = new Set(
  process.platform === "darwin"
    ? [
        0xfeedface,
        0xcefaedfe,
        0xfeedfacf,
        0xcffaedfe, // Mach-O
        0xcafebabe,
        0xbebafeca,
        0xcafebabf,
        0xbfbafeca, // universal binaries
      ]
    : [0x7f454c46],
); // ELF

// Linux reads BINPRM_BUF_SIZE bytes for exec. XNU uses IMG_SHSIZE and also
// treats "#" as a shebang terminator. Arguments are left entirely to the OS.
const macShebang = process.platform === "darwin";
const legacyLinuxShebang =
  process.platform === "linux" &&
  /^(?:[0-4]\.|5\.0(?:\.|-|$))/u.test(release());
const headerSize = macShebang ? 512 : 256;
function toolHeader(path: string): "native" | "text" | string[] | undefined {
  try {
    for (const chunk of readChunks(path, undefined, headerSize)) {
      if (chunk.length >= 4 && nativeImageMagic.has(chunk.readUInt32BE()))
        return "native";
      if (chunk[0] !== 35 || chunk[1] !== 33) return "text";
      const line = chunk.subarray(2).toString("latin1");
      if (macShebang && !/[#\n]/u.test(line)) return "text";
      const pattern = macShebang
        ? /^[ \t]*([^ \t#\n\0]+)/u
        : /^[ \t]*([^ \t\n\0]+)/u;
      const token = pattern.exec(line);
      const names: string[] = [];
      if (
        token &&
        (macShebang ||
          chunk.length < headerSize ||
          token[0].length < line.length)
      )
        names.push(token[1]!);
      // Older Linux kernels could execute a name truncated at header byte 127.
      // Check both spellings on those releases, including vendor backports.
      if (legacyLinuxShebang && token && token[0].length > 125) {
        const truncated = pattern.exec(line.slice(0, 125))?.[1];
        if (truncated) names.push(truncated);
      }
      return names.length
        ? names.map((name) => decodePosixBytes(Buffer.from(name, "latin1")))
        : "text";
    }
    return "text";
  } catch {
    return undefined;
  }
}

function interpreterCheck(
  cwd: string,
  allowsPath: (path: string) => boolean,
  shared: boolean,
  scripts?: Map<string, string>,
) {
  const checked = new Map<string, boolean>();
  function allows(path: string, loader = false): boolean {
    const prior = checked.get(path);
    if (prior !== undefined) return prior;
    if (!executable(path)) return true; // Leave missing loaders and EACCES to exec.
    const header = toolHeader(path);
    if (!header) return false;
    if (typeof header === "string") {
      if (loader) checked.set(path, true);
      return true;
    }
    checked.set(path, true); // A cycle without a protected path is an OS launch error.
    const safe = header.every((interpreter) => {
      // A campaign's PATH is reused by children in different working directories.
      if (shared && !isAbsolute(interpreter)) return false;
      const file = isAbsolute(interpreter)
        ? interpreter
        : append(cwd, interpreter);
      // XNU redirects once; Linux can chain interpreter scripts.
      return allowsPath(file) && (macShebang || allows(file, true));
    });
    if (safe && header.length === 1 && isAbsolute(header[0]!))
      scripts?.set(path, header[0]!);
    checked.set(path, safe);
    return safe;
  }
  return allows;
}

// libuv can return Win32 link targets using the extended drive or UNC spelling.
function windowsLinkPath(path: string): string {
  return path
    .replace(/^\\\\[?.]\\UNC\\/iu, "\\\\")
    .replace(/^\\\\[?.]\\(?=[a-z]:\\)/iu, "");
}

function linkTarget(path: string): string | undefined {
  if (sep === "\\") {
    let info: ReturnType<typeof lstat>;
    try {
      info = lstat(path);
    } catch (error) {
      // Only an absent entry may later materialize in an external directory.
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    if (!("isNameSurrogate" in info) || !info.isNameSurrogate()) return;
    // SDK source paths are UTF-8. An unreadable reparse target cannot be trusted.
    if (!path.isWellFormed())
      throw new Error("Cannot inspect this Windows link");
    return windowsLinkPath(
      decodeUtf8(readlinkSync(fsPath(path), { encoding: "buffer" })),
    );
  }
  const name = encodePosixPath(path);
  if (lstatSync(name, { throwIfNoEntry: false })?.isSymbolicLink())
    return decodePosixBytes(readlinkSync(name, { encoding: "buffer" }));
}

function canonicalComponent(path: string): string {
  return sep === "\\"
    ? windowsLinkPath(canonical(path, false))
    : decodePosixBytes(resolvePosixPath(encodePosixPath(path), false));
}

// A campaign can replace files in its checkouts after preparing the workers.
// Check every component owned by the campaign, including intermediate links
// whose current destination is an external executable.
function campaignPathResolver(
  isProtected: (path: string) => boolean,
  cwd: string,
) {
  const resolved = new Map<string, string | null>();
  function expand(directory: string, target: string): string | null {
    // Win32 normalizes drive-relative and rooted names before filesystem
    // lookup. POSIX processes ".." after following the preceding symlink.
    const path =
      sep === "\\" ? resolve(directory, windowsLinkPath(target)) : target;
    const root = parse(path).root;
    let parent =
      root && sep === "\\" ? canonicalComponent(root) : root || directory;
    for (const part of path.slice(root.length).split(sep)) {
      if (!part || part === ".") continue;
      if (part === "..") {
        parent = dirname(parent);
        continue;
      }
      if (isProtected(parent)) return null;
      const child = append(parent, part);
      if (!resolved.has(child)) {
        resolved.set(child, null); // Detect symlink cycles while expanding.
        const link = linkTarget(child);
        // Filesystems may canonicalize case or DOS short names even without a link.
        resolved.set(
          child,
          link === undefined ? canonicalComponent(child) : expand(parent, link),
        );
      }
      const next = resolved.get(child);
      if (!next) return null;
      parent = next;
    }
    return parent;
  }
  return (path: string) => {
    try {
      const target = expand(cwd, path);
      return target !== null && !isProtected(target) ? target : null;
    } catch {
      return null;
    }
  };
}

function campaignPathCheck(
  isProtected: (path: string) => boolean,
  cwd: string,
) {
  const resolvePath = campaignPathResolver(isProtected, cwd);
  return (path: string) => resolvePath(path) !== null;
}

// Confirm the dispatcher starts through a link on the actual temporary mount.
// The probe reaches only the system shell, before the operator directory is attached.
function scriptDispatcher(
  view: string,
  origin: string,
  allows: (path: string, link: boolean) => boolean,
) {
  const probe = append(view, "sh");
  try {
    const dispatcher = createRequire(import.meta.url).resolve(
      "../scripts/dispatch_inventory_tool",
    );
    if (
      !allows(dispatcher, true) ||
      !allows("/bin/sh", true) ||
      !executable(dispatcher)
    )
      return;
    symlinkSync("/bin", fsPath(origin));
    symlinkSync(dispatcher, fsPath(probe));
    const args = ["-c", "exit 73"];
    const options = { env: { PATH: "/dev/null" }, stdio: "ignore" } as const;
    const env =
      allows("/usr/bin/env", true) &&
      spawnSync("/usr/bin/env", [probe, ...args], options).status === 73;
    if (env || spawnSync(probe, args, options).status === 73)
      return { dispatcher, env };
  } catch {
    // Older or non-executable installations still support direct tool links.
    return;
  } finally {
    rmSync(fsPath(probe), { force: true });
    rmSync(fsPath(origin), { force: true });
  }
}

function scriptPathDirectory(
  directory: string,
  isProtected: (path: string) => boolean,
  temporary: string[],
  scripts: ReadonlyMap<string, string>,
  allows: (path: string, link: boolean) => boolean,
): string {
  const entries = readdirSync(fsPath(directory), {
    withFileTypes: true,
    encoding: "buffer",
  });
  // Bun returns bare names for buffer-encoded directory entries.
  const nameOf = (entry: (typeof entries)[number]) =>
    decodePosixBytes(Buffer.isBuffer(entry) ? entry : entry.name);
  const allowed = entries.filter((entry) => {
    const path = append(directory, nameOf(entry));
    const kind = Buffer.isBuffer(entry) ? lstat(path) : entry;
    const link = kind.isSymbolicLink();
    return (!link && !kind.isFile()) || allows(path, link);
  });
  if (allowed.length === entries.length) return directory;
  // Keep safe neighbors in their original PATH position. env and the kernel
  // then handle lookup, argument splitting and missing interpreters normally.
  let copy: string | undefined;
  for (const path of [tmpdir(), "/tmp"]) {
    try {
      const parent = canonical(path);
      if (!parent.includes(delimiter) && !isProtected(parent)) {
        const candidate = append(
          parent,
          `codex-security-tools-${randomUUID()}`,
        );
        mkdirSync(fsPath(candidate), { mode: 0o700 });
        copy = candidate;
        break;
      }
    } catch {
      // Another external temporary directory may be usable.
    }
  }
  if (!copy)
    throw new Error("No external temporary directory for inventory tools");
  temporary.push(copy);
  const view = append(copy, "bin"),
    origin = append(copy, "origin");
  mkdirSync(fsPath(view), { mode: 0o700 });
  const systems = new Map<string, string | undefined>();
  const retained = allowed.map((entry) => {
    const name = nameOf(entry);
    const path = append(directory, name);
    const loader = scripts.get(path);
    // A forwarder would hide execvp's fallthrough for a missing kernel loader.
    // Forward only scripts with a system interpreter whose launch we can prove.
    if (loader && !systems.has(loader)) {
      systems.set(
        loader,
        executable(loader)
          ? ["/bin/sh", "/usr/bin/env"].find((system) =>
              sameFile(loader, system),
            )
          : undefined,
      );
    }
    return { name, path, interpreter: loader && systems.get(loader) };
  });
  const launch = retained.some((tool) => tool.interpreter)
    ? scriptDispatcher(view, origin, allows)
    : undefined;
  if (launch) symlinkSync(fsPath(directory), fsPath(origin));
  for (const tool of retained) {
    const forward =
      tool.interpreter === "/bin/sh" ||
      (tool.interpreter === "/usr/bin/env" && launch?.env);
    const target = launch && forward ? launch.dispatcher : tool.path;
    symlinkSync(fsPath(target), fsPath(append(view, tool.name)));
  }
  return view;
}

function protectedPathBoundary(roots: readonly string[]) {
  const key = (path: string) =>
    sep === "\\" ? windowsLinkPath(path).toLowerCase() : path;
  const boundaries = new Set(roots.map(key));
  return (entry: string) => {
    for (const parent of ancestors(entry))
      if (boundaries.has(key(parent))) return true;
    return false;
  };
}

export function protectedHostPathResolver(
  cwd: string,
  roots: readonly string[],
) {
  return campaignPathResolver(protectedPathBoundary(roots), cwd);
}

export function inventoryToolPath(
  path: string,
  cwd: string,
  roots: readonly string[],
  mode: "native" | "script" | "campaign",
) {
  const temporary: string[] = [];
  const isProtected = protectedPathBoundary(roots);
  const pathAllowed = campaignPathCheck(isProtected, cwd);
  // Windows removes unsafe search entries in the SDK, before CreateProcess.
  if (windows) return { path, allows: pathAllowed, cleanup() {} };
  const scripts = new Map<string, string>();
  const interpreterAllowed = interpreterCheck(
    cwd,
    pathAllowed,
    mode === "campaign",
    scripts,
  );
  const allows = (file: string) =>
    pathAllowed(file) && interpreterAllowed(file);
  const directories = path.split(delimiter).flatMap((entry) => {
    try {
      const lookup = isAbsolute(entry) ? entry : append(cwd, entry);
      if (mode === "campaign" && !pathAllowed(lookup)) return [];
      let directory = canonical(lookup);
      if (isProtected(directory)) return [];
      if (mode !== "native")
        directory = scriptPathDirectory(
          directory,
          isProtected,
          temporary,
          scripts,
          (file, link) => (link ? allows(file) : interpreterAllowed(file)),
        );
      // A directory containing ":" can be on PATH through an external alias.
      if (directory.includes(delimiter))
        return lookup.includes(delimiter) ||
          isProtected(resolve(lookup)) ||
          !pathAllowed(lookup)
          ? []
          : [lookup];
      return [directory];
    } catch {
      return [];
    }
  });
  // An empty POSIX PATH searches the current directory.
  return {
    path: directories.join(delimiter) || "/dev/null",
    allows,
    cleanup() {
      for (const directory of temporary) {
        try {
          rmSync(fsPath(directory), { recursive: true, force: true });
        } catch {
          // Cleanup must not change the tool or campaign's exit status.
        }
      }
    },
  };
}

function* trustedTools(
  name: "git" | "rg",
  target: string,
  protectedRoot: string,
  rawWindowsLookup = false,
): Generator<string, undefined> {
  const configured =
    name === "git" ? environmentValue("CODEX_SECURITY_GIT") : undefined;
  if (configured === "") return;
  if (configured !== undefined && !isAbsolute(configured))
    throw new Error(
      "CODEX_SECURITY_GIT must name an absolute trusted executable.",
    );
  const searchPath =
    environmentValue("PATH") ?? (windows ? ".;C:\\bin" : "/usr/bin:/bin");
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
  const cwd = name === "git" ? process.cwd() : target;
  const pathAllowed = campaignPathCheck(
    (path) => isRepositoryPath(protectedRoot, path),
    cwd,
  );
  const interpreterAllowed =
    !windows && interpreterCheck(cwd, pathAllowed, false);
  let lookupDenied = false;
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
    } catch (error) {
      if (
        !windows &&
        name === "rg" &&
        !isRepositoryPath(protectedRoot, resolve(candidate))
      ) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "EACCES" || code === "EPERM") lookupDenied = true;
        else if (code !== "ENOENT" && code !== "ENOTDIR") throw error;
      }
      continue;
    }
    if (
      ((windows || name === "git") && !executable(resolved)) ||
      (windows &&
        (!/\.(exe|com)$/iu.test(candidate) || /\.(bat|cmd)$/iu.test(resolved)))
    )
      continue;
    // POSIX resolves each symlink before a following "..".
    const inRepository =
      [invocation, resolved].some((path) =>
        isRepositoryPath(protectedRoot, path),
      ) ||
      (windows
        ? isRepositoryPath(protectedRoot, resolve(candidate))
        : !pathAllowed(candidate));
    if (
      (inRepository &&
        !(name === "rg" && selectedBundledRipgrep(resolved, protectedRoot))) ||
      (interpreterAllowed && !interpreterAllowed(resolved))
    ) {
      if (configured !== undefined)
        throw new Error(
          "CODEX_SECURITY_GIT must stay outside the protected repository.",
        );
      continue;
    }
    yield inRepository ? resolved : invocation;
  }
  if (lookupDenied)
    throw Object.assign(new Error("spawn rg EACCES"), { code: "EACCES" });
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

type ToolOptions = SpawnOptions & {
  cwd?: string;
  stdio: ["ignore" | "pipe", "pipe", "pipe"];
};

const inventoryViews = new AsyncLocalStorage<
  Map<string, ReturnType<typeof inventoryToolPath>>
>();

export async function withInventoryToolPaths<T>(
  run: () => Promise<T>,
): Promise<T> {
  const views = new Map<string, ReturnType<typeof inventoryToolPath>>();
  try {
    return await inventoryViews.run(views, run);
  } finally {
    for (const view of views.values()) view.cleanup();
  }
}

function spawnInventoryTool(
  command: string,
  args: string[],
  options: ToolOptions,
  inherited: Record<string, string>,
  root: string,
) {
  if (windows || inherited.PATH === undefined)
    return spawnTool(command, args, options, inherited);
  const cwd = options.cwd ?? process.cwd();
  const mode =
    executable(command) && toolHeader(command) !== "native"
      ? "script"
      : "native";
  const views = inventoryViews.getStore();
  const key = JSON.stringify([root, cwd, inherited.PATH, mode]);
  let view = views?.get(key);
  if (!view) {
    view = inventoryToolPath(inherited.PATH, cwd, [root], mode);
    views?.set(key, view);
  }
  const PATH = view.path;
  try {
    const result = spawnTool(
      command,
      args,
      { ...options, env: { ...(options.env ?? process.env), PATH } },
      { ...inherited, PATH },
    );
    if (!views) result.child.once("close", view.cleanup);
    return result;
  } catch (error) {
    if (!views) view.cleanup();
    throw error;
  }
}

function spawnTool(
  command: string,
  args: string[],
  spawnOptions: ToolOptions,
  inheritedEnvironment: Record<string, string>,
  inputFd: 0 | 3 = 0,
) {
  const options = { ...spawnOptions, env: helperEnvironment(spawnOptions.env) };
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
  const env = options.env;
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

function inheritedToolPaths(additional: string[] = []): Record<string, string> {
  const keys = Object.keys(process.env).sort();
  const toolConfiguration = keys.filter((name) => {
    const key = windows ? name.toUpperCase() : name;
    return (
      [
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_PARAMETERS",
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
      const value = environmentValue(key);
      return value === undefined ? [] : [[name, value]];
    }),
  );
}

function gitProcess(repo: string, args: string[]) {
  const root = protectedToolRoot(repo);
  const command = trustedTools("git", repo, root).next().value;
  if (!command) return undefined;
  const env: NodeJS.ProcessEnv = { ...process.env };
  const inherited = inheritedToolPaths();
  for (const name of Object.keys(env)) {
    const key = windows ? name.toUpperCase() : name;
    if (repositoryEnvironment.includes(key)) delete env[name];
  }
  env.GIT_LITERAL_PATHSPECS = "1";
  env.GIT_NO_LAZY_FETCH = "1";
  env.GIT_ALLOW_PROTOCOL = "";
  return spawnInventoryTool(
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
    root,
  );
}

export async function runRipgrep(
  args: string[],
  repo: string,
): Promise<ToolResult> {
  const root = protectedToolRoot(repo);
  const inherited = inheritedToolPaths([
    "RIPGREP_CONFIG_PATH",
    "CODEX_SECURITY_GIT",
  ]);
  const rawWindowsLookup =
    windows && [repo, ...args, ...Object.values(inherited)].some(rawToolValue);
  let denied: unknown;
  for (const command of trustedTools("rg", repo, root, rawWindowsLookup)) {
    try {
      return await collect(
        spawnInventoryTool(
          command,
          args,
          {
            cwd: repo,
            stdio: ["ignore", "pipe", "pipe"],
          },
          inherited,
          root,
        ),
      );
    } catch (error) {
      // POSIX PATH lookup continues if a candidate cannot be executed, including
      // a script whose interpreter is missing. Preserve actual tool exit statuses.
      const code = (error as NodeJS.ErrnoException).code;
      if (
        windows ||
        (code !== "ENOENT" && code !== "EACCES" && code !== "ENOTDIR")
      )
        throw error;
      if (code === "EACCES") denied = error;
    }
  }
  throw (
    denied ?? Object.assign(new Error("spawn rg ENOENT"), { code: "ENOENT" })
  );
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

const unavailableGit: ToolResult = {
  status: 127,
  signal: null,
  stdout: Buffer.alloc(0),
  stderr: "",
};

export async function git(repo: string, args: string[]) {
  try {
    const execution = gitProcess(repo, args);
    if (execution) {
      execution.child.stdin!.end();
      return await collect(execution);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return unavailableGit;
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
  if (result.status !== 0)
    throw new Error(
      result.stderr.trim() ||
        (result.signal
          ? `Git terminated by ${result.signal}`
          : `Git exited with status ${result.status}`),
    );
  return result.stdout;
}

export async function ignoredTrackedPaths(repo: string, scope: string) {
  try {
    const result = await git(repo, [
      "ls-files",
      "--cached",
      "--ignored",
      "--exclude-standard",
      "-z",
      "--",
      scope,
    ]);
    return result === unavailableGit ? [] : paths(requireSuccess(result));
  } catch (error) {
    throw new Error(
      `git ls-files: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
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
  renameSource?: string;
}
async function changed(repo: string, args: string[]): Promise<Change[]> {
  const result = await git(repo, [
    "diff",
    "--ignore-submodules=all",
    "--raw",
    "-z",
    "--diff-filter=ACMRDT",
    ...args,
    "--",
  ]);
  if (result.status !== 0 && result.stderr.trim()) {
    const detail = result.stderr
      .trim()
      .replace(
        /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/gu,
        (control) =>
          `\\u${control.charCodeAt(0).toString(16).padStart(4, "0")}`,
      );
    throw new Error(
      `Git diff failed with ${result.signal ?? `exit code ${result.status}`}: ${detail}`,
    );
  }
  const fields = paths(requireSuccess(result));
  const changes: Change[] = [];
  for (let index = 0; index < fields.length;) {
    const metadata = fields[index++]!.split(" "),
      status = metadata.at(-1)![0]!;
    const renameSource = status === "R" ? fields[index] : undefined;
    if (status === "C" || status === "R") index++;
    const path = fields[index++]!;
    if (
      (status === "D" ? metadata[0]!.slice(1) : metadata[1]!).startsWith("100")
    )
      changes.push({ path, status, renameSource });
  }
  return changes;
}
export async function changedPaths(
  repo: string,
  base: string,
  head: string,
  mode: string,
): Promise<Change[]> {
  if (mode === "revisions") return changed(repo, [`${base}..${head}`]);
  const unstaged = await changed(repo, [base]),
    staged = await changed(repo, ["--cached", base]);
  const result = new Map(staged.map((change) => [change.path, change]));
  for (const change of unstaged) result.set(change.path, change);
  function localStatus(path: string, status: string): string | undefined {
    if (path.split("/").some((part) => sourceMetadata.has(part))) return;
    if (status === "D") return status;
    const absolute = append(repo, path);
    try {
      if ((status === "M" || status === "R") && linkedParent(repo, absolute))
        return status === "M" ? "D" : undefined;
      return regular(absolute) ? status : undefined;
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
    }
  }

  const selected = new Map<string, string>();
  for (const { path, status, renameSource } of result.values()) {
    const chosen = localStatus(path, status);
    if (chosen) selected.set(path, chosen);
    else if (
      renameSource !== undefined &&
      !selected.has(renameSource) &&
      localStatus(renameSource, "D")
    )
      selected.set(renameSource, "D");
  }
  for (const path of paths(
    requireSuccess(
      await git(repo, ["ls-files", "--others", "--exclude-standard", "-z"]),
    ),
  ))
    if (!path.endsWith("/") && localStatus(path, "A")) selected.set(path, "A");
  return [...selected].map(([path, status]) => ({ path, status }));
}

/** Consume each complete blob while retaining at most the preview prefix. */
export async function blobSamples(
  repo: string,
  names: string[],
): Promise<([Buffer, boolean] | undefined)[]> {
  if (!names.length) return [];
  const nulInput = names.some((name) => /[\r\n]/u.test(name));
  const separator = nulInput ? "\0" : "\n";
  const child = gitProcess(repo, [
    "cat-file",
    "--batch",
    ...(nulInput ? ["-z"] : []),
  ])?.child as ChildProcessWithoutNullStreams | undefined;
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

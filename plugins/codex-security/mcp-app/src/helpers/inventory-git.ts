import {
  environmentValue,
  resolvedPathText as canonical,
} from "./helper-files";
import {
  spawn,
  type SpawnOptions,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import {
  basename,
  dirname,
  delimiter,
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";
import { createRequire } from "node:module";
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
  walk,
  windows,
} from "./inventory-paths";
import { createSourceSampler } from "./source-preview";

interface ToolResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: Buffer;
  stderr: string;
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

function trustedTool(name: "git" | "rg", target: string): string | undefined {
  let protectedRoot = canonical(target);
  for (const ancestor of ancestors(protectedRoot))
    if (exists(append(ancestor, ".git"))) protectedRoot = ancestor;
  const configured =
    name === "git" ? environmentValue("CODEX_SECURITY_GIT") : undefined;
  if (configured === "") return undefined;
  if (configured !== undefined && !isAbsolute(configured))
    throw new Error(
      "CODEX_SECURITY_GIT must name an absolute trusted executable.",
    );
  const candidates =
    configured !== undefined
      ? [configured]
      : (environmentValue("PATH") ?? (windows ? ".;C:\\bin" : "/usr/bin:/bin"))
          .split(delimiter)
          .flatMap((entry) =>
            (windows ? [`${name}.exe`, `${name}.com`] : [name]).map((name) =>
              append(windows ? entry.replace(/^"|"$/gu, "") : entry, name),
            ),
          );
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
    if (inRepository) {
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

function spawnTool(
  command: string,
  args: string[],
  options: SpawnOptions & {
    cwd?: string;
    stdio: ["ignore" | "pipe", "pipe", "pipe"];
  },
  inheritedEnvironment: Record<string, string>,
) {
  const raw = (value: string) =>
    (windows ? /[\ud800-\udfff]/u : /[\udc80-\udcff]/u).test(value);
  const environment = Object.fromEntries(
    Object.entries(inheritedEnvironment).filter(([, value]) => raw(value)),
  );
  const values = [
    command,
    ...args,
    ...(typeof options.cwd === "string" ? [options.cwd] : []),
    ...Object.values(environment),
  ];
  if (!values.some(raw)) return spawn(command, args, options);
  if (windows) {
    const binary = createRequire(import.meta.url).resolve(
      `./native/${nativeTarget}/windows.node`,
    );
    return spawnWindowsProcess(binary, command, args, options, environment);
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
    'exec "$@"',
  ].join("\n");
  return spawn("/bin/sh", ["-c", script], { ...options, cwd: undefined });
}

function inheritedToolPaths(additional: string[] = []): Record<string, string> {
  const keys = Object.keys(process.env).sort();
  const gitConfiguration = keys.filter((name) => {
    const key = windows ? name.toUpperCase() : name;
    return (
      [
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_PARAMETERS",
      ].includes(key) || /^GIT_CONFIG_VALUE_\d+$/u.test(key)
    );
  });
  return Object.fromEntries(
    [
      "HOME",
      "PATH",
      "XDG_CONFIG_HOME",
      ...additional,
      ...gitConfiguration,
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
  const command = trustedTool("git", repo);
  if (!command) return undefined;
  const env: NodeJS.ProcessEnv = { ...process.env };
  const inherited = inheritedToolPaths();
  for (const name of Object.keys(env)) {
    const key = windows ? name.toUpperCase() : name;
    if (repositoryEnvironment.includes(key) || key === "GIT_LITERAL_PATHSPECS")
      delete env[name];
  }
  env.GIT_LITERAL_PATHSPECS = "1";
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
  ) as ChildProcessWithoutNullStreams;
}

export async function runRipgrep(
  args: string[],
  repo: string,
): Promise<ToolResult> {
  const command = trustedTool("rg", repo);
  if (!command)
    throw Object.assign(new Error("spawn rg ENOENT"), { code: "ENOENT" });
  return runTool(command, args, repo);
}

export async function runTool(
  command: string,
  args: string[],
  cwd?: string,
  input?: Buffer,
): Promise<ToolResult> {
  const child = spawnTool(
    command,
    args,
    {
      cwd,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    },
    inheritedToolPaths(["RIPGREP_CONFIG_PATH", "CODEX_SECURITY_GIT"]),
  );
  child.stdin?.on("error", () => {});
  child.stdin?.end(input);
  return collect(child);
}

async function collect(child: ReturnType<typeof spawn>): Promise<ToolResult> {
  const stdout: Buffer[] = [],
    stderr: Buffer[] = [];
  child.stdout!.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr!.on("data", (chunk: Buffer) => stderr.push(chunk));
  await new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", () => resolve());
  });
  return {
    status: child.exitCode,
    signal: child.signalCode,
    stdout: Buffer.concat(stdout),
    stderr: Buffer.concat(stderr).toString("utf8"),
  };
}

export async function git(repo: string, args: string[]) {
  try {
    const child = gitProcess(repo, args);
    if (child) {
      child.stdin.end();
      return await collect(child);
    }
  } catch (error) {
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
  if (result.status !== 0)
    throw new Error(
      result.stderr.trim() ||
        (result.signal
          ? `Git terminated by ${result.signal}`
          : `Git exited with status ${result.status}`),
    );
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
      for (const child of nested ?? walk(path))
        if (!relative(path, child).split(sep).includes(".git"))
          found.add(child);
    }
  }
  return [...found];
}

export interface Change {
  path: string;
  status: string;
}
async function changed(repo: string, args: string[]): Promise<Change[]> {
  const fields = paths(
    requireSuccess(
      await git(repo, [
        "diff",
        "--ignore-submodules=all",
        "--raw",
        "-z",
        "--diff-filter=ACMRDT",
        ...args,
      ]),
    ),
  );
  const changes: Change[] = [];
  for (let index = 0; index < fields.length;) {
    const metadata = fields[index++]!.split(" "),
      status = metadata.at(-1)![0]!;
    if (status === "C" || status === "R") index++;
    const path = fields[index++]!;
    if (
      (status === "D" ? metadata[0]!.slice(1) : metadata[1]!).startsWith("100")
    )
      changes.push({ path, status });
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
  for (const path of paths(
    requireSuccess(
      await git(repo, ["ls-files", "--others", "--exclude-standard", "-z"]),
    ),
  ))
    if (!path.endsWith("/")) result.set(path, { path, status: "A" });
  return [...result.values()].filter(
    ({ path, status }) => status === "D" || regular(append(repo, path)),
  );
}

/** Consume each complete blob while retaining at most the preview prefix. */
export async function blobSamples(
  repo: string,
  names: string[],
): Promise<([Buffer, boolean] | undefined)[]> {
  if (!names.length) return [];
  const child = gitProcess(repo, ["cat-file", "--batch", "-z"]);
  if (!child) return names.map(() => undefined);
  const completion = new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => resolve(code ?? 1));
  });
  child.stderr.resume();
  child.stdin.on("error", () => {});
  child.stdin.end(encodeGitPath(names.join("\0") + "\0"));
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

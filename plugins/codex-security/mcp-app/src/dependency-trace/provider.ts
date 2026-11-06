import { spawn } from "node:child_process";
import { webcrypto } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  mkdtemp,
  open,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  extname,
  isAbsolute,
  join,
  matchesGlob,
  relative,
  resolve,
  sep,
} from "node:path";
import {
  isWithin,
  resolveTrustedExecutable,
  type TrustedExecutable,
} from "../trusted-executable.ts";
import { catalogEvidence, catalogNames, maxCatalogBytes } from "./catalog.ts";
import {
  dependencyEvidence,
  dependencyManifestGlob,
  isDependencyManifest,
} from "./dependencies.ts";
import type {
  TraceEvidence,
  TraceProvider,
  TraceScope,
  ScopeResult,
} from "./types.js";

const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_SOURCE_BYTES = 1024 * 1024;
const MAX_RECORDS = 64;
const PROJECT_CONFIG_GLOB =
  "{*.yaml,*.yml,*.json,*.toml,*.tf,*.hcl,BUILD,BUILD.bazel,*.bzl,Dockerfile,Dockerfile.*,*.Dockerfile,Containerfile,Containerfile.*}";
const MANIFEST_GLOB =
  "{package.json,package-lock.json,npm-shrinkwrap.json,pnpm-lock.yaml,yarn.lock,bun.lock,Cargo.toml,Cargo.lock,go.mod,go.sum,pyproject.toml,uv.lock,poetry.lock,Pipfile,Pipfile.lock,requirements*.txt,setup.cfg,setup.py,Dockerfile,*.Dockerfile,Containerfile,*.Containerfile,BUILD,BUILD.bazel,MODULE.bazel,MODULE.bazel.lock,WORKSPACE,WORKSPACE.bazel,*.bzl,Gemfile,Gemfile.lock,pom.xml,build.gradle,build.gradle.kts,gradle.lockfile}";
const identifier = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const languages: Record<string, string> = {
  ".py": "python",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
};

const sourceGlob = `{${Object.keys(languages)
  .map((ext) => "*" + ext)
  .join(",")}}`;

export function isTraceSourceFile(path: string): boolean {
  return Object.hasOwn(languages, extname(path));
}

function empty(reason: string): ScopeResult {
  return { evidence: [], next: [], complete: false, reason };
}

async function invoke(
  tool: TrustedExecutable,
  args: string[],
  cwd: string,
  signal: AbortSignal,
  mode?: "grep" | "list",
  input?: number,
): Promise<{ stdout: string; truncated: boolean }> {
  signal.throwIfAborted();
  const windows = process.platform === "win32";
  const child = spawn(tool.executable, args, {
    cwd,
    detached: !windows,
    stdio: [input ?? "ignore", "pipe", "pipe"],
    env: {
      ...tool.environment,
      SEMGREP_SEND_METRICS: "off",
      SEMGREP_ENABLE_VERSION_CHECK: "0",
      OPENGREP_ENABLE_VERSION_CHECK: "0",
    },
    windowsHide: true,
  });
  let stopping = false;
  function stop() {
    if (stopping || child.pid === undefined) return;
    stopping = true;
    // Some OpenGrep installations launch a separate native engine process.
    if (windows) {
      const taskkill = join(
        process.env.SystemRoot || "C:\\Windows",
        "System32",
        "taskkill.exe",
      );
      const killer = spawn(taskkill, ["/T", "/F", "/PID", String(child.pid)], {
        stdio: "ignore",
        windowsHide: true,
      });
      killer.once("error", () => child.kill());
      killer.once("close", (code) => {
        if (code !== 0) child.kill();
      });
    } else {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    }
  }
  const output: Buffer[] = [],
    errors: Buffer[] = [];
  let size = 0,
    truncated = false;
  function collect(chunks: Buffer[], chunk: Buffer) {
    if (truncated) return;
    const remaining = MAX_RESPONSE_BYTES - size;
    chunks.push(chunk.subarray(0, remaining));
    size += chunk.length;
    if (size > MAX_RESPONSE_BYTES) {
      truncated = true;
      stop();
    }
  }
  child.stdout!.on("data", (chunk: Buffer) => collect(output, chunk));
  child.stderr!.on("data", (chunk: Buffer) => collect(errors, chunk));
  signal.addEventListener("abort", stop, { once: true });
  try {
    const code = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    signal.throwIfAborted();
    if (truncated && !mode)
      throw new Error("OpenGrep response exceeded the byte limit.");
    if (!truncated && code !== 0 && !(mode === "grep" && code === 1))
      throw new Error(
        Buffer.concat(errors).toString().trim() ||
          `Tool exited with status ${code}.`,
      );
    return { stdout: Buffer.concat(output).toString(), truncated };
  } finally {
    signal.removeEventListener("abort", stop);
  }
}

function leaf(scope: TraceScope) {
  return scope.symbol?.split(/::|\./u).at(-1) || scope.package;
}

function fileAnalyzer(scope: TraceScope, path: string) {
  if (isDependencyManifest(path)) return "manifest";
  if (scope.symbol && isTraceSourceFile(path) && identifier.test(leaf(scope)))
    return "opengrep";
}

async function checkoutTarget(root: string, requested: string) {
  const canonicalRoot = await realpath(root);
  if (isAbsolute(requested))
    throw new Error("A checkout-relative scope is required.");
  const path = resolve(canonicalRoot, requested);
  if (!isWithin(canonicalRoot, path) || (await realpath(path)) !== path)
    throw new Error("Scope must be a non-symlink path in the checkout.");
  return { path, canonicalRoot };
}

// These are locations to inspect. A CI check and a service declaration can
// both reference the same project without identifying the same application.
export async function findProjectReferences(
  root: string,
  project: string,
  signal?: AbortSignal,
): Promise<{
  references: { path: string; line: number }[];
  complete: boolean;
  reason?: string;
}> {
  const timeout = AbortSignal.timeout(3000);
  const budget = signal ? AbortSignal.any([signal, timeout]) : timeout;
  const references: { path: string; line: number }[] = [];
  try {
    budget.throwIfAborted();
    const { canonicalRoot, path } = await checkoutTarget(root, project);
    if (path === canonicalRoot)
      throw new Error("Expected a project below the checkout root.");
    const needle = relative(canonicalRoot, path).split(sep).join("/");
    // ripgrep searches literally. Filter partial path components such as
    // "apps/mail-preview" for "apps/mail" before publishing candidate lines.
    const literal = needle.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    const component = new RegExp(
      "(?<![\\p{L}\\p{N}_.-])" + literal + "(?![\\p{L}\\p{N}_.-])",
      "u",
    );
    const rg = await resolveTrustedExecutable("rg", process.env, canonicalRoot);
    if (!rg) throw new Error("ripgrep is unavailable.");
    const { stdout, truncated } = await invoke(
      rg,
      [
        "--no-config",
        "--threads",
        "1",
        "--fixed-strings",
        "--json",
        "--hidden",
        "--type-add",
        `projectconfig:${PROJECT_CONFIG_GLOB}`,
        "--type",
        "projectconfig",
        "--glob",
        "!.git",
        "-e",
        needle,
        "--",
        canonicalRoot,
      ],
      tmpdir(),
      budget,
      "grep",
    );
    let reason = truncated
      ? "Project reference output exceeded the byte limit."
      : undefined;
    for (const row of stdout.split("\n").slice(0, -1)) {
      const { type, data } = JSON.parse(row);
      if (type !== "match") continue;
      if (
        typeof data.path.text !== "string" ||
        typeof data.lines.text !== "string"
      ) {
        reason ??= "A matching path or line was not UTF-8.";
        continue;
      }
      if (!component.test(data.lines.text)) continue;
      if (references.length === MAX_RECORDS) {
        reason = "Project reference limit reached.";
        break;
      }
      references.push({
        path: relative(canonicalRoot, data.path.text).split(sep).join("/"),
        line: data.line_number,
      });
    }
    return reason
      ? { references, complete: false, reason }
      : { references, complete: true };
  } catch (error) {
    signal?.throwIfAborted();
    return {
      references,
      complete: false,
      reason: timeout.aborted
        ? "Project reference search timed out."
        : (error instanceof Error ? error.message : String(error)).slice(
            0,
            500,
          ),
    };
  }
}

async function snapshot(path: string, maxBytes = MAX_SOURCE_BYTES) {
  const handle = await open(
    path,
    constants.O_RDONLY |
      (constants.O_NOFOLLOW ?? 0) |
      (constants.O_NONBLOCK ?? 0),
  );
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > maxBytes)
      throw new Error(
        "File exceeds the intrafile scope or is not a regular file.",
      );
    const contents = Buffer.alloc(metadata.size + 1);
    const { bytesRead } = await handle.read(contents);
    if (bytesRead !== metadata.size)
      throw new Error("File changed while reading.");
    return contents.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

// A finding is a syntactic candidate. A bare or member call can have a
// different binding; the report must establish package identity separately.
function rules(scope: TraceScope, language: string) {
  const name = leaf(scope);
  const pkg = scope.package;
  const calls: object[] = [
    { pattern: `${name}(...)` },
    { pattern: `$RECEIVER.${name}(...)` },
  ];
  if (
    language === "python" &&
    pkg.split(".").every((part) => identifier.test(part))
  ) {
    calls.push({ pattern: `${pkg}.${name}(...)` });
  } else if (language !== "python" && /^[@A-Za-z0-9._/-]+$/u.test(pkg)) {
    calls.push({
      patterns: [
        {
          "pattern-inside": `import {${name} as $ALIAS} from ${JSON.stringify(pkg)};\n...`,
        },
        { pattern: "$ALIAS(...)" },
      ],
    });
  }
  const match = { "pattern-either": calls };
  const context =
    language === "python"
      ? ["def $CALLER(...):\n  ..."]
      : [
          "function $CALLER(...) { ... }",
          "const $CALLER = (...) => ...",
          "class $CLASS { ... $CALLER(...) { ... } ... }",
        ];
  const base = {
    languages: [language],
    severity: "INFO",
    message: "Candidate call",
  };
  const withCaller = {
    patterns: [
      match,
      {
        "pattern-either": context.map((pattern) => ({
          "pattern-inside": pattern,
        })),
      },
    ],
  };
  if (scope.source_symbol) {
    return {
      rules: [
        {
          ...base,
          id: "flow",
          mode: "taint",
          message: "Candidate same-file flow",
          "pattern-sources": [
            { pattern: `${scope.source_symbol}(...)`, exact: true },
          ],
          // Disjoint sinks keep the enclosing caller when it is known, without
          // emitting a caller finding for every untainted call in the file.
          "pattern-sinks": [
            withCaller,
            {
              patterns: [
                match,
                ...context.map((pattern) => ({
                  "pattern-not-inside": pattern,
                })),
              ],
            },
          ],
        },
      ],
    };
  }
  return {
    rules: [
      { ...base, id: "call", ...match },
      { ...base, id: "caller", ...withCaller },
    ],
  };
}

// Keep repository configuration, filenames and ignore rules out of the native
// parser. The temporary input is exactly the bytes whose fingerprint we cache.
export function localProvider(root: string): TraceProvider {
  const tools = new Map<string, Promise<TrustedExecutable | null>>();
  function tool(name: string) {
    const existing = tools.get(name);
    if (existing) return existing;
    const found = resolveTrustedExecutable(name, process.env, root);
    tools.set(name, found);
    return found;
  }

  const target = (scope: TraceScope) => checkoutTarget(root, scope.path ?? ".");

  async function grep(
    args: string[],
    cwd: string,
    signal: AbortSignal,
    input?: number,
  ) {
    const rg = await tool("rg");
    if (!rg) throw new Error("ripgrep is unavailable.");
    return invoke(
      rg,
      ["--no-config", "--threads", "1", "--fixed-strings", ...args],
      cwd,
      signal,
      "grep",
      input,
    );
  }

  async function checkoutGit(checkout: string) {
    const metadata = await lstat(join(checkout, ".git")).catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
    if (!metadata) return undefined;
    const git = await tool("git");
    if (!git)
      throw new Error(
        "Git unavailable; tracked ignored files cannot be checked.",
      );
    const environment = Object.fromEntries(
      Object.entries(git.environment).filter(
        ([name]) => !name.toUpperCase().startsWith("GIT_"),
      ),
    );
    return { ...git, environment };
  }

  // Only probe siblings of files that matched this query. Most queries do not
  // have a catalog nearby and need no extra child process.
  async function adjacentCatalogs(
    files: Set<string>,
    checkout: string,
    git: TrustedExecutable | undefined,
    signal: AbortSignal,
  ) {
    const dirs = new Set(
      [...files]
        .filter((file) => !catalogNames.includes(basename(file)))
        .map((file) => dirname(file)),
    );
    const paths: string[] = [];
    for (const dir of dirs) {
      signal.throwIfAborted();
      for (const name of catalogNames) {
        const candidate = join(dir, name);
        if ((await lstat(candidate).catch(() => undefined))?.isFile())
          paths.push(candidate);
      }
    }
    if (!paths.length) return [];
    const toRelative = (file: string) =>
      relative(checkout, file).split(sep).join("/");
    // Keep ignored, untracked catalogs out of results just like source files.
    if (git) {
      const list = await invoke(
        git,
        [
          "--literal-pathspecs",
          "-c",
          "core.fsmonitor=false",
          "-C",
          checkout,
          "ls-files",
          "--cached",
          "--others",
          "--exclude-standard",
          "-z",
          "--",
          ...paths.map(toRelative),
        ],
        tmpdir(),
        signal,
        "list",
      );
      const visible = new Set(list.stdout.split("\0").slice(0, -1));
      return paths.map(toRelative).filter((file) => visible.has(file));
    }
    const rg = await tool("rg");
    if (!rg) return [];
    const list = await invoke(
      rg,
      [
        "--no-config",
        "--threads",
        "1",
        "--files",
        "--max-depth",
        "1",
        "--hidden",
        "--type-add",
        "catalog:catalog-info.{yaml,yml}",
        "--type",
        "catalog",
        "--null",
        "--",
        ...new Set(paths.map((file) => dirname(file))),
      ],
      tmpdir(),
      signal,
      "list",
    );
    const visible = new Set(list.stdout.split("\0").slice(0, -1));
    return paths.filter((file) => visible.has(file)).map(toRelative);
  }

  function trackedIgnoredFiles(
    git: TrustedExecutable,
    dir: string,
    checkout: string,
    signal: AbortSignal,
  ) {
    // Read only index metadata for the scope. Contents come from the worktree.
    return invoke(
      git,
      [
        "--no-pager",
        "--literal-pathspecs",
        "-c",
        "core.fsmonitor=false",
        "-C",
        checkout,
        "ls-files",
        "--cached",
        "--ignored",
        "--exclude-standard",
        "-z",
        "--",
        relative(checkout, dir) || ".",
      ],
      tmpdir(),
      signal,
      "list",
    );
  }

  async function findTrackedIgnored(
    list: Promise<{ stdout: string; truncated: boolean }>,
    dir: string,
    checkout: string,
    include: (filename: string) => boolean,
    needle: string,
    files: Set<string>,
    signal: AbortSignal,
  ) {
    const { stdout, truncated } = await list;
    const paths = stdout
      .split("\0")
      .slice(0, -1)
      .filter((name) => include(basename(name)));
    let reason =
      truncated || paths.length > MAX_RECORDS
        ? "Tracked ignored file limit reached; narrow the directory."
        : undefined;
    for (const name of paths.slice(0, MAX_RECORDS)) {
      signal.throwIfAborted();
      const path = resolve(checkout, name);
      if (files.has(path) || !isWithin(dir, path)) continue;
      try {
        if ((await realpath(path)) !== path) continue;
        const handle = await open(
          path,
          constants.O_RDONLY |
            (constants.O_NOFOLLOW ?? 0) |
            (constants.O_NONBLOCK ?? 0),
        );
        try {
          if (!(await handle.stat()).isFile()) continue;
          // Passing an open descriptor keeps ripgrep from following a replacement symlink.
          const match = await grep(
            ["--count", "--max-count", "1", "-e", needle, "--", "-"],
            tmpdir(),
            signal,
            handle.fd,
          );
          if (match.stdout.trim() === "1") files.add(path);
        } finally {
          await handle.close();
        }
      } catch (error) {
        signal.throwIfAborted();
        // Tracked files can be deleted locally before the index is updated.
        if ((error as NodeJS.ErrnoException).code !== "ENOENT")
          reason = "Could not check every tracked ignored file.";
      }
      if (files.size > MAX_RECORDS)
        return "Candidate file limit reached; narrow the directory.";
    }
    return reason;
  }

  let nativeVersion: string | undefined;
  const versionProbes = new WeakMap<AbortSignal, Promise<string | undefined>>();
  async function opengrepVersion(signal: AbortSignal) {
    if (nativeVersion) return nativeVersion;
    let probe = versionProbes.get(signal);
    if (!probe) {
      probe = (async () => {
        const executable = await tool("opengrep");
        if (!executable) return undefined;
        const { stdout } = await invoke(
          executable,
          ["--version"],
          tmpdir(),
          signal,
        );
        nativeVersion = JSON.stringify([executable.executable, stdout.trim()]);
        return nativeVersion;
      })();
      versionProbes.set(signal, probe);
    }
    return probe;
  }

  async function snapshotFingerprint(
    analyzer: "manifest" | "opengrep",
    contents: Uint8Array<ArrayBuffer>,
    signal: AbortSignal,
  ) {
    const versionKey =
      analyzer === "manifest"
        ? "manifest-declarations-v1"
        : await opengrepVersion(signal).catch(() => undefined);
    signal.throwIfAborted();
    if (!versionKey) return undefined;
    const digest = await webcrypto.subtle.digest("SHA-256", contents);
    // The scope key already contains the package, symbol, version and path.
    return JSON.stringify([
      "intrafile-rules-v3",
      versionKey,
      Buffer.from(digest).toString("hex"),
    ]);
  }

  return {
    async fingerprint(scope, signal) {
      if (scope.kind !== "file") return undefined;
      const { path } = await target(scope);
      const analyzer = fileAnalyzer(scope, path);
      if (!analyzer) return undefined;
      return snapshotFingerprint(analyzer, await snapshot(path), signal);
    },
    async run(scope, signal): Promise<ScopeResult> {
      try {
        signal.throwIfAborted();
        if (
          scope.source_symbol &&
          (!identifier.test(scope.source_symbol) || !scope.symbol)
        ) {
          return empty(
            "Same-file flow requires a source identifier and a sink symbol.",
          );
        }
        const { path, canonicalRoot } = await target(scope);
        if (scope.kind === "catalog") {
          if (!catalogNames.includes(basename(path)))
            return empty("Expected a catalog descriptor.");
          const contents = await snapshot(path, maxCatalogBytes);
          signal.throwIfAborted();
          return {
            evidence: catalogEvidence(
              contents.toString(),
              relative(canonicalRoot, path).split(sep).join("/"),
            ),
            next: [],
            complete: true,
          };
        }
        const needle = scope.kind === "manifests" ? scope.package : leaf(scope);
        if (scope.kind !== "file") {
          if (!(await stat(path)).isDirectory())
            return empty("Search scope must be a directory.");
          let gitGap: string | undefined;
          const git = await checkoutGit(canonicalRoot).catch((error: Error) => {
            gitGap = error.message;
            return undefined;
          });
          // An explicitly passed directory is traversed by rg even if its parent
          // ignores it. In that case only inspect the tracked files below it.
          let ignoredRoot = false;
          if (git && path !== canonicalRoot) {
            const ignored = await invoke(
              git,
              [
                "--no-pager",
                "-c",
                "core.fsmonitor=false",
                "-C",
                canonicalRoot,
                "check-ignore",
                "--no-index",
                "--",
                "./" + relative(canonicalRoot, path).split(sep).join("/"),
              ],
              tmpdir(),
              signal,
              "grep",
            ).catch((error: Error) => {
              signal.throwIfAborted();
              gitGap = error.message;
              return undefined;
            });
            ignoredRoot = Boolean(ignored?.stdout);
          }
          // A symbol search only scans supported source. Dependency discovery
          // reads known manifests and can point to imports in source files.
          const manifests = scope.kind === "manifests";
          const symbolSearch = !manifests && !!scope.symbol;
          const supported = !symbolSearch || identifier.test(needle);
          const structuralGlob = symbolSearch
            ? sourceGlob
            : dependencyManifestGlob;
          const isStructural = symbolSearch
            ? isTraceSourceFile
            : isDependencyManifest;
          const leadGlobs = manifests
            ? [MANIFEST_GLOB]
            : [MANIFEST_GLOB, sourceGlob];
          let ignoredFiles: ReturnType<typeof trackedIgnoredFiles> | undefined;
          async function matchingFiles(structural: boolean) {
            if (!structural && symbolSearch)
              return { files: new Set<string>() };
            const globs = structural ? [structuralGlob] : leadGlobs;
            const types = globs.flatMap((glob) => [
              "--type-add",
              `included:${glob}`,
            ]);
            types.push("--type", "included");
            if (!structural)
              types.push(
                "--type-add",
                `parsed:${structuralGlob}`,
                "--type-not",
                "parsed",
              );
            const { stdout, truncated } = ignoredRoot
              ? { stdout: "", truncated: false }
              : await grep(
                  [
                    "--files-with-matches",
                    "--null",
                    "--hidden",
                    ...(git ? ["--no-ignore-dot"] : []),
                    ...types,
                    "--glob",
                    "!.git",
                    "-e",
                    needle,
                    "--",
                    path,
                  ],
                  tmpdir(),
                  signal,
                );
            const matched = new Set(stdout.split("\0").slice(0, -1));
            const limit = structural
              ? "Candidate file limit reached; narrow the directory."
              : "Text match sample truncated.";
            let reason =
              truncated || matched.size > MAX_RECORDS ? limit : gitGap;
            if (git && !reason) {
              ignoredFiles ??= trackedIgnoredFiles(
                git,
                path,
                canonicalRoot,
                signal,
              );
              reason = await findTrackedIgnored(
                ignoredFiles,
                path,
                canonicalRoot,
                (name) =>
                  isStructural(name) === structural &&
                  (structural ||
                    matchesGlob(name, MANIFEST_GLOB) ||
                    (!manifests && isTraceSourceFile(name))),
                needle,
                matched,
                signal,
              ).catch((error: Error) => {
                signal.throwIfAborted();
                return (
                  "Tracked ignored file lookup failed: " +
                  error.message.slice(0, 500)
                );
              });
            }
            return {
              files: new Set([...matched].slice(0, MAX_RECORDS)),
              reason,
            };
          }
          const [scan, leads] = await Promise.all([
            matchingFiles(true),
            matchingFiles(false),
          ]);
          const files = scan.files;
          let reason = [
            ...(!supported
              ? ["OpenGrep call matching requires a supported identifier."]
              : []),
            scan.reason,
            leads.reason,
          ]
            .filter(Boolean)
            .join(" ");
          const checkoutPath = (file: string) =>
            relative(canonicalRoot, file).split(sep).join("/");
          const next = (supported ? [...files] : []).map(
            (file): TraceScope => ({
              ...scope,
              kind: "file",
              ...(scope.kind === "manifests"
                ? { symbol: undefined, source_symbol: undefined }
                : {}),
              path: checkoutPath(file),
            }),
          );
          if (next.length && next.length < MAX_RECORDS && !gitGap) {
            const catalogs = await adjacentCatalogs(
              files,
              canonicalRoot,
              git,
              signal,
            ).catch(() => {
              signal.throwIfAborted();
              return [];
            });
            for (const catalog of catalogs) {
              if (next.length === MAX_RECORDS) {
                reason ||=
                  "Candidate file limit reached; narrow the directory.";
                break;
              }
              next.push({
                kind: "catalog",
                package: scope.package,
                path: catalog,
              });
            }
          }
          const complete = !reason;
          return {
            evidence: [],
            textMatches: [...leads.files, ...files].map((file) => ({
              source: checkoutPath(file),
              text: needle,
            })),
            next,
            complete,
            ...(complete
              ? {}
              : {
                  reason,
                }),
          };
        }
        const analyzer = fileAnalyzer(scope, path);
        if (!analyzer)
          return empty(
            "Call and flow matching requires a supported source file and sink symbol.",
          );
        const contents = await snapshot(path);
        const file = relative(canonicalRoot, path).split(sep).join("/");
        if (analyzer === "manifest") {
          const evidence = dependencyEvidence(
            contents.toString("utf8"),
            file,
            scope.package,
          );
          const complete = evidence.length <= MAX_RECORDS;
          return {
            evidence: evidence.slice(0, MAX_RECORDS),
            next: [],
            complete,
            ...(complete
              ? {
                  fingerprint: await snapshotFingerprint(
                    analyzer,
                    contents,
                    signal,
                  ),
                }
              : { reason: "Dependency declaration limit reached." }),
          };
        }
        const opengrep = await tool("opengrep");
        if (!opengrep)
          return empty("OpenGrep is required for call and flow matching.");
        const directory = await mkdtemp(
          join(tmpdir(), "codex-security-trace-"),
        );
        try {
          const extension = extname(path);
          const language = languages[extension];
          const filename =
            extension === ".mts" || extension === ".cts"
              ? "input.ts"
              : `input${extension}`;
          await writeFile(join(directory, filename), contents);
          const fileEntity = { kind: "file", name: file };
          await writeFile(
            join(directory, "rules.json"),
            JSON.stringify(rules(scope, language)),
          );
          const { stdout } = await invoke(
            opengrep,
            [
              "scan",
              "--disable-version-check",
              "--jobs",
              "1",
              "--no-git-ignore",
              // Per-rule engine limit. Process RSS also includes the runtime.
              "--max-memory",
              "256",
              ...(scope.source_symbol ? ["--taint-intrafile"] : []),
              "--json",
              "-c",
              "rules.json",
              filename,
            ],
            directory,
            signal,
          );
          const output = JSON.parse(stdout) as {
            results: {
              check_id: string;
              start: { line: number; offset: number };
              extra: {
                metavars?: Record<string, { abstract_content: string }>;
              };
            }[];
            errors: unknown[];
            paths?: { scanned?: string[] };
          };
          const callers = new Map<number, string>();
          for (const finding of output.results) {
            const name = finding.extra.metavars?.["$CALLER"]?.abstract_content;
            if (name && identifier.test(name))
              callers.set(finding.start.offset, name);
          }
          const matches = output.results.filter(
            (finding) =>
              finding.check_id.split(".").at(-1) ===
              (scope.source_symbol ? "flow" : "call"),
          );
          const evidence: TraceEvidence[] = [];
          const callerNames = new Set<string>();
          for (const { start, extra } of matches.slice(0, MAX_RECORDS)) {
            const caller = callers.get(start.offset);
            const from = caller
              ? { kind: "symbol", name: caller, scope: file }
              : fileEntity;
            if (!scope.source_symbol && caller && caller !== needle)
              callerNames.add(caller);
            let calleeText = extra.metavars?.["$ALIAS"]?.abstract_content;
            if (calleeText === undefined && !extra.metavars?.["$RECEIVER"]) {
              // OpenGrep can match a bare Python import alias by its original
              // name. Read the identifier at the native match's byte offset.
              const paren = contents.indexOf("(", start.offset);
              if (paren !== -1) {
                const name = contents
                  .toString("utf8", start.offset, paren)
                  .trim();
                if (identifier.test(name)) calleeText = name;
              }
            }
            evidence.push({
              source: file,
              line: start.line,
              step: {
                from,
                relation: scope.source_symbol
                  ? "candidate_flow"
                  : "candidate_call",
                calleeText: calleeText ?? needle,
                ...(scope.source_symbol && { sourceText: scope.source_symbol }),
              },
            });
          }
          const next = [...callerNames].map((symbol) => ({ ...scope, symbol }));
          const scanned = output.paths?.scanned?.some(
            (scanned) =>
              resolve(directory, scanned) === join(directory, filename),
          );
          const reason = !scanned
            ? "OpenGrep skipped the file."
            : output.errors.length
              ? "OpenGrep reported incomplete analysis."
              : matches.length > MAX_RECORDS
                ? "Call-site limit reached."
                : undefined;
          return {
            evidence,
            next,
            complete: !reason,
            ...(reason
              ? { reason }
              : {
                  fingerprint: await snapshotFingerprint(
                    "opengrep",
                    contents,
                    signal,
                  ),
                }),
          };
        } finally {
          await rm(directory, { recursive: true, force: true });
        }
      } catch (error) {
        signal.throwIfAborted();
        const message = error instanceof Error ? error.message : String(error);
        // A native diagnostic can include an entire rejected source line.
        return empty(
          message.length > 1500 ? message.slice(0, 1500) + "…" : message,
        );
      }
    },
  };
}

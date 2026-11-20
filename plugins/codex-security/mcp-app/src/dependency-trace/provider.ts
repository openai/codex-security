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
  type FileHandle,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  extname,
  isAbsolute,
  join,
  matchesGlob,
  normalize,
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
import { configIdentity } from "./rule-config.ts";
import type { DiscoveryScope } from "./discovery-scope.ts";
import {
  dependencyEvidence,
  dependencyManifestGlob,
  isDependencyManifest,
} from "./dependencies.ts";
import type {
  TextMatch,
  TraceEvidence,
  TraceProvider,
  TraceScope,
  ScopeResult,
  RuleExecution,
} from "./types.js";

// Native tool output is processed before the separate model response pages.
const MAX_RESPONSE_BYTES = 2560 * 1024;
const MAX_SOURCE_BYTES = 1024 * 1024;
const SOURCE_BATCH_SIZE = 16;

class OpenGrepOutputLimitError extends Error {}
const PROJECT_CONFIG_GLOB =
  "{*.yaml,*.yml,*.json,*.toml,*.tf,*.hcl,BUILD,BUILD.bazel,*.bzl,Dockerfile,Dockerfile.*,*.Dockerfile,Containerfile,Containerfile.*}";
const MANIFEST_GLOB =
  "{package.json,package-lock.json,npm-shrinkwrap.json,pnpm-lock.yaml,yarn.lock,bun.lock,Cargo.toml,Cargo.lock,go.mod,go.sum,pyproject.toml,uv.lock,poetry.lock,Pipfile,Pipfile.lock,requirements*.txt,setup.cfg,setup.py,Dockerfile,*.Dockerfile,Containerfile,*.Containerfile,BUILD,BUILD.bazel,MODULE.bazel,MODULE.bazel.lock,WORKSPACE,WORKSPACE.bazel,*.bzl,Gemfile,Gemfile.lock,pom.xml,build.gradle,build.gradle.kts,gradle.lockfile}";
const identifier = /^[A-Za-z_][A-Za-z0-9_]*$/u;
const languages: Record<string, string> = {
  ".go": "go",
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

function nativeDiagnostics(stdout: string): string {
  try {
    const parsed = JSON.parse(stdout);
    if (Array.isArray(parsed?.errors) && parsed.errors.length > 0)
      return JSON.stringify(parsed.errors);
  } catch {
    /* Preserve non-JSON native diagnostics verbatim. */
  }
  return stdout;
}

async function invoke(
  tool: TrustedExecutable,
  args: string[],
  cwd: string,
  signal: AbortSignal,
  mode?: "grep" | "list" | "files",
  input?: number | number[] | FileHandle,
): Promise<{ stdout: string; truncated: boolean; stderr?: string }> {
  signal.throwIfAborted();
  const windows = process.platform === "win32";
  const fromStart =
    typeof input === "object" && !Array.isArray(input) ? input : undefined;
  const child = spawn(tool.executable, args, {
    cwd,
    detached: !windows,
    stdio: Array.isArray(input)
      ? ["ignore", "pipe", "pipe", ...input]
      : [
          fromStart ? "pipe" : typeof input === "number" ? input : "ignore",
          "pipe",
          "pipe",
        ],
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
    // Filename discovery feeds bounded source batches, not a model response.
    // Applying the diagnostic budget here would lose the rest of the files.
    if (chunks === output && (mode === "list" || mode === "files")) {
      chunks.push(chunk);
      return;
    }
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
  let source: ReturnType<FileHandle["createReadStream"]> | undefined;
  let inputError: Error | undefined;
  try {
    if (fromStart) {
      source = fromStart.createReadStream({ start: 0, autoClose: false });
      source.once("error", (error) => {
        inputError = error;
        stop();
      });
      child.stdin!.on("error", (error: NodeJS.ErrnoException) => {
        source?.destroy();
        // rg stops reading as soon as its first requested match is found.
        if (error.code !== "EPIPE") {
          inputError = error;
          stop();
        }
      });
      source.pipe(child.stdin!);
    }
    const code = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    signal.throwIfAborted();
    if (inputError) throw inputError;
    if (truncated && !mode)
      throw new OpenGrepOutputLimitError(
        "OpenGrep response exceeded the byte limit.",
      );
    if (
      !truncated &&
      code !== 0 &&
      !((mode === "grep" || mode === "files") && code === 1)
    )
      throw new Error(
        [
          Buffer.concat(errors).toString().trim(),
          ...(!mode
            ? [nativeDiagnostics(Buffer.concat(output).toString()).trim()]
            : []),
        ]
          .filter(Boolean)
          .join("\n") || `Tool exited with status ${code}.`,
      );
    return {
      stdout: Buffer.concat(output).toString(),
      truncated,
      ...(!mode ? { stderr: Buffer.concat(errors).toString() } : {}),
    };
  } finally {
    source?.destroy();
    signal.removeEventListener("abort", stop);
  }
}

function leaf(scope: TraceScope) {
  return scope.symbol?.split(/::|\./u).at(-1) || scope.package;
}

// Match both literals within the same file before scheduling source batches.
function sourceSearchPattern(symbol: string, terms: readonly string[]) {
  const operation = "\\b" + symbol + "\\b";
  const symbolPattern = new RegExp(operation, "u");
  const alternatives = terms.map((term) => {
    const literal = term.replace(/[.*+?^$(){}|[\]\\]/gu, "\\$&");
    if (symbol.includes(term)) return operation;
    if (symbolPattern.test(term)) return literal;
    return literal + ".*" + operation + "|" + operation + ".*" + literal;
  });
  return "(?s)(?:" + alternatives.join("|") + ")";
}

// An interpreter's static inline program is text to the outer parser.
function inlinePythonOperationLeads(
  file: string,
  contents: Buffer,
  symbol: string,
  terms: readonly string[],
  structuralLines: ReadonlySet<number>,
): TextMatch[] {
  if (!contents.includes("-c")) return [];
  const source = contents.toString("utf8");
  const literalStarts = new Set<number>();
  const scriptNames = new Set<string>();
  const launch =
    /(?:\bsys\.executable|(["'])python(?:3(?:\.\d+)?)?\1)\s*,\s*(["'])-c\2\s*,\s*/gu;
  const reference = /[A-Za-z_]\w*(?=\s*[,)\]])/uy;
  for (const match of source.matchAll(launch)) {
    const start = match.index + match[0].length;
    reference.lastIndex = start;
    const name = reference.exec(source)?.[0];
    if (name) scriptNames.add(name);
    else literalStarts.add(start);
  }
  if (scriptNames.size > 0) {
    const assignment = /^[ \t]*([A-Za-z_]\w*)[ \t]*=[ \t]*/gmu;
    for (const match of source.matchAll(assignment)) {
      if (scriptNames.has(match[1]))
        literalStarts.add(match.index + match[0].length);
    }
  }

  const literal = /[rRuU]?("""|''')(.*?)\1/suy;
  const operation = new RegExp("\\b" + symbol + "[ \\t]*\\(", "u");
  const lines = new Set<number>();
  for (const start of literalStarts) {
    literal.lastIndex = start;
    const match = literal.exec(source);
    const body = match?.[2];
    if (!match || !body || !terms.some((term) => body.includes(term))) continue;
    const bodyStart = start + match[0].length - body.length - match[1].length;
    const firstLine = source.slice(0, bodyStart).split("\n").length;
    for (const [offset, line] of body.split("\n").entries()) {
      const originalLine = firstLine + offset;
      if (
        !structuralLines.has(originalLine) &&
        !line.trimStart().startsWith("#") &&
        operation.test(line)
      ) {
        lines.add(originalLine);
      }
    }
  }
  return [...lines].map((line) => ({ source: file, line, text: symbol }));
}

function fileAnalyzer(scope: TraceScope, path: string) {
  if (isDependencyManifest(path)) return "manifest";
  if (scope.rules !== undefined) return "opengrep";
  if (isTraceSourceFile(path)) return "opengrep";
}

function sourceBatches(
  scope: TraceScope,
  files: readonly string[],
): TraceScope[] {
  const groups = new Map<string, string[]>();
  for (const file of [...new Set(files)].sort()) {
    const language = languages[extname(file)] ?? extname(file);
    let group = groups.get(language);
    if (!group) {
      group = [];
      groups.set(language, group);
    }
    group.push(file);
  }
  const scopes: TraceScope[] = [];
  for (const group of groups.values()) {
    for (let offset = 0; offset < group.length; offset += SOURCE_BATCH_SIZE) {
      scopes.push({
        ...scope,
        kind: "source_batch",
        files: group.slice(offset, offset + SOURCE_BATCH_SIZE),
      });
    }
  }
  return scopes;
}

export function sourceFileScopes(
  scope: TraceScope,
  files: readonly string[],
): TraceScope[] {
  const direct: TraceScope[] = [];
  const source: string[] = [];
  for (const file of files) {
    if (fileAnalyzer(scope, file) === "opengrep")
      source.push(normalize(file).split(sep).join("/"));
    else direct.push({ ...scope, kind: "file", path: file });
  }
  return [...direct, ...sourceBatches(scope, source)];
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

const MISSING_RULES =
  "OpenGrep call and flow analysis requires model-authored rules in the trace request.";

function executedConfig(scope: TraceScope) {
  if (!scope.rules?.length) throw new Error(MISSING_RULES);
  return { rules: scope.rules };
}

function taintIntrafile(scope: TraceScope) {
  return Boolean(
    scope.source_symbol || scope.rules?.some((rule) => rule.mode === "taint"),
  );
}

// Keep repository configuration, filenames and ignore rules out of the native
// parser. The temporary input is exactly the bytes whose fingerprint we cache.
export function localProvider(
  root: string,
  discoveryScope?: DiscoveryScope,
): TraceProvider {
  const tools = new Map<string, Promise<TrustedExecutable | null>>();
  let inheritedDescriptors = true;
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
    input?: number | number[] | FileHandle,
    mode: "grep" | "files" = "grep",
  ) {
    const rg = await tool("rg");
    if (!rg) throw new Error("ripgrep is unavailable.");
    return invoke(
      rg,
      ["--no-config", "--threads", "1", "--fixed-strings", ...args],
      cwd,
      signal,
      mode,
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
    searchArgs: string[],
    files: Set<string>,
    signal: AbortSignal,
  ) {
    const { stdout, truncated } = await list;
    const paths = stdout
      .split("\0")
      .slice(0, -1)
      .filter((name) => include(basename(name)));
    let reason = truncated
      ? "Tracked ignored file listing did not finish."
      : undefined;
    for (let offset = 0; offset < paths.length; offset += SOURCE_BATCH_SIZE) {
      const inputs: { path: string; handle: FileHandle }[] = [];
      try {
        for (const name of paths.slice(offset, offset + SOURCE_BATCH_SIZE)) {
          signal.throwIfAborted();
          const path = resolve(checkout, name);
          if (files.has(path) || !isWithin(dir, path)) continue;
          let handle: FileHandle | undefined;
          try {
            if ((await realpath(path)) !== path) continue;
            handle = await open(
              path,
              constants.O_RDONLY |
                (constants.O_NOFOLLOW ?? 0) |
                (constants.O_NONBLOCK ?? 0),
            );
            if (!(await handle.stat()).isFile()) continue;
            inputs.push({ path, handle });
            handle = undefined;
          } catch (error) {
            signal.throwIfAborted();
            // Tracked files can be deleted locally before the index is updated.
            if ((error as NodeJS.ErrnoException).code !== "ENOENT")
              reason = "Could not check every tracked ignored file.";
          } finally {
            await handle?.close();
          }
        }
        if (!inputs.length) continue;
        // Reuse the opened source: a launcher can consume its descriptor first.
        async function searchStdin(fromStart: boolean) {
          for (const { path, handle } of inputs) {
            const match = await grep(
              ["--count-matches", "--max-count", "1", ...searchArgs, "--", "-"],
              tmpdir(),
              signal,
              fromStart ? handle : handle.fd,
            );
            if (match.truncated)
              reason ??= "Tracked ignored file search did not finish.";
            if (Number(match.stdout.trim()) > 0) files.add(path);
          }
        }
        if (process.platform === "win32" || !inheritedDescriptors) {
          await searchStdin(process.platform !== "win32");
        } else {
          const names = inputs.map((_, index) => "/dev/fd/" + (index + 3));
          try {
            const match = await grep(
              ["--files-with-matches", "--null", ...searchArgs, "--", ...names],
              tmpdir(),
              signal,
              inputs.map(({ handle }) => handle.fd),
              "files",
            );
            if (match.truncated)
              reason ??= "Tracked ignored file search did not finish.";
            const found = new Set(match.stdout.split("\0").slice(0, -1));
            for (const [index, { path }] of inputs.entries())
              if (found.has(names[index])) files.add(path);
          } catch (error) {
            signal.throwIfAborted();
            if (
              !(error instanceof Error) ||
              !error.message
                .split("\n")
                .some(
                  (line) =>
                    (line.includes("Bad file descriptor (os error 9)") ||
                      line.includes(
                        "No such file or directory (os error 2)",
                      )) &&
                    names.some((name) => line.includes(name + ":")),
                )
            )
              throw error;
            // Some trusted launchers close additional inherited descriptors.
            inheritedDescriptors = false;
            await searchStdin(true);
          }
        }
      } finally {
        await Promise.all(inputs.map(({ handle }) => handle.close()));
      }
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
    scope?: TraceScope,
  ) {
    if (analyzer === "opengrep" && !scope?.rules?.length) return undefined;
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
      ...(analyzer === "opengrep"
        ? [
            configIdentity(executedConfig(scope!)).sha256,
            taintIntrafile(scope!),
          ]
        : []),
      Buffer.from(digest).toString("hex"),
    ]);
  }

  async function batchFingerprint(
    inputs: readonly { file: string; contents: Buffer<ArrayBuffer> }[],
    signal: AbortSignal,
    scope: TraceScope,
  ) {
    const fingerprints = await Promise.all(
      inputs.map(({ contents }) =>
        snapshotFingerprint("opengrep", contents, signal, scope),
      ),
    );
    return fingerprints.every((fingerprint) => fingerprint !== undefined)
      ? JSON.stringify(fingerprints)
      : undefined;
  }

  async function sourceSnapshot(file: string) {
    const { path } = await checkoutTarget(root, file);
    return snapshot(path);
  }

  async function scanCalls(
    scope: TraceScope,
    inputs: readonly { file: string; contents: Buffer<ArrayBuffer> }[],
    signal: AbortSignal,
  ): Promise<ScopeResult[]> {
    if (!scope.rules?.length) return inputs.map(() => empty(MISSING_RULES));
    const opengrep = await tool("opengrep");
    if (!opengrep)
      return inputs.map(() =>
        empty("OpenGrep is required for call and flow matching."),
      );
    const directory = await mkdtemp(join(tmpdir(), "codex-security-trace-"));
    let ruleExecution: RuleExecution | undefined;
    try {
      const language = languages[extname(inputs[0].file)];
      const config = executedConfig(scope);
      const identity = configIdentity(config);
      if (scope.rules !== undefined) {
        const engine = await opengrepVersion(signal);
        const taint = taintIntrafile(scope);
        ruleExecution = {
          id: configIdentity([identity.sha256, engine, taint]).sha256,
          configSha256: identity.sha256,
          config: JSON.parse(identity.text),
          engine: engine!,
          taintIntrafile: taint,
        };
      }
      const filenames = inputs.map(({ file }, index) => {
        const extension = extname(file);
        return (
          "input-" +
          index +
          (extension === ".mts" || extension === ".cts" ? ".ts" : extension)
        );
      });
      await Promise.all(
        inputs.map(({ contents }, index) =>
          writeFile(join(directory, filenames[index]), contents),
        ),
      );
      await writeFile(join(directory, "rules.json"), identity.text);
      const { stdout, stderr } = await invoke(
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
          ...(taintIntrafile(scope) ? ["--taint-intrafile"] : []),
          "--json",
          "-c",
          "rules.json",
          ...filenames,
        ],
        directory,
        signal,
      );
      const output = JSON.parse(stdout) as {
        results: {
          path: string;
          check_id: string;
          start: { line: number; col: number; offset: number };
          end: { line: number; col: number; offset: number };
          extra: {
            metadata?: Record<string, unknown>;
            metavars?: Record<string, { abstract_content: string }>;
          };
        }[];
        errors: unknown[];
        paths?: { scanned?: string[] };
      };
      const byFile = new Map<string, typeof output.results>();
      for (const finding of output.results) {
        const path = resolve(directory, finding.path);
        const previous = byFile.get(path);
        if (previous) previous.push(finding);
        else byFile.set(path, [finding]);
      }
      const scanned = new Set(
        output.paths?.scanned?.map((file) => resolve(directory, file)),
      );
      const needle = leaf(scope);
      return inputs.map(({ file, contents }, index) => {
        const path = join(directory, filenames[index]);
        const findings = byFile.get(path) ?? [];
        const fileEntity = { kind: "file", name: file };
        const callers = new Map<number, string>();
        for (const finding of findings) {
          const name = finding.extra.metavars?.["$CALLER"]?.abstract_content;
          if (name && identifier.test(name))
            callers.set(finding.start.offset, name);
        }
        const matches = findings;
        const evidence: TraceEvidence[] = [];
        const callerNames = new Set<string>();
        const ruleLeads: TextMatch[] = [];
        for (const { start, end, extra, check_id } of matches) {
          const provenance = ruleExecution
            ? { ruleExecutionId: ruleExecution.id, nativeRuleId: check_id }
            : {};
          if (
            scope.rules !== undefined &&
            extra.metadata?.evidence_kind === "unresolved_lead"
          ) {
            ruleLeads.push({
              source: file,
              line: start.line,
              text: contents.toString("utf8", start.offset, end.offset),
              ...provenance,
            });
            continue;
          }
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
            match: { start, end, ...provenance },
            step: {
              ...provenance,
              from,
              relation: scope.source_symbol
                ? "candidate_flow"
                : "candidate_call",
              calleeText: calleeText ?? needle,
              ...(scope.source_symbol && { sourceText: scope.source_symbol }),
            },
          });
        }
        const next = [...callerNames].map((symbol) => ({
          ...scope,
          symbol,
          ...(scope.rules === undefined ? {} : { rules: undefined }),
        }));
        const reason =
          [
            ...(!scanned.has(path) ? ["OpenGrep skipped a file."] : []),
            ...(output.errors.length
              ? [
                  "OpenGrep reported incomplete analysis: " +
                    JSON.stringify(output.errors),
                ]
              : []),
            ...((!scanned.has(path) || output.errors.length > 0) &&
            stderr?.trim()
              ? [stderr.trim()]
              : []),
          ].join(" ") || undefined;
        const textMatches = [
          ...ruleLeads,
          ...(language === "python" &&
          scope.source_terms &&
          !scope.source_symbol
            ? inlinePythonOperationLeads(
                file,
                contents,
                needle,
                scope.source_terms,
                new Set(matches.map(({ start }) => start.line)),
              )
            : []),
        ];
        return {
          ...(ruleExecution && { ruleExecution }),
          evidence,
          next,
          complete: !reason,
          ...(textMatches.length > 0 && { textMatches }),
          ...(reason && { reason }),
        };
      });
    } catch (error) {
      signal.throwIfAborted();
      if (!(error instanceof OpenGrepOutputLimitError)) {
        if (!ruleExecution) throw error;
        const message = error instanceof Error ? error.message : String(error);
        return inputs.map(() => ({
          ...empty(message),
          ruleExecution,
        }));
      }
      if (inputs.length === 1)
        return [
          { ...empty(error.message), ...(ruleExecution && { ruleExecution }) },
        ];
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
    // A dense file can exhaust the shared process output budget. Retain the
    // other files' results by splitting only the batch that overflowed.
    const midpoint = Math.floor(inputs.length / 2);
    return [
      ...(await scanCalls(scope, inputs.slice(0, midpoint), signal)),
      ...(await scanCalls(scope, inputs.slice(midpoint), signal)),
    ];
  }

  return {
    async fingerprint(scope, signal) {
      if (scope.kind === "source_batch") {
        if (!scope.rules?.length) return undefined;
        const inputs = await Promise.all(
          scope.files!.map(async (file) => ({
            file,
            contents: await sourceSnapshot(file),
          })),
        );
        return batchFingerprint(inputs, signal, scope);
      }
      if (scope.kind !== "file") return undefined;
      const { path } = await target(scope);
      const analyzer = fileAnalyzer(scope, path);
      if (!analyzer) return undefined;
      return snapshotFingerprint(analyzer, await snapshot(path), signal, scope);
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
        if (scope.kind === "source_batch") {
          const snapshots = await Promise.allSettled(
            scope.files!.map(async (file) => ({
              file,
              contents: await sourceSnapshot(file),
            })),
          );
          signal.throwIfAborted();
          const inputs = snapshots.flatMap((item) =>
            item.status === "fulfilled" ? [item.value] : [],
          );
          const unreadable = snapshots.flatMap((result) =>
            result.status === "rejected"
              ? [
                  result.reason instanceof Error
                    ? result.reason.message
                    : String(result.reason),
                ]
              : [],
          );
          if (!inputs.length)
            return empty(
              unreadable.join(" ") || "No source files could be read.",
            );
          const scanned = await scanCalls(scope, inputs, signal);
          const results = await Promise.all(
            inputs.map(async ({ file, contents }, index) => {
              const current = await sourceSnapshot(file).catch(() => undefined);
              return current?.equals(contents)
                ? scanned[index]
                : empty("Source changed during analysis.");
            }),
          );
          signal.throwIfAborted();
          const complete =
            inputs.length === snapshots.length &&
            results.every((result) => result.complete);
          const reasons = new Set(
            results.flatMap((result) => (result.reason ? [result.reason] : [])),
          );
          for (const reason of unreadable) reasons.add(reason);
          const textMatches = results.flatMap(
            (result) => result.textMatches ?? [],
          );
          return {
            ...(complete && {
              fingerprint: await batchFingerprint(inputs, signal, scope),
            }),
            ...(scanned.find((result) => result.ruleExecution)
              ?.ruleExecution && {
              ruleExecution: scanned.find((result) => result.ruleExecution)!
                .ruleExecution,
            }),
            evidence: results.flatMap((result) => result.evidence),
            ...(textMatches.length > 0 && { textMatches }),
            next: scope.source_terms
              ? []
              : results.flatMap((result, index) =>
                  result.next.map((next) => ({
                    ...next,
                    kind: "file" as const,
                    files: undefined,
                    path: inputs[index].file,
                  })),
                ),
            complete,
            ...(!complete && { reason: [...reasons].join(" ") }),
          };
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
          const supported =
            !symbolSearch ||
            scope.rules !== undefined ||
            identifier.test(needle);
          const terms =
            scope.kind === "search" && supported
              ? scope.source_terms
              : undefined;
          const searchArgs = terms
            ? [
                "--no-fixed-strings",
                "--multiline",
                "-e",
                sourceSearchPattern(needle, terms),
              ]
            : ["-e", needle];
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
                    ...(terms ? ["--sort", "path"] : []),
                    ...searchArgs,
                    "--",
                    path,
                  ],
                  tmpdir(),
                  signal,
                  undefined,
                  "files",
                );
            const matched = new Set(stdout.split("\0").slice(0, -1));
            let reason = truncated ? "File discovery did not finish." : gitGap;
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
                searchArgs,
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
              files: matched,
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
          const omissions =
            supported && discoveryScope
              ? discoveryScope.omit(
                  [...new Set([...files, ...leads.files])].map(checkoutPath),
                  symbolSearch,
                )
              : [];
          if (omissions.length) {
            const skipped = new Set(omissions.map((entry) => entry.path));
            for (const matches of [files, leads.files]) {
              for (const file of matches) {
                if (skipped.has(checkoutPath(file))) matches.delete(file);
              }
            }
          }
          const scopeCoverage = omissions.length ? { omissions } : {};
          if (terms) {
            const next = sourceBatches(scope, [...files].map(checkoutPath));
            return {
              evidence: [],
              next,
              complete: !reason,
              ...scopeCoverage,
              ...(reason && { reason }),
            };
          }
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
          if (next.length && !gitGap) {
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
            ...scopeCoverage,
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
          return {
            evidence,
            next: [],
            complete: true,
            fingerprint: await snapshotFingerprint(
              analyzer,
              contents,
              signal,
              scope,
            ),
          };
        }
        const [result] = await scanCalls(scope, [{ file, contents }], signal);
        return result.complete
          ? {
              ...result,
              fingerprint: await snapshotFingerprint(
                analyzer,
                contents,
                signal,
                scope,
              ),
            }
          : result;
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

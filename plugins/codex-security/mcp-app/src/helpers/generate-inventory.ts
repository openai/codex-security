import {
  environmentValue,
  isMissingPathError,
  normalizePath,
  resolvedPathText as canonical,
} from "./helper-files";
import { randomBytes } from "node:crypto";
import { renameSync, unlinkSync } from "node:fs";
import { dirname, isAbsolute, parse, posix, relative, sep } from "node:path";
import { parseArgs } from "node:util";
import { mkdir, readFile, writeFile } from "./helper-files";
import { expandHome, windowsFiles, windowsJoin } from "./resolve-security-md";
import { decodePosixBytes, encodePosixPath } from "./posix-path";
import { stringifyJson } from "./json";
import {
  compare,
  print,
  reportCommandError,
  ArgumentError,
} from "./rank-worklists";
import { decodeUtf8 } from "./utf8";
import {
  ancestors,
  append,
  directory,
  exists,
  fsPath,
  inside,
  linkedParent,
  lstat,
  regular,
  rejectStreams,
  sameFile,
  stat,
  sourceMetadata,
  walk,
  windows,
} from "./inventory-paths";
import {
  blobSamples,
  changedPaths,
  decodeGitPath,
  directoryPaths,
  encodeGitPath,
  git,
  runRipgrep,
} from "./inventory-git";
import { PREVIEW_BYTES, previewForBytes, sampleFile } from "./source-preview";
import {
  writeHostedOutput,
  writeHostedScopeInventory,
} from "./hosted-scope-inventory";

export type InventoryCommand =
  | "generate-in-scope-files"
  | "make-repo-scope-input"
  | "make-hosted-repo-scope-input"
  | "make-diff-rank-input";
export interface InventoryOptions {
  repo: string;
  out: string;
  scope?: string;
  scopesFile?: string;
  stateDir?: string;
  area?: string;
  previewBytes?: number;
  base?: string;
  head?: string;
  mode?: string;
}

function scopePath(
  repo: string,
  scope: string,
  home: string | undefined,
  explicit: boolean,
  rejectLinks: boolean,
): string {
  const requested = normalizePath(explicit ? scope : expandHome(scope, home));
  rejectStreams(requested);
  const requestedRoot = parse(requested).root;
  const path = windows
    ? append(
        windowsFiles()
          .absolute(Buffer.from(windowsJoin(repo, requestedRoot), "utf16le"))
          .toString("utf16le"),
        requested.slice(requestedRoot.length),
      )
    : isAbsolute(requested)
      ? requested
      : append(repo, requested);
  if (rejectLinks) {
    inside(repo, path);
    // Do not normalize away a link before checking link/.. scopes.
    let ancestor = repo;
    const lexical = path.slice(repo.length + (repo.endsWith(sep) ? 0 : 1));
    for (const part of lexical.split(windows ? /[\\/]/u : /\//u)) {
      if (!part || part === ".") continue;
      if (part === "..") {
        if (ancestor === repo)
          throw new Error(`Scope must be inside repo: ${path}`);
        ancestor = dirname(ancestor);
        continue;
      }
      ancestor = append(ancestor, part);
      const info = lstat(ancestor);
      if (
        info.isSymbolicLink() ||
        ("isNameSurrogate" in info && info.isNameSurrogate())
      )
        throw new Error(
          `Requested scope must not contain symbolic links: ${ancestor}`,
        );
    }
  }
  const resolved = canonical(path);
  inside(repo, resolved);
  if (!directory(resolved) && !regular(resolved))
    throw new Error(`Scope path not found: ${resolved}`);
  return resolved;
}

class RipgrepUnavailableError extends Error {}

interface ScopeFiles {
  paths: string[];
  failure?: Error;
}

function toolFailure(
  name: "Git" | "ripgrep",
  result: {
    status: number | null;
    signal: NodeJS.Signals | null;
    stderr: string;
  },
): Error {
  const detail = result.stderr.trim();
  return new Error(
    detail ||
      (result.signal
        ? `${name} terminated by ${result.signal}`
        : `${name} exited with status ${result.status}`),
  );
}

async function scopeRipgrep(
  repo: string,
  requested: string | string[],
  nonVcs = false,
  maxDepth?: number,
) {
  return runRipgrep(
    [
      "--files",
      "--null",
      "--hidden",
      "--path-separator",
      "/",
      ...(nonVcs ? ["--no-ignore-vcs"] : []),
      ...(maxDepth === undefined ? [] : ["--max-depth", String(maxDepth)]),
      "--glob",
      "!**/{.git,.svn}",
      "--glob",
      "!**/{.git,.svn}/**",
      "--",
      ...(Array.isArray(requested) ? requested : [requested]),
    ],
    repo,
  );
}

function rawRipgrepPaths(data: Buffer): Set<string> {
  const paths = new Set<string>();
  for (let start = 0; start < data.length;) {
    let end = data.indexOf(0, start);
    if (end < 0) end = data.length;
    let path = data.subarray(start, end);
    if (path[0] === 0x2e && path[1] === 0x2f) path = path.subarray(2);
    if (path.length) paths.add(path.toString("hex"));
    start = end + 1;
  }
  return paths;
}

function hasApplicableNonVcsRules(repo: string, path: string): boolean {
  if (environmentValue("RIPGREP_CONFIG_PATH")) return true;
  const parent = dirname(append(repo, path));
  return [...ancestors(parent)].some(
    (ancestor) =>
      statFile(append(ancestor, ".ignore")) ||
      statFile(append(ancestor, ".rgignore")),
  );
}

async function ripgrepScopeFiles(
  repo: string,
  requested: string,
  scope: string,
): Promise<ScopeFiles> {
  let result;
  try {
    result = await scopeRipgrep(repo, requested);
  } catch (error) {
    throw new RipgrepUnavailableError(
      `could not run ripgrep: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
  if (result.signal) throw toolFailure("ripgrep", result);
  let failure =
    result.status === 0 || result.status === 1
      ? undefined
      : toolFailure("ripgrep", result);
  const paths = decodePosixBytes(result.stdout).split("\0").filter(Boolean);
  const trackedRoot = directory(scope) ? scope : dirname(scope);
  if (
    [...ancestors(trackedRoot)].some((path) => exists(append(path, ".git")))
  ) {
    const owner = await git(trackedRoot, ["rev-parse", "--show-toplevel"]);
    if (owner.signal) throw toolFailure("Git", owner);
    const ownerRoot =
      owner.status === 0
        ? canonical(
            decodeGitPath(owner.stdout).replace(
              windows ? /\r?\n$/u : /\n$/u,
              "",
            ),
          )
        : undefined;
    const ownerScope = ownerRoot ? inside(ownerRoot, scope) : undefined;
    const tracked = ownerRoot
      ? await git(ownerRoot, [
          "ls-files",
          "--cached",
          "--ignored",
          "--exclude-standard",
          "-z",
          "--",
          ".",
        ])
      : undefined;
    if (tracked?.signal) throw toolFailure("Git", tracked);
    if (tracked?.status === 0 && ownerRoot) {
      const prefix =
        requested === "." || requested.startsWith("./") ? "./" : "";
      const candidates: string[] = [];
      const scopeDepth = ownerScope === "." ? 0 : ownerScope!.split("/").length;
      const scopeIsDirectory = directory(scope);
      const matchingPrefixes = new Map<string, boolean>();
      for (const path of decodeGitPath(tracked.stdout).split("\0")) {
        if (!path) continue;
        try {
          const parts = path.split("/");
          if (scopeIsDirectory) {
            if (parts.length <= scopeDepth) continue;
            if (scopeDepth) {
              const indexedPrefix = append(
                ownerRoot,
                parts.slice(0, scopeDepth).join(sep),
              );
              if (!matchingPrefixes.has(indexedPrefix))
                matchingPrefixes.set(
                  indexedPrefix,
                  sameFile(indexedPrefix, scope),
                );
              if (!matchingPrefixes.get(indexedPrefix)) continue;
            }
          }
          const absolute = append(ownerRoot, path);
          if (!scopeIsDirectory && !sameFile(absolute, scope)) continue;
          if (!regular(absolute)) continue;
          candidates.push(inside(repo, absolute));
        } catch (error) {
          failure ??= error instanceof Error ? error : new Error(String(error));
        }
      }
      if (candidates.length) {
        const filtered = new Set(
          candidates.filter((path) => hasApplicableNonVcsRules(repo, path)),
        );
        paths.push(
          ...candidates
            .filter((path) => !filtered.has(path))
            .map((path) => prefix + path),
        );
        if (filtered.size) {
          const allowed = await scopeRipgrep(
            repo,
            [...new Set([...filtered].map((path) => posix.dirname(path)))],
            true,
            1,
          );
          if (allowed.signal) throw toolFailure("ripgrep", allowed);
          if (allowed.status !== 0 && allowed.status !== 1)
            failure ??= toolFailure("ripgrep", allowed);
          const allowedPaths = rawRipgrepPaths(allowed.stdout);
          paths.push(
            ...[...filtered]
              .filter((path) =>
                allowedPaths.has(encodeGitPath(path).toString("hex")),
              )
              .map((path) => prefix + path),
          );
        }
      }
    } else if (tracked && tracked.status !== 127)
      failure ??= toolFailure("Git", tracked);
    else if (
      owner.status !== 0 &&
      owner.status !== 127 &&
      !/not a git repository/iu.test(owner.stderr)
    )
      failure ??= toolFailure("Git", owner);
  }
  return {
    paths,
    failure,
  };
}

function hasRipgrepOnlyRules(scope: string): boolean {
  if (environmentValue("RIPGREP_CONFIG_PATH")) return true;
  const names = new Set([".ignore", ".rgignore"]);
  for (const path of ancestors(scope)) {
    if ([...names].some((name) => statFile(append(path, name)))) return true;
  }
  for (const path of walk(scope, true, true)) {
    if (names.has(path.slice(path.lastIndexOf(sep) + 1)) && statFile(path))
      return true;
  }
  return false;
}

function statFile(path: string): boolean {
  try {
    return stat(path).isFile();
  } catch (error) {
    if (isMissingPathError(error)) return false;
    throw error;
  }
}

async function scopeCandidates(
  repo: string,
  scope: string,
): Promise<ScopeFiles> {
  if (regular(scope)) return { paths: [scope] };
  try {
    const result = await ripgrepScopeFiles(
      repo,
      relative(repo, scope) || ".",
      scope,
    );
    return {
      paths: result.paths.map((path) =>
        append(repo, path.startsWith("./") ? path.slice(2) : path),
      ),
      failure: result.failure,
    };
  } catch (error) {
    if (!(error instanceof RipgrepUnavailableError)) throw error;
    const indexed = await directoryPaths(scope);
    if (indexed !== undefined) {
      if (hasRipgrepOnlyRules(scope))
        throw new Error(
          "Could not safely enumerate ignored scoped files without Git or ripgrep.",
          { cause: error },
        );
      return { paths: indexed };
    }
    const ignoreNames = [".gitignore", ".ignore", ".rgignore"];
    let ignored =
      [...ancestors(repo)].some((path) => exists(append(path, ".git"))) ||
      [...ancestors(scope)].some((path) => {
        try {
          inside(repo, path);
        } catch {
          return false;
        }
        return ignoreNames.some((name) => statFile(append(path, name)));
      });
    const files: string[] = [];
    if (!ignored)
      for (const path of walk(scope, false, true)) {
        if (
          ignoreNames.some((name) => path.endsWith(sep + name)) &&
          statFile(path)
        ) {
          ignored = true;
          break;
        }
        files.push(path);
      }
    if (ignored)
      throw new Error(
        "Could not safely enumerate ignored scoped files without Git or ripgrep.",
      );
    return { paths: files };
  }
}

interface RequestedScopes {
  paths: string[];
  filePaths: Set<string>;
  firstMatchOnly: boolean;
  preserveKinds: boolean;
}

function loadScopes(path: string): RequestedScopes {
  let scopes: unknown;
  try {
    scopes = JSON.parse(decodeUtf8(readFile(path)));
  } catch {
    throw new Error(`Unable to read scopes file: ${path}`);
  }
  const paths = Array.isArray(scopes)
    ? scopes
    : scopes && typeof scopes === "object"
      ? (scopes as Record<string, unknown>).paths
      : undefined;
  const preserveKinds = Boolean(
    scopes &&
    !Array.isArray(scopes) &&
    typeof scopes === "object" &&
    Object.hasOwn(scopes, "filePaths"),
  );
  const filePaths = preserveKinds
    ? (scopes as Record<string, unknown>).filePaths
    : [];
  if (
    !Array.isArray(paths) ||
    !paths.length ||
    paths.some((scope: unknown) => typeof scope !== "string" || !scope) ||
    !Array.isArray(filePaths) ||
    filePaths.some(
      (scope: unknown) =>
        typeof scope !== "string" || !scope || !paths.includes(scope),
    )
  )
    throw new Error(
      `Scopes file must contain a non-empty JSON string array: ${path}`,
    );
  return {
    paths: paths as string[],
    filePaths: new Set(filePaths as string[]),
    firstMatchOnly: !Array.isArray(scopes),
    preserveKinds,
  };
}

function inventoryOutput(value: string): string {
  if (!value || value.includes("\0"))
    throw new Error("--out: expected an inventory file path");
  if (exists(value) && lstat(value).isSymbolicLink())
    throw new Error("--out: refusing to replace a symbolic link");
  const output = canonical(value, false);
  if (exists(output) && !regular(output))
    throw new Error(`--out: expected a regular file path: ${output}`);
  return output;
}

function replaceInventory(output: string, rows: Buffer[]): void {
  mkdir(dirname(output));
  const temporary = append(
    dirname(output),
    `.${randomBytes(12).toString("hex")}.tmp`,
  );
  try {
    writeFile(temporary, rows, true);
    if (windows)
      windowsFiles().rename(
        Buffer.from(temporary, "utf16le"),
        Buffer.from(output, "utf16le"),
      );
    else renameSync(fsPath(temporary), fsPath(output));
  } finally {
    if (exists(temporary)) {
      if (windows) windowsFiles().unlink(Buffer.from(temporary, "utf16le"));
      else unlinkSync(fsPath(temporary));
    }
  }
}

export async function generateInventory(
  command: InventoryCommand,
  options: InventoryOptions,
  home = environmentValue("HOME"),
): Promise<{ count: number; output: string }> {
  const repo = canonical(expandHome(options.repo, home));
  if (!directory(repo)) throw new Error(`Repo path not found: ${repo}`);
  const outputPath = expandHome(options.out, home),
    inventory = command === "generate-in-scope-files";
  const output = inventory ? inventoryOutput(outputPath) : outputPath;
  const rankRows = new Map<
    string,
    { path: string; area?: string; preview?: string }
  >();
  const inventoryRows: Buffer[] = [];
  const diff =
    command === "make-diff-rank-input" ||
    (inventory && options.base !== undefined);
  const scope = options.scope ?? ".";
  const resolveInventoryScope = () => {
    if (!scope || scope.includes("\0"))
      throw new Error("--scope: expected a non-empty file or directory");
    try {
      return scopePath(repo, scope, home, false, false);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.startsWith("Scope must be inside repo"))
        throw new Error(`--scope: path must remain inside --repo: ${scope}`);
      if (error instanceof Error && "code" in error)
        throw new Error(`--scope: path does not exist: ${scope}`);
      throw error;
    }
  };
  if (inventory && !diff) {
    const absolute = resolveInventoryScope();
    const requested = isAbsolute(expandHome(scope, home))
      ? inside(repo, absolute)
      : scope;
    const listed = await ripgrepScopeFiles(repo, requested, absolute);
    let listingFailure = listed.failure;
    for (const path of listed.paths) {
      const candidate = append(
        repo,
        path.startsWith("./") ? path.slice(2) : path,
      );
      try {
        if (directory(absolute) && linkedParent(absolute, candidate)) continue;
      } catch (error) {
        listingFailure ??=
          error instanceof Error ? error : new Error(String(error));
        continue;
      }
      if (path.split("/").some((part) => sourceMetadata.has(part))) continue;
      if (/[\r\n]/u.test(path))
        throw new Error(
          "Repository contains a path that cannot fit in the file inventory",
        );
      inventoryRows.push(encodeGitPath(path + "\n"));
    }
    if (inventoryRows.length === 0 && listingFailure) throw listingFailure;
  } else if (diff) {
    if (
      inventory &&
      ![".", "./"].includes(
        isAbsolute(expandHome(scope, home))
          ? inside(repo, scopePath(repo, scope, home, false, false))
          : scope,
      )
    )
      throw new Error("--scope: diff scans must use the repository root");
    const mode = options.mode ?? "revisions",
      base = options.base!,
      head = options.head ?? "HEAD";
    const changes = await changedPaths(repo, base, head, mode).catch(
      (error: unknown) => {
        if (inventory)
          throw new Error(
            `could not resolve the selected Git changes: ${error instanceof Error ? error.message : String(error)}`,
          );
        throw error;
      },
    );
    const refs = changes.filter(
      ({ status }) => mode === "revisions" || status === "D",
    );
    const samples = new Map(refs.map((change, index) => [change.path, index]));
    const blobs = await blobSamples(
      repo,
      refs.map(({ path, status }) => `${status === "D" ? base : head}:${path}`),
    );
    for (const { path, status } of changes) {
      let preview = "";
      if (samples.has(path)) {
        const sample = blobs[samples.get(path)!];
        if (!sample)
          throw new Error(
            `Unable to read committed diff blob: ${status === "D" ? base : head}:${path}`,
          );
        if (sample[1]) continue;
        if (!inventory && status !== "D")
          preview = previewForBytes(sample[0], options.previewBytes)[0];
      } else {
        const absolute = append(repo, path);
        if (!regular(absolute)) continue;
        let contained = true;
        try {
          inside(repo, canonical(absolute));
        } catch {
          if (inventory) continue;
          contained = false;
        }
        if (contained) {
          const [sample, binary] = sampleFile(absolute);
          if (binary) continue;
          if (!inventory)
            preview = previewForBytes(sample, options.previewBytes)[0];
        }
      }
      if (inventory) {
        const encoded = encodeGitPath(path);
        if (/[\r\n]/u.test(path))
          throw new Error(
            "Git changes contain a path that cannot fit in the file inventory",
          );
        inventoryRows.push(Buffer.concat([encoded, Buffer.from("\n")]));
      } else
        rankRows.set(path, { path, area: options.area ?? "diff", preview });
    }
  } else {
    const scopes = loadScopes(expandHome(options.scopesFile!, home));
    let listingFailure: unknown;
    selectedScopes: for (const value of scopes.paths) {
      try {
        const selected = scopePath(repo, value, home, true, true);
        if (
          scopes.firstMatchOnly &&
          scopes.preserveKinds &&
          scopes.filePaths.has(value) !== regular(selected)
        )
          continue;
        const candidates = await scopeCandidates(repo, selected);
        const previousSize = rankRows.size;
        for (const path of candidates.paths) {
          let name: string;
          try {
            if (directory(selected) && linkedParent(selected, path)) continue;
            if (!regular(path)) continue;
            name = inside(repo, canonical(path));
          } catch (error) {
            listingFailure ??= error;
            continue;
          }
          if (name.split("/").some((part) => sourceMetadata.has(part)))
            continue;
          rankRows.set(name, { path: name });
          if (scopes.firstMatchOnly) break selectedScopes;
        }
        if (rankRows.size === previousSize && candidates.failure)
          listingFailure ??= candidates.failure;
      } catch (error) {
        if (!scopes.firstMatchOnly) throw error;
        listingFailure ??= error;
      }
    }
    if (rankRows.size === 0 && listingFailure) throw listingFailure;
  }
  if (inventory) {
    const unique = [
      ...new Map(
        inventoryRows.map((row) => [row.toString("hex"), row]),
      ).values(),
    ].sort(Buffer.compare);
    replaceInventory(output, unique);
    return { count: unique.length, output };
  }
  const rows = [...rankRows.values()]
    .sort((left, right) => compare(left.path, right.path))
    .map((row) =>
      Buffer.from(
        stringifyJson(row, 0).replace(
          /[\u007f-\uffff]/g,
          (unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`,
        ) + (windows ? "\r\n" : "\n"),
      ),
    );
  if (command === "make-hosted-repo-scope-input") {
    if (options.stateDir !== undefined) {
      const hosted = writeHostedScopeInventory(
        expandHome(options.stateDir, home),
        expandHome(options.scopesFile!, home),
        repo,
        output,
        rows,
      );
      if (hosted !== undefined) return { count: rows.length, output: hosted };
    }
    if (windows) replaceInventory(output, rows);
    else writeHostedOutput(output, rows);
  } else {
    mkdir(dirname(output));
    writeFile(output, rows);
  }
  return { count: rows.length, output };
}

export async function inventoryCommand(
  command: InventoryCommand,
  args: string[],
  home = environmentValue("HOME"),
): Promise<number> {
  const inventory = command === "generate-in-scope-files",
    diff = command === "make-diff-rank-input",
    scoped = !inventory && !diff;
  const required = [
    "repo",
    "out",
    inventory ? "scope" : diff ? "base" : "scopes-file",
  ];
  const optional = inventory
    ? ["diff-base", "diff-head", "diff-mode"]
    : diff
      ? ["head", "mode", "area", "preview-bytes"]
      : [];
  if (command === "make-hosted-repo-scope-input") optional.push("state-dir");
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} ${required.map((name) => `--${name} VALUE`).join(" ")}`;
  try {
    let values: Record<string, string | boolean | undefined>;
    try {
      const normalizedArgs = args.flatMap((value, index) =>
        value === "--preview-bytes" && /^-\d+$/u.test(args[index + 1] ?? "")
          ? [`${value}=${args[index + 1]}`]
          : index > 0 &&
              args[index - 1] === "--preview-bytes" &&
              /^-\d+$/u.test(value)
            ? []
            : [value],
      );
      values = parseArgs({
        args: normalizedArgs,
        options: {
          ...Object.fromEntries(
            [...required, ...optional].map((name) => [
              name,
              { type: "string" as const },
            ]),
          ),
          help: { type: "boolean", short: "h" },
        },
      }).values;
      if (values.help) {
        print(
          `${usage}\n\nGenerate deterministic repository file inventories and bounded source previews.\n\n${[...required, ...optional].map((name) => `  --${name} VALUE`).join("\n")}

Directory scopes honor tool ignore rules; explicitly requested files are retained.
Defaults: scope=., head=HEAD, mode=revisions, preview-bytes=1024; area uses the scope or diff.`,
        );
        return 0;
      }
      if (required.some((name) => values[name] === undefined))
        throw new Error(
          `Missing required options: ${required
            .filter((name) => values[name] === undefined)
            .map((name) => `--${name}`)
            .join(", ")}`,
        );
      const mode = values["diff-mode"] ?? values.mode;
      if (mode !== undefined && mode !== "revisions" && mode !== "local-patch")
        throw new Error("mode must be revisions or local-patch");
      if (
        values["preview-bytes"] !== undefined &&
        !/^[+-]?\d+$/u.test(String(values["preview-bytes"]).trim())
      )
        throw new Error("--preview-bytes must be an integer");
    } catch (error) {
      throw new ArgumentError(
        error instanceof Error ? error.message : String(error),
      );
    }
    const { count, output } = await generateInventory(
      command,
      {
        repo: values.repo as string,
        out: values.out as string,
        scope: values.scope as string | undefined,
        scopesFile: values["scopes-file"] as string | undefined,
        stateDir: values["state-dir"] as string | undefined,
        area: values.area as string | undefined,
        previewBytes:
          values["preview-bytes"] === undefined
            ? PREVIEW_BYTES
            : Number(values["preview-bytes"]),
        base: (values["diff-base"] ?? values.base) as string | undefined,
        head: (values["diff-head"] ?? values.head) as string | undefined,
        mode: (values["diff-mode"] ?? values.mode) as string | undefined,
      },
      home,
    );
    print(
      inventory
        ? `Recorded ${count} in-scope files.`
        : `Wrote ${count} ${scoped ? "scoped paths" : "rows"} to ${output}`,
    );
    return 0;
  } catch (error) {
    const code = reportCommandError(error, command, usage);
    return inventory ? 2 : code;
  }
}

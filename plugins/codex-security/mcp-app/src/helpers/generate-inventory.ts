import {
  environmentValue,
  isMissingPathError,
  normalizePath,
  resolvedPathText as canonical,
} from "./helper-files";
import { randomBytes } from "node:crypto";
import { renameSync, unlinkSync } from "node:fs";
import { dirname, isAbsolute, parse, relative, sep } from "node:path";
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
  lstat,
  linkedParent,
  regular,
  sameFile,
  rejectStreams,
  stat,
  sourceMetadata,
  walk,
  windows,
} from "./inventory-paths";
import {
  blobSamples,
  changedPaths,
  configuredIgnoreFile,
  decodeGitPath,
  directoryPaths,
  directoryFilteringRoot,
  encodeGitPath,
  git,
  gitWorkingTree,
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

export function scopePath(
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

async function scopeCandidates(
  repo: string,
  scope: string,
  temporaryDirectory: string,
): Promise<string[]> {
  if (regular(scope)) return [scope];
  const diagnostics: string[] = [];
  const usable = (path: string) => {
    try {
      inside(scope, path);
    } catch {
      return false;
    }
    try {
      return !linkedParent(scope, path) && regular(path);
    } catch (error) {
      if (isMissingPathError(error)) return false;
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EACCES" || code === "EPERM") {
        diagnostics.push(
          error instanceof Error ? error.message : String(error),
        );
        return false;
      }
      throw error;
    }
  };
  const filteringRoot = await directoryFilteringRoot(scope);
  const configuredIgnore = await configuredIgnoreFile(repo);
  const searchRoot =
    configuredIgnore === undefined
      ? repo
      : ((await gitWorkingTree(repo)) ?? repo);
  let extraIgnore: string | undefined;
  if (configuredIgnore !== undefined && configuredIgnore !== "") {
    try {
      if (stat(configuredIgnore).isFile()) extraIgnore = configuredIgnore;
    } catch (error) {
      if (!isMissingPathError(error)) throw error;
    }
  }
  const finish = (paths: string[]) => {
    const selected = [
      ...new Set(paths.filter(usable).map((path) => canonical(path))),
    ];
    if (!selected.length && diagnostics.length)
      throw new Error(diagnostics.join("\n"));
    return selected;
  };
  let result;
  try {
    result = await runRipgrep(
      [
        "--files",
        "--hidden",
        "--no-require-git",
        ...(configuredIgnore === undefined ? [] : ["--no-ignore-global"]),
        ...(extraIgnore === undefined ? [] : ["--ignore-file", extraIgnore]),
        "--null",
        "--glob",
        "!**/{.git,.svn}",
        "--glob",
        "!**/{.git,.svn}/**",
        "--",
        relative(searchRoot, filteringRoot) || ".",
      ],
      searchRoot,
    );
  } catch {
    const isIgnoreFile = (path: string) => {
      try {
        return stat(path).isFile();
      } catch (error) {
        if (isMissingPathError(error)) return false;
        throw error;
      }
    };
    const dotRules = [".ignore", ".rgignore"];
    const inheritedRules = [...ancestors(scope)].some((parent) =>
      dotRules.some((name) => isIgnoreFile(append(parent, name))),
    );
    const indexed = await directoryPaths(scope, diagnostics);
    if (indexed !== undefined) {
      let unsupported = inheritedRules;
      const roots = [
        scope,
        ...indexed.filter((path) => {
          const info = lstat(path);
          return (
            info.isDirectory() &&
            !info.isSymbolicLink() &&
            !("isNameSurrogate" in info && info.isNameSurrogate()) &&
            exists(append(path, ".git"))
          );
        }),
      ];
      for (const root of roots) {
        const ignored = await git(root, [
          "--no-literal-pathspecs",
          "ls-files",
          "--cached",
          "--others",
          "--ignored",
          "--exclude-standard",
          "-z",
          "--",
          ":(literal).ignore",
          ":(literal).rgignore",
          ":(glob)**/.ignore",
          ":(glob)**/.rgignore",
        ]);
        const rules = [
          ...indexed.filter((path) =>
            dotRules.some((name) => path.endsWith(sep + name)),
          ),
          ...(ignored.status === 0
            ? decodeGitPath(ignored.stdout)
                .split("\0")
                .filter(Boolean)
                .map((path) => append(root, path))
            : []),
        ];
        for (const path of rules) {
          if (!isIgnoreFile(path)) continue;
          const parent = dirname(path);
          if (sameFile(parent, scope)) {
            unsupported = true;
            break;
          }
          const excluded = await git(root, [
            "--no-literal-pathspecs",
            "check-ignore",
            "--quiet",
            "--",
            parent,
          ]);
          if (excluded.status !== 0) {
            unsupported = true;
            break;
          }
        }
        if (unsupported) break;
      }
      if (unsupported)
        throw new Error(
          "Could not safely enumerate ignored scoped files without Git or ripgrep.",
        );
      return finish(indexed);
    }
    const ignoreNames = [".gitignore", ...dotRules];
    let ignored =
      inheritedRules ||
      [...ancestors(repo)].some((path) => exists(append(path, ".git"))) ||
      [...ancestors(scope)].some((parent) => {
        try {
          inside(repo, parent);
        } catch {
          return false;
        }
        return ignoreNames.some((name) => isIgnoreFile(append(parent, name)));
      });
    const errors: unknown[] = [];
    const files: string[] = [];
    if (!ignored)
      for (const path of walk(scope, true, true, errors)) {
        if (
          ignoreNames.some((name) => path.endsWith(sep + name)) &&
          isIgnoreFile(path)
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
    if (!files.some(usable) && errors.length) throw errors[0];
    return finish(files);
  }
  const failed = result.status !== 0 && result.status !== 1;
  if (failed && (result.status !== 2 || result.signal !== null))
    throw new Error(
      "Could not enumerate scoped repository files" +
        (result.signal ? " (" + result.signal + ")" : "") +
        ": " +
        result.stderr.trim(),
    );
  const selected = decodePosixBytes(result.stdout)
    .split("\0")
    .filter(Boolean)
    .map((path) => append(searchRoot, path));
  // Match the existing inventory command's override for Git-ignored tracked files.
  const ignoredTracked = new Map<string, string[]>();
  await directoryPaths(scope, diagnostics, ignoredTracked);
  selected.push(...(ignoredTracked.get(scope) ?? []));
  const candidates = new Set(
    [...ignoredTracked]
      .filter(([root]) => root !== scope)
      .flatMap(([, paths]) => paths)
      .filter(usable)
      .map((path) => canonical(path)),
  );
  if (candidates.size) {
    // Prune to indexed paths in a file, below native .ignore/.rgignore precedence.
    // This avoids entering unrelated Git-excluded subtrees or growing process argv.
    const rules = ["/*"],
      directories = new Set<string>();
    const literal = (path: string) => path.replace(/[\\*?\[]/gu, "\\$&");
    for (const path of candidates) {
      const parts = relative(searchRoot, path).split(sep);
      for (let index = 1; index < parts.length; index += 1) {
        const directory = literal(parts.slice(0, index).join("/"));
        if (directories.has(directory)) continue;
        directories.add(directory);
        rules.push(`!/${directory}/`, `/${directory}/*`);
      }
      rules.push(`!/${literal(parts.join("/"))}`);
    }
    const pruning = append(
      temporaryDirectory,
      `.inventory-${randomBytes(12).toString("hex")}.ignore`,
    );
    mkdir(temporaryDirectory);
    writeFile(pruning, [encodePosixPath(rules.join("\n") + "\n")], true);
    try {
      const tracked = await runRipgrep(
        [
          "--files",
          "--hidden",
          "--no-ignore-vcs",
          "--no-require-git",
          "--null",
          "--ignore-file",
          pruning,
          "--",
          ".",
        ],
        searchRoot,
      );
      if (tracked.status !== 0 && tracked.status !== 1)
        diagnostics.push(
          tracked.stderr.trim() || "Could not enumerate ignored tracked files",
        );
      selected.push(
        ...decodePosixBytes(tracked.stdout)
          .split("\0")
          .filter(Boolean)
          .map((path) => append(searchRoot, path))
          .filter((path) => candidates.has(canonical(path))),
      );
    } finally {
      if (windows) windowsFiles().unlink(Buffer.from(pruning, "utf16le"));
      else unlinkSync(fsPath(pruning));
    }
  }
  if (failed) {
    diagnostics.push(
      result.stderr.trim() ||
        "ripgrep could not finish enumerating the selected files",
    );
    if (!selected.some(usable)) throw new Error(diagnostics.join("\n"));
  }
  return finish(selected);
}

function loadScopes(path: string): string[] {
  let scopes: unknown;
  try {
    scopes = JSON.parse(decodeUtf8(readFile(path)));
  } catch {
    throw new Error(`Unable to read scopes file: ${path}`);
  }
  if (
    !Array.isArray(scopes) ||
    !scopes.length ||
    scopes.some((scope: unknown) => typeof scope !== "string" || !scope)
  )
    throw new Error(
      `Scopes file must contain a non-empty JSON string array: ${path}`,
    );
  return scopes as string[];
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
    const result = await runRipgrep(
      [
        "--files",
        "--null",
        "--hidden",
        "--path-separator",
        "/",
        "--glob",
        "!**/{.git,.svn}",
        "--glob",
        "!**/{.git,.svn}/**",
        "--",
        requested,
      ],
      repo,
    ).catch((error: unknown) => {
      throw new Error(
        `could not run ripgrep: ${error instanceof Error ? error.message : String(error)}`,
      );
    });
    if (result.status !== 0 && result.status !== 1)
      throw new Error(
        `ripgrep ${result.signal ? `terminated by ${result.signal}` : `exited with status ${result.status}`}${result.stderr.trim() ? `: ${result.stderr.trim()}` : ""}`,
      );
    let bytes = result.stdout;
    if ([...ancestors(repo)].some((path) => exists(append(path, ".git")))) {
      const tracked = await git(repo, [
        "ls-files",
        "--cached",
        "--ignored",
        "--exclude-standard",
        "-z",
        "--",
        requested,
      ]).catch((error: unknown) => {
        if (error instanceof Error && "code" in error)
          return { status: 127, stdout: Buffer.alloc(0) };
        throw error;
      });
      if (tracked.status === 0) {
        const prefix =
          requested === "." || requested.startsWith("./") ? "./" : "";
        const paths = decodeGitPath(tracked.stdout)
          .split("\0")
          .filter((path) => path && regular(append(repo, path)));
        bytes = Buffer.concat([
          bytes,
          encodeGitPath(paths.map((path) => prefix + path + "\0").join("")),
        ]);
      }
    }
    for (const path of decodePosixBytes(bytes).split("\0").filter(Boolean)) {
      if (path.split("/").some((part) => sourceMetadata.has(part))) continue;
      if (/[\r\n]/u.test(path))
        throw new Error(
          "Repository contains a path that cannot fit in the file inventory",
        );
      inventoryRows.push(encodePosixPath(path + "\n"));
    }
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
    const resolved = scopes.map((value) =>
      scopePath(repo, value, home, true, true),
    );
    for (const selected of resolved) {
      for (const path of await scopeCandidates(
        repo,
        selected,
        dirname(output),
      )) {
        let name: string;
        try {
          if (!regular(path)) continue;
          name = inside(repo, canonical(path));
        } catch {
          continue;
        }
        if (name.split("/").some((part) => sourceMetadata.has(part))) continue;
        rankRows.set(name, { path: name });
      }
    }
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

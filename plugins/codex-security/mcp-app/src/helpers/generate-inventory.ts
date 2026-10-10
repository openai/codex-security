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
import { isUtf8 } from "node:buffer";
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
  regular,
  rejectStreams,
  stat,
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

export type InventoryCommand =
  | "generate-in-scope-files"
  | "make-repo-rank-input"
  | "make-repo-scope-input"
  | "make-diff-rank-input";
export interface InventoryOptions {
  repo: string;
  out: string;
  scope?: string;
  scopesFile?: string;
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

async function scopeCandidates(repo: string, scope: string): Promise<string[]> {
  if (regular(scope)) return [scope];
  const indexed = await directoryPaths(scope);
  if (indexed !== undefined) return indexed;
  let result;
  try {
    result = await runRipgrep(
      [
        "--files",
        "--hidden",
        "--no-require-git",
        "--null",
        "--glob",
        "!**/.git",
        "--glob",
        "!**/.git/**",
        "--",
        relative(repo, scope) || ".",
      ],
      repo,
    );
    // The raw POSIX path bridge reports exec failures as shell statuses 126/127.
    if (!windows && (result.status === 126 || result.status === 127))
      throw new Error(result.stderr);
  } catch {
    const ignoreNames = [".gitignore", ".ignore", ".rgignore"];
    const isIgnoreFile = (path: string) => {
      try {
        return stat(path).isFile();
      } catch (error) {
        if (isMissingPathError(error)) return false;
        throw error;
      }
    };
    let ignored =
      [...ancestors(repo)].some((path) => exists(append(path, ".git"))) ||
      [...ancestors(scope)].some((path) => {
        try {
          inside(repo, path);
        } catch {
          return false;
        }
        return ignoreNames.some((name) => isIgnoreFile(append(path, name)));
      });
    const files: string[] = [];
    if (!ignored)
      for (const path of walk(scope)) {
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
    return files;
  }
  if (result.status !== 0 && result.status !== 1)
    throw new Error(
      `Could not enumerate scoped repository files${result.signal ? ` (${result.signal})` : ""}: ${result.stderr.trim()}`,
    );
  return decodePosixBytes(result.stdout)
    .split("\0")
    .filter(Boolean)
    .map((path) => append(repo, path));
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

function writeInventory(output: string, rows: Buffer[]): number {
  const unique = [
    ...new Map(rows.map((row) => [row.toString("hex"), row])).values(),
  ].sort(Buffer.compare);
  mkdir(dirname(output));
  const temporary = append(
    dirname(output),
    `.${randomBytes(12).toString("hex")}.tmp`,
  );
  try {
    writeFile(temporary, unique, true);
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
  return unique.length;
}

export async function generateInventory(
  command: InventoryCommand,
  options: InventoryOptions,
  home = environmentValue("HOME"),
): Promise<number> {
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
        "!**/.git",
        "--glob",
        "!**/.git/**",
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
    if (exists(append(repo, ".git"))) {
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
          contained = false;
        }
        if (contained || inventory) {
          const [sample, binary] = sampleFile(absolute);
          if (binary) continue;
          if (!inventory)
            preview = previewForBytes(sample, options.previewBytes)[0];
        }
      }
      if (inventory) {
        const encoded = encodePosixPath(path);
        if (!isUtf8(encoded))
          throw new Error(
            "Git changes contain a path that cannot be encoded as UTF-8 for the file inventory",
          );
        if (/[\r\n]/u.test(path))
          throw new Error(
            "Git changes contain a path that cannot fit in the file inventory",
          );
        inventoryRows.push(Buffer.concat([encoded, Buffer.from("\n")]));
      } else
        rankRows.set(path, { path, area: options.area ?? "diff", preview });
    }
  } else {
    const explicit = options.scopesFile !== undefined,
      scoped = command === "make-repo-scope-input";
    const scopes = explicit
      ? loadScopes(expandHome(options.scopesFile!, home))
      : [scope];
    const resolved = scopes.map((value) =>
      scopePath(repo, value, home, explicit, scoped),
    );
    const direct = new Set(explicit ? resolved.filter(regular) : []);
    for (const selected of resolved) {
      const area = options.area || inside(repo, selected);
      for (const path of await scopeCandidates(repo, selected)) {
        let name: string;
        try {
          if (!regular(path)) continue;
          const resolvedPath = canonical(path);
          inside(repo, resolvedPath);
          name = inside(repo, scoped ? resolvedPath : path);
        } catch {
          continue;
        }
        if (name.split("/").includes(".git") || rankRows.has(name)) continue;
        if (scoped) rankRows.set(name, { path: name });
        else {
          const [sample, binary] = sampleFile(path);
          if (binary && !direct.has(path)) continue;
          rankRows.set(name, {
            path: name,
            area,
            preview: binary
              ? ""
              : previewForBytes(sample, options.previewBytes)[0],
          });
        }
      }
    }
  }
  if (inventory) return writeInventory(output, inventoryRows);
  mkdir(dirname(output));
  writeFile(
    output,
    [...rankRows.values()]
      .sort((left, right) => compare(left.path, right.path))
      .map((row) =>
        Buffer.from(
          stringifyJson(row, 0).replace(
            /[\u007f-\uffff]/g,
            (unit) => `\\u${unit.charCodeAt(0).toString(16).padStart(4, "0")}`,
          ) + (windows ? "\r\n" : "\n"),
        ),
      ),
  );
  return rankRows.size;
}

export async function inventoryCommand(
  command: InventoryCommand,
  args: string[],
  home = environmentValue("HOME"),
): Promise<number> {
  const inventory = command === "generate-in-scope-files",
    diff = command === "make-diff-rank-input",
    scoped = command === "make-repo-scope-input";
  const required = [
    "repo",
    "out",
    ...(inventory
      ? ["scope"]
      : diff
        ? ["base"]
        : scoped
          ? ["scopes-file"]
          : []),
  ];
  const optional = inventory
    ? ["diff-base", "diff-head", "diff-mode"]
    : diff
      ? ["head", "mode", "area", "preview-bytes"]
      : scoped
        ? []
        : ["scope", "scopes-file", "area", "preview-bytes"];
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
    const count = await generateInventory(
      command,
      {
        repo: values.repo as string,
        out: values.out as string,
        scope: values.scope as string | undefined,
        scopesFile: values["scopes-file"] as string | undefined,
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
        : `Wrote ${count} ${scoped ? "scoped paths" : "rows"} to ${expandHome(values.out as string, home)}`,
    );
    return 0;
  } catch (error) {
    const code = reportCommandError(error, command, usage);
    return inventory ? 2 : code;
  }
}

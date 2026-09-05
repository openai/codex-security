import {
  closeSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  statSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, parse, sep } from "node:path";
import { parseArgs } from "node:util";
import { unixBinding, windowsBinding } from "../native";
import { windowsFileSystem } from "../../../native/windows-files.mjs";
import {
  decodePosixBytes,
  encodePosixPath,
  SymlinkLoopError,
  resolvePosixPath,
} from "./posix-path";

const MAX_SECURITY_MD_BYTES = 1024 * 1024;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
class HomeExpansionError extends Error {}
const windows = process.platform === "win32";
const windowsFiles = () => windowsFileSystem(windowsBinding());
const encodePath = (path: string) =>
  windows ? Buffer.from(path, "utf16le") : encodePosixPath(path);
const decodePath = (path: Buffer) =>
  windows ? path.toString("utf16le") : decodePosixBytes(path);
type FileInfo = Pick<Stats, "isDirectory" | "isFile" | "isSymbolicLink"> & {
  isReparsePoint?: () => boolean;
};
const statPath = (path: Buffer): FileInfo =>
  windows ? windowsFiles().stat(path) : statSync(path);

function windowsParts(value: string): [string, string, string] {
  const path = value.replaceAll("/", "\\");
  if (path.startsWith("\\\\")) {
    const start = path.slice(0, 8).toUpperCase() === "\\\\?\\UNC\\" ? 8 : 2;
    const server = path.indexOf("\\", start);
    const share = server === -1 ? -1 : path.indexOf("\\", server + 1);
    return share === -1
      ? [value, "", ""]
      : [value.slice(0, share), value[share]!, value.slice(share + 1)];
  }
  const drive = path[1] === ":" ? 2 : 0;
  const root = path[drive] === "\\" ? 1 : 0;
  return [
    value.slice(0, drive),
    value.slice(drive, drive + root),
    value.slice(drive + root),
  ];
}

function windowsJoin(left: string, right: string): string {
  const [leftDrive, leftRoot, leftPath] = windowsParts(left);
  const [rightDrive, rightRoot, rightPath] = windowsParts(right);
  if (rightRoot) return (rightDrive || leftDrive) + rightRoot + rightPath;
  if (rightDrive && rightDrive.toLowerCase() !== leftDrive.toLowerCase())
    return right;
  const drive = rightDrive || leftDrive;
  const path =
    leftPath + (leftPath && !/[/\\]$/u.test(leftPath) ? "\\" : "") + rightPath;
  const root =
    leftRoot || (path && drive && !/[:/\\]$/u.test(drive) ? "\\" : "");
  return drive + root + path;
}

function parsedPath(value: string): string {
  // pathlib removes empty and '.' components while preserving symlink/.. pairs.
  let root = windows
    ? windowsParts(value).slice(0, 2).join("").replaceAll("/", "\\")
    : value.startsWith("//") && !value.startsWith("///")
      ? "//"
      : parse(value).root;
  if (windows && root.startsWith("\\\\") && !root.endsWith("\\")) {
    const parts = root.split("\\");
    if ((parts.length === 4 && !"?.".includes(parts[2]!)) || parts.length === 6)
      root += "\\";
  }
  const parts = value
    .slice(root.length)
    .split(process.platform === "win32" ? /[/\\]/u : /\//u)
    .filter((part) => part !== "" && part !== ".");
  if (windows && !root && windowsParts(parts[0] ?? "")[0]) parts.unshift(".");
  return root + parts.join(sep) || ".";
}

function resolvedPath(path: Buffer): Buffer {
  if (process.platform !== "win32") return resolvePosixPath(path);
  try {
    return windowsFiles().realpath(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP")
      throw new SymlinkLoopError(`Symlink loop from ${decodePath(path)}`);
    throw error;
  }
}

function expandHome(path: string, posixHome: string | undefined): string {
  if (!path.startsWith("~")) return path;
  if (process.platform === "win32") {
    const environment = (name: string) =>
      windowsBinding()
        .windowsEnvironment(Buffer.from(name, "utf16le"))
        ?.toString("utf16le");
    const separator = path.search(/[/\\]/u);
    const end = separator === -1 ? path.length : separator;
    const username = path.slice(1, end);
    const currentUsername = environment("USERNAME");
    let home = environment("USERPROFILE");
    const homePath = environment("HOMEPATH");
    if (home === undefined && homePath !== undefined) {
      home = windowsJoin(environment("HOMEDRIVE") ?? "", homePath);
    }
    if (home === undefined)
      throw new HomeExpansionError("Could not determine home directory.");
    if (username !== "" && username !== currentUsername) {
      const [drive, root, tail] = windowsParts(home);
      const separator = Math.max(tail.lastIndexOf("/"), tail.lastIndexOf("\\"));
      if (currentUsername !== tail.slice(separator + 1)) {
        throw new HomeExpansionError("Could not determine home directory.");
      }
      const parent =
        drive + root + tail.slice(0, separator + 1).replace(/[/\\]+$/u, "");
      home = windowsJoin(parent, username);
    }
    if (home.startsWith("~"))
      throw new HomeExpansionError("Could not determine home directory.");
    return windowsJoin(home, separator === -1 ? "" : path.slice(end + 1));
  }
  if (path === "~" || path.startsWith("~/")) {
    const home = posixHome ?? homedir();
    if (home.startsWith("~"))
      throw new HomeExpansionError("Could not determine home directory.");
    return home + path.slice(1) || "/";
  }
  const separator = path.indexOf("/");
  const end = separator === -1 ? path.length : separator;
  const result = unixBinding().userHome(encodePosixPath(path.slice(1, end)));
  if (result.value === null)
    throw new HomeExpansionError("Could not determine home directory.");
  const home = decodePosixBytes(result.value).replace(/\/+$/u, "");
  if (home.startsWith("~"))
    throw new HomeExpansionError("Could not determine home directory.");
  return home + path.slice(end) || "/";
}

function appendPath(directory: Buffer, name: Buffer): Buffer {
  const separator = encodePath(sep);
  return Buffer.concat(
    directory.subarray(-separator.length).equals(separator)
      ? [directory, name]
      : [directory, separator, name],
  );
}

function parentDirectory(path: Buffer): Buffer {
  if (process.platform === "win32")
    return encodePath(dirname(decodePath(path)));
  const separator = path.lastIndexOf(0x2f);
  return separator === -1
    ? Buffer.from(".")
    : path.subarray(0, Math.max(1, separator));
}

// Both paths are already canonical absolute Windows paths.
export function windowsRelativePath(path: string, root: string) {
  const parts = (value: string) => value.replace(/\\+$/u, "").split("\\");
  const parent = parts(root);
  const target = parts(path);
  return parent.every(
    (part, index) => part.toLowerCase() === target[index]?.toLowerCase(),
  )
    ? target.slice(parent.length).join("\\")
    : undefined;
}

function inside(path: Buffer, root: Buffer, label: string): Buffer {
  if (process.platform === "win32") {
    const result = windowsRelativePath(decodePath(path), decodePath(root));
    if (result !== undefined) return encodePath(result);
  } else {
    if (path.equals(root)) return Buffer.alloc(0);
    const prefix = appendPath(root, Buffer.alloc(0));
    if (path.subarray(0, prefix.length).equals(prefix)) {
      return path.subarray(prefix.length);
    }
  }
  throw new Error(`${label} is outside the scan root: ${decodePath(path)}`);
}

function resolveRoot(repo: string, posixHome: string | undefined): Buffer {
  let root: Buffer;
  try {
    root = resolvedPath(encodePath(parsedPath(expandHome(repo, posixHome))));
  } catch (error) {
    if (
      error instanceof SymlinkLoopError ||
      error instanceof HomeExpansionError
    )
      throw error;
    throw new Error(`scan root does not exist: ${repo}`);
  }
  if (!statPath(root).isDirectory()) {
    throw new Error(`scan root is not a directory: ${decodePath(root)}`);
  }
  return root;
}

function fileStat(path: Buffer): FileInfo | undefined {
  try {
    return statPath(path);
  } catch (error) {
    if (
      ["ENOENT", "ENOTDIR", "ELOOP"].includes(
        (error as NodeJS.ErrnoException).code ?? "",
      ) ||
      (windows &&
        [21, 123].includes((error as { winerror?: number }).winerror ?? 0))
    ) {
      return undefined;
    }
    throw error;
  }
}

function asciiJson(value: string): string {
  return JSON.stringify(value).replace(
    /[\u007f-\uffff]/g,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

function comparePaths(left: string, right: string): number {
  let leftIndex = 0;
  let rightIndex = 0;
  while (leftIndex < left.length && rightIndex < right.length) {
    const leftPoint = left.codePointAt(leftIndex)!;
    const rightPoint = right.codePointAt(rightIndex)!;
    if (leftPoint !== rightPoint) return leftPoint - rightPoint;
    leftIndex += leftPoint > 0xffff ? 2 : 1;
    rightIndex += rightPoint > 0xffff ? 2 : 1;
  }
  return left.length - right.length;
}

function listSecurityMd(repo: string, posixHome: string | undefined): string[] {
  const root = resolveRoot(repo, posixHome);
  const policies: string[] = [];
  function walk(directory: Buffer, prefix: string): void {
    const entries = (
      windows
        ? windowsFiles().entriesWithTypes(directory)
        : readdirSync(directory, { encoding: "buffer", withFileTypes: true })
    ).map((entry) => ({
      bytes: entry.name,
      name: decodePath(entry.name),
      entry,
    }));
    entries.sort((left, right) => comparePaths(left.name, right.name));
    for (const { bytes, name, entry: listedEntry } of entries) {
      if (name === ".git") continue;
      const path = appendPath(directory, bytes);
      const source = prefix === "" ? name : `${prefix}/${name}`;
      const listedDirectory =
        listedEntry.isDirectory() && !listedEntry.isSymbolicLink();
      if (!listedDirectory && name !== "SECURITY.md") continue;
      let entry: FileInfo | undefined;
      try {
        entry = windows
          ? windowsFiles().stat(path, false)
          : lstatSync(path, { throwIfNoEntry: listedDirectory });
      } catch (error) {
        if (
          listedDirectory ||
          !["ENOENT", "ENOTDIR"].includes(
            (error as NodeJS.ErrnoException).code ?? "",
          )
        )
          throw error;
      }
      if (entry === undefined) continue;
      if (listedDirectory && !entry.isDirectory()) continue;
      if (entry.isDirectory()) {
        if (!entry.isReparsePoint?.()) walk(path, source);
      } else if (
        name === "SECURITY.md" &&
        (entry.isFile() || entry.isSymbolicLink())
      ) {
        // Directory links, including junctions named SECURITY.md, are not policies.
        if (entry.isSymbolicLink() && fileStat(path)?.isDirectory()) continue;
        policies.push(source);
      }
    }
  }
  walk(root, "");
  return policies.sort(comparePaths);
}

function readPolicy(path: Buffer, displayedPath: Buffer): string {
  const buffer = Buffer.alloc(MAX_SECURITY_MD_BYTES + 1);
  let length = 0;
  if (windows) {
    length = windowsFiles().readInto(path, buffer);
  } else {
    const file = openSync(path, "r");
    try {
      while (length < buffer.length) {
        const count = readSync(
          file,
          buffer,
          length,
          buffer.length - length,
          null,
        );
        if (count === 0) break;
        length += count;
      }
    } finally {
      closeSync(file);
    }
  }
  if (length > MAX_SECURITY_MD_BYTES) {
    throw new Error(`SECURITY.md exceeds 1 MiB: ${decodePath(displayedPath)}`);
  }
  try {
    return utf8.decode(buffer.subarray(0, length));
  } catch {
    throw new Error(
      `SECURITY.md is not valid UTF-8: ${decodePath(displayedPath)}`,
    );
  }
}

function resolveSecurityMd(
  repo: string,
  scope: string,
  posixHome: string | undefined,
): string {
  const root = resolveRoot(repo, posixHome);
  const expandedScope = parsedPath(expandHome(scope, posixHome));
  const requestedScope =
    process.platform === "win32"
      ? windowsFiles().absolute(
          encodePath(windowsJoin(decodePath(root), expandedScope)),
        )
      : expandedScope.startsWith("/")
        ? encodePosixPath(expandedScope)
        : appendPath(root, encodePosixPath(expandedScope));
  let resolvedScope: Buffer;
  try {
    // Resolve links before '..', including Python's accepted file/.. paths.
    resolvedScope = resolvedPath(requestedScope);
  } catch (error) {
    if (error instanceof SymlinkLoopError) throw error;
    throw new Error(`scan scope does not exist: ${decodePath(requestedScope)}`);
  }
  inside(resolvedScope, root, "scan scope");
  const targetDirectory = statPath(resolvedScope).isDirectory()
    ? resolvedScope
    : parentDirectory(resolvedScope);
  const directories = [targetDirectory];
  let current = targetDirectory;
  while (inside(current, root, "scan scope").length !== 0) {
    current = parentDirectory(current);
    directories.unshift(current);
  }

  const sections: string[] = [];
  for (const directory of directories) {
    const policy = appendPath(directory, encodePath("SECURITY.md"));
    if (!fileStat(policy)?.isFile()) continue;
    const resolvedPolicy = resolvedPath(policy);
    inside(resolvedPolicy, root, "SECURITY.md");
    const content = readPolicy(resolvedPolicy, policy);
    // Match Python's whitespace-only guidance without discarding a UTF-8 BOM.
    if (/^[\p{White_Space}\u001c-\u001f]*$/u.test(content)) continue;
    const source = decodePath(inside(policy, root, "SECURITY.md"))
      .split(sep)
      .join("/");
    let section = `## SECURITY.md source: ${asciiJson(source)}\n\n${content}`;
    if (!section.endsWith("\n")) section += "\n";
    sections.push(section);
  }
  return sections.join("\n");
}

export function resolveSecurityMdCommand(
  args: string[],
  posixHome = process.env.HOME,
): number {
  try {
    const options = {
      repo: { type: "string" },
      list: { type: "boolean" },
      scope: { type: "string" },
      out: { type: "string", default: "-" },
      help: { type: "boolean", short: "h" },
    } as const;
    const names = Object.keys(options) as (keyof typeof options)[];
    let parsedArgs: string[] = [];
    for (let index = 0; index < args.length; index++) {
      let arg = args[index]!;
      if (arg === "--") throw new Error("Unexpected argument '--'");
      if (arg.startsWith("-h")) {
        if (/^-h+-/u.test(arg)) throw new Error(`Unexpected argument '${arg}'`);
        if (/^-h+=/u.test(arg)) parseArgs({ args: [arg], options });
        arg = "--help";
      }
      if (arg.startsWith("--") && arg !== "--") {
        const equals = arg.indexOf("=");
        const name = arg.slice(2, equals === -1 ? undefined : equals);
        const matches = names.filter((option) => option.startsWith(name));
        const option = matches.length === 1 ? matches[0] : undefined;
        if (option !== undefined) {
          // argparse accepts unique long-option prefixes.
          arg = `--${option}${equals === -1 ? "" : arg.slice(equals)}`;
          const next = args[index + 1];
          if (
            equals === -1 &&
            options[option].type === "string" &&
            next !== undefined
          ) {
            const prefix = next.split("=", 1)[0]!;
            const optional =
              next.startsWith("-h") ||
              names.some((name) => `--${name}`.startsWith(prefix));
            // Declared options take precedence over negative numbers and spaces.
            if (
              !next.startsWith("-") ||
              next === "-" ||
              (!optional &&
                (next.includes(" ") ||
                  /^-(?:\p{Decimal_Number}+|\p{Decimal_Number}*\.\p{Decimal_Number}+)\n?$/u.test(
                    next,
                  )))
            ) {
              arg += `=${next}`;
              index++;
            }
          }
        }
        if (matches.length) parseArgs({ args: [arg], options });
      }
      parsedArgs.push(arg);
      if (arg === "--help") {
        parsedArgs = [arg];
        break;
      }
    }
    const { values } = parseArgs({
      args: parsedArgs,
      options,
    });
    if (values.help) {
      console.log(
        "Concatenate the SECURITY.md files that apply to a scan path.\n\n" +
          "Usage: launch_codex_security_mcp[.cmd] --helper resolve-security-md --repo PATH [--list | --scope PATH] [--out PATH]\n\n" +
          "--out PATH  output path, or - for stdout (default: -)",
      );
      return 0;
    }
    if (values.repo === undefined) throw new Error("--repo is required");
    if (values.list && values.scope !== undefined) {
      throw new Error("--list cannot be combined with --scope");
    }
    if (!values.list && values.scope === undefined) {
      throw new Error("--scope is required unless --list is specified");
    }
    const repo = parsedPath(values.repo);
    const guidance = values.list
      ? `[${listSecurityMd(repo, posixHome).map(asciiJson).join(", ")}]\n`
      : resolveSecurityMd(repo, parsedPath(values.scope!), posixHome);
    const outputPath = parsedPath(values.out);
    if (outputPath === "-") {
      process.stdout.write(Buffer.from(guidance, "utf8"));
    } else {
      const output = encodePath(outputPath);
      if (windows) {
        windowsFiles().mkdir(parentDirectory(output));
        windowsFiles().writeFile(
          output,
          Buffer.from(guidance.replace(/\n/g, "\r\n")),
        );
      } else {
        mkdirSync(parentDirectory(output), { recursive: true });
        writeFileSync(output, guidance, "utf8");
      }
    }
  } catch (error) {
    console.error(`resolve-security-md: error: ${(error as Error).message}`);
    return error instanceof SymlinkLoopError ||
      error instanceof HomeExpansionError
      ? 1
      : 2;
  }
  return 0;
}

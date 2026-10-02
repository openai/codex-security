import { decodeUtf8 } from "./utf8";
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
import { basename, dirname, sep, win32 } from "node:path";
import { parseArgs } from "node:util";
import { unixBinding, windowsBinding } from "../native";
import { windowsFileSystem } from "../../../native/windows-files.mjs";
import {
  decodePosixBytes,
  encodePosixPath,
  resolvePosixPath,
} from "./posix-path";

const MAX_SECURITY_MD_BYTES = 1024 * 1024;
const windows = process.platform === "win32";
export const windowsFiles = () => windowsFileSystem(windowsBinding());
const encodePath = (path: string) =>
  windows ? Buffer.from(path, "utf16le") : encodePosixPath(path);
const decodePath = (path: Buffer) =>
  windows ? path.toString("utf16le") : decodePosixBytes(path);
type FileInfo = Pick<Stats, "isDirectory" | "isFile" | "isSymbolicLink"> & {
  isReparsePoint?: () => boolean;
};
const statPath = (path: Buffer): FileInfo =>
  windows ? windowsFiles().stat(path) : statSync(path);

function windowsJoin(left: string, right: string): string {
  if (right.startsWith("\\\\?\\") || right.startsWith("\\\\.\\")) return right;
  const namespaced = left.startsWith("\\\\?\\");
  const base = left.startsWith("\\\\?\\UNC\\")
    ? `\\\\${left.slice(8)}`
    : namespaced
      ? left.slice(4)
      : left;
  const drive = win32.parse(right).root;
  if (
    drive.endsWith(":") &&
    drive.toLowerCase() !== base.slice(0, 2).toLowerCase()
  )
    return right;
  const joined = win32.resolve(base, right);
  return namespaced && !win32.isAbsolute(right)
    ? win32.toNamespacedPath(joined)
    : joined;
}

export function parsedPath(value: string): string {
  if (!windows) return value || ".";
  const root = win32.parse(value).root.replaceAll("/", "\\");
  const parts = value
    .slice(root.length)
    .split(/[/\\]/u)
    .filter((part) => part !== "" && part !== ".");
  if (!root && win32.parse(parts[0] ?? "").root) parts.unshift(".");
  return root + parts.join(sep) || ".";
}

export function resolvedPath(path: Buffer, strict = true): Buffer {
  return windows
    ? windowsFiles().realpath(path, strict)
    : resolvePosixPath(path, strict);
}

export function expandHome(
  path: string,
  posixHome: string | undefined,
): string {
  if (!path.startsWith("~")) return path;
  if (process.platform === "win32") {
    // path.join('C:', 'name') is rooted; 'C:.' keeps it drive-relative.
    const joinHome = (home: string, child: string) =>
      win32.join(
        home.length === 2 && home[1] === ":" ? `${home}.` : home,
        child,
      );
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
      home = `${environment("HOMEDRIVE") ?? ""}${homePath}`;
    }
    if (home === undefined)
      throw new Error("Could not determine home directory.");
    // node:path recognizes share roots in ordinary UNC paths, not extended UNC.
    const namespacedUnc = home.slice(0, 8).toUpperCase() === "\\\\?\\UNC\\";
    if (namespacedUnc) home = `\\\\${home.slice(8)}`;
    if (username !== "" && username !== currentUsername) {
      if (currentUsername !== win32.parse(home).base) {
        throw new Error("Could not determine home directory.");
      }
      home = joinHome(win32.dirname(home), username);
    }
    if (home.startsWith("~"))
      throw new Error("Could not determine home directory.");
    const expanded = joinHome(
      home,
      separator === -1 ? "" : path.slice(end + 1),
    );
    return namespacedUnc ? win32.toNamespacedPath(expanded) : expanded;
  }
  if (path === "~" || path.startsWith("~/")) {
    const home = posixHome ?? homedir();
    if (home.startsWith("~"))
      throw new Error("Could not determine home directory.");
    return home + path.slice(1) || "/";
  }
  const separator = path.indexOf("/");
  const end = separator === -1 ? path.length : separator;
  const result = unixBinding().userHome(encodePosixPath(path.slice(1, end)));
  if (result.value === null)
    throw new Error("Could not determine home directory.");
  const home = decodePosixBytes(result.value).replace(/\/+$/u, "");
  if (home.startsWith("~"))
    throw new Error("Could not determine home directory.");
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

export function windowsRelativePath(
  path: Buffer,
  root: Buffer,
  allowMissing = false,
): Buffer | undefined {
  const files = windowsFiles();
  const rootIdentity = files.identity(root);
  const parts: string[] = [];
  let current = path;
  while (true) {
    try {
      const identity = files.identity(current);
      if (
        identity.volume === rootIdentity.volume &&
        identity.fileId.equals(rootIdentity.fileId)
      )
        return encodePath(parts.reverse().join("\\"));
    } catch (error) {
      if (!allowMissing || (error as NodeJS.ErrnoException).code !== "ENOENT")
        throw error;
    }
    const parent = parentDirectory(current);
    if (parent.equals(current)) return undefined;
    parts.push(basename(decodePath(current)));
    current = parent;
  }
}

function inside(path: Buffer, root: Buffer, label: string): Buffer {
  if (process.platform === "win32") {
    const result = windowsRelativePath(path, root);
    if (result !== undefined) return result;
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
  const expanded = encodePath(parsedPath(expandHome(repo, posixHome)));
  let root: Buffer;
  try {
    root = resolvedPath(expanded);
  } catch {
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

function listSecurityMd(repo: string, posixHome: string | undefined): string[] {
  const root = resolveRoot(repo, posixHome);
  const policies: string[] = [];
  function walk(directory: Buffer, prefix: string): void {
    const entries = windows
      ? windowsFiles().entriesWithTypes(directory)
      : readdirSync(directory, { encoding: "buffer", withFileTypes: true });
    for (const listedEntry of entries) {
      const bytes = listedEntry.name;
      const name = decodePath(bytes);
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
  return policies.sort();
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
    return decodeUtf8(buffer.subarray(0, length));
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
  let requestedScope: Buffer;
  if (windows) {
    const files = windowsFiles();
    const requestedRoot = decodePath(
      files.absolute(encodePath(parsedPath(expandHome(repo, posixHome)))),
    );
    // Keep ordinary paths for OS normalization; canonicalize explicit device roots.
    const scopeRoot =
      requestedRoot.startsWith("\\\\?\\") || requestedRoot.startsWith("\\\\.\\")
        ? decodePath(root)
        : requestedRoot;
    requestedScope = files.absolute(
      encodePath(windowsJoin(scopeRoot, expandedScope)),
    );
  } else {
    requestedScope = expandedScope.startsWith("/")
      ? encodePosixPath(expandedScope)
      : appendPath(root, encodePosixPath(expandedScope));
  }
  let resolvedScope: Buffer;
  try {
    resolvedScope = resolvedPath(requestedScope);
  } catch {
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
    const { values } = parseArgs({
      args,
      options: {
        repo: { type: "string" },
        list: { type: "boolean" },
        scope: { type: "string" },
        out: { type: "string", default: "-" },
        help: { type: "boolean", short: "h" },
      },
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
    return 2;
  }
  return 0;
}

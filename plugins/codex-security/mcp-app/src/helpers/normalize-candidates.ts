import { decodeUtf8 } from "./utf8";
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, sep } from "node:path";
import {
  decodePosixBytes,
  encodePosixPath,
  resolvePosixPath,
  SymlinkLoopError,
} from "./posix-path";
import {
  expandHome,
  HomeExpansionError,
  parsedPath,
  windowsRelativePath,
} from "./resolve-security-md";
import { windowsBinding } from "../native";
import {
  pathText,
  widePath,
  windowsFileSystem,
} from "../../../native/windows-files.mjs";

import { object } from "./python-json";

const trim = (value: string) =>
  value.replace(
    /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
    "",
  );
const roles = [
  "entrypoint",
  "entrypoint/wrapper",
  "source",
  "root_control",
  "sink",
  "concrete_implementation",
  "evidence",
];
const fields = new Set([
  "candidate_id",
  "cwe_ids",
  "locations",
  "summary",
  "evidence",
  "context",
  "instance",
]);
type Row = Record<string, unknown>;
interface Location {
  path: string;
  start_line: number;
  end_line: number;
  role: string;
}
interface Candidate {
  cwe_ids: string[];
  locations: Location[];
  summary: string;
  evidence: string;
  context?: string;
  instance?: string;
}

function compare(left: string, right: string): number {
  const a = Array.from(left, (value) => value.codePointAt(0)!);
  const b = Array.from(right, (value) => value.codePointAt(0)!);
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index]! - b[index]!;
  }
  return a.length - b.length;
}

function stableJson(value: unknown): string {
  if (typeof value === "string") {
    if (/[\ud800-\udfff]/u.test(value))
      throw new Error("UTF-8 cannot encode an unpaired surrogate");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (object(value))
    return `{${Object.keys(value)
      .sort(compare)
      .map((key) => `${stableJson(key)}:${stableJson(value[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
}

const windows = process.platform === "win32";
const windowsFiles = () => windowsFileSystem(windowsBinding());
const fsPath = (value: string) =>
  windows ? widePath(value) : encodePosixPath(value);
const readFile = (path: string) =>
  windows ? windowsFiles().readFile(fsPath(path)) : readFileSync(fsPath(path));
const stat = (path: string) =>
  windows ? windowsFiles().stat(fsPath(path)) : statSync(fsPath(path));
const pathKey = (value: string) =>
  process.platform === "win32" ? value.toLowerCase() : value;

function resolvedPath(value: string, strict = true): string {
  if (process.platform !== "win32")
    return decodePosixBytes(
      resolvePosixPath(encodePosixPath(parsedPath(value)), strict),
    );
  try {
    return pathText(windowsFiles().realpath(widePath(value), strict));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP")
      throw new SymlinkLoopError(`Symlink loop from ${value}`);
    throw error;
  }
}

function inside(path: string, root: string, allowMissing = false): string {
  let result: string | undefined;
  if (windows) {
    const bytes = windowsRelativePath(
      widePath(path),
      widePath(root),
      allowMissing,
    );
    result = bytes === undefined ? undefined : pathText(bytes);
  } else {
    result = relative(root, path);
  }
  if (
    result === undefined ||
    isAbsolute(result) ||
    result === ".." ||
    result.startsWith(`..${sep}`)
  )
    throw new Error("path: must resolve inside --repo-root");
  return result.split(sep).join("/");
}

function relativeFile(value: unknown, root: string): [string, string] {
  if (typeof value !== "string" || value === "" || value.includes("\0"))
    throw new Error("path: expected a non-empty repository-relative path");
  const raw =
    process.platform === "win32" ? value.replaceAll("\\", "/") : value;
  if (
    raw.startsWith("/") ||
    raw.split("/").includes("..") ||
    (process.platform === "win32" && /^[A-Za-z]:/u.test(raw))
  )
    throw new Error(
      "path: expected a repository-relative path without traversal",
    );
  const path = resolvedPath(`${root}${sep}${raw}`);
  const name = inside(path, root);
  if (!stat(path).isFile()) throw new Error("path: expected a regular file");
  return [name, path];
}

function readScope(
  path: string,
  root: string,
  allowMissing: boolean,
): Set<string> {
  const contents = decodeUtf8(readFile(path));
  const lines = contents.split("\n");
  const listed = new Set(lines);
  const isFile = (value: string) => {
    try {
      relativeFile(value, root);
      return true;
    } catch (error) {
      if (error instanceof SymlinkLoopError) throw error;
      return false;
    }
  };
  const carriage = new Map<string, [boolean, boolean]>();
  if (process.platform !== "win32") {
    for (const line of lines) {
      if (line.endsWith("\r") && line !== "\r")
        carriage.set(line, [isFile(line), isFile(line.slice(0, -1))]);
    }
  }
  const crlf =
    lines.includes("\r") ||
    [...carriage.values()].some(([literal, stripped]) => stripped && !literal);
  const literalEvidence = [...carriage.values()].some(
    ([literal, stripped]) => literal && !stripped,
  );
  const scope = new Set<string>();
  for (const [index, original] of lines.entries()) {
    let line = original;
    if (process.platform === "win32" || line === "\r") {
      if (line.endsWith("\r")) line = line.slice(0, -1);
    } else if (line.endsWith("\r")) {
      const [literal, stripped] = carriage.get(line)!;
      if (stripped && !literal) line = line.slice(0, -1);
      else if (stripped && literal) {
        if (
          (index === lines.length - 1 && !contents.endsWith("\n")) ||
          listed.has(line.slice(0, -1))
        ) {
          // An unterminated row or a separately listed sibling preserves CR.
        } else if (crlf && !literalEvidence) line = line.slice(0, -1);
        else if (!(literalEvidence && !crlf))
          throw new Error(
            `in-scope file row ${index + 1}: ambiguous carriage-return paths`,
          );
      } else if (!literal && crlf) line = line.slice(0, -1);
    }
    if (line === "") continue;
    try {
      scope.add(relativeFile(line, root)[0]);
    } catch (error) {
      if (error instanceof SymlinkLoopError) throw error;
      if (allowMissing && (error as NodeJS.ErrnoException).code === "ENOENT") {
        if (
          line.startsWith("/") ||
          line.split("/").includes("..") ||
          line.includes("\0")
        )
          throw new Error(
            `in-scope file row ${index + 1}: unsafe deleted path`,
          );
        try {
          scope.add(
            inside(resolvedPath(`${root}${sep}${line}`, false), root, true),
          );
        } catch (error) {
          if (error instanceof SymlinkLoopError) throw error;
          throw new Error(
            `in-scope file row ${index + 1}: path escapes repository`,
          );
        }
      } else {
        throw new Error(
          `in-scope file row ${index + 1}: ${(error as Error).message}`,
        );
      }
    }
  }
  return scope;
}

function textField(
  row: Row,
  field: string,
  required = true,
): string | undefined {
  const value = row[field];
  if ((value === undefined || value === null) && !required) return undefined;
  if (typeof value !== "string" || trim(value) === "")
    throw new Error(`${field}: expected a non-empty string`);
  return trim(value);
}

function cweIds(row: Row): string[] {
  const values = row.cwe_ids;
  if (!Array.isArray(values)) throw new Error("cwe_ids: expected an array");
  const found = new Set<bigint>();
  for (const value of values) {
    if (typeof value !== "string")
      throw new Error("cwe_ids: expected CWE strings");
    const match = /^CWE-(\p{Decimal_Number}+)$/iu.exec(trim(value));
    if (match === null)
      throw new Error(`cwe_ids: unsupported value ${JSON.stringify(value)}`);
    const digits = Array.from(match[1]!, (digit) => {
      let point = digit.codePointAt(0)!;
      let offset = 0;
      while (/\p{Decimal_Number}/u.test(String.fromCodePoint(point - 1))) {
        point--;
        offset++;
      }
      return String(offset % 10);
    }).join("");
    const number = BigInt(digits);
    if (number < 1n)
      throw new Error(`cwe_ids: unsupported value ${JSON.stringify(value)}`);
    found.add(number);
  }
  return [...found]
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
    .map((number) => `CWE-${number}`);
}

function positiveLine(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1)
    throw new Error(`${field}: expected a positive integer`);
  return value;
}

function normalizeLocations(
  row: Row,
  root: string,
  lineCounts: Map<string, number>,
): Location[] {
  if (!Array.isArray(row.locations) || row.locations.length === 0)
    throw new Error("locations: expected a non-empty array");
  const normalized = new Map<string, Location>();
  for (const item of row.locations) {
    if (!object(item)) throw new Error("locations: expected location objects");
    const unknown = Object.keys(item)
      .filter(
        (key) => !["path", "start_line", "end_line", "role"].includes(key),
      )
      .sort(compare);
    if (unknown.length)
      throw new Error(`locations: unsupported fields ${unknown.join(", ")}`);
    const [name, source] = relativeFile(item.path, root);
    if (
      trim(name) === "" ||
      name.includes("\\") ||
      name.split("/").some((part) => part.includes(":"))
    )
      throw new Error("path: expected a safe repository-relative POSIX path");
    const start = positiveLine(item.start_line, "start_line");
    const end = positiveLine(
      item.end_line === undefined ? start : item.end_line,
      "end_line",
    );
    if (end < start)
      throw new Error("end_line: must be greater than or equal to start_line");
    const key = pathKey(source);
    if (!lineCounts.has(key)) {
      const bytes = readFile(source);
      const contents = bytes.toString("latin1");
      const lines =
        contents.split(/\r\n|[\r\n]/u).length -
        (contents === "" || /[\r\n]$/u.test(contents) ? 1 : 0);
      lineCounts.set(key, lines);
    }
    const count = lineCounts.get(key)!;
    if (end > count)
      throw new Error(`line range ${start}-${end} exceeds ${name}:${count}`);
    if (typeof item.role !== "string" || !roles.includes(item.role))
      throw new Error(`role: unsupported value ${String(item.role)}`);
    const location = {
      path: name,
      start_line: start,
      end_line: end,
      role: item.role,
    };
    normalized.set(stableJson(location), location);
  }
  return [...normalized.values()].sort(
    (a, b) =>
      roles.indexOf(a.role) - roles.indexOf(b.role) ||
      compare(a.path, b.path) ||
      a.start_line - b.start_line ||
      a.end_line - b.end_line,
  );
}

function normalizeCandidate(
  row: Row,
  root: string,
  scope: Set<string>,
  lineCounts: Map<string, number>,
): Candidate {
  const unknown = Object.keys(row)
    .filter((key) => !fields.has(key))
    .sort(compare);
  if (unknown.length)
    throw new Error(`unsupported fields ${unknown.join(", ")}`);
  if ("candidate_id" in row) textField(row, "candidate_id");
  const locations = normalizeLocations(row, root, lineCounts);
  if (!locations.some((item) => scope.has(item.path)))
    throw new Error("locations: expected at least one in-scope file");
  const result: Candidate = {
    cwe_ids: cweIds(row),
    locations,
    summary: textField(row, "summary")!,
    evidence: textField(row, "evidence")!,
  };
  const context = textField(row, "context", false);
  if (context !== undefined) result.context = context;
  const instance = textField(row, "instance", false);
  if (instance !== undefined) result.instance = instance;
  return result;
}

function combine(rows: Candidate[]): (Candidate & { candidate_id: string })[] {
  const groups = new Map<string, Candidate[]>();
  for (const row of rows) {
    const key = stableJson({
      cwe_ids: row.cwe_ids,
      locations: row.locations,
      instance: row.instance ?? null,
    });
    const group = groups.get(key) ?? [];
    group.push(row);
    groups.set(key, group);
  }
  return [...groups.keys()].sort(compare).map((key) => {
    const group = groups.get(key)!;
    const merged = (field: "summary" | "evidence" | "context") =>
      [
        ...new Set(
          group
            .map((row) => row[field])
            .filter((value): value is string => value !== undefined),
        ),
      ]
        .sort(compare)
        .join("\n");
    const result = {
      ...group[0]!,
      candidate_id: `candidate-${createHash("sha256").update(key).digest("hex").slice(0, 16)}`,
      summary: merged("summary"),
      evidence: merged("evidence"),
    };
    const context = merged("context");
    if (context !== "") result.context = context;
    return result;
  });
}

function argumentsFor(args: string[]): Record<string, string[] | boolean> {
  const names = [
    "input",
    "out",
    "repo-root",
    "in-scope-files",
    "allow-missing-in-scope",
    "help",
  ];
  function option(value: string): string | undefined {
    if (value === "-h") return "help";
    if (value.startsWith("--") && value !== "--") {
      const name = value.slice(2).split("=", 1)[0]!;
      const matches = names.filter((item) => item.startsWith(name));
      if (matches.includes(name)) return name;
      if (matches.length === 1) return matches[0];
      if (matches.length > 1) throw new Error(`ambiguous option: ${value}`);
    }
    if (
      !value.startsWith("-") ||
      value === "-" ||
      (!value.startsWith("-h") &&
        (value.includes(" ") ||
          /^-(?:\p{Decimal_Number}+|\p{Decimal_Number}*\.\p{Decimal_Number}+)\n?$/u.test(
            value,
          )))
    )
      return undefined;
    throw new Error(`unrecognized argument: ${value}`);
  }
  const values: Record<string, string[] | boolean> = {};
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    const name = option(argument);
    if (name === undefined)
      throw new Error(`unrecognized argument: ${argument}`);
    const equals = argument.indexOf("=");
    if (name === "help" || name === "allow-missing-in-scope") {
      if (equals !== -1)
        throw new Error(`argument --${name} does not take a value`);
      values[name] = true;
      if (name === "help") return values;
      continue;
    }
    const found: string[] = [];
    if (equals !== -1) found.push(argument.slice(equals + 1));
    else {
      while (
        index + 1 < args.length &&
        option(args[index + 1]!) === undefined
      ) {
        found.push(args[++index]!);
        if (name !== "input") break;
      }
    }
    if (found.length === 0)
      throw new Error(
        `argument --${name}: expected ${name === "input" ? "at least one argument" : "one argument"}`,
      );
    values[name] = found;
  }
  for (const name of ["input", "out", "repo-root", "in-scope-files"]) {
    if (values[name] === undefined) throw new Error(`--${name} is required`);
  }
  return values;
}

export function normalizeCandidatesCommand(
  args: string[],
  posixHome = process.env.HOME,
): number {
  try {
    const values = argumentsFor(args);
    if (values.help) {
      console.log(
        "Validate and combine security-scan candidates into deterministic JSONL.\n",
      );
      console.log(
        "Usage: launch_codex_security_mcp[.cmd] --helper normalize-candidates --input PATH [PATH ...] --out PATH --repo-root PATH --in-scope-files PATH [--allow-missing-in-scope]",
      );
      return 0;
    }
    const paths = (name: string, strict = true) =>
      (values[name] as string[]).map((value) =>
        resolvedPath(expandHome(parsedPath(value), posixHome), strict),
      );
    const root = paths("repo-root")[0]!;
    if (!stat(root).isDirectory())
      throw new Error("--repo-root: expected a directory");
    const output = paths("out", false)[0]!;
    const scopePath = paths("in-scope-files")[0]!;
    const inputs = [
      ...new Map(paths("input").map((path) => [pathKey(path), path])).values(),
    ].sort((a, b) => compare(pathKey(a), pathKey(b)));
    if (inputs.some((path) => pathKey(path) === pathKey(output)))
      throw new Error("--out: must not also be an input");
    if (pathKey(output) === pathKey(scopePath))
      throw new Error("--out: must not replace --in-scope-files");
    const scope = readScope(
      scopePath,
      root,
      values["allow-missing-in-scope"] === true,
    );
    const lineCounts = new Map<string, number>();
    const rows: Candidate[] = [];
    for (const source of inputs) {
      const lines = decodeUtf8(readFile(source)).split(/\r\n|[\r\n]/u);
      for (const [index, line] of lines.entries()) {
        if (trim(line) === "") continue;
        try {
          const row: unknown = JSON.parse(line);
          if (!object(row)) throw new Error("expected a JSON object");
          rows.push(normalizeCandidate(row, root, scope, lineCounts));
        } catch (error) {
          if (error instanceof SymlinkLoopError) throw error;
          throw new Error(
            `${source} row ${index + 1}: ${(error as Error).message}`,
          );
        }
      }
    }
    const combined = combine(rows);
    if (windows) windowsFiles().mkdir(fsPath(dirname(output)));
    else mkdirSync(fsPath(dirname(output)), { recursive: true });
    const temporary = join(
      dirname(output),
      `.${basename(output)}.${randomBytes(6).toString("base64url")}.tmp`,
    );
    let created = false;
    try {
      if (windows) {
        function* contents() {
          created = true;
          for (const row of combined)
            yield Buffer.from(`${stableJson(row)}\r\n`);
        }
        windowsFiles().writeFile(fsPath(temporary), contents(), true);
        windowsFiles().rename(fsPath(temporary), fsPath(output));
      } else {
        const descriptor = openSync(fsPath(temporary), "wx", 0o600);
        created = true;
        try {
          for (const row of combined)
            writeFileSync(descriptor, `${stableJson(row)}\n`, "utf8");
        } finally {
          closeSync(descriptor);
        }
        renameSync(fsPath(temporary), fsPath(output));
      }
    } finally {
      try {
        if (created) {
          if (windows) windowsFiles().unlink(fsPath(temporary));
          else unlinkSync(fsPath(temporary));
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    const message = `Combined ${rows.length} candidate rows into ${combined.length} rows in ${output}\n`;
    process.stdout.write(
      process.platform === "win32"
        ? message.replace(/\n/gu, "\r\n")
        : encodePosixPath(message),
    );
    return 0;
  } catch (error) {
    console.error(`normalize_candidates: ${(error as Error).message}`);
    return error instanceof SymlinkLoopError ||
      error instanceof HomeExpansionError
      ? 1
      : 2;
  }
}

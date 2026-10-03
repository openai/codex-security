import { isRecord as object } from "../record.js";
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
import { dirname, isAbsolute, join, relative, sep } from "node:path";
import { parseArgs } from "node:util";
import { decodePosixBytes, encodePosixPath } from "./posix-path";
import {
  expandHome,
  resolvedPath as resolveFilePath,
  windowsFiles,
  windowsRelativePath,
} from "./resolve-security-md";
import { pathText, widePath } from "../../../native/windows-files.mjs";

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
const locationFields = new Set(["path", "start_line", "end_line", "role"]);
const jsonFields = [...fields, ...locationFields].sort();
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
  return left < right ? -1 : left > right ? 1 : 0;
}

function stableJson(value: unknown): string {
  return JSON.stringify(value, jsonFields);
}

const windows = process.platform === "win32";
const fsPath = (value: string) =>
  windows ? widePath(value) : encodePosixPath(value);
const readFile = (path: string) =>
  windows ? windowsFiles().readFile(fsPath(path)) : readFileSync(fsPath(path));
const stat = (path: string) =>
  windows ? windowsFiles().stat(fsPath(path)) : statSync(fsPath(path));
const pathKey = (value: string) => (windows ? value.toLowerCase() : value);

function resolvedPath(value: string, strict = true): string {
  const path = resolveFilePath(fsPath(value), strict);
  return windows ? pathText(path) : decodePosixBytes(path);
}

function inside(path: string, root: string, allowMissing = false): string {
  const result = windows
    ? windowsRelativePath(
        widePath(path),
        widePath(root),
        allowMissing,
      )?.toString("utf16le")
    : relative(root, path);
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
  const raw = windows ? value.replaceAll("\\", "/") : value;
  if (
    raw.startsWith("/") ||
    raw.split("/").includes("..") ||
    (windows && /^[A-Za-z]:/u.test(raw))
  )
    throw new Error(
      "path: expected a repository-relative path without traversal",
    );
  const path = resolvedPath(join(root, raw));
  const name = inside(path, root);
  if (!stat(path).isFile()) throw new Error("path: expected a regular file");
  return [name, path];
}

function readScope(
  path: string,
  root: string,
  allowMissing: boolean,
): Set<string> {
  const lines = decodeUtf8(readFile(path)).split(/\r?\n/u);
  const scope = new Set<string>();
  for (const [index, line] of lines.entries()) {
    if (line === "") continue;
    try {
      scope.add(relativeFile(line, root)[0]);
    } catch (error) {
      if (allowMissing && (error as NodeJS.ErrnoException).code === "ENOENT") {
        try {
          scope.add(inside(resolvedPath(join(root, line), false), root, true));
        } catch (error) {
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
  if (typeof value !== "string" || value.trim() === "")
    throw new Error(`${field}: expected a non-empty string`);
  return value.trim();
}

function cweIds(row: Row): string[] {
  const values = row.cwe_ids;
  if (!Array.isArray(values)) throw new Error("cwe_ids: expected an array");
  const found = new Set<bigint>();
  for (const value of values) {
    if (typeof value !== "string")
      throw new Error("cwe_ids: expected CWE strings");
    const match = /^CWE-(\d+)$/iu.exec(value.trim());
    if (match === null)
      throw new Error(`cwe_ids: unsupported value ${JSON.stringify(value)}`);
    const number = BigInt(match[1]!);
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
      .filter((key) => !locationFields.has(key))
      .sort();
    if (unknown.length)
      throw new Error(`locations: unsupported fields ${unknown.join(", ")}`);
    const [name, source] = relativeFile(item.path, root);
    if (name.trim() === "" || name.includes("\\") || name.includes(":"))
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
    .sort();
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
  for (const field of ["context", "instance"] as const) {
    const value = textField(row, field, false);
    if (value !== undefined) result[field] = value;
  }
  return result;
}

function combine(groups: Map<string, Candidate[]>) {
  return [...groups]
    .sort(([a], [b]) => compare(a, b))
    .map(([key, group]) => {
      const merged = (field: "summary" | "evidence" | "context") =>
        [
          ...new Set(
            group
              .map((row) => row[field])
              .filter((value): value is string => value !== undefined),
          ),
        ]
          .sort()
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

function argumentsFor(args: string[]) {
  const { values, tokens } = parseArgs({
    args,
    allowPositionals: true,
    tokens: true,
    options: {
      input: { type: "string", multiple: true },
      out: { type: "string" },
      "repo-root": { type: "string" },
      "in-scope-files": { type: "string" },
      "allow-missing-in-scope": { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  let collectingInputs = false;
  for (const token of tokens) {
    if (token.kind === "option") collectingInputs = token.name === "input";
    else if (token.kind === "positional") {
      if (!collectingInputs)
        throw new Error(`unrecognized argument: ${token.value}`);
      values.input!.push(token.value);
    }
  }
  if (!values.help) {
    for (const name of ["input", "out", "repo-root", "in-scope-files"] as const)
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
    const resolve = (value: string, strict = true) =>
      resolvedPath(expandHome(value, posixHome), strict);
    const root = resolve(values["repo-root"]!);
    if (!stat(root).isDirectory())
      throw new Error("--repo-root: expected a directory");
    const output = resolve(values.out!, false);
    const scopePath = resolve(values["in-scope-files"]!);
    const inputs = [
      ...new Map(
        values.input!.map((value) => {
          const path = resolve(value);
          return [pathKey(path), path];
        }),
      ).values(),
    ].sort((a, b) => compare(pathKey(a), pathKey(b)));
    if (inputs.some((path) => pathKey(path) === pathKey(output)))
      throw new Error("--out: must not also be an input");
    if (pathKey(output) === pathKey(scopePath))
      throw new Error("--out: must not replace --in-scope-files");
    const scope = readScope(
      scopePath,
      root,
      values["allow-missing-in-scope"] ?? false,
    );
    const lineCounts = new Map<string, number>();
    const groups = new Map<string, Candidate[]>();
    let rowCount = 0;
    for (const source of inputs) {
      const lines = decodeUtf8(readFile(source)).split(/\r?\n/u);
      for (const [index, line] of lines.entries()) {
        if (line.trim() === "") continue;
        let candidate: Candidate;
        try {
          const row: unknown = JSON.parse(line);
          if (!object(row)) throw new Error("expected a JSON object");
          candidate = normalizeCandidate(row, root, scope, lineCounts);
        } catch (error) {
          throw new Error(
            `${source} row ${index + 1}: ${(error as Error).message}`,
          );
        }
        const key = stableJson({
          cwe_ids: candidate.cwe_ids,
          locations: candidate.locations,
          instance: candidate.instance ?? null,
        });
        const group = groups.get(key) ?? [];
        group.push(candidate);
        groups.set(key, group);
        rowCount++;
      }
    }
    const combined = combine(groups);
    if (windows) windowsFiles().mkdir(fsPath(dirname(output)));
    else mkdirSync(fsPath(dirname(output)), { recursive: true });
    const temporary = fsPath(
      join(
        dirname(output),
        `.candidates-${randomBytes(6).toString("base64url")}.tmp`,
      ),
    );
    let created = false;
    function* contents() {
      created = true;
      for (const row of combined) yield Buffer.from(`${stableJson(row)}\n`);
    }
    try {
      if (windows) {
        windowsFiles().writeFile(temporary, contents(), true);
        windowsFiles().rename(temporary, fsPath(output));
      } else {
        const descriptor = openSync(temporary, "wx", 0o600);
        try {
          for (const chunk of contents()) writeFileSync(descriptor, chunk);
        } finally {
          closeSync(descriptor);
        }
        renameSync(temporary, fsPath(output));
      }
    } finally {
      try {
        if (created) {
          if (windows) windowsFiles().unlink(temporary);
          else unlinkSync(temporary);
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    console.log(
      `Combined ${rowCount} candidate rows into ${combined.length} rows in ${output}`,
    );
    return 0;
  } catch (error) {
    console.error(`normalize_candidates: ${(error as Error).message}`);
    return 2;
  }
}

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  createReadStream,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { EOL, homedir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";

const CWE = /^CWE-(\p{Decimal_Number}+)$/iu;
const ROLES = new Map([
  ["entrypoint", 0],
  ["entrypoint/wrapper", 1],
  ["source", 2],
  ["root_control", 3],
  ["sink", 4],
  ["concrete_implementation", 5],
  ["evidence", 6],
]);
const FIELDS = new Set([
  "candidate_id",
  "cwe_ids",
  "locations",
  "summary",
  "evidence",
  "context",
  "instance",
]);
const LOCATION_FIELDS = new Set(["path", "start_line", "end_line", "role"]);
const PYTHON_WHITESPACE_START =
  /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/u;
const PYTHON_WHITESPACE_END =
  /[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/u;

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };
type JsonObject = Record<string, unknown>;

interface Location {
  path: string;
  start_line: number;
  end_line: number;
  role: string;
}

interface NormalizedCandidate {
  cwe_ids: string[];
  locations: Location[];
  summary: string;
  evidence: string;
  context?: string;
  instance?: string;
}

interface CombinedCandidate extends NormalizedCandidate {
  candidate_id: string;
}

interface CliArguments {
  inputs: string[];
  output: string;
  repoRoot: string;
  scopePath: string;
  allowMissingInScope: boolean;
}

const LONG_OPTIONS = [
  "--help",
  "--input",
  "--out",
  "--repo-root",
  "--in-scope-files",
  "--allow-missing-in-scope",
] as const;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function pythonStrip(value: string): string {
  return value
    .replace(PYTHON_WHITESPACE_START, "")
    .replace(PYTHON_WHITESPACE_END, "");
}

function comparePythonStrings(left: string, right: string): number {
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

function canonicalValue(value: unknown): JsonValue {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number"
  ) {
    return value;
  }
  if (typeof value === "string") {
    if (!value.isWellFormed()) {
      throw new Error("expected valid Unicode text");
    }
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (isObject(value)) {
    const result: { [key: string]: JsonValue } = {};
    for (const key of Object.keys(value).sort(comparePythonStrings)) {
      result[key] = canonicalValue(value[key]);
    }
    return result;
  }
  throw new Error("expected a JSON value");
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

function textField(
  row: JsonObject,
  field: string,
  required = true,
): string | undefined {
  const value = row[field];
  if ((value === null || value === undefined) && !required) return undefined;
  if (typeof value !== "string" || !pythonStrip(value)) {
    throw new Error(`${field}: expected a non-empty string`);
  }
  return pythonStrip(value);
}

function cweIds(row: JsonObject): string[] {
  const value = row["cwe_ids"];
  if (!Array.isArray(value)) throw new Error("cwe_ids: expected an array");
  const found = new Set<string>();
  for (const item of value) {
    if (typeof item !== "string") {
      throw new Error("cwe_ids: expected CWE strings");
    }
    const match = CWE.exec(pythonStrip(item));
    const number = match?.[1] === undefined ? 0n : decimalInteger(match[1]);
    if (match === null || number < 1n) {
      throw new Error(`cwe_ids: unsupported value ${JSON.stringify(item)}`);
    }
    found.add(number.toString());
  }
  return [...found]
    .sort((left, right) => {
      const leftNumber = BigInt(left);
      const rightNumber = BigInt(right);
      return leftNumber < rightNumber ? -1 : leftNumber > rightNumber ? 1 : 0;
    })
    .map((number) => `CWE-${number}`);
}

function decimalInteger(value: string): bigint {
  return BigInt(
    Array.from(value, (digit) => {
      const point = digit.codePointAt(0)!;
      let start = point;
      // Unicode decimal digits form consecutive sets of ten, sometimes adjacent.
      while (/\p{Decimal_Number}/u.test(String.fromCodePoint(start - 1)))
        start -= 1;
      return (point - start) % 10;
    }).join(""),
  );
}

function errorCode(error: unknown): string | undefined {
  return error instanceof Error
    ? (error as NodeJS.ErrnoException).code
    : undefined;
}

function relativeInside(root: string, candidate: string): string | undefined {
  const result = relative(root, candidate);
  if (result === ".." || result.startsWith(`..${sep}`) || isAbsolute(result)) {
    return undefined;
  }
  return result.split(sep).join("/");
}

function posixParts(value: string): string[] {
  return value.split("/").filter((part) => part !== "" && part !== ".");
}

export function relativeFile(
  value: unknown,
  repoRoot: string,
): [string, string] {
  if (typeof value !== "string" || !value || value.includes("\0")) {
    throw new Error("path: expected a non-empty repository-relative path");
  }
  const raw =
    process.platform === "win32" ? value.replaceAll("\\", "/") : value;
  const parts = posixParts(raw);
  if (
    raw.startsWith("/") ||
    parts.includes("..") ||
    (process.platform === "win32" && /^[A-Za-z]:/u.test(raw))
  ) {
    throw new Error(
      "path: expected a repository-relative path without traversal",
    );
  }
  const source = realpathSync(resolve(repoRoot, ...parts));
  const relativePath = relativeInside(repoRoot, source);
  if (relativePath === undefined) {
    throw new Error("path: must resolve inside --repo-root");
  }
  if (!statSync(source).isFile()) {
    throw new Error("path: expected a regular file");
  }
  return [relativePath, source];
}

function positiveLine(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error(`${field}: expected a positive integer`);
  }
  return value;
}

function countLines(source: string): number {
  const contents = readFileSync(source);
  if (contents.length === 0) return 0;
  let lines = 0;
  for (let index = 0; index < contents.length; index += 1) {
    const byte = contents[index];
    if (byte === 0x0d) {
      lines += 1;
      if (contents[index + 1] === 0x0a) index += 1;
    } else if (byte === 0x0a) {
      lines += 1;
    }
  }
  const last = contents[contents.length - 1];
  return last === 0x0a || last === 0x0d ? lines : lines + 1;
}

function normalizeLocations(
  row: JsonObject,
  repoRoot: string,
  lineCounts: Map<string, number>,
): Location[] {
  const value = row["locations"];
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("locations: expected a non-empty array");
  }
  const normalized = new Map<string, Location>();
  for (const item of value) {
    if (!isObject(item)) {
      throw new Error("locations: expected location objects");
    }
    const unknown = Object.keys(item)
      .filter((field) => !LOCATION_FIELDS.has(field))
      .sort(comparePythonStrings);
    if (unknown.length > 0) {
      throw new Error(`locations: unsupported fields ${unknown.join(", ")}`);
    }
    const [relativePath, source] = relativeFile(item["path"], repoRoot);
    if (
      !pythonStrip(relativePath) ||
      relativePath.includes("\\") ||
      relativePath.split("/").some((part) => part.includes(":"))
    ) {
      throw new Error("path: expected a safe repository-relative POSIX path");
    }
    const start = positiveLine(item["start_line"], "start_line");
    const end = positiveLine(
      Object.hasOwn(item, "end_line") ? item["end_line"] : start,
      "end_line",
    );
    if (end < start) {
      throw new Error("end_line: must be greater than or equal to start_line");
    }
    let lineCount = lineCounts.get(source);
    if (lineCount === undefined) {
      lineCount = countLines(source);
      lineCounts.set(source, lineCount);
    }
    if (end > lineCount) {
      throw new Error(
        `line range ${start}-${end} exceeds ${relativePath}:${lineCount}`,
      );
    }
    const role = item["role"];
    if (typeof role !== "string" || !ROLES.has(role)) {
      throw new Error(`role: unsupported value ${JSON.stringify(role)}`);
    }
    const location = {
      path: relativePath,
      start_line: start,
      end_line: end,
      role,
    };
    normalized.set(canonicalJson(location), location);
  }
  return [...normalized.values()].sort((left, right) => {
    const role = ROLES.get(left.role)! - ROLES.get(right.role)!;
    if (role !== 0) return role;
    const path = comparePythonStrings(left.path, right.path);
    if (path !== 0) return path;
    return left.start_line - right.start_line || left.end_line - right.end_line;
  });
}

function resolveAllowMissing(value: string): string {
  const absolute =
    process.platform === "win32"
      ? resolve(value)
      : isAbsolute(value)
        ? value
        : `${process.cwd()}${process.cwd().endsWith(sep) ? "" : sep}${value}`;
  const splitPath = (path: string): { parts: string[]; root: string } => {
    const root = parse(path).root;
    const remainder = path.slice(root.length);
    return {
      root,
      parts:
        process.platform === "win32"
          ? remainder.split(/[\\/]/u)
          : remainder.split("/"),
    };
  };
  const initialPath = splitPath(absolute);
  let parts: (string | { symlink: string })[] = initialPath.parts;
  let current = initialPath.root;
  let index = 0;
  const activeLinks = new Set<string>();
  while (index < parts.length) {
    const component = parts[index++]!;
    if (typeof component !== "string") {
      activeLinks.delete(component.symlink);
      continue;
    }
    if (!component || component === ".") continue;
    if (component === "..") {
      current = dirname(current);
      continue;
    }
    const candidate = join(current, component);
    let entry;
    try {
      entry = lstatSync(candidate);
    } catch (error) {
      if (errorCode(error) === "ENOENT") {
        current = candidate;
        continue;
      }
      throw error;
    }
    if (!entry.isSymbolicLink()) {
      current = candidate;
      continue;
    }
    const target = readlinkSync(candidate);
    const remainder = parts.slice(index);
    const targetPath = splitPath(target);
    if (activeLinks.has(candidate)) {
      throw new Error(`too many symbolic links while resolving ${value}`);
    }
    activeLinks.add(candidate);
    current = isAbsolute(target) ? targetPath.root : dirname(candidate);
    parts = [...targetPath.parts, { symlink: candidate }, ...remainder];
    index = 0;
  }
  return current;
}

export function readScope(
  scopePath: string,
  repoRoot: string,
  allowMissing = false,
): Set<string> {
  const contents = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: true,
  }).decode(readFileSync(scopePath));
  const lines = contents.split("\n");
  const listedRows = new Set(lines);
  const isScopeFile = (value: string): boolean => {
    try {
      relativeFile(value, repoRoot);
      return true;
    } catch {
      return false;
    }
  };
  const carriageRows = new Map<string, [boolean, boolean]>();
  if (process.platform !== "win32") {
    for (const line of lines) {
      if (line.endsWith("\r") && line !== "\r") {
        carriageRows.set(line, [
          isScopeFile(line),
          isScopeFile(line.slice(0, -1)),
        ]);
      }
    }
  }
  const crlfEvidence =
    lines.some((line) => line === "\r") ||
    [...carriageRows.values()].some(
      ([literal, stripped]) => stripped && !literal,
    );
  const literalEvidence = [...carriageRows.values()].some(
    ([literal, stripped]) => literal && !stripped,
  );

  const scope = new Set<string>();
  for (const [index, originalLine] of lines.entries()) {
    const number = index + 1;
    let line = originalLine;
    if (process.platform === "win32" || line === "\r") {
      if (line.endsWith("\r")) line = line.slice(0, -1);
    } else if (line.endsWith("\r")) {
      const [literal, stripped] = carriageRows.get(line)!;
      if (stripped && !literal) {
        line = line.slice(0, -1);
      } else if (stripped && literal) {
        if (number === lines.length && !contents.endsWith("\n")) {
          // A final unterminated carriage return is part of the path.
        } else if (listedRows.has(line.slice(0, -1))) {
          // The stripped spelling is listed separately, so this row is literal.
        } else if (crlfEvidence && !literalEvidence) {
          line = line.slice(0, -1);
        } else if (!literalEvidence || crlfEvidence) {
          throw new Error(
            `in-scope file row ${number}: ambiguous carriage-return paths`,
          );
        }
      } else if (!literal && crlfEvidence) {
        line = line.slice(0, -1);
      }
    }
    if (!line) continue;
    try {
      const [relativePath] = relativeFile(line, repoRoot);
      scope.add(relativePath);
    } catch (error) {
      if (allowMissing && errorCode(error) === "ENOENT") {
        const parts = posixParts(line);
        if (
          line.startsWith("/") ||
          parts.includes("..") ||
          line.includes("\0")
        ) {
          throw new Error(`in-scope file row ${number}: unsafe deleted path`);
        }
        const resolved = resolveAllowMissing(resolve(repoRoot, line));
        const relativePath = relativeInside(repoRoot, resolved);
        if (relativePath === undefined) {
          throw new Error(
            `in-scope file row ${number}: path escapes repository`,
          );
        }
        scope.add(relativePath);
        continue;
      }
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`in-scope file row ${number}: ${message}`);
    }
  }
  return scope;
}

export function normalizeCandidate(
  row: JsonObject,
  repoRoot: string,
  scope: Set<string>,
  lineCounts: Map<string, number>,
): NormalizedCandidate {
  const unknown = Object.keys(row)
    .filter((field) => !FIELDS.has(field))
    .sort(comparePythonStrings);
  if (unknown.length > 0) {
    throw new Error(`unsupported fields ${unknown.join(", ")}`);
  }
  if (Object.hasOwn(row, "candidate_id")) textField(row, "candidate_id");
  const locations = normalizeLocations(row, repoRoot, lineCounts);
  if (!locations.some((location) => scope.has(location.path))) {
    throw new Error("locations: expected at least one in-scope file");
  }
  const result: NormalizedCandidate = {
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

function identity(row: NormalizedCandidate): string {
  return canonicalJson({
    cwe_ids: row.cwe_ids,
    locations: row.locations,
    instance: row.instance ?? null,
  });
}

function mergedText(
  group: NormalizedCandidate[],
  field: "summary" | "evidence" | "context",
): string {
  const values = new Set<string>();
  for (const item of group) {
    const value = item[field];
    if (value !== undefined) values.add(value);
  }
  return [...values].sort(comparePythonStrings).join("\n");
}

export function combine(rows: NormalizedCandidate[]): CombinedCandidate[] {
  const groups = new Map<string, NormalizedCandidate[]>();
  for (const row of rows) {
    const key = identity(row);
    const group = groups.get(key);
    if (group === undefined) groups.set(key, [row]);
    else group.push(row);
  }
  const combined: CombinedCandidate[] = [];
  for (const [key, group] of [...groups.entries()].sort(([left], [right]) =>
    comparePythonStrings(left, right),
  )) {
    const first = group[0]!;
    const candidateId = createHash("sha256")
      .update(key)
      .digest("hex")
      .slice(0, 16);
    const result: CombinedCandidate = {
      candidate_id: `candidate-${candidateId}`,
      cwe_ids: first.cwe_ids,
      locations: first.locations,
      summary: mergedText(group, "summary"),
      evidence: mergedText(group, "evidence"),
    };
    const context = mergedText(group, "context");
    if (context) result.context = context;
    if (first.instance !== undefined) result.instance = first.instance;
    combined.push(result);
  }
  return combined;
}

async function* lines(source: string): AsyncGenerator<[number, string]> {
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  // Keep a trailing carriage return until the next chunk so CRLF stays together.
  const newline = /\r\n|\n|\r(?!$)/u;
  let remainder = "";
  let number = 0;
  for await (const chunk of createReadStream(source)) {
    remainder += decoder.decode(chunk as Buffer, { stream: true });
    let boundary = newline.exec(remainder);
    while (boundary !== null) {
      const end = boundary.index + boundary[0].length;
      number += 1;
      yield [number, remainder.slice(0, end)];
      remainder = remainder.slice(end);
      boundary = newline.exec(remainder);
    }
  }
  remainder += decoder.decode();
  if (remainder) yield [number + 1, remainder];
}

function expandUser(value: string): string {
  if (!value.startsWith("~")) return value;
  const boundary = value.search(
    process.platform === "win32" ? /[\\/]/u : /\//u,
  );
  const end = boundary === -1 ? value.length : boundary;
  const userName = value.slice(1, end);
  let userDirectory = homedir();
  if (userName && process.platform === "win32") {
    const currentUser = process.env["USERNAME"];
    if (userName !== currentUser) {
      if (basename(userDirectory) !== currentUser) {
        throw new Error("Could not determine home directory.");
      }
      userDirectory = join(dirname(userDirectory), userName);
    }
  } else if (userName) {
    const account =
      process.platform === "darwin"
        ? execFileSync("dscacheutil", ["-q", "user", "-a", "name", userName], {
            encoding: "utf8",
          })
        : execFileSync("getent", ["passwd", userName], { encoding: "utf8" });
    const directory =
      process.platform === "darwin"
        ? /^dir: (.*)$/mu.exec(account)?.[1]
        : account.trimEnd().split(":")[5];
    if (directory === undefined)
      throw new Error("Could not determine home directory.");
    userDirectory = directory;
  }
  return userDirectory + value.slice(end);
}

function isArgumentValue(value: string): boolean {
  return (
    !value.startsWith("-") ||
    value === "-" ||
    /^-(?:\p{Decimal_Number}+|\p{Decimal_Number}*\.\p{Decimal_Number}+)$/u.test(
      value,
    )
  );
}

function resolveLongOption(argument: string): {
  attachedValue?: string;
  option: string;
} {
  if (argument === "-h") return { option: "--help" };
  if (!argument.startsWith("--")) return { option: argument };
  const equals = argument.indexOf("=");
  const spelling = equals === -1 ? argument : argument.slice(0, equals);
  const exact = LONG_OPTIONS.find((option) => option === spelling);
  const matches =
    exact === undefined
      ? LONG_OPTIONS.filter((option) => option.startsWith(spelling))
      : [exact];
  if (matches.length === 0) return { option: argument };
  if (matches.length > 1) {
    throw new Error(`ambiguous option ${spelling}`);
  }
  return {
    option: matches[0]!,
    ...(equals === -1 ? {} : { attachedValue: argument.slice(equals + 1) }),
  };
}

function parseArguments(argv: string[]): CliArguments | undefined {
  let inputs: string[] | undefined;
  let output: string | undefined;
  let repoRoot: string | undefined;
  let scopePath: string | undefined;
  let allowMissingInScope = false;
  const unrecognized: string[] = [];
  const takeValue = (
    index: number,
    option: string,
    attachedValue: string | undefined,
  ): string => {
    if (attachedValue !== undefined) return attachedValue;
    const value = argv[index + 1];
    if (value === undefined || !isArgumentValue(value)) {
      throw new Error(`${option}: expected a value`);
    }
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    const { attachedValue, option } = resolveLongOption(argument);
    if (option === "--input") {
      const values: string[] =
        attachedValue === undefined ? [] : [attachedValue];
      while (
        attachedValue === undefined &&
        argv[index + 1] !== undefined &&
        isArgumentValue(argv[index + 1]!)
      ) {
        values.push(argv[(index += 1)]!);
      }
      if (values.length === 0)
        throw new Error("--input: expected one or more values");
      inputs = values;
    } else if (option === "--out") {
      output = takeValue(index, option, attachedValue);
      if (attachedValue === undefined) index += 1;
    } else if (option === "--repo-root") {
      repoRoot = takeValue(index, option, attachedValue);
      if (attachedValue === undefined) index += 1;
    } else if (option === "--in-scope-files") {
      scopePath = takeValue(index, option, attachedValue);
      if (attachedValue === undefined) index += 1;
    } else if (option === "--allow-missing-in-scope" || option === "--help") {
      if (attachedValue !== undefined) {
        throw new Error(`${option}: does not take a value`);
      }
      if (option === "--help") return undefined;
      allowMissingInScope = true;
    } else {
      unrecognized.push(argument);
    }
  }
  if (unrecognized.length > 0)
    throw new Error(`unrecognized arguments ${unrecognized.join(" ")}`);
  if (inputs === undefined) throw new Error("--input is required");
  if (output === undefined) throw new Error("--out is required");
  if (repoRoot === undefined) throw new Error("--repo-root is required");
  if (scopePath === undefined) throw new Error("--in-scope-files is required");
  return { inputs, output, repoRoot, scopePath, allowMissingInScope };
}

function writeCombined(output: string, rows: CombinedCandidate[]): void {
  mkdirSync(dirname(output), { recursive: true });
  const directory = mkdtempSync(
    join(dirname(output), `.${parse(output).base}.`),
  );
  const temporary = join(directory, "output");
  try {
    const descriptor = openSync(temporary, "wx", 0o600);
    try {
      for (const row of rows) {
        writeFileSync(descriptor, `${canonicalJson(row)}${EOL}`, {
          encoding: "utf8",
        });
      }
    } finally {
      closeSync(descriptor);
    }
    renameSync(temporary, output);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

async function normalizeCandidates(
  args: CliArguments,
): Promise<[number, number, string]> {
  const repoRoot = realpathSync.native(expandUser(args.repoRoot));
  if (!statSync(repoRoot).isDirectory()) {
    throw new Error("--repo-root: expected a directory");
  }
  const output = resolveAllowMissing(expandUser(args.output));
  const scopePath = realpathSync.native(expandUser(args.scopePath));
  const inputs = [
    ...new Set(
      args.inputs.map((value) => realpathSync.native(expandUser(value))),
    ),
  ].sort(comparePythonStrings);
  if (inputs.some((input) => relative(input, output) === ""))
    throw new Error("--out: must not also be an input");
  if (relative(scopePath, output) === "") {
    throw new Error("--out: must not replace --in-scope-files");
  }
  const scope = readScope(scopePath, repoRoot, args.allowMissingInScope);
  const lineCounts = new Map<string, number>();
  const rows: NormalizedCandidate[] = [];
  for (const source of inputs) {
    for await (const [number, line] of lines(source)) {
      if (!pythonStrip(line)) continue;
      try {
        const value: unknown = JSON.parse(
          line,
          (key, value: unknown, context?: { source?: string }) => {
            if (
              (key === "start_line" || key === "end_line") &&
              typeof value === "number" &&
              /[.eE]/u.test(context?.source ?? "")
            ) {
              throw new Error(`${key}: expected a positive integer`);
            }
            return value;
          },
        );
        if (!isObject(value)) throw new Error("expected a JSON object");
        rows.push(normalizeCandidate(value, repoRoot, scope, lineCounts));
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`${source} row ${number}: ${message}`);
      }
    }
  }
  const combined = combine(rows);
  writeCombined(output, combined);
  return [rows.length, combined.length, output];
}

const HELP = `Validate and combine security-scan candidates into deterministic JSONL.

Usage: normalize_candidates.mjs --input <path> [path ...] --out <path> --repo-root <path> --in-scope-files <path> [--allow-missing-in-scope]`;

async function runCli(): Promise<void> {
  try {
    const args = parseArguments(process.argv.slice(2));
    if (args === undefined) {
      process.stdout.write(`${HELP.replaceAll("\n", EOL)}${EOL}`);
      return;
    }
    const [rows, combined, output] = await normalizeCandidates(args);
    process.stdout.write(
      `Combined ${rows} candidate rows into ${combined} rows in ${output}${EOL}`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`normalize_candidates: ${message}${EOL}`);
    process.exitCode = 2;
  }
}

const entrypoint = process.argv[1];
if (
  entrypoint !== undefined &&
  realpathSync(fileURLToPath(import.meta.url)) === realpathSync(entrypoint)
) {
  await runCli();
}

import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const ROLES = [
  "entrypoint",
  "entrypoint/wrapper",
  "source",
  "root_control",
  "sink",
  "concrete_implementation",
  "evidence",
] as const;
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

interface Location {
  path: string;
  start_line: number;
  end_line: number;
  role: (typeof ROLES)[number];
}

interface NormalizedCandidate {
  cwe_ids: string[];
  locations: Location[];
  summary: string;
  evidence: string;
  context?: string;
  instance?: string;
}

type CombinedCandidate = NormalizedCandidate & { candidate_id: string };

function object(
  value: unknown,
  fields: ReadonlySet<string>,
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("expected an object");
  }
  const extra = Object.keys(value).filter((key) => !fields.has(key));
  if (extra.length) throw new Error(`unsupported fields: ${extra.join(", ")}`);
  return value as Record<string, unknown>;
}

function text(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${field}: expected a non-empty string`);
  }
  return value.trim();
}

function positiveLine(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error(`${field}: expected a positive integer`);
  }
  return value;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isMissingFile(error: unknown): boolean {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}

function readLines(path: string): string[] {
  return new TextDecoder("utf-8", { fatal: true })
    .decode(readFileSync(path))
    .split(/\r?\n/u);
}

function repoFile(value: unknown, repoRoot: string) {
  if (typeof value !== "string" || !value || value.includes("\0")) {
    throw new Error("path: expected a repository-relative file");
  }
  const raw =
    process.platform === "win32" ? value.replaceAll("\\", "/") : value;
  if (
    isAbsolute(raw) ||
    raw.split("/").includes("..") ||
    (process.platform === "win32" && /^[A-Za-z]:/u.test(raw))
  ) {
    throw new Error(
      "path: expected a repository-relative path without traversal",
    );
  }
  const source = realpathSync.native(resolve(repoRoot, raw));
  const path = relative(repoRoot, source);
  if (path === ".." || path.startsWith(`..${sep}`) || isAbsolute(path)) {
    throw new Error("path: must resolve inside --repo-root");
  }
  if (!statSync(source).isFile())
    throw new Error("path: expected a regular file");
  return { path: path.split(sep).join("/"), source };
}

function cweIds(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error("cwe_ids: expected an array");
  const found = new Set<bigint>();
  for (const item of value) {
    const match = typeof item === "string" && /^CWE-(\d+)$/iu.exec(item.trim());
    if (!match || BigInt(match[1]!) < 1n) {
      throw new Error(`cwe_ids: unsupported value ${JSON.stringify(item)}`);
    }
    found.add(BigInt(match[1]!));
  }
  return [...found]
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))
    .map((number) => `CWE-${number}`);
}

function countLines(path: string): number {
  const contents = readFileSync(path, "utf8");
  return contents === ""
    ? 0
    : contents.split("\n").length - (contents.endsWith("\n") ? 1 : 0);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function normalizeLocations(
  value: unknown,
  repoRoot: string,
  lineCounts: Map<string, number>,
): Location[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error("locations: expected a non-empty array");
  }
  const locations = new Map<string, Location>();
  for (const raw of value) {
    const item = object(raw, LOCATION_FIELDS);
    const { path, source } = repoFile(item["path"], repoRoot);
    if (!path.trim() || /[\\:]/u.test(path)) {
      throw new Error("path: expected a safe repository-relative POSIX path");
    }
    const start = positiveLine(item["start_line"], "start_line");
    const end =
      item["end_line"] === undefined
        ? start
        : positiveLine(item["end_line"], "end_line");
    const lineCount = lineCounts.get(source) ?? countLines(source);
    lineCounts.set(source, lineCount);
    if (end < start || end > lineCount) {
      throw new Error(
        `invalid line range ${start}-${end} for ${path} (${lineCount} lines)`,
      );
    }
    const role = ROLES.find((role) => role === item["role"]);
    if (role === undefined) throw new Error("role: unsupported value");
    const location = { path, start_line: start, end_line: end, role };
    locations.set(JSON.stringify(location), location);
  }
  return [...locations.values()].sort(
    (left, right) =>
      ROLES.indexOf(left.role) - ROLES.indexOf(right.role) ||
      compareStrings(left.path, right.path) ||
      left.start_line - right.start_line ||
      left.end_line - right.end_line,
  );
}

function readScope(
  path: string,
  repoRoot: string,
  allowMissing: boolean,
): Set<string> {
  const scope = new Set<string>();
  for (const [index, line] of readLines(path).entries()) {
    if (!line) continue;
    try {
      scope.add(repoFile(line, repoRoot).path);
    } catch (error) {
      if (!allowMissing || !isMissingFile(error)) {
        throw new Error(`in-scope file row ${index + 1}: ${message(error)}`);
      }
    }
  }
  return scope;
}

export function normalizeCandidate(
  value: unknown,
  repoRoot: string,
  scope: Set<string>,
  lineCounts: Map<string, number>,
): NormalizedCandidate {
  const row = object(value, FIELDS);
  const locations = normalizeLocations(row["locations"], repoRoot, lineCounts);
  if (!locations.some((location) => scope.has(location.path))) {
    throw new Error("locations: expected at least one in-scope file");
  }
  const result: NormalizedCandidate = {
    cwe_ids: cweIds(row["cwe_ids"]),
    locations,
    summary: text(row["summary"], "summary"),
    evidence: text(row["evidence"], "evidence"),
  };
  for (const field of ["context", "instance"] as const) {
    if (row[field] != null) result[field] = text(row[field], field);
  }
  return result;
}

function identity({
  cwe_ids,
  locations,
  instance,
}: NormalizedCandidate): string {
  return JSON.stringify({ cwe_ids, locations, instance });
}

function mergedText(
  rows: NormalizedCandidate[],
  field: "summary" | "evidence" | "context",
): string {
  const values = rows
    .map((row) => row[field])
    .filter((value) => value !== undefined);
  return [...new Set(values)].sort().join("\n");
}

export function combine(rows: NormalizedCandidate[]): CombinedCandidate[] {
  return [...Map.groupBy(rows, identity)]
    .sort(([left], [right]) => compareStrings(left, right))
    .map(([key, group]) => {
      const { cwe_ids, locations, instance } = group[0]!;
      return {
        candidate_id: `candidate-${createHash("sha256").update(key).digest("hex").slice(0, 16)}`,
        cwe_ids,
        locations,
        summary: mergedText(group, "summary"),
        evidence: mergedText(group, "evidence"),
        context: mergedText(group, "context") || undefined,
        instance,
      };
    });
}

function writeCombined(
  output: string,
  rows: CombinedCandidate[],
  inputs: string[],
): void {
  try {
    const target = realpathSync.native(output);
    if (inputs.some((input) => relative(input, target) === "")) {
      throw new Error("--out: must not replace an input or the scope file");
    }
  } catch (error) {
    if (!isMissingFile(error)) throw error;
  }
  mkdirSync(dirname(output), { recursive: true });
  const directory = mkdtempSync(join(dirname(output), ".normalize-"));
  const temporary = join(directory, "candidates.jsonl");
  try {
    writeFileSync(
      temporary,
      rows.map((row) => `${JSON.stringify(row)}\n`).join(""),
      { mode: 0o600 },
    );
    renameSync(temporary, output);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

const HELP = `Validate and combine security-scan candidates into deterministic JSONL.

Usage: normalize_candidates.mjs --input <file> [--input <file> ...] --out <file> --repo-root <directory> --in-scope-files <file> [--allow-missing-in-scope]

Input and scope files use LF or CRLF lines. Missing scope entries are skipped when allowed.
Use full option names. The invoking shell expands home paths.`;

function main(argv: string[]): void {
  const { values } = parseArgs({
    args: argv,
    options: {
      input: { type: "string", multiple: true },
      out: { type: "string" },
      "repo-root": { type: "string" },
      "in-scope-files": { type: "string" },
      "allow-missing-in-scope": { type: "boolean", default: false },
      help: { type: "boolean", short: "h" },
    },
  });
  if (values.help) {
    console.log(HELP);
    return;
  }
  const {
    input: inputFiles,
    out,
    "repo-root": root,
    "in-scope-files": scopeFile,
  } = values;
  if (
    !inputFiles?.length ||
    out === undefined ||
    root === undefined ||
    scopeFile === undefined
  ) {
    throw new Error(
      "--input, --out, --repo-root and --in-scope-files are required",
    );
  }
  const repoRoot = realpathSync.native(resolve(root));
  if (!statSync(repoRoot).isDirectory())
    throw new Error("--repo-root: expected a directory");
  const scopePath = realpathSync.native(resolve(scopeFile));
  const inputs = [
    ...new Set(inputFiles.map((path) => realpathSync.native(resolve(path)))),
  ];
  const output = resolve(out);
  const scope = readScope(
    scopePath,
    repoRoot,
    values["allow-missing-in-scope"],
  );
  const lineCounts = new Map<string, number>();
  const rows: NormalizedCandidate[] = [];
  for (const source of inputs) {
    for (const [index, line] of readLines(source).entries()) {
      if (!line.trim()) continue;
      try {
        rows.push(
          normalizeCandidate(JSON.parse(line), repoRoot, scope, lineCounts),
        );
      } catch (error) {
        throw new Error(`${source} row ${index + 1}: ${message(error)}`);
      }
    }
  }
  const combined = combine(rows);
  writeCombined(output, combined, [...inputs, scopePath]);
  console.log(
    `Combined ${rows.length} candidate rows into ${combined.length} rows in ${output}`,
  );
}

const entrypoint = process.argv[1];
if (
  entrypoint !== undefined &&
  realpathSync.native(fileURLToPath(import.meta.url)) ===
    realpathSync.native(entrypoint)
) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`normalize_candidates: ${message(error)}`);
    process.exitCode = 2;
  }
}

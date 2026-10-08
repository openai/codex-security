import { dirname } from "node:path";
import { parseArgs } from "node:util";
import {
  filesystemErrorMessage,
  mkdir,
  normalizePath,
  readUtf8Lines,
  writeFile,
} from "./helper-files";
import { encodePosixPath } from "./posix-path";
import { formatDiagnostic, object, parseJson } from "./json";
import { expandHome } from "./resolve-security-md";

export interface RankRow {
  path: string;
  area: string;
  preview?: string;
  reason?: string;
  score?: number;
  include?: boolean;
}
const blank = (value: string) => value.trim().length === 0;
export function compare(left: string, right: string): number {
  const a = Array.from(left, (character) => character.codePointAt(0)!);
  const b = Array.from(right, (character) => character.codePointAt(0)!);
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index]! - b[index]!;
  }
  return a.length - b.length;
}

export function missingNames(
  expected: Iterable<string>,
  actual: Iterable<string>,
): string[] {
  const present = new Set(actual);
  return Array.from(expected)
    .filter((name) => !present.has(name))
    .sort(compare);
}

export function loadRankRows(
  path: string,
  selection: boolean,
  label = selection ? "Rank output" : "Rank input",
): RankRow[] {
  const fields = selection
    ? ["path", "area", "score", "include", "reason"]
    : ["path", "area", "preview"];
  const rows = Array.from(readUtf8Lines(path, label), (line, index) => {
    const fail = (message: string): never => {
      throw new Error(`${path}:${index + 1}: ${message}`);
    };
    if (blank(line)) fail("blank JSONL rows are not allowed");
    let row: unknown;
    try {
      row = parseJson(line);
    } catch (error) {
      if (error instanceof SyntaxError) fail(`invalid JSON: ${error.message}`);
      throw error;
    }
    if (!object(row)) return fail("expected a JSON object");
    const actual = Object.keys(row);
    const missing = missingNames(fields, actual);
    const unexpected = missingNames(actual, fields);
    const details: string[] = [];
    if (missing.length)
      details.push(`missing fields ${formatDiagnostic(missing)}`);
    if (unexpected.length)
      details.push(`unexpected fields ${formatDiagnostic(unexpected)}`);
    if (details.length) fail(details.join("; "));
    for (const field of selection
      ? ["path", "area"]
      : ["path", "area", "preview"]) {
      if (
        typeof row[field] !== "string" ||
        (field === "path" && blank(row[field]))
      )
        fail(
          `${field} must be ${field === "path" ? "a non-empty string" : "a string"}`,
        );
    }
    if (selection) {
      if (typeof row.score !== "number" || !Number.isInteger(row.score))
        fail("score must be an integer from 1 through 10");
      if ((row.score as number) < 1 || (row.score as number) > 10)
        fail("score must be from 1 through 10");
      if (typeof row.include !== "boolean") fail("include must be a boolean");
      if (typeof row.reason !== "string" || blank(row.reason))
        fail("reason must be a non-empty string");
    }
    return row as unknown as RankRow;
  });
  return rows;
}

export function requireUniquePaths(rows: RankRow[], label: string): void {
  const seen = new Set<string>(),
    duplicates = new Set<string>();
  for (const row of rows) {
    if (seen.has(row.path)) duplicates.add(row.path);
    seen.add(row.path);
  }
  if (duplicates.size)
    throw new Error(
      `${label} contains duplicate paths: ${formatDiagnostic([...duplicates].sort(compare))}`,
    );
}

export function writeRankRows(output: string, rows: RankRow[]): void {
  mkdir(dirname(output));
  function* contents(): Iterable<Buffer> {
    for (const row of rows) {
      const json = JSON.stringify(row);
      yield Buffer.from(json + (process.platform === "win32" ? "\r\n" : "\n"));
    }
  }
  writeFile(output, contents());
}

export class ArgumentError extends Error {}
export function argumentsFor(
  args: string[],
  required: readonly string[],
  integerOptions: readonly string[] = [],
): Record<string, string | number | true> {
  try {
    const { values }: { values: Record<string, string | boolean | undefined> } =
      parseArgs({
        args,
        options: {
          ...Object.fromEntries(
            [...required, ...integerOptions].map((name) => [
              name,
              { type: "string" as const },
            ]),
          ),
          help: { type: "boolean", short: "h" },
        },
      });
    if (values.help) return { help: true };
    const missing = required.filter((name) => values[name] === undefined);
    if (missing.length)
      throw new Error(
        `Missing required options: ${missing.map((name) => `--${name}`).join(", ")}`,
      );
    const result: Record<string, string | number | true> = {};
    for (const [name, value] of Object.entries(values)) {
      if (typeof value !== "string") continue;
      if (!integerOptions.includes(name)) result[name] = value;
      else {
        const number = Number(value);
        if (!/^[+-]?\d+$/u.test(value.trim()) || !Number.isInteger(number))
          throw new Error(`--${name} must be an integer`);
        result[name] = number;
      }
    }
    return result;
  } catch (error) {
    throw new ArgumentError(
      error instanceof Error ? error.message : String(error),
    );
  }
}

export function print(message: string, stderr = false): void {
  let text = message + "\n";
  if (stderr)
    text = text.replace(
      /[\ud800-\udfff]/gu,
      (character) =>
        `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
    );
  (stderr ? process.stderr : process.stdout).write(
    process.platform === "win32"
      ? text.replaceAll("\n", "\r\n")
      : stderr
        ? text
        : encodePosixPath(text),
  );
}

export function worklistPath(
  value: string,
  posixHome: string | undefined,
): string {
  return normalizePath(expandHome(normalizePath(value), posixHome));
}

export function reportCommandError(
  error: unknown,
  command: string,
  usage: string,
): number {
  const message = filesystemErrorMessage(error);
  print(
    error instanceof ArgumentError
      ? `${usage}\n${command}: error: ${message}`
      : message,
    true,
  );
  return error instanceof ArgumentError ? 2 : 1;
}

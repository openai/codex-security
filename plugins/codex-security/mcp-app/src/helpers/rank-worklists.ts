import { decodeUtf8 } from "./utf8";
import { dirname } from "node:path";
import { mkdir, readFile, writeFile } from "./helper-files";
import { encodePosixPath } from "./posix-path";
import { JsonSyntaxError, object, parseJson, pythonRepr } from "./python-json";
import { expandHome, parsedPath } from "./resolve-security-md";

export interface RankRow {
  path: string;
  area: string;
  preview?: string;
  reason?: string;
  score?: bigint;
  include?: boolean;
}
const trim = (value: string) =>
  value.replace(
    /^[\p{White_Space}\u001c-\u001f]+|[\p{White_Space}\u001c-\u001f]+$/gu,
    "",
  );
export function compare(left: string, right: string): number {
  const a = Array.from(left, (character) => character.codePointAt(0)!);
  const b = Array.from(right, (character) => character.codePointAt(0)!);
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index]! - b[index]!;
  }
  return a.length - b.length;
}

export function loadRankRows(
  path: string,
  selection: boolean,
): RankRow[] {
  const contents = decodeUtf8(readFile(path));
  const lines = contents === "" ? [] : contents.split(/\r\n|[\r\n]/u);
  if (lines.at(-1) === "") lines.pop();
  const fields = selection
    ? ["path", "area", "score", "include", "reason"]
    : ["path", "area", "preview"];
  const rows = lines.map((line, index) => {
    const fail = (message: string): never => {
      throw new Error(`${path}:${index + 1}: ${message}`);
    };
    if (trim(line) === "") fail("blank JSONL rows are not allowed");
    let row: unknown;
    try {
      row = parseJson(line);
    } catch (error) {
      if (error instanceof JsonSyntaxError)
        fail(
          `invalid JSON: ${error.message.replace(/: line \d+ column \d+ \(char \d+\)$/u, "")}`,
        );
      throw error;
    }
    if (!object(row)) return fail("expected a JSON object");
    const missing = fields
      .filter((field) => !Object.hasOwn(row, field))
      .sort(compare);
    const unexpected = Object.keys(row)
      .filter((field) => !fields.includes(field))
      .sort(compare);
    const details: string[] = [];
    if (missing.length) details.push(`missing fields ${pythonRepr(missing)}`);
    if (unexpected.length)
      details.push(`unexpected fields ${pythonRepr(unexpected)}`);
    if (details.length) fail(details.join("; "));
    for (const field of selection
      ? ["path", "area"]
      : ["path", "area", "preview"]) {
      if (
        typeof row[field] !== "string" ||
        (field === "path" && trim(row[field]) === "")
      )
        fail(
          `${field} must be ${field === "path" ? "a non-empty string" : "a string"}`,
        );
    }
    if (selection) {
      if (typeof row.score !== "bigint")
        fail("score must be an integer from 1 through 10");
      if ((row.score as bigint) < 1n || (row.score as bigint) > 10n)
        fail("score must be from 1 through 10");
      if (typeof row.include !== "boolean") fail("include must be a boolean");
      if (typeof row.reason !== "string" || trim(row.reason) === "")
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
      `${label} contains duplicate paths: ${pythonRepr([...duplicates].sort(compare))}`,
    );
}

export function writeRankRows(output: string, rows: RankRow[]): void {
  mkdir(dirname(output));
  function* contents(): Iterable<Buffer> {
    for (const row of rows) {
      const json = JSON.stringify(row, (_key, value: unknown) =>
        typeof value === "bigint" ? Number(value) : value,
      ).replace(
        /[\u007f-\uffff]/g,
        (character) =>
          `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
      );
      yield Buffer.from(json + (process.platform === "win32" ? "\r\n" : "\n"));
    }
  }
  writeFile(output, contents());
}

export class ArgumentError extends Error {}
function integer(value: string, option: string): bigint {
  const text = value.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
  if (!/^[+-]?\p{Decimal_Number}+(?:_\p{Decimal_Number}+)*$/u.test(text))
    throw new ArgumentError(
      `argument --${option}: invalid int value: ${pythonRepr(value)}`,
    );
  return BigInt(
    Array.from(text.replaceAll("_", ""), (character) => {
      if (!/\p{Decimal_Number}/u.test(character)) return character;
      const point = character.codePointAt(0)!;
      let start = point;
      while (/\p{Decimal_Number}/u.test(String.fromCodePoint(start - 1)))
        start--;
      return String((point - start) % 10);
    }).join(""),
  );
}

export function argumentsFor(
  args: string[],
  required: readonly string[],
  integerOptions: readonly string[] = [],
): Record<string, string | bigint | true> {
  const names = [...required, "help", ...integerOptions];
  const values: Record<string, string | bigint | true> = {};
  const extra: string[] = [];
  const looksOptional = (arg: string) =>
    arg.startsWith("-") &&
    arg !== "-" &&
    !arg.includes(" ") &&
    !/^-(?:\p{Decimal_Number}+|\p{Decimal_Number}*\.\p{Decimal_Number}+)\n?$/u.test(
      arg,
    );
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (arg === "--") {
      extra.push(...args.slice(index));
      break;
    }
    const equals = arg.indexOf("=");
    const option = equals === -1 ? arg : arg.slice(0, equals);
    const matches = option.startsWith("--")
      ? names.filter((name) => `--${name}`.startsWith(option))
      : [];
    const name =
      names.find((name) => option === `--${name}`) ??
      (arg.startsWith("-h")
        ? "help"
        : matches.length === 1
          ? matches[0]
          : undefined);
    if (matches.length > 1 && !name)
      throw new ArgumentError(
        `ambiguous option: ${arg} could match ${matches.map((name) => `--${name}`).join(", ")}`,
      );
    if (!name) {
      extra.push(arg);
      continue;
    }
    if (name === "help") {
      if (equals !== -1)
        throw new ArgumentError(
          `argument -h/--help: ignored explicit argument ${pythonRepr(arg.slice(equals + 1))}`,
        );
      return { help: true };
    }
    let value: string;
    if (equals !== -1) value = arg.slice(equals + 1);
    else {
      if (index + 1 === args.length || looksOptional(args[index + 1]!))
        throw new ArgumentError(`argument --${name}: expected one argument`);
      value = args[++index]!;
    }
    values[name] = integerOptions.includes(name) ? integer(value, name) : value;
  }
  const missing = required.filter((name) => values[name] === undefined);
  if (missing.length)
    throw new ArgumentError(
      `the following arguments are required: ${missing.map((name) => `--${name}`).join(", ")}`,
    );
  if (extra.length)
    throw new ArgumentError(`unrecognized arguments: ${extra.join(" ")}`);
  return values;
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
  return parsedPath(expandHome(parsedPath(value), posixHome));
}

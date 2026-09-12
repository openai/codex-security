import { statSync } from "node:fs";
import { basename, sep } from "node:path";
import { unixBinding, windowsBinding } from "../native";
import {
  pathText,
  widePath,
  windowsFileSystem,
  windowsJoin,
} from "../../../native/windows-files.mjs";
import { mkdir } from "./helper-files";
import { decodePosixBytes, encodePosixPath } from "./posix-path";
import { pythonRepr } from "./python-json";
import { parsedPath } from "./resolve-security-md";
import {
  ArgumentError,
  argumentsFor,
  compare,
  loadRankRows,
  print,
  requireUniquePaths,
  worklistPath,
  writeRankRows,
  type RankRow,
} from "./rank-worklists";

type Command =
  | "make-rank-shards"
  | "validate-rank-shard"
  | "merge-rank-outputs";

export function childPath(directory: string, name: string): string {
  return parsedPath(
    process.platform === "win32"
      ? windowsJoin(directory, name)
      : directory + sep + name,
  );
}

function shardNames(directory: string, kind: "input" | "output"): string[] {
  const matches = (name: string) => {
    // Python's Unicode case-insensitive globbing includes these ASCII equivalents.
    const matched =
      process.platform === "win32"
        ? name.replace(/[İı]/gu, "i").replace(/ſ/gu, "s").toLowerCase()
        : name;
    return (
      matched.startsWith("rank-shard-") && matched.endsWith(`.${kind}.jsonl`)
    );
  };
  try {
    if (process.platform === "win32")
      return windowsFileSystem(windowsBinding())
        .entriesWithTypes(widePath(directory))
        .map((entry) => pathText(entry.name))
        .filter(matches);
    const { errno, value } = unixBinding().directoryEntries(
      encodePosixPath(directory),
      false,
    );
    return errno
      ? []
      : value.map((entry) => decodePosixBytes(entry.name)).filter(matches);
  } catch (error) {
    // pathlib glob ignores directory enumeration OSErrors.
    if (!(error instanceof Error) || !("errno" in error || "winerror" in error))
      throw error;
    return [];
  }
}

function discoverInputShards(directory: string): string[] {
  let isDirectory = false;
  try {
    isDirectory = (
      process.platform === "win32"
        ? windowsFileSystem(windowsBinding()).stat(widePath(directory))
        : statSync(encodePosixPath(directory))
    ).isDirectory();
  } catch (error) {
    const { code, winerror } = error as NodeJS.ErrnoException & {
      winerror?: number;
    };
    if (
      !["ENOENT", "ENOTDIR", "EBADF", "ELOOP"].includes(code ?? "") &&
      winerror !== 21 &&
      winerror !== 123
    )
      throw error;
  }
  if (!isDirectory)
    throw new Error(`Rank shard directory missing: ${directory}`);
  const names = shardNames(directory, "input");
  const actual = new Set(names);
  const expected = names.map(
    (_, index) =>
      `rank-shard-${String(index + 1).padStart(4, "0")}.input.jsonl`,
  );
  if (expected.some((name) => !actual.has(name)))
    throw new Error(
      `Rank input shards must use contiguous canonical names; expected=${pythonRepr(expected)}; actual=${pythonRepr(names)}`,
    );
  return expected.map((name) => childPath(directory, name));
}

function validateShard(input: string, output: string): [RankRow[], RankRow[]] {
  const inputs = loadRankRows(input, false);
  requireUniquePaths(inputs, `Rank input shard ${basename(input)}`);
  const outputs = loadRankRows(output, true);
  requireUniquePaths(outputs, `Rank output shard ${basename(output)}`);
  const expected = new Map(inputs.map((row) => [row.path, row.area]));
  const actual = new Set(outputs.map((row) => row.path));
  const missing = [...expected.keys()]
    .filter((path) => !actual.has(path))
    .sort(compare);
  const unknown = [...actual]
    .filter((path) => !expected.has(path))
    .sort(compare);
  if (missing.length || unknown.length)
    throw new Error(
      `${output}: paths do not match its input shard; missing=${pythonRepr(missing)}; unknown=${pythonRepr(unknown)}`,
    );
  for (const row of outputs)
    if (row.area !== expected.get(row.path))
      throw new Error(
        `${output}: area does not match rank input for ${row.path}`,
      );
  return [inputs, outputs];
}

function makeShards(
  inputArgument: string,
  directoryArgument: string,
  maximum: bigint,
  posixHome: string | undefined,
): void {
  if (maximum < 1n) throw new Error("--max-rows must be at least 1");
  const input = worklistPath(inputArgument, posixHome);
  const rows = loadRankRows(input, false);
  requireUniquePaths(rows, "Rank input");
  const directory = worklistPath(directoryArgument, posixHome);
  mkdir(directory);
  if (
    shardNames(directory, "input").length ||
    shardNames(directory, "output").length
  )
    throw new Error(
      `Rank shard directory already contains shard files: ${directory}`,
    );
  let count = 0;
  const size = Number(maximum);
  for (let start = 0; start < rows.length; start += size) {
    const name = `rank-shard-${String(++count).padStart(4, "0")}.input.jsonl`;
    writeRankRows(childPath(directory, name), rows.slice(start, start + size));
  }
  print(`Wrote ${count} rank shards to ${directory}`);
}

function mergeShards(
  inputArgument: string,
  directoryArgument: string,
  outputArgument: string,
  posixHome: string | undefined,
): void {
  const input = worklistPath(inputArgument, posixHome);
  const authoritative = loadRankRows(input, false);
  requireUniquePaths(authoritative, "Rank input");
  const directory = worklistPath(directoryArgument, posixHome);
  const shards = discoverInputShards(directory);
  const expected = new Set(
    shards.map((path) =>
      basename(path).replaceAll(".input.jsonl", ".output.jsonl"),
    ),
  );
  const actual = new Set(shardNames(directory, "output"));
  const missing = [...expected]
    .filter((name) => !actual.has(name))
    .sort(compare);
  const unexpected = [...actual]
    .filter((name) => !expected.has(name))
    .sort(compare);
  if (missing.length || unexpected.length) {
    const details: string[] = [];
    if (missing.length)
      details.push(`missing output shards ${pythonRepr(missing)}`);
    if (unexpected.length)
      details.push(`unexpected output shards ${pythonRepr(unexpected)}`);
    throw new Error(`Rank shard outputs are incomplete: ${details.join("; ")}`);
  }
  const shardedInputs: RankRow[] = [];
  const outputByPath = new Map<string, RankRow>();
  for (const shard of shards) {
    const outputShard = childPath(
      directory,
      basename(shard).replaceAll(".input.jsonl", ".output.jsonl"),
    );
    const [inputs, outputs] = validateShard(shard, outputShard);
    for (const row of inputs) shardedInputs.push(row);
    for (const row of outputs) {
      if (outputByPath.has(row.path))
        throw new Error(`Rank outputs contain duplicate path: ${row.path}`);
      outputByPath.set(row.path, row);
    }
  }
  if (
    shardedInputs.length !== authoritative.length ||
    shardedInputs.some((row, index) => {
      const expectedRow = authoritative[index]!;
      return (
        row.path !== expectedRow.path ||
        row.area !== expectedRow.area ||
        row.preview !== expectedRow.preview
      );
    })
  )
    throw new Error(
      "Rank input shards do not exactly partition the authoritative rank input",
    );
  const merged = authoritative.map((row) => outputByPath.get(row.path)!);
  const output = worklistPath(outputArgument, posixHome);
  writeRankRows(output, merged);
  print(`Merged ${merged.length} ranking rows into ${output}`);
}

export function rankShardsCommand(
  command: Command,
  args: string[],
  posixHome = process.env.HOME,
): number {
  const required =
    command === "make-rank-shards"
      ? ["rank-input", "out-dir"]
      : command === "validate-rank-shard"
        ? ["input", "output"]
        : ["rank-input", "shard-dir", "out"];
  const integers = command === "make-rank-shards" ? ["max-rows"] : [];
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} [-h] ${required.map((name) => `--${name} PATH`).join(" ")}${integers.length ? " [--max-rows INT]" : ""}`;
  try {
    const values = argumentsFor(args, required, integers);
    if (values.help) {
      const description =
        command === "make-rank-shards"
          ? "Partition rank_input.jsonl into deterministic worker input shards."
          : command === "validate-rank-shard"
            ? "Validate one worker output against its rank input shard."
            : "Validate worker shard outputs and create rank_output.jsonl.";
      print(
        `${usage}\n\n${description}\n\noptions:\n  -h, --help  show this help message and exit\n${required.map((name) => `  --${name} PATH`).join("\n")}${integers.length ? "\n  --max-rows INT  Maximum rows per shard. Defaults to 150." : ""}`,
      );
      return 0;
    }
    if (command === "make-rank-shards") {
      const maximum = (values["max-rows"] ?? 150n) as bigint;
      makeShards(
        values["rank-input"] as string,
        values["out-dir"] as string,
        maximum,
        posixHome,
      );
    } else if (command === "validate-rank-shard") {
      const input = worklistPath(values.input as string, posixHome);
      const output = worklistPath(values.output as string, posixHome);
      const [, rows] = validateShard(input, output);
      print(`Validated ${rows.length} ranking rows in ${output}`);
    } else {
      mergeShards(
        values["rank-input"] as string,
        values["shard-dir"] as string,
        values.out as string,
        posixHome,
      );
    }
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    print(
      error instanceof ArgumentError
        ? `${usage}\n${command}: error: ${message}`
        : message,
      true,
    );
    return error instanceof ArgumentError ? 2 : 1;
  }
}

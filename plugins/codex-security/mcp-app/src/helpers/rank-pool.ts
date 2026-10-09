import { isDeepStrictEqual as same } from "node:util";
import { createHash } from "node:crypto";
import { basename, dirname } from "node:path";
import { mkdir, readFile, writeFile } from "./helper-files";
import { formatDiagnostic, object, parseJson } from "./json";
import { decodeUtf8 } from "./utf8";
import { encodePosixPath } from "./posix-path";
import { resolvedPath } from "./resolve-security-md";
import {
  childPath,
  discoverInputShards,
  outputShardName,
  shardNames,
  validateShard,
} from "./rank-shards";
import {
  argumentsFor,
  compare,
  missingNames,
  print,
  reportCommandError,
  worklistPath,
} from "./rank-worklists";

type Command =
  "make-rank-pool-plan" | "validate-rank-worker" | "validate-rank-pool";
interface Worker {
  input_shards: string[];
  output_shards: string[];
  slot: number;
}

function requirePlanDirectory(plan: string, directory: string): void {
  const expected = childPath(dirname(plan), "rank_shards");
  const key = (value: string) =>
    process.platform === "win32"
      ? resolvedPath(Buffer.from(value, "utf16le"), false)
          .toString("utf16le")
          .toLowerCase()
      : resolvedPath(encodePosixPath(value), false).toString("latin1");
  if (key(directory) !== key(expected))
    throw new Error(
      `Rank shard directory must be the assignment plan's sibling rank_shards directory; expected=${expected}; actual=${directory}`,
    );
}

function makePlan(directory: string, slots: number, output: string): void {
  requirePlanDirectory(output, directory);
  const inputs = discoverInputShards(directory).map((path) => basename(path));
  const count = Math.min(inputs.length, slots, 6);
  const workers = Array.from({ length: count }, (_, index): Worker => {
    const assigned = inputs.filter(
      (_, inputIndex) => inputIndex % count === index,
    );
    return {
      input_shards: assigned,
      output_shards: assigned.map(outputShardName),
      slot: index + 1,
    };
  });
  const plan = {
    ranking_worker_count: count,
    schema_version: 1,
    shard_count: inputs.length,
    strategy: "round_robin",
    workers,
  };
  mkdir(dirname(output));
  writeFile(output, [
    Buffer.from(
      (JSON.stringify(plan, null, 2) + "\n").replaceAll(
        "\n",
        process.platform === "win32" ? "\r\n" : "\n",
      ),
    ),
  ]);
  print(
    `Assigned ${inputs.length} rank shards to ${count} ranking workers in ${output}`,
  );
}

function integer(value: unknown, label: string, minimum: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < minimum)
    throw new Error(`${label} must be an integer of at least ${minimum}`);
  return value;
}

function strings(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length === 0)
    throw new Error(`${label} must be a non-empty list`);
  if (value.some((item: unknown) => typeof item !== "string" || !item))
    throw new Error(`${label} entries must be non-empty strings`);
  return value as string[];
}

function fields(
  value: Record<string, unknown>,
  expected: string[],
  label: string,
): void {
  const actual = Object.keys(value);
  const missing = missingNames(expected, actual);
  const unexpected = missingNames(actual, expected);
  if (missing.length || unexpected.length)
    throw new Error(
      `${label} fields do not match schema; missing=${formatDiagnostic(missing)}; unexpected=${formatDiagnostic(unexpected)}`,
    );
}

function validatePlan(plan: string, directory: string) {
  requirePlanDirectory(plan, directory);
  const misplaced = [
    ...shardNames(dirname(plan), "input"),
    ...shardNames(dirname(plan), "output"),
  ].sort(compare);
  if (misplaced.length)
    throw new Error(
      `Rank shard artifacts must be stored in the assignment plan's sibling rank_shards directory; misplaced=${formatDiagnostic(misplaced)}`,
    );
  const inputs = discoverInputShards(directory);
  const inputNames = inputs.map((path) => basename(path));
  const outputNames = inputNames.map(outputShardName);
  const bytes = readFile(plan, "Rank pool plan");
  let payload: unknown;
  try {
    payload = parseJson(decodeUtf8(bytes).replace(/^\uFEFF/u, ""));
  } catch (error) {
    if (error instanceof SyntaxError)
      throw new Error(`${plan}: invalid JSON: ${error.message}`);
    throw error;
  }
  if (!object(payload)) throw new Error(`${plan}: expected a JSON object`);
  fields(
    payload,
    [
      "schema_version",
      "strategy",
      "shard_count",
      "ranking_worker_count",
      "workers",
    ],
    `${plan}: rank pool plan`,
  );
  if (integer(payload.schema_version, `${plan}: schema_version`, 1) !== 1)
    throw new Error(`${plan}: schema_version must be 1`);
  if (payload.strategy !== "round_robin")
    throw new Error(`${plan}: strategy must be round_robin`);
  const shardCount = integer(payload.shard_count, `${plan}: shard_count`, 0);
  if (shardCount !== inputs.length)
    throw new Error(
      `${plan}: shard_count does not match input shards; plan=${shardCount}; actual=${inputs.length}`,
    );
  const workerCount = integer(
    payload.ranking_worker_count,
    `${plan}: ranking_worker_count`,
    0,
  );
  if (shardCount > 0 && workerCount === 0)
    throw new Error(
      `${plan}: ranking_worker_count must be at least 1 when input shards exist`,
    );
  if (workerCount > shardCount)
    throw new Error(`${plan}: ranking_worker_count cannot exceed shard_count`);
  if (workerCount > 6)
    throw new Error(`${plan}: ranking_worker_count cannot exceed 6`);
  if (!Array.isArray(payload.workers) || payload.workers.length !== workerCount)
    throw new Error(
      `${plan}: workers must contain exactly ${workerCount} worker assignments`,
    );
  payload.workers.forEach((raw: unknown, index) => {
    const label = `${plan}: workers[${index}]`;
    if (!object(raw)) throw new Error(`${label} must be a JSON object`);
    fields(raw, ["slot", "input_shards", "output_shards"], label);
    const slot = integer(raw.slot, `${label}.slot`, 1);
    if (slot !== index + 1)
      throw new Error(`${label}.slot must be ${index + 1}`);
    const assignedInputs = strings(raw.input_shards, `${label}.input_shards`);
    const assignedOutputs = strings(
      raw.output_shards,
      `${label}.output_shards`,
    );
    if (assignedInputs.length !== assignedOutputs.length)
      throw new Error(
        `${label} input_shards and output_shards lengths must match`,
      );
    if (!same(assignedOutputs, assignedInputs.map(outputShardName)))
      throw new Error(`${label}.output_shards do not match its input_shards`);
  });
  const workers = payload.workers as Worker[];
  const counts = new Map<string, number>();
  for (const worker of workers)
    for (const name of worker.input_shards)
      counts.set(name, (counts.get(name) ?? 0) + 1);
  const missing = missingNames(inputNames, counts.keys());
  const duplicates = [...counts]
    .filter(([, count]) => count > 1)
    .map(([name]) => name)
    .sort(compare);
  const unexpected = missingNames(counts.keys(), inputNames);
  if (missing.length || duplicates.length || unexpected.length)
    throw new Error(
      `${plan}: pool plan must assign each input shard exactly once; missing=${formatDiagnostic(missing)}; duplicates=${formatDiagnostic(duplicates)}; unexpected=${formatDiagnostic(unexpected)}`,
    );
  for (const [index, worker] of workers.entries()) {
    const assigned = inputNames.filter(
      (_, inputIndex) => inputIndex % workers.length === index,
    );
    if (!same(worker.input_shards, assigned))
      throw new Error(
        `${plan}: worker slot ${index + 1} does not match the deterministic round_robin assignment`,
      );
  }
  return { inputs, outputNames, workers, bytes };
}

function validateWorker(
  plan: string,
  directory: string,
  slotArgument: unknown,
): void {
  const { workers, bytes } = validatePlan(plan, directory);
  const slot = integer(slotArgument, "--slot", 1);
  if (slot > workers.length)
    throw new Error(`--slot must be at most ${workers.length}`);
  const worker = workers[slot - 1]!;
  let rows = 0;
  const digest = createHash("sha256");
  for (const [index, name] of worker.input_shards.entries()) {
    const output = childPath(directory, worker.output_shards[index]!);
    const [, outputs] = validateShard(childPath(directory, name), output);
    const outputBytes = readFile(output);
    rows += outputs.length;
    digest
      .update(worker.output_shards[index]!)
      .update("\0")
      .update(outputBytes)
      .update("\0");
  }
  print(
    "RANK_WORKER_RECEIPT " +
      JSON.stringify({
        output_shards: worker.output_shards.length,
        outputs_sha256: digest.digest("hex"),
        plan_sha256: createHash("sha256").update(bytes).digest("hex"),
        ranking_worker_count: workers.length,
        rows,
        schema_version: 1,
        slot: slot,
        status: "complete",
      }),
  );
}

function validatePool(plan: string, directory: string): void {
  const { inputs, outputNames, workers } = validatePlan(plan, directory);
  const actual = shardNames(directory, "output");
  const missing = missingNames(outputNames, actual);
  const unexpected = missingNames(actual, outputNames);
  if (missing.length || unexpected.length)
    throw new Error(
      `Rank pool outputs are incomplete; missing output shards=${formatDiagnostic(missing)}; unexpected output shards=${formatDiagnostic(unexpected)}`,
    );
  let rows = 0;
  for (const input of inputs) {
    const [, outputs] = validateShard(
      input,
      childPath(directory, outputShardName(basename(input))),
    );
    rows += outputs.length;
  }
  print(
    `Validated ${workers.length} ranking workers, ${inputs.length} shards, and ${rows} ranking rows`,
  );
}

export function rankPoolCommand(
  command: Command,
  args: string[],
  posixHome = process.env.HOME,
): number {
  const required =
    command === "make-rank-pool-plan"
      ? ["shard-dir", "usable-worker-slots", "out"]
      : command === "validate-rank-worker"
        ? ["plan", "shard-dir", "slot"]
        : ["plan", "shard-dir"];
  const integers =
    command === "make-rank-pool-plan"
      ? ["usable-worker-slots"]
      : command === "validate-rank-worker"
        ? ["slot"]
        : [];
  const syntax = required
    .map((name) => `--${name} ${integers.includes(name) ? "INT" : "PATH"}`)
    .join(" ");
  const usage = `usage: launch_codex_security_mcp[.cmd] --helper ${command} [-h] ${syntax}`;
  try {
    const values = argumentsFor(args, required, integers);
    if (values.help) {
      const description =
        command === "make-rank-pool-plan"
          ? "Assign rank shards to a deterministic bounded worker pool. Usable worker slots are capped at 6."
          : command === "validate-rank-worker"
            ? "Validate one assigned ranking-worker slot and emit its completion receipt."
            : "Validate a rank pool plan and every assigned shard output.";
      print(
        `${usage}\n\n${description}\n\noptions:\n  -h, --help  show this help message and exit\n${required.map((name) => `  --${name} ${integers.includes(name) ? "INT" : "PATH"}`).join("\n")}`,
      );
      return 0;
    }
    if (command === "make-rank-pool-plan") {
      const slots = values["usable-worker-slots"] as number;
      if (slots < 1)
        throw new Error("--usable-worker-slots must be at least 1");
      const directory = worklistPath(values["shard-dir"] as string, posixHome);
      const output = worklistPath(values.out as string, posixHome);
      makePlan(directory, slots, output);
    } else {
      const plan = worklistPath(values.plan as string, posixHome);
      const directory = worklistPath(values["shard-dir"] as string, posixHome);
      if (command === "validate-rank-worker")
        validateWorker(plan, directory, values.slot);
      else validatePool(plan, directory);
    }
    return 0;
  } catch (error) {
    return reportCommandError(error, command, usage);
  }
}

import { createHash } from "node:crypto";
import { basename, dirname } from "node:path";
import { mkdir, readFile, writeFile } from "./helper-files";
import {
  JsonSyntaxError,
  object,
  parseJsonBytes,
  pythonRepr,
} from "./python-json";
import { resolvedPath } from "./resolve-path";
import {
  childPath,
  discoverInputShards,
  shardNames,
  validateShard,
} from "./rank-shards";
import {
  ArgumentError,
  argumentsFor,
  compare,
  print,
  worklistPath,
} from "./rank-worklists";

type Command =
  | "make-rank-pool-plan"
  | "validate-rank-worker"
  | "validate-rank-pool";
interface Worker {
  input_shards: string[];
  output_shards: string[];
  slot: number;
}
const outputName = (name: string) =>
  name.replaceAll(".input.jsonl", ".output.jsonl");
const same = (left: string[], right: string[]) =>
  left.length === right.length &&
  left.every((name, index) => name === right[index]);

function requirePlanDirectory(plan: string, directory: string): void {
  const expected = childPath(dirname(plan), "rank_shards");
  const key = (value: string) => {
    const path = resolvedPath(value, false);
    return process.platform === "win32" ? path.toLowerCase() : path;
  };
  if (key(directory) !== key(expected))
    throw new Error(
      `Rank shard directory must be the assignment plan's sibling rank_shards directory; expected=${expected}; actual=${directory}`,
    );
}

function makePlan(directory: string, slots: bigint, output: string): void {
  requirePlanDirectory(output, directory);
  const inputs = discoverInputShards(directory).map((path) => basename(path));
  const count = Math.min(inputs.length, Number(slots), 6);
  const workers = Array.from({ length: count }, (_, index): Worker => {
    const assigned = inputs.filter(
      (_, inputIndex) => inputIndex % count === index,
    );
    return {
      input_shards: assigned,
      output_shards: assigned.map(outputName),
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

function integer(value: unknown, label: string, minimum: bigint): bigint {
  if (typeof value !== "bigint" || value < minimum)
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
  const missing = expected
    .filter((name) => !Object.hasOwn(value, name))
    .sort(compare);
  const unexpected = actual
    .filter((name) => !expected.includes(name))
    .sort(compare);
  if (missing.length || unexpected.length)
    throw new Error(
      `${label} fields do not match schema; missing=${pythonRepr(missing)}; unexpected=${pythonRepr(unexpected)}`,
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
      `Rank shard artifacts must be stored in the assignment plan's sibling rank_shards directory; misplaced=${pythonRepr(misplaced)}`,
    );
  const inputs = discoverInputShards(directory);
  const inputNames = inputs.map((path) => basename(path));
  const outputNames = inputNames.map(outputName);
  const bytes = readFile(plan);
  let payload: unknown;
  try {
    payload = parseJsonBytes(bytes);
  } catch (error) {
    if (error instanceof JsonSyntaxError)
      throw new Error(
        `${plan}: invalid JSON: ${error.message.replace(/: line \d+ column \d+ \(char \d+\)$/u, "")}`,
      );
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
  if (integer(payload.schema_version, `${plan}: schema_version`, 1n) !== 1n)
    throw new Error(`${plan}: schema_version must be 1`);
  if (payload.strategy !== "round_robin")
    throw new Error(`${plan}: strategy must be round_robin`);
  const shardCount = integer(payload.shard_count, `${plan}: shard_count`, 0n);
  if (shardCount !== BigInt(inputs.length))
    throw new Error(
      `${plan}: shard_count does not match input shards; plan=${shardCount}; actual=${inputs.length}`,
    );
  const workerCount = integer(
    payload.ranking_worker_count,
    `${plan}: ranking_worker_count`,
    0n,
  );
  if (shardCount > 0n && workerCount === 0n)
    throw new Error(
      `${plan}: ranking_worker_count must be at least 1 when input shards exist`,
    );
  if (workerCount > shardCount)
    throw new Error(`${plan}: ranking_worker_count cannot exceed shard_count`);
  if (workerCount > 6n)
    throw new Error(`${plan}: ranking_worker_count cannot exceed 6`);
  if (
    !Array.isArray(payload.workers) ||
    BigInt(payload.workers.length) !== workerCount
  )
    throw new Error(
      `${plan}: workers must contain exactly ${workerCount} worker assignments`,
    );
  const workers = payload.workers.map((raw: unknown, index): Worker => {
    const label = `${plan}: workers[${index}]`;
    if (!object(raw)) throw new Error(`${label} must be a JSON object`);
    fields(raw, ["slot", "input_shards", "output_shards"], label);
    const slot = integer(raw.slot, `${label}.slot`, 1n);
    if (slot !== BigInt(index + 1))
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
    if (!same(assignedOutputs, assignedInputs.map(outputName)))
      throw new Error(`${label}.output_shards do not match its input_shards`);
    return {
      slot: Number(slot),
      input_shards: assignedInputs,
      output_shards: assignedOutputs,
    };
  });
  for (const [index, worker] of workers.entries()) {
    const assigned = inputNames.filter(
      (_, inputIndex) => inputIndex % workers.length === index,
    );
    if (
      !same(worker.input_shards, assigned) ||
      !same(worker.output_shards, assigned.map(outputName))
    )
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
  const slot = integer(slotArgument, "--slot", 1n);
  if (slot > BigInt(workers.length))
    throw new Error(`--slot must be at most ${workers.length}`);
  const worker = workers[Number(slot) - 1]!;
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
        slot: Number(slot),
        status: "complete",
      }),
  );
}

function validatePool(plan: string, directory: string): void {
  const { inputs, outputNames, workers } = validatePlan(plan, directory);
  const actual = new Set(shardNames(directory, "output"));
  const expected = new Set(outputNames);
  const missing = outputNames.filter((name) => !actual.has(name)).sort(compare);
  const unexpected = [...actual]
    .filter((name) => !expected.has(name))
    .sort(compare);
  if (missing.length || unexpected.length)
    throw new Error(
      `Rank pool outputs are incomplete; missing output shards=${pythonRepr(missing)}; unexpected output shards=${pythonRepr(unexpected)}`,
    );
  let rows = 0;
  for (const input of inputs) {
    const [, outputs] = validateShard(
      input,
      childPath(directory, outputName(basename(input))),
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
      const slots = values["usable-worker-slots"] as bigint;
      if (slots < 1n)
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

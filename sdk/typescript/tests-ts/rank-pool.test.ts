import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const node = Bun.which("node")!;
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const newline = process.platform === "win32" ? "\r\n" : "\n";
const roots: string[] = [];
interface Worker {
  slot: number;
  input_shards: string[];
  output_shards: string[];
}
interface Plan {
  schema_version: number;
  strategy: string;
  shard_count: number;
  ranking_worker_count: number;
  workers: Worker[];
}
const shardName = (index: number, output = false) =>
  `rank-shard-${String(index).padStart(4, "0")}.${output ? "output" : "input"}.jsonl`;
const row = (index: number) => ({
  path: `src/file_${index}.py`,
  area: "src",
  preview: `value = ${index}`,
});
const ranked = (index: number) => ({
  path: row(index).path,
  area: "src",
  score: 5,
  include: true,
  reason: "runtime surface",
});
function fixture(count = 5) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "rank-pool-")));
  roots.push(root);
  const directory = join(root, "rank_shards");
  mkdirSync(directory);
  for (let index = 1; index <= count; index++)
    writeFileSync(
      join(directory, shardName(index)),
      JSON.stringify(row(index)) + "\n",
    );
  return { root, directory, plan: join(root, "assignments.json") };
}
type Fixture = ReturnType<typeof fixture>;
function run(f: Fixture, command: string, args: string[], env = process.env) {
  return spawnSync(node, [helper, command, ...args], {
    cwd: f.root,
    env,
    encoding: "utf8",
    input: "stdin is not a plan",
  });
}
function make(f: Fixture, slots = "2", extra: string[] = []) {
  return run(f, "make-rank-pool-plan", [
    "--shard-dir",
    f.directory,
    "--usable-worker-slots",
    slots,
    "--out",
    f.plan,
    ...extra,
  ]);
}
function validate(f: Fixture, slot?: string, extra: string[] = []) {
  return run(
    f,
    slot === undefined ? "validate-rank-pool" : "validate-rank-worker",
    [
      "--plan",
      f.plan,
      "--shard-dir",
      f.directory,
      ...(slot === undefined ? [] : ["--slot", slot]),
      ...extra,
    ],
  );
}
function plan(f: Fixture): Plan {
  return JSON.parse(readFileSync(f.plan, "utf8")) as Plan;
}
function change(f: Fixture, edit: (value: Plan) => void) {
  const value = plan(f);
  edit(value);
  writeFileSync(f.plan, JSON.stringify(value));
}
function complete(f: Fixture, slots?: number[]) {
  for (const worker of plan(f).workers) {
    if (slots && !slots.includes(worker.slot)) continue;
    for (const name of worker.output_shards) {
      const index = Number(name.match(/([0-9]+)\.output/u)![1]);
      writeFileSync(
        join(f.directory, name),
        JSON.stringify(ranked(index)) + "\n",
      );
    }
  }
}
function encoded(text: string, encoding: string): Buffer {
  const little = encoding.endsWith("le");
  if (encoding === "utf8") return Buffer.from(text);
  if (encoding === "utf8-bom")
    return Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(text)]);
  if (encoding.startsWith("utf16")) {
    const bytes = Buffer.from(text, "utf16le");
    return little ? bytes : bytes.swap16();
  }
  const points = Array.from(text, (character) => character.codePointAt(0)!);
  const bytes = Buffer.alloc(points.length * 4);
  points.forEach((point, index) =>
    little
      ? bytes.writeUInt32LE(point, index * 4)
      : bytes.writeUInt32BE(point, index * 4),
  );
  return bytes;
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("rank pool helpers", () => {
  test("writes stable sorted JSON and assigns every shard round-robin", () => {
    const f = fixture();
    expect(make(f).stdout).toBe(
      `Assigned 5 rank shards to 2 ranking workers in ${f.plan}${newline}`,
    );
    const expected: Plan = {
      ranking_worker_count: 2,
      schema_version: 1,
      shard_count: 5,
      strategy: "round_robin",
      workers: [
        {
          input_shards: [1, 3, 5].map((index) => shardName(index)),
          output_shards: [1, 3, 5].map((index) => shardName(index, true)),
          slot: 1,
        },
        {
          input_shards: [2, 4].map((index) => shardName(index)),
          output_shards: [2, 4].map((index) => shardName(index, true)),
          slot: 2,
        },
      ],
    };
    expect(readFileSync(f.plan, "utf8")).toBe(
      (JSON.stringify(expected, null, 2) + "\n").replaceAll("\n", newline),
    );
    const first = readFileSync(f.plan);
    expect(make(f).status).toBe(0);
    expect(readFileSync(f.plan)).toEqual(first);
    complete(f);
    expect(validate(f).stdout).toBe(
      `Validated 2 ranking workers, 5 shards, and 5 ranking rows${newline}`,
    );
  });

  test.each([
    [0, "6", 0],
    [2, "8", 2],
    [8, "12", 6],
    [8, "9".repeat(400), 6],
  ] as const)(
    "caps %i shards with %s usable slots at %i workers",
    (count, slots, workers) => {
      const f = fixture(count);
      expect(make(f, slots).status).toBe(0);
      expect(plan(f).ranking_worker_count).toBe(workers);
      expect(plan(f).workers).toHaveLength(workers);
      complete(f);
      expect(validate(f).status).toBe(0);
      if (count === 0)
        expect(validate(f, "1").stderr).toBe(
          `--slot must be at most 0${newline}`,
        );
    },
  );

  test("validates one worker independently and binds its receipt to raw plan and output bytes", () => {
    const f = fixture();
    make(f);
    complete(f, [1]);
    const names = [1, 3, 5].map((index) => shardName(index, true));
    const output = join(f.directory, names[1]!);
    writeFileSync(output, JSON.stringify(ranked(3), null, 0) + "\r\n");
    const bytes = Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      readFileSync(f.plan),
    ]);
    writeFileSync(f.plan, bytes);
    const digest = createHash("sha256");
    for (const name of names)
      digest
        .update(name)
        .update("\0")
        .update(readFileSync(join(f.directory, name)))
        .update("\0");
    const result = validate(f, "1");
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toBe(
      "RANK_WORKER_RECEIPT " +
        JSON.stringify({
          output_shards: 3,
          outputs_sha256: digest.digest("hex"),
          plan_sha256: createHash("sha256").update(bytes).digest("hex"),
          ranking_worker_count: 2,
          rows: 3,
          schema_version: 1,
          slot: 1,
          status: "complete",
        }) +
        newline,
    );
    expect(existsSync(join(f.directory, shardName(2, true)))).toBe(false);
    expect(validate(f).stderr).toContain("missing output shards");
    const second = run(f, "validate-rank-worker", [
      "--plan",
      f.plan,
      "--shard-dir",
      f.directory,
      "--slot",
      "2",
    ]);
    expect(second.status).toBe(1);
    expect(second.stdout).toBe("");
  });

  test("accepts completed slots without requiring worker receipts or unrelated outputs", () => {
    const f = fixture();
    make(f);
    complete(f);
    writeFileSync(join(f.directory, "unrelated.txt"), "untouched");
    expect(validate(f, "1").status).toBe(0);
    expect(validate(f, "2").status).toBe(0);
    expect(validate(f).status).toBe(0);
    writeFileSync(
      join(f.directory, shardName(2, true)),
      "invalid unassigned output",
    );
    expect(validate(f, "1").status).toBe(0);
    expect(validate(f).status).toBe(1);
  });

  test.each(["missing", "invalid JSON", "duplicate", "area", "paths"])(
    "rejects %s assigned output",
    (kind) => {
      const f = fixture();
      make(f);
      complete(f);
      const output = join(f.directory, shardName(3, true));
      if (kind === "missing") rmSync(output);
      else if (kind === "invalid JSON") writeFileSync(output, "{bad json}\n");
      else if (kind === "duplicate")
        writeFileSync(output, (JSON.stringify(ranked(3)) + "\n").repeat(2));
      else
        writeFileSync(
          output,
          JSON.stringify({
            ...ranked(3),
            [kind === "area" ? "area" : "path"]: "different",
          }) + "\n",
        );
      expect(validate(f, "1").status).toBe(1);
      expect(validate(f, "1").stdout).toBe("");
      expect(validate(f).status).toBe(1);
    },
  );

  test("reports both missing and unexpected output shards", () => {
    const f = fixture();
    make(f);
    complete(f);
    rmSync(join(f.directory, shardName(5, true)));
    writeFileSync(join(f.directory, shardName(9999, true)), "");
    expect(validate(f).stderr).toBe(
      `Rank pool outputs are incomplete; missing output shards=['${shardName(5, true)}']; unexpected output shards=['${shardName(9999, true)}']${newline}`,
    );
  });

  test.each(["input", "output"])(
    "rejects a misplaced %s shard before loading the plan",
    (kind) => {
      const f = fixture();
      const name = shardName(1, kind === "output");
      writeFileSync(join(f.root, name), "");
      expect(validate(f).stderr).toContain(`misplaced=['${name}']`);
      expect(validate(f, "1").status).toBe(1);
      // Plan creation has no misplaced-artifact check in the original helper.
      expect(make(f).status).toBe(0);
    },
  );

  test("requires the sibling shard directory and resolves aliases with parent traversal", () => {
    const f = fixture();
    mkdirSync(join(f.root, "other"));
    const bad = { ...f, directory: join(f.root, "other") };
    expect(make(bad).stderr).toContain(
      "must be the assignment plan's sibling rank_shards directory",
    );
    expect(validate(bad, "1").stderr).toContain(
      "must be the assignment plan's sibling rank_shards directory",
    );
    symlinkSync(
      f.directory,
      join(f.root, "alias"),
      process.platform === "win32" ? "junction" : "dir",
    );
    expect(make({ ...f, directory: join(f.root, "alias") }).status).toBe(0);
    complete(f);
    expect(
      validate({
        ...f,
        plan: f.directory + sep + ".." + sep + "assignments.json",
      }).status,
    ).toBe(0);
    expect(
      validate({
        ...f,
        directory: f.root + sep + "missing" + sep + ".." + sep + "rank_shards",
      }).status,
    ).toBe(process.platform === "win32" ? 0 : 1);
  });

  test("checks shard existence and names before loading a missing or malformed plan", () => {
    const f = fixture(0);
    expect(validate(f).stderr).toContain(f.plan);
    writeFileSync(f.plan, "bad");
    writeFileSync(join(f.directory, "rank-shard-001.input.jsonl"), "");
    expect(validate(f).stderr).toContain("contiguous canonical names");
    expect(make(f).status).toBe(1);
    expect(readFileSync(f.plan, "utf8")).toBe("bad");
    rmSync(f.directory, { recursive: true });
    expect(make(f).stderr).toContain("Rank shard directory missing");
  });

  test.each([
    [
      "root fields",
      (p: Plan) => {
        Object.assign(p, { extra: true });
      },
      "unexpected=['extra']",
    ],
    [
      "version type",
      (p: Plan) => {
        Object.assign(p, { schema_version: true });
      },
      "schema_version must be an integer",
    ],
    [
      "version",
      (p: Plan) => {
        p.schema_version = 2;
      },
      "schema_version must be 1",
    ],
    [
      "strategy",
      (p: Plan) => {
        p.strategy = "other";
      },
      "strategy must be round_robin",
    ],
    [
      "shard count",
      (p: Plan) => {
        p.shard_count = 4;
      },
      "shard_count does not match",
    ],
    [
      "worker count",
      (p: Plan) => {
        p.ranking_worker_count = 0;
      },
      "must be at least 1",
    ],
    [
      "workers type",
      (p: Plan) => {
        Object.assign(p, { workers: {} });
      },
      "exactly 2 worker assignments",
    ],
    [
      "worker object",
      (p: Plan) => {
        p.workers[0] = null as unknown as Worker;
      },
      "must be a JSON object",
    ],
    [
      "worker fields",
      (p: Plan) => {
        Object.assign(p.workers[0]!, { extra: true });
      },
      "unexpected=['extra']",
    ],
    [
      "slot",
      (p: Plan) => {
        p.workers[0]!.slot = 2;
      },
      ".slot must be 1",
    ],
    [
      "empty assignments",
      (p: Plan) => {
        p.workers[0]!.input_shards = [];
      },
      "must be a non-empty list",
    ],
    [
      "empty name",
      (p: Plan) => {
        p.workers[0]!.input_shards[0] = "";
      },
      "entries must be non-empty strings",
    ],
    [
      "unequal assignments",
      (p: Plan) => {
        p.workers[0]!.input_shards.pop();
      },
      "lengths must match",
    ],
    [
      "output name",
      (p: Plan) => {
        p.workers[0]!.output_shards[0] = "wrong";
      },
      "do not match its input_shards",
    ],
    [
      "duplicate assignments",
      (p: Plan) => {
        p.workers[0]!.input_shards[1] = shardName(1);
        p.workers[0]!.output_shards[1] = shardName(1, true);
      },
      "does not match the deterministic round_robin assignment",
    ],
    [
      "round robin",
      (p: Plan) => {
        p.workers[0]!.input_shards.reverse();
        p.workers[0]!.output_shards.reverse();
      },
      "does not match the deterministic round_robin assignment",
    ],
  ] as const)("rejects tampered %s", (_name, edit, message) => {
    const f = fixture();
    make(f);
    change(f, edit);
    const result = validate(f);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(message);
    expect(validate(f, "1").stdout).toBe("");
  });

  test.each(["utf8", "utf8-bom", "utf16le", "utf16be", "utf32le", "utf32be"])(
    "accepts %s plan bytes and hashes the original encoding",
    (encoding) => {
      const f = fixture(1);
      make(f);
      complete(f);
      for (const bom of encoding.startsWith("utf16") ||
      encoding.startsWith("utf32")
        ? [false, true]
        : [false]) {
        const text = JSON.stringify({
          ranking_worker_count: 1,
          schema_version: 1,
          shard_count: 1,
          strategy: "round_robin",
          workers: [
            {
              input_shards: [shardName(1)],
              output_shards: [shardName(1, true)],
              slot: 1,
            },
          ],
        });
        const bytes = encoded((bom ? "\ufeff" : "") + text, encoding);
        writeFileSync(f.plan, bytes);
        const result = validate(f, "1");
        expect(result.status).toBe(0);
        expect(
          JSON.parse(result.stdout.slice("RANK_WORKER_RECEIPT ".length))
            .plan_sha256,
        ).toBe(createHash("sha256").update(bytes).digest("hex"));
        expect(validate(f).status).toBe(0);
      }
    },
  );

  test.each(["{bad}", "[]", "null", "1", "true", "", "{} trailing"])(
    "rejects malformed or nonobject plan %s",
    (text) => {
      const f = fixture();
      writeFileSync(f.plan, text);
      expect(validate(f).status).toBe(1);
      expect(validate(f).stdout).toBe("");
    },
  );

  test("rejects malformed UTF-8 even in an overwritten plan value", () => {
    const f = fixture(0);
    make(f);
    const rest = readFileSync(f.plan, "utf8").slice(1);
    writeFileSync(f.plan, '{"strategy":"\\ud800",' + rest);
    expect(validate(f).status).toBe(0);
    writeFileSync(
      f.plan,
      Buffer.concat([
        Buffer.from('{"strategy":"'),
        Buffer.from([0xed, 0xa0, 0x80]),
        Buffer.from('",' + rest),
      ]),
    );
    const result = validate(f);
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
  });

  test("preserves duplicate-key last value and integer-versus-float validation", () => {
    const f = fixture(0);
    make(f);
    const text = readFileSync(f.plan, "utf8");
    writeFileSync(
      f.plan,
      text.replace(
        '"schema_version": 1',
        '"schema_version": 2, "schema_version": 1',
      ),
    );
    expect(validate(f).status).toBe(0);
    for (const value of ["1.0", "1e0", "true", "NaN", "Infinity", "-1"]) {
      writeFileSync(
        f.plan,
        text.replace('"schema_version": 1', `"schema_version": ${value}`),
      );
      expect(validate(f).stderr).toContain(
        "schema_version must be an integer of at least 1",
      );
    }
  });

  test.each(["+2_0", "２０", "٢٠", " 20 "])(
    "accepts required integer argument %s with existing abbreviations",
    (value) => {
      const f = fixture(1);
      expect(make(f, value).status).toBe(0);
      complete(f);
      expect(validate(f, "1", ["--sl=+1"]).status).toBe(0);
    },
  );

  test("preserves argument failure statuses and validation order", () => {
    const f = fixture();
    for (const value of ["0", "-1"])
      expect(make({ ...f, directory: "missing" }, value).stderr).toBe(
        `--usable-worker-slots must be at least 1${newline}`,
      );
    for (const value of ["1.0", "1__0", "\u001c20"])
      expect(make(f, value).status).toBe(2);
    for (const command of [
      "make-rank-pool-plan",
      "validate-rank-worker",
      "validate-rank-pool",
    ]) {
      expect(run(f, command, []).status).toBe(2);
      expect(run(f, command, ["--help"]).status).toBe(0);
    }
    expect(validate(f, "0").stderr).toContain(f.plan);
    make(f);
    expect(validate(f, "0").stderr).toBe(
      `--slot must be an integer of at least 1${newline}`,
    );
    expect(validate(f, "9".repeat(400)).stderr).toBe(
      `--slot must be at most 2${newline}`,
    );
    expect(validate(f, "1", ["--s", "1"]).status).toBe(2);
  });

  test("preserves literal dash paths, output aliases, and existing file permissions", () => {
    const f = fixture(0);
    const dash = { ...f, directory: "rank_shards", plan: "-" };
    writeFileSync(join(f.root, "-"), "previous", { mode: 0o640 });
    expect(make(dash).status).toBe(0);
    expect(validate(dash).status).toBe(0);
    if (process.platform !== "win32")
      expect(statSync(join(f.root, "-")).mode & 0o777).toBe(0o640);
    symlinkSync(
      join(f.root, "-"),
      f.plan,
      process.platform === "win32" ? "file" : undefined,
    );
    expect(make(f).status).toBe(0);
    expect(readFileSync(f.plan)).toEqual(readFileSync(join(f.root, "-")));
    expect(readdirSync(f.directory)).toHaveLength(0);
  });

  test.skipIf(process.platform === "win32")(
    "uses raw POSIX bytes for plan and shard paths",
    () => {
      const f = fixture(0);
      const pathBytes =
        process.platform === "darwin" ? Buffer.from("é") : Buffer.from([255]);
      const suffix = Array.from(
        pathBytes,
        (byte) => `\\${byte.toString(8).padStart(3, "0")}`,
      ).join("");
      const raw = Buffer.concat([Buffer.from(f.root + "/"), pathBytes]);
      mkdirSync(raw);
      mkdirSync(Buffer.concat([raw, Buffer.from("/rank_shards")]));
      const launcher = join(
        PLUGIN_ROOT,
        "scripts",
        "launch_codex_security_mcp",
      );
      const result = spawnSync(
        "bash",
        [
          "-c",
          `r="$1"/$(printf '${suffix}'); "$2" --helper make-rank-pool-plan --shard-dir "$r/rank_shards" --usable-worker-slots 1 --out "$r/plan.json"`,
          "rank-pool",
          f.root,
          launcher,
        ],
        { env: { ...process.env, CODEX_MCP_NODE_PATH: node } },
      );
      expect(result.status).toBe(0);
      const output = Buffer.concat([raw, Buffer.from("/plan.json")]);
      expect(JSON.parse(readFileSync(output, "utf8")).shard_count).toBe(0);
      expect(result.stdout.includes(output)).toBe(true);
    },
  );
});

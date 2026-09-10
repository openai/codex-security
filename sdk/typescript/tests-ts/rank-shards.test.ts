import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const node = Bun.which("node")!;
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const roots: string[] = [];
const newline = process.platform === "win32" ? "\r\n" : "\n";
type Row = Record<string, unknown>;
const candidate = (path: string, area = "src") => ({
  path,
  area,
  preview: "source preview",
});
const ranked = (row: Row) => ({
  path: row["path"],
  area: row["area"],
  score: 5,
  include: true,
  reason: "runtime surface",
});
function fixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "rank-shards-")));
  roots.push(root);
  return {
    root,
    input: join(root, "input.jsonl"),
    directory: join(root, "shards"),
    output: join(root, "output.jsonl"),
  };
}
type Fixture = ReturnType<typeof fixture>;
function write(path: string, rows: Row[]) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, rows.map((row) => JSON.stringify(row) + "\n").join(""));
}
function read(path: string): Row[] {
  const text = readFileSync(path, "utf8").trim();
  return text === ""
    ? []
    : text.split(/\r?\n/u).map((line) => JSON.parse(line) as Row);
}
function run(f: Fixture, command: string, args: string[], env = process.env) {
  return spawnSync(node, [helper, command, ...args], {
    cwd: f.root,
    encoding: "utf8",
    env,
    input: "stdin is not a worklist",
  });
}
function make(f: Fixture, args: string[] = []) {
  return run(f, "make-rank-shards", [
    "--rank-input",
    f.input,
    "--out-dir",
    f.directory,
    ...args,
  ]);
}
function merge(f: Fixture, args: string[] = []) {
  return run(f, "merge-rank-outputs", [
    "--rank-input",
    f.input,
    "--shard-dir",
    f.directory,
    "--out",
    f.output,
    ...args,
  ]);
}
function shard(f: Fixture, index: number, output = false) {
  return join(
    f.directory,
    `rank-shard-${String(index).padStart(4, "0")}.${output ? "output" : "input"}.jsonl`,
  );
}
function validate(f: Fixture, index = 1) {
  return run(f, "validate-rank-shard", [
    "--input",
    shard(f, index),
    "--output",
    shard(f, index, true),
  ]);
}
function complete(f: Fixture) {
  for (const name of readdirSync(f.directory).filter((name) =>
    name.endsWith(".input.jsonl"),
  ))
    write(
      f.directory + sep + name.replace(".input.", ".output."),
      read(f.directory + sep + name)
        .reverse()
        .map(ranked),
    );
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("rank shard helpers", () => {
  test.skipIf(process.platform !== "win32")(
    "joins shard names beneath Windows roots without changing their path kind",
    async () => {
      const { childPath } = (await import(
        new URL(
          "../../../plugins/codex-security/mcp-app/src/helpers/rank-shards.ts",
          import.meta.url,
        ).href
      )) as { childPath: (directory: string, name: string) => string };
      const name = "rank-shard-0001.input.jsonl";
      for (const [directory, prefix] of [
        ["/", "\\"],
        ["\\", "\\"],
        ["C:", "C:"],
        ["C:\\", "C:\\"],
        ["\\\\server\\share", "\\\\server\\share\\"],
        ["\\\\?\\C:\\", "\\\\?\\C:\\"],
        ["\\\\?\\UNC\\server\\share\\", "\\\\?\\UNC\\server\\share\\"],
      ]) {
        expect(childPath(directory!, name)).toBe(prefix! + name);
      }
    },
  );

  test("partitions deterministically at the default 150 rows and refuses existing shards", () => {
    const f = fixture();
    const rows = Array.from({ length: 312 }, (_, index) =>
      candidate(`src/file_${index}.py`),
    );
    write(f.input, rows);
    expect(make(f).stdout).toBe(
      `Wrote 3 rank shards to ${f.directory}${newline}`,
    );
    expect(readdirSync(f.directory).sort()).toEqual(
      [1, 2, 3].map((index) => `rank-shard-000${index}.input.jsonl`),
    );
    expect([1, 2, 3].map((index) => read(shard(f, index)).length)).toEqual([
      150, 150, 12,
    ]);
    expect([1, 2, 3].flatMap((index) => read(shard(f, index)))).toEqual(rows);
    const original = readFileSync(shard(f, 1));
    const second = make(f);
    expect(second.status).toBe(1);
    expect(second.stderr).toContain("already contains shard files");
    expect(readFileSync(shard(f, 1))).toEqual(original);
  });

  test.skipIf(process.platform === "win32")(
    "preserves existing shards alongside Unicode and raw-byte filenames",
    () => {
      const f = fixture();
      write(f.input, [candidate("new.py")]);
      write(shard(f, 1), [candidate("preserved.py")]);
      writeFileSync(join(f.directory, "é.txt"), "unrelated Unicode file");
      if (process.platform === "linux")
        writeFileSync(
          Buffer.concat([Buffer.from(f.directory + "/"), Buffer.from([255])]),
          "unrelated undecodable file",
        );
      const original = readFileSync(shard(f, 1));
      const result = make(f);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("already contains shard files");
      expect(readFileSync(shard(f, 1))).toEqual(original);
      rmSync(shard(f, 1));
      expect(make(f).status).toBe(0);
      expect(read(shard(f, 1))).toEqual([candidate("new.py")]);
    },
  );

  test("validates one completed shard independently and restores authoritative merge order", () => {
    const f = fixture();
    const rows = Array.from({ length: 7 }, (_, index) =>
      candidate(`src/file_${index}.py`),
    );
    write(f.input, rows);
    expect(make(f, ["--max-rows", "5"]).status).toBe(0);
    write(shard(f, 1, true), read(shard(f, 1)).reverse().map(ranked));
    const checked = validate(f);
    expect(checked.status).toBe(0);
    expect(checked.stdout).toBe(
      `Validated 5 ranking rows in ${shard(f, 1, true)}${newline}`,
    );
    expect(existsSync(shard(f, 2, true))).toBe(false);
    complete(f);
    const result = merge(f);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(
      `Merged 7 ranking rows into ${f.output}${newline}`,
    );
    expect(read(f.output)).toEqual(rows.map(ranked));
  });

  test("creates zero shards and merges an empty input while ignoring unrelated files", () => {
    const f = fixture();
    write(f.input, []);
    mkdirSync(f.directory);
    writeFileSync(join(f.directory, "notes.txt"), "retain notes");
    expect(make(f).stdout).toBe(
      `Wrote 0 rank shards to ${f.directory}${newline}`,
    );
    writeFileSync(f.output, "previous contents");
    expect(merge(f).stdout).toBe(
      `Merged 0 ranking rows into ${f.output}${newline}`,
    );
    expect(readFileSync(f.output)).toHaveLength(0);
    expect(readFileSync(join(f.directory, "notes.txt"), "utf8")).toBe(
      "retain notes",
    );
    write(shard(f, 1), []);
    write(shard(f, 1, true), []);
    expect(validate(f).status).toBe(0);
  });

  test.each(["1", "+2_0", "２０", "٢٠", " 20 ", "9".repeat(400)])(
    "accepts Python integer shard size %s",
    (size) => {
      const f = fixture();
      write(f.input, [candidate("a.py"), candidate("b.py")]);
      expect(make(f, ["--max-rows", size]).status).toBe(0);
      expect(readdirSync(f.directory)).toHaveLength(size === "1" ? 2 : 1);
    },
  );

  test.each(["0", "-1"])(
    "rejects nonpositive shard size %s before input access",
    (size) => {
      const f = fixture();
      const result = make(f, ["--max-rows", size]);
      expect(result.status).toBe(1);
      expect(result.stderr).toBe(`--max-rows must be at least 1${newline}`);
      expect(existsSync(f.directory)).toBe(false);
    },
  );

  test("keeps last repeated arguments, unique abbreviations, and argument failures", () => {
    const f = fixture();
    write(f.input, [candidate("a.py"), candidate("b.py")]);
    expect(make(f, ["--max-rows", "1", "--max-r=2"]).status).toBe(0);
    expect(readdirSync(f.directory)).toHaveLength(1);
    for (const args of [
      ["--max-rows", "1.0"],
      ["--max-rows", "1__0"],
      ["--max-rows", "\u001c20"],
      ["--max-rows"],
      ["--unknown"],
      ["extra"],
      ["--"],
    ]) {
      expect(make(f, args).status).toBe(2);
    }
    for (const command of [
      "make-rank-shards",
      "validate-rank-shard",
      "merge-rank-outputs",
    ]) {
      expect(run(f, command, []).status).toBe(2);
      expect(run(f, command, ["--help"]).status).toBe(0);
    }
    expect(make(f, ["--help"]).stdout).toContain("Defaults to 150");
    complete(f);
    expect(merge(f, ["--o", f.output]).status).toBe(0);
  });

  test("preserves JSON property order, ASCII escapes, and platform newlines", () => {
    const f = fixture();
    writeFileSync(
      f.input,
      '{"preview":"é\\n","path":"old","path":"𐀀.py","area":"\\udcff"}\r',
    );
    expect(make(f).status).toBe(0);
    expect(readFileSync(shard(f, 1), "utf8")).toBe(
      '{"preview":"\\u00e9\\n","path":"\\ud800\\udc00.py","area":"\\udcff"}' +
        newline,
    );
    writeFileSync(
      shard(f, 1, true),
      '{"reason":"é","include":false,"score":5,"area":"\\udcff","path":"𐀀.py"}',
    );
    expect(merge(f).status).toBe(0);
    expect(readFileSync(f.output, "utf8")).toBe(
      '{"reason":"\\u00e9","include":false,"score":5,"area":"\\udcff","path":"\\ud800\\udc00.py"}' +
        newline,
    );
  });

  test.each([
    ["{not json}\n", "invalid JSON"],
    [
      '{"path":"a.py","area":"src","score":10,"include":true}',
      "missing fields ['reason']",
    ],
    [
      JSON.stringify({ ...ranked(candidate("a.py")), score: true }),
      "score must be an integer",
    ],
    [
      '{"path":"a.py","area":"src","score":5.0,"include":true,"reason":"x"}',
      "score must be an integer",
    ],
    [
      JSON.stringify({ ...ranked(candidate("a.py")), score: 11 }),
      "score must be from 1 through 10",
    ],
    [
      JSON.stringify({ ...ranked(candidate("a.py")), include: "true" }),
      "include must be a boolean",
    ],
    [
      JSON.stringify({ ...ranked(candidate("a.py")), reason: "\t" }),
      "reason must be a non-empty string",
    ],
    [
      JSON.stringify(ranked(candidate("b.py"))),
      "paths do not match its input shard",
    ],
    [
      JSON.stringify(ranked(candidate("a.py", "other"))),
      "area does not match rank input",
    ],
    ["", "paths do not match its input shard"],
    ["\n", "blank JSONL rows are not allowed"],
    [
      JSON.stringify({ ...ranked(candidate("a.py")), preview: "extra" }),
      "unexpected fields ['preview']",
    ],
  ])(
    "rejects invalid worker output %j without overwriting the merged file",
    (data, message) => {
      const f = fixture();
      write(f.input, [candidate("a.py")]);
      expect(make(f).status).toBe(0);
      writeFileSync(shard(f, 1, true), data!);
      writeFileSync(f.output, "preserve existing output");
      for (const result of [validate(f), merge(f)]) {
        expect(result.status).toBe(1);
        expect(result.stderr).toContain(message!);
      }
      expect(readFileSync(f.output, "utf8")).toBe("preserve existing output");
    },
  );

  test("rejects missing, unexpected, and duplicate worker outputs", () => {
    const f = fixture();
    write(f.input, [candidate("a.py")]);
    expect(make(f).status).toBe(0);
    expect(validate(f).stderr).toContain(shard(f, 1, true));
    write(shard(f, 2, true), []);
    expect(merge(f).stderr).toContain(
      "missing output shards ['rank-shard-0001.output.jsonl']; unexpected output shards ['rank-shard-0002.output.jsonl']",
    );
    rmSync(shard(f, 2, true));
    const row = ranked(candidate("a.py"));
    write(shard(f, 1, true), [row, row]);
    expect(validate(f).stderr).toContain(
      "Rank output shard rank-shard-0001.output.jsonl contains duplicate paths: ['a.py']",
    );
    expect(merge(f).stderr).toContain("duplicate paths");
  });

  test.each([
    "rank-shard-x.input.jsonl",
    "rank-shard-001.input.jsonl",
    "rank-shard-0000.input.jsonl",
    "rank-shard-00001.input.jsonl",
    "rank-shard-0002.input.jsonl",
  ])("rejects noncanonical shard name %s", (name) => {
    const f = fixture();
    write(f.input, [candidate("a.py")]);
    expect(make(f).status).toBe(0);
    renameSync(shard(f, 1), join(f.directory, name));
    const result = merge(f);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(name);
    expect(existsSync(f.output)).toBe(false);
  });

  test("rejects gaps in shard names above four digits", () => {
    const f = fixture();
    write(f.input, []);
    write(join(f.directory, "rank-shard-9999.input.jsonl"), []);
    write(join(f.directory, "rank-shard-10000.input.jsonl"), []);
    const result = merge(f);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("contiguous canonical names");
    expect(existsSync(f.output)).toBe(false);
  });

  test.each([
    "RANK-SHARD-0001.INPUT.JSONL",
    "rank-shard-0001.İnput.jsonl",
    "rank-shard-0001.ınput.jsonl",
    "rank-shard-0001.input.jſonl",
    "ranK-shard-0001.input.jsonl",
  ])(
    "matches shard globs using the platform's filename case rules: %s",
    (name) => {
      const f = fixture();
      write(f.input, []);
      write(join(f.directory, name), []);
      const creation = make(f);
      const result = merge(f);
      if (process.platform === "win32") {
        expect(creation.status).toBe(1);
        expect(creation.stderr).toContain("already contains shard files");
        expect(result.status).toBe(1);
        expect(result.stderr).toContain("contiguous canonical names");
      } else {
        expect(creation.status).toBe(0);
        expect(result.status).toBe(0);
        expect(readFileSync(f.output)).toHaveLength(0);
      }
    },
  );

  test.each(["order", "preview", "duplicate across shards"])(
    "rejects an invalid authoritative partition: %s",
    (change) => {
      const f = fixture();
      const rows = [candidate("a.py"), candidate("b.py")];
      write(f.input, rows);
      expect(make(f, ["--max-rows", "1"]).status).toBe(0);
      if (change === "order") write(f.input, [...rows].reverse());
      if (change === "preview")
        write(shard(f, 1), [{ ...rows[0], preview: "changed" }]);
      if (change === "duplicate across shards") write(shard(f, 2), [rows[0]!]);
      complete(f);
      const result = merge(f);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(
        change === "duplicate across shards"
          ? "Rank outputs contain duplicate path: a.py"
          : "do not exactly partition the authoritative rank input",
      );
      expect(existsSync(f.output)).toBe(false);
    },
  );

  test("rejects duplicate or malformed authoritative rows before creating a shard directory", () => {
    const f = fixture();
    for (const data of [
      JSON.stringify(candidate("a.py")) +
        "\n" +
        JSON.stringify(candidate("a.py")),
      "{}",
      "\u001c\n",
      "\ufeff{}",
      Buffer.from([255]),
    ]) {
      writeFileSync(f.input, data);
      expect(make(f).status).toBe(1);
      expect(merge(f).status).toBe(1);
      expect(existsSync(f.directory)).toBe(false);
    }
  });

  test("treats a matching directory as an existing shard and reports a missing shard directory", () => {
    const f = fixture();
    write(f.input, []);
    expect(merge(f).stderr).toContain("Rank shard directory missing");
    mkdirSync(shard(f, 1, true), { recursive: true });
    expect(make(f).stderr).toContain("already contains shard files");
  });

  test("uses literal dash paths, expands homes, and accepts output/input aliasing", () => {
    const f = fixture();
    write(join(f.root, "-"), [candidate("a.py")]);
    const env = { ...process.env, HOME: f.root, USERPROFILE: f.root };
    const result = run(
      f,
      "make-rank-shards",
      ["--rank-input", "-", "--out-dir", "~/shards"],
      env,
    );
    expect(result.status).toBe(0);
    complete(f);
    const merged = merge({ ...f, input: "-", output: "-" });
    expect(merged.status).toBe(0);
    expect(merged.stdout).toBe(`Merged 1 ranking rows into -${newline}`);
    expect(read(join(f.root, "-"))).toEqual([ranked(candidate("a.py"))]);
  });

  test.skipIf(process.platform === "win32")(
    "keeps symlink/.. traversal and existing output permissions",
    () => {
      const f = fixture();
      const outside = fixture();
      mkdirSync(join(outside.root, "nested"));
      symlinkSync(join(outside.root, "nested"), join(f.root, "link"));
      const directory = f.root + "/link/../shards";
      write(f.input, [candidate("a.py")]);
      expect(make({ ...f, directory }).status).toBe(0);
      expect(
        existsSync(join(outside.root, "shards", "rank-shard-0001.input.jsonl")),
      ).toBe(true);
      expect(existsSync(f.directory)).toBe(false);
      complete({ ...f, directory });
      const target = join(f.root, "target.jsonl");
      writeFileSync(target, "existing", { mode: 0o640 });
      symlinkSync(target, f.output);
      expect(merge({ ...f, directory }).status).toBe(0);
      expect(statSync(target).mode & 0o777).toBe(0o640);
      expect(read(target)).toEqual([ranked(candidate("a.py"))]);
    },
  );

  test.skipIf(process.platform === "win32")(
    "launcher preserves POSIX shard directory bytes",
    () => {
      const f = fixture();
      const pathBytes =
        process.platform === "darwin" ? Buffer.from("é") : Buffer.from([255]);
      const suffix = Array.from(
        pathBytes,
        (byte) => `\\${byte.toString(8).padStart(3, "0")}`,
      ).join("");
      write(f.input, [candidate("a.py")]);
      const launcher = join(
        PLUGIN_ROOT,
        "scripts",
        "launch_codex_security_mcp",
      );
      const result = spawnSync(
        "sh",
        [
          "-c",
          `exec "$1" --helper make-rank-shards --rank-input "$2/input.jsonl" --out-dir "$2/shards-$(printf '${suffix}')"`,
          "sh",
          launcher,
          f.root,
        ],
        { env: { ...process.env, CODEX_MCP_NODE_PATH: node } },
      );
      expect(result.status).toBe(0);
      const directory = Buffer.concat([
        Buffer.from(f.root + "/shards-"),
        pathBytes,
      ]);
      const input = Buffer.concat([
        directory,
        Buffer.from("/rank-shard-0001.input.jsonl"),
      ]);
      const output = Buffer.concat([
        directory,
        Buffer.from("/rank-shard-0001.output.jsonl"),
      ]);
      writeFileSync(output, JSON.stringify(ranked(candidate("a.py"))) + "\n");
      expect(JSON.parse(readFileSync(input, "utf8"))).toEqual(
        candidate("a.py"),
      );
      const merged = spawnSync(
        "sh",
        [
          "-c",
          `exec "$1" --helper merge-rank-outputs --rank-input "$2/input.jsonl" --shard-dir "$2/shards-$(printf '${suffix}')" --out "$2/output.jsonl"`,
          "sh",
          launcher,
          f.root,
        ],
        { env: { ...process.env, CODEX_MCP_NODE_PATH: node } },
      );
      expect(merged.status).toBe(0);
      expect(read(f.output)).toEqual([ranked(candidate("a.py"))]);
    },
  );
});

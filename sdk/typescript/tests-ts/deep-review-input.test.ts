import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
const ranked = (path: string, score = 5, include = true, area = "src") => ({
  path,
  area,
  score,
  include,
  reason: "runtime surface",
});
function fixture() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "deep-review-input-")));
  roots.push(root);
  return {
    root,
    input: join(root, "input.jsonl"),
    output: join(root, "output.jsonl"),
  };
}
function write(path: string, rows: Row[]) {
  writeFileSync(path, rows.map((row) => JSON.stringify(row) + "\n").join(""));
}
function read(path: string) {
  const text = readFileSync(path, "utf8").trim();
  return text === ""
    ? []
    : text.split(/\r?\n/u).map((line) => JSON.parse(line));
}
function run(
  f: ReturnType<typeof fixture>,
  selection: boolean,
  args: string[] = [],
  env = process.env,
) {
  return spawnSync(
    node,
    [
      helper,
      selection ? "select-deep-review-input" : "copy-deep-review-input",
      selection ? "--rank-output" : "--rank-input",
      f.input,
      "--out",
      f.output,
      ...args,
    ],
    { cwd: f.root, encoding: "utf8", env },
  );
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("deep-review worklists", () => {
  test("copies all candidates in input order and selects included ranked rows", () => {
    const f = fixture();
    write(f.input, [candidate("a.py", "core"), candidate("b.py", "api")]);
    expect(run(f, false).status).toBe(0);
    expect(read(f.output)).toEqual([
      { path: "a.py", area: "core" },
      { path: "b.py", area: "api" },
    ]);
    write(f.input, [
      ranked("c.py", 8, true, "api"),
      ranked("a.py", 10, true, "core"),
      ranked("b.py", 8, true, "api"),
      ranked("d.py", 2, false, "core"),
    ]);
    const result = run(f, true, ["--top-percent", "67"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(
      `Selected 2 of 3 rows into ${f.output}${newline}`,
    );
    expect(read(f.output)).toEqual([
      { path: "a.py", area: "core" },
      { path: "b.py", area: "api" },
    ]);
  });
  test("honors explicit 20 percent and defaults to 100 percent", () => {
    const f = fixture();
    write(
      f.input,
      Array.from({ length: 5 }, (_, index) =>
        ranked(`src/file_${index}.py`, 10 - index),
      ),
    );
    expect(run(f, true, ["--top-percent", "20"]).status).toBe(0);
    expect(read(f.output)).toEqual([{ path: "src/file_0.py", area: "src" }]);
    expect(run(f, true).status).toBe(0);
    expect(read(f.output)).toHaveLength(5);
  });
  test("falls back to all rows when workers exclude everything", () => {
    const f = fixture();
    write(f.input, [
      ranked("b.py", 2, false, "api"),
      ranked("a.py", 9, false, "core"),
    ]);
    expect(run(f, true).status).toBe(0);
    expect(read(f.output)).toEqual([
      { path: "a.py", area: "core" },
      { path: "b.py", area: "api" },
    ]);
  });
  test.each([false, true])(
    "closes an empty worklist with an empty output (selection=%s)",
    (selection) => {
      const f = fixture();
      write(f.input, []);
      writeFileSync(f.output, "previous contents");
      expect(run(f, selection).status).toBe(0);
      expect(readFileSync(f.output)).toHaveLength(0);
    },
  );
  test.each([
    ["0", 1],
    ["-10", 1],
    ["1", 1],
    ["200", 3],
    ["+2_0", 1],
    ["２０", 1],
    ["٢٠", 1],
    ["9".repeat(308), 3],
  ] as const)("preserves accepted integer percentage %s", (percent, count) => {
    const f = fixture();
    write(f.input, [ranked("a.py"), ranked("b.py"), ranked("c.py")]);
    expect(run(f, true, ["--top-percent", percent]).status).toBe(0);
    expect(read(f.output)).toHaveLength(count);
  });
  test("reports float conversion overflow only for nonempty selected worklists", () => {
    const f = fixture();
    write(f.input, [ranked("a.py")]);
    expect(run(f, true, ["--top-percent", "9".repeat(400)]).status).toBe(1);
    expect(existsSync(f.output)).toBe(false);
    write(f.input, []);
    expect(run(f, true, ["--top-percent", "9".repeat(400)]).status).toBe(0);
  });
  test("orders tied paths by Unicode code points and writes compact ASCII JSON", () => {
    const f = fixture();
    write(f.input, [
      ranked("𐀀.py", 5, true, "é"),
      ranked("\ue000.py", 5, true, "\udcff"),
      ranked("\u007f.py", 5, true, "\t"),
    ]);
    expect(run(f, true).status).toBe(0);
    expect(readFileSync(f.output, "utf8")).toBe(
      [
        '{"path":"\\u007f.py","area":"\\t"}',
        '{"path":"\\ue000.py","area":"\\udcff"}',
        '{"path":"\\ud800\\udc00.py","area":"\\u00e9"}',
        "",
      ].join(newline),
    );
  });
  test.each(["\n", "\r\n", "\r"])(
    "accepts universal input newline %j with an unterminated last row",
    (separator) => {
      const f = fixture();
      writeFileSync(
        f.input,
        JSON.stringify(candidate("a.py")) +
          separator +
          JSON.stringify(candidate("b.py")),
      );
      expect(run(f, false).status).toBe(0);
      expect(read(f.output)).toHaveLength(2);
    },
  );
  const invalid: Array<[boolean, string | Buffer, string]> = [
    [false, "\n", "blank JSONL rows are not allowed"],
    [false, "\u001c\n", "blank JSONL rows are not allowed"],
    [false, "{}\n\n", "missing fields"],
    [false, "{not json}\n", "invalid JSON"],
    [false, "[]\n", "expected a JSON object"],
    [
      false,
      JSON.stringify({ ...candidate("a.py"), extra: true }),
      "unexpected fields ['extra']",
    ],
    [
      false,
      JSON.stringify(candidate("\u001f")),
      "path must be a non-empty string",
    ],
    [
      false,
      JSON.stringify({ ...candidate("a.py"), preview: 1 }),
      "preview must be a string",
    ],
    [
      false,
      JSON.stringify({ ...candidate("a.py"), area: null }),
      "area must be a string",
    ],
    [
      true,
      JSON.stringify({ ...ranked("a.py"), score: true }),
      "score must be an integer",
    ],
    [
      true,
      '{"path":"a.py","area":"src","score":5.0,"include":true,"reason":"x"}',
      "score must be an integer",
    ],
    [
      true,
      '{"path":"a.py","area":"src","score":1e1,"include":true,"reason":"x"}',
      "score must be an integer",
    ],
    [
      true,
      JSON.stringify(ranked("a.py", 11)),
      "score must be from 1 through 10",
    ],
    [
      true,
      JSON.stringify({ ...ranked("a.py"), include: 1 }),
      "include must be a boolean",
    ],
    [
      true,
      JSON.stringify({ ...ranked("a.py"), reason: "\t" }),
      "reason must be a non-empty string",
    ],
    [
      false,
      "\ufeff" + JSON.stringify(candidate("a.py")),
      "invalid JSON: Unexpected UTF-8 BOM",
    ],
    [false, Buffer.from([0xff]), "encoded data"],
  ];
  test.each(invalid)(
    "rejects invalid worklist data (selection=%s, data=%j)",
    (selection, text, message) => {
      const f = fixture();
      writeFileSync(f.input, text);
      writeFileSync(f.output, "preserve existing output");
      const result = run(f, selection);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(message);
      expect(readFileSync(f.output, "utf8")).toBe("preserve existing output");
    },
  );
  test.each([false, true])(
    "rejects repeated paths before output (selection=%s)",
    (selection) => {
      const f = fixture();
      write(
        f.input,
        selection
          ? [ranked("a.py"), ranked("a.py")]
          : [candidate("a.py"), candidate("a.py")],
      );
      const result = run(f, selection);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("contains duplicate paths: ['a.py']");
      expect(existsSync(f.output)).toBe(false);
    },
  );
  test("accepts duplicate JSON object keys and empty area/preview as before", () => {
    const f = fixture();
    writeFileSync(
      f.input,
      '{"path":"unused.py","path":"a.py","area":"","preview":""}',
    );
    expect(run(f, false).status).toBe(0);
    expect(read(f.output)).toEqual([{ path: "a.py", area: "" }]);
  });
  test("allows replacing the input after all rows have been read", () => {
    const f = fixture();
    write(f.input, [candidate("b.py"), candidate("a.py")]);
    expect(run({ ...f, output: f.input }, false).status).toBe(0);
    expect(read(f.input)).toEqual([
      { path: "b.py", area: "src" },
      { path: "a.py", area: "src" },
    ]);
  });
  test("expands homes, creates output parents, and preserves path spelling in status", () => {
    const f = fixture();
    write(f.input, [candidate("a.py")]);
    const env = { ...process.env, HOME: f.root, USERPROFILE: f.root };
    const result = run(
      { ...f, input: "~/input.jsonl", output: "./nested/./output.jsonl" },
      false,
      [],
      env,
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(
      `Copied 1 rows into ${join("nested", "output.jsonl")}${newline}`,
    );
    expect(read(join(f.root, "nested", "output.jsonl"))).toHaveLength(1);
  });
  test("reports missing input and preserves argument parsing status", () => {
    const f = fixture();
    writeFileSync(f.output, "previous output\n");
    for (const selection of [false, true]) {
      const result = run(f, selection);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(f.input);
      expect(readFileSync(f.output, "utf8")).toBe("previous output\n");
    }
    write(f.input, [ranked("a.py")]);
    expect(run(f, true, ["--top-percent=20"]).status).toBe(0);
    expect(run(f, true, ["--top-p", "20"]).status).toBe(0);
    for (const args of [
      ["--top-percent", "1.0"],
      ["--top-percent"],
      ["--unknown"],
      ["extra"],
      ["--top-percent", "1__0"],
      ["--top-percent", "\u001c20"],
    ])
      expect(run(f, true, args).status).toBe(2);
    expect(run(f, true, ["--help"]).stdout).toContain("Defaults to 100");
  });
  test.skipIf(process.platform === "win32")(
    "follows existing input/output symlinks and preserves existing output permissions",
    () => {
      const f = fixture();
      const target = join(f.root, "target.jsonl");
      writeFileSync(target, "existing", { mode: 0o640 });
      symlinkSync(target, f.output);
      write(f.input, [candidate("a.py")]);
      const inputLink = join(f.root, "input-link");
      symlinkSync(f.input, inputLink);
      expect(run({ ...f, input: inputLink }, false).status).toBe(0);
      expect(read(target)).toHaveLength(1);
      expect(statSync(target).mode & 0o777).toBe(0o640);
    },
  );
  test.skipIf(process.platform === "win32")(
    "launcher preserves POSIX input and output path bytes",
    () => {
      const f = fixture();
      // APFS requires valid UTF-8 filenames; Linux also permits undecodable bytes.
      const [inputBytes, outputBytes] =
        process.platform === "darwin"
          ? [Buffer.from("é"), Buffer.from("ö")]
          : [Buffer.from([0xff]), Buffer.from([0xfe])];
      const shellBytes = (bytes: Buffer) =>
        Array.from(
          bytes,
          (byte) => `\\${byte.toString(8).padStart(3, "0")}`,
        ).join("");
      const input = Buffer.concat([Buffer.from(f.root + "/in-"), inputBytes!]);
      const output = Buffer.concat([
        Buffer.from(f.root + "/nested-"),
        inputBytes!,
        Buffer.from("/out-"),
        outputBytes!,
      ]);
      writeFileSync(input, JSON.stringify(candidate("a.py")) + "\n");
      const launcher = join(
        PLUGIN_ROOT,
        "scripts",
        "launch_codex_security_mcp",
      );
      const result = spawnSync(
        "sh",
        [
          "-c",
          `exec "$1" --helper copy-deep-review-input --rank-input "$2/in-$(printf '${shellBytes(inputBytes!)}')" --out "$2/nested-$(printf '${shellBytes(inputBytes!)}')/out-$(printf '${shellBytes(outputBytes!)}')"`,
          "sh",
          launcher,
          f.root,
        ],
        { env: { ...process.env, CODEX_MCP_NODE_PATH: node } },
      );
      expect(result.status).toBe(0);
      expect(readFileSync(output, "utf8")).toBe(
        '{"path":"a.py","area":"src"}\n',
      );
      expect(result.stdout).toEqual(
        Buffer.concat([
          Buffer.from("Copied 1 rows into "),
          output,
          Buffer.from("\n"),
        ]),
      );
    },
  );
  test.skipIf(process.platform !== "win32")(
    "Windows launcher reads and writes paths with spaces",
    () => {
      const f = fixture();
      const input = join(f.root, "rank input.jsonl"),
        output = join(f.root, "deep review.jsonl");
      write(input, [candidate("a.py")]);
      const caller = join(f.root, "caller.cmd");
      const launcher = join(
        PLUGIN_ROOT,
        "scripts",
        "launch_codex_security_mcp.cmd",
      );
      writeFileSync(
        caller,
        `@echo off\r\ncall "${launcher}" --helper copy-deep-review-input --rank-input "${input}" --out "${output}"\r\nexit /b %errorlevel%\r\n`,
      );
      const result = spawnSync(
        process.env["ComSpec"] ?? "cmd.exe",
        ["/d", "/s", "/c", `""${caller}""`],
        {
          env: { ...process.env, CODEX_MCP_NODE_PATH: node },
          encoding: "utf8",
          windowsVerbatimArguments: true,
        },
      );
      expect(result.status, result.stderr || result.error?.message).toBe(0);
      expect(read(output)).toEqual([{ path: "a.py", area: "src" }]);
    },
  );
});

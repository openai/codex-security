import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runCommand } from "./support/shell.js";
import { removeTemporaryDirectory } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { windowsHelperFixture } from "./windows-helper-command.js";
import {
  hasWindowsLoopbackShare,
  windowsLoopbackPath,
} from "./windows-helper-location.js";

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
afterEach(async () => {
  await Promise.all(roots.splice(0).map(removeTemporaryDirectory));
});

describe("deep-review worklists", () => {
  test("selects rows with long internal whitespace without rescanning suffixes", async () => {
    const f = fixture();
    write(f.input, [
      { ...ranked("a.py"), reason: "a" + " ".repeat(128000) + "b" },
    ]);
    const result = await runCommand(
      node,
      [
        helper,
        "select-deep-review-input",
        "--rank-output",
        f.input,
        "--out",
        f.output,
      ],
      { cwd: f.root, timeout: 5000 },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(read(f.output)).toEqual([{ path: "a.py", area: "src" }]);
  });
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
    "closes an empty worklist with an empty output (selection=%j)",
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
    ["+20", 1],
  ] as const)(
    "selects the requested integer percentage %s",
    (percent, count) => {
      const f = fixture();
      write(f.input, [ranked("a.py"), ranked("b.py"), ranked("c.py")]);
      expect(run(f, true, [`--top-percent=${percent}`]).status).toBe(0);
      expect(read(f.output)).toHaveLength(count);
    },
  );
  test("orders tied Unicode paths and preserves their contents", () => {
    const f = fixture();
    write(f.input, [
      ranked("𐀀.py", 5, true, "é"),
      ranked("\ue000.py", 5, true, "\udcff"),
      ranked("\u007f.py", 5, true, "\t"),
    ]);
    expect(run(f, true).status).toBe(0);
    expect(read(f.output)).toEqual([
      { path: "\u007f.py", area: "\t" },
      { path: "\ue000.py", area: "\udcff" },
      { path: "𐀀.py", area: "é" },
    ]);
  });
  test.each([
    ["\n", false],
    ["\n", true],
    ["\r\n", false],
    ["\r\n", true],
    ["\r", false],
    ["\r", true],
  ] as const)(
    "accepts UTF-8 rows with newline %j and final terminator %j",
    (separator, terminated) => {
      const f = fixture();
      writeFileSync(
        f.input,
        JSON.stringify(candidate("é.py", "雪")) +
          separator +
          JSON.stringify(candidate("b.py")) +
          (terminated ? separator : ""),
      );
      expect(run(f, false).status).toBe(0);
      expect(read(f.output)).toEqual([
        { path: "é.py", area: "雪" },
        { path: "b.py", area: "src" },
      ]);
    },
  );
  test("reads split UTF-8 sequences and CRLF without adding or losing rows", () => {
    const f = fixture();
    const prefix = '{"path":"a.py","area":"src","preview":"';
    const first = prefix + "x".repeat(65_535 - prefix.length) + '雪"}';
    const second = JSON.stringify(candidate("b.py"));
    const padding = 2 * 65_536 - Buffer.byteLength(first + "\n" + second) - 1;
    writeFileSync(
      f.input,
      first +
        "\n" +
        second +
        " ".repeat(padding) +
        "\r\n" +
        JSON.stringify(candidate("c.py")) +
        "\r",
    );
    expect(run(f, false).status).toBe(0);
    expect(read(f.output)).toEqual([
      { path: "a.py", area: "src" },
      { path: "b.py", area: "src" },
      { path: "c.py", area: "src" },
    ]);
  });
  test.skipIf(process.platform === "win32")(
    "closes worklist descriptors after completion or early failure",
    async () => {
      if (
        runTestInSubprocess(
          import.meta.path,
          "closes worklist descriptors after completion or early failure",
        )
      )
        return;
      const files = await import("node:fs");
      const opening = spyOn(files, "openSync");
      const helperSource = new URL(
        "../../../plugins/codex-security/mcp-app/src/helpers/helper-files.ts",
        import.meta.url,
      );
      const { readUtf8Lines } = await import(helperSource.href);
      const f = fixture();
      try {
        for (const mode of ["complete", "return", "decode", "consumer"]) {
          writeFileSync(
            f.input,
            mode === "decode" ? Buffer.from([0x61, 10, 0xc3]) : "a\nb\n",
          );
          opening.mockClear();
          const iterator = readUtf8Lines(f.input)[Symbol.iterator]();
          try {
            expect(iterator.next().value).toBe("a");
            const descriptor = opening.mock.results[0]!.value as number;
            expect(files.fstatSync(descriptor).isFile()).toBe(true);
            const remaining = { [Symbol.iterator]: () => iterator };
            if (mode === "return") iterator.return!();
            else if (mode === "decode")
              expect(() => iterator.next()).toThrow("encoded data");
            else if (mode === "consumer")
              expect(() =>
                Array.from(remaining, () => {
                  throw new Error("consumer failed");
                }),
              ).toThrow("consumer failed");
            else expect(Array.from(remaining)).toEqual(["b"]);
            expect(() => files.fstatSync(descriptor)).toThrow("EBADF");
          } finally {
            iterator.return!();
          }
        }
      } finally {
        opening.mockRestore();
      }
    },
  );
  const invalid: Array<[boolean, string | Buffer, string]> = [
    [false, "\n", "blank JSONL rows are not allowed"],
    [
      false,
      JSON.stringify(candidate("a.py")) + "\r\n\r",
      ":2: blank JSONL rows are not allowed",
    ],
    [false, "\u001c\n", "invalid JSON"],
    [false, "{}\n\n", "missing fields"],
    [false, "{not json}\n", "invalid JSON"],
    [false, "[]\n", "expected a JSON object"],
    [
      false,
      JSON.stringify({ ...candidate("a.py"), extra: true }),
      'unexpected fields ["extra"]',
    ],
    [false, JSON.stringify(candidate("  ")), "path must be a non-empty string"],
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
      '{"path":"a.py","area":"src","score":5.5,"include":true,"reason":"x"}',
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
    [false, "\ufeff" + JSON.stringify(candidate("a.py")), "invalid JSON"],
    [false, Buffer.from([0xff]), "encoded data"],
    [
      false,
      Buffer.concat([
        Buffer.from(JSON.stringify(candidate("é.py")) + "\r\n"),
        Buffer.from([0xc3]),
      ]),
      "encoded data",
    ],
    [
      false,
      Buffer.concat([
        Buffer.from('{"path":"a.py","area":"src","preview":"'),
        Buffer.from([0xed, 0xa0, 0x80]),
        Buffer.from('"}'),
      ]),
      "encoded data",
    ],
  ];
  test.each(invalid)(
    "rejects invalid worklist data (selection=%j, data=%j)",
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
    "rejects repeated paths before output (selection=%j)",
    (selection) => {
      const f = fixture();
      write(
        f.input,
        selection
          ? [ranked("a-\u007f\u009b.py"), ranked("a-\u007f\u009b.py")]
          : [candidate("a-\u007f\u009b.py"), candidate("a-\u007f\u009b.py")],
      );
      const result = run(f, selection);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain(
        'contains duplicate paths: ["a-\\u007f\\u009b.py"]',
      );
      expect(result.stderr).not.toMatch(/[\u007f-\u009f]/u);
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
  test.each([false, true])(
    "removes pathlib dot and empty components from input and output (selection=%j)",
    (selection) => {
      const f = fixture();
      write(f.input, [selection ? ranked("a.py") : candidate("a.py")]);
      for (const suffix of ["/.", "///", "/./."]) {
        const result = run(
          { ...f, input: f.input + suffix, output: f.output + suffix },
          selection,
        );
        expect(result.status, result.stderr).toBe(0);
        expect(result.stdout).toBe(
          `${selection ? "Selected 1 of 1" : "Copied 1"} rows into ${f.output}${newline}`,
        );
        expect(read(f.output)).toEqual([{ path: "a.py", area: "src" }]);
      }
    },
  );
  test("reports missing input and preserves argument parsing status", () => {
    const f = fixture();
    writeFileSync(f.output, "previous output\n");
    const inputs = [f.input, join(f.output, "child.jsonl")];
    if (process.platform !== "win32") {
      const loop = join(f.root, "loop-\x1b[2J.jsonl");
      symlinkSync(loop, loop);
      inputs.push(loop);
    }
    for (const selection of [false, true]) {
      for (const input of inputs) {
        const result = run({ ...f, input }, selection);
        expect(result.status).toBe(1);
        expect(result.stderr).toBe(
          `Rank ${selection ? "output" : "input"} missing: ${input}${newline}`,
        );
      }
      expect(readFileSync(f.output, "utf8")).toBe("previous output\n");
    }
    write(f.input, [ranked("a.py")]);
    expect(run(f, true, ["--top-percent=20"]).status).toBe(0);
    expect(run(f, true, ["--top-percent", "20"]).status).toBe(0);
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
    "escapes controls in filesystem errors but preserves other command text",
    () => {
      const f = fixture();
      f.input = join(f.root, "input-\x1b[2J.jsonl");
      f.output = join(f.root, "output-\x1b[2J.jsonl");
      for (const selection of [false, true]) {
        const missing = run(f, selection);
        expect(missing.status).toBe(1);
        expect(missing.stderr).toBe(
          `Rank ${selection ? "output" : "input"} missing: ${f.input}\n`,
        );
        writeFileSync(f.input, "{}\n");
        const invalid = run(f, selection);
        expect(invalid.status).toBe(1);
        expect(invalid.stderr).toStartWith(`${f.input}:1: missing fields`);
        write(f.input, [selection ? ranked("a.py") : candidate("a.py")]);
        mkdirSync(f.output);
        const collision = run(f, selection);
        expect(collision.status).toBe(1);
        expect(collision.stderr).toMatch(/\\(?:x1b|u001b)\[2J/);
        expect(collision.stderr).not.toContain("\x1b");
        rmSync(f.output, { recursive: true });
        const success = run(f, selection);
        expect(success.status).toBe(0);
        expect(success.stdout).toBe(
          `${selection ? "Selected 1 of 1" : "Copied 1"} rows into ${f.output}\n`,
        );
        rmSync(f.input);
        rmSync(f.output);
      }
    },
  );
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
    "preserves symlink-sensitive parent traversal for both input and output",
    () => {
      const f = fixture();
      const child = join(f.root, "child");
      mkdirSync(join(child, "nested"), { recursive: true });
      symlinkSync(join(child, "nested"), join(f.root, "link"));
      write(f.input, [candidate("wrong.py")]);
      writeFileSync(f.output, "output sentinel");
      const input = join(child, "input.jsonl");
      for (const selection of [false, true]) {
        write(input, [selection ? ranked("right.py") : candidate("right.py")]);
        const result = run(
          {
            ...f,
            input: "link/../input.jsonl/.",
            output: "link/../output.jsonl/.",
          },
          selection,
        );
        expect(result.status, result.stderr).toBe(0);
        expect(read(join(child, "output.jsonl"))).toEqual([
          { path: "right.py", area: "src" },
        ]);
        expect(readFileSync(f.output, "utf8")).toBe("output sentinel");
      }
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
  for (const location of ["absolute", "relative", "unc"] as const)
    test.skipIf(
      process.platform !== "win32" ||
        (location === "unc" && !hasWindowsLoopbackShare),
    )(
      `documented PowerShell copy command preserves ${location} literal paths and worklist contents`,
      async () => {
        const f = fixture();
        const launcher = windowsHelperFixture(f.root);
        const discovery = join(
          f.root,
          "discovery %USERNAME% !EXPAND! \u96ea's",
        );
        const expandedDiscovery = discovery.replace(
          "%USERNAME%",
          "expanded-user",
        );
        for (const directory of [discovery, expandedDiscovery])
          mkdirSync(directory);
        write(join(discovery, "rank_input.jsonl"), [
          candidate("caf\u00e9/\u96ea.py"),
        ]);
        write(join(expandedDiscovery, "rank_input.jsonl"), [
          candidate("wrong.py"),
        ]);
        const output = join(discovery, "deep_review_input.jsonl");
        const expandedOutput = join(
          expandedDiscovery,
          "deep_review_input.jsonl",
        );
        const caller = join(f.root, "caller");
        mkdirSync(caller);
        const workingDirectory =
          location === "unc" ? windowsLoopbackPath(caller) : caller;
        const argument = (path: string) =>
          location === "absolute" ? path : relative(caller, path);
        for (const powershell of launcher.powershells) {
          rmSync(output, { force: true });
          writeFileSync(expandedOutput, "expanded output sentinel");
          const result = await launcher.run(
            powershell,
            "skills/security-scan/references/scan-artifacts-and-ledger.md",
            {
              "<plugin_dir>": argument(launcher.plugin),
              "<discovery_dir>": argument(discovery),
            },
            undefined,
            workingDirectory,
          );
          expect(result.stdout, result.diagnostics).not.toContain(
            "expanded-plugin-used",
          );
          expect(result.status, result.diagnostics).toBe(0);
          if (location !== "unc")
            expect(result.stderr, result.diagnostics).toBe("");
          expect(existsSync(output), result.diagnostics).toBe(true);
          expect(read(output), result.diagnostics).toEqual([
            { path: "caf\u00e9/\u96ea.py", area: "src" },
          ]);
          expect(readFileSync(expandedOutput, "utf8"), result.diagnostics).toBe(
            "expanded output sentinel",
          );
        }
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

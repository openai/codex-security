import { spawnSync } from "node:child_process";
import {
  chmodSync,
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
  args: string[] = [],
  env = process.env,
) {
  return spawnSync(
    node,
    [
      helper,
      "copy-deep-review-input",
      "--rank-input",
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
  test("copies every candidate in input order and preserves Unicode fields", () => {
    const f = fixture();
    write(f.input, [
      candidate("𐀀.py", "é"),
      candidate("\ue000.py", "\udcff"),
      candidate("b.py", "api"),
    ]);
    const result = run(f);
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(`Copied 3 rows into ${f.output}${newline}`);
    expect(read(f.output)).toEqual([
      { path: "𐀀.py", area: "é" },
      { path: "\ue000.py", area: "\udcff" },
      { path: "b.py", area: "api" },
    ]);
  });
  test("closes an empty worklist with an empty output", () => {
    const f = fixture();
    write(f.input, []);
    writeFileSync(f.output, "previous contents");
    expect(run(f).status).toBe(0);
    expect(readFileSync(f.output)).toHaveLength(0);
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
      expect(run(f).status).toBe(0);
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
    expect(run(f).status).toBe(0);
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
  const invalid: Array<[string | Buffer, string]> = [
    ["\n", "blank JSONL rows are not allowed"],
    [
      JSON.stringify(candidate("a.py")) + "\r\n\r",
      ":2: blank JSONL rows are not allowed",
    ],
    ["\u001c\n", "invalid JSON"],
    ["{}\n\n", "missing fields"],
    ["{not json}\n", "invalid JSON"],
    ["[]\n", "expected a JSON object"],
    [
      JSON.stringify({ ...candidate("a.py"), extra: true }),
      'unexpected fields ["extra"]',
    ],
    [JSON.stringify(candidate("  ")), "path must be a non-empty string"],
    [
      JSON.stringify({ ...candidate("a.py"), preview: 1 }),
      "preview must be a string",
    ],
    [
      JSON.stringify({ ...candidate("a.py"), area: null }),
      "area must be a string",
    ],
    ["\ufeff" + JSON.stringify(candidate("a.py")), "invalid JSON"],
    [Buffer.from([0xff]), "encoded data"],
    [
      Buffer.concat([
        Buffer.from(JSON.stringify(candidate("é.py")) + "\r\n"),
        Buffer.from([0xc3]),
      ]),
      "encoded data",
    ],
    [
      Buffer.concat([
        Buffer.from('{"path":"a.py","area":"src","preview":"'),
        Buffer.from([0xed, 0xa0, 0x80]),
        Buffer.from('"}'),
      ]),
      "encoded data",
    ],
  ];
  test.each(invalid)("rejects invalid worklist data %j", (text, message) => {
    const f = fixture();
    writeFileSync(f.input, text);
    writeFileSync(f.output, "preserve existing output");
    const result = run(f);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(message);
    expect(readFileSync(f.output, "utf8")).toBe("preserve existing output");
  });
  test("rejects repeated paths before output", () => {
    const f = fixture();
    write(f.input, [
      candidate("a-\u007f\u009b.py"),
      candidate("a-\u007f\u009b.py"),
    ]);
    const result = run(f);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      'contains duplicate paths: ["a-\\u007f\\u009b.py"]',
    );
    expect(result.stderr).not.toMatch(/[\u007f-\u009f]/u);
    expect(existsSync(f.output)).toBe(false);
  });
  test("accepts duplicate JSON object keys and empty area/preview as before", () => {
    const f = fixture();
    writeFileSync(
      f.input,
      '{"path":"unused.py","path":"a.py","area":"","preview":""}',
    );
    expect(run(f).status).toBe(0);
    expect(read(f.output)).toEqual([{ path: "a.py", area: "" }]);
  });
  test("allows replacing the input after all rows have been read", () => {
    const f = fixture();
    write(f.input, [candidate("b.py"), candidate("a.py")]);
    expect(run({ ...f, output: f.input }).status).toBe(0);
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
      [],
      env,
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toBe(
      `Copied 1 rows into ${join("nested", "output.jsonl")}${newline}`,
    );
    expect(read(join(f.root, "nested", "output.jsonl"))).toHaveLength(1);
  });
  test("removes pathlib dot and empty components from input and output", () => {
    const f = fixture();
    write(f.input, [candidate("a.py")]);
    for (const suffix of ["/.", "///", "/./."]) {
      const result = run({
        ...f,
        input: f.input + suffix,
        output: f.output + suffix,
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe(`Copied 1 rows into ${f.output}${newline}`);
      expect(read(f.output)).toEqual([{ path: "a.py", area: "src" }]);
    }
  });
  test("reports missing input and preserves argument parsing status", () => {
    const f = fixture();
    writeFileSync(f.output, "previous output\n");
    const inputs = [f.input, join(f.output, "child.jsonl")];
    if (process.platform !== "win32") {
      const loop = join(f.root, "loop-\x1b[2J.jsonl");
      symlinkSync(loop, loop);
      inputs.push(loop);
    }
    for (const input of inputs) {
      const result = run({ ...f, input });
      expect(result.status).toBe(1);
      expect(result.stderr).toBe(`Rank input missing: ${input}${newline}`);
    }
    expect(readFileSync(f.output, "utf8")).toBe("previous output\n");
    for (const args of [["--unknown"], ["extra"], ["--rank-input"]])
      expect(run(f, args).status).toBe(2);
    expect(run(f, ["--help"]).stdout).toContain("copy-deep-review-input");
  });
  test.skipIf(process.platform === "win32")(
    "escapes controls in filesystem errors but preserves other command text",
    () => {
      const f = fixture();
      f.input = join(f.root, "input-\x1b[2J.jsonl");
      f.output = join(f.root, "output-\x1b[2J.jsonl");
      const missing = run(f);
      expect(missing.status).toBe(1);
      expect(missing.stderr).toBe(`Rank input missing: ${f.input}\n`);
      writeFileSync(f.input, "{}\n");
      const invalid = run(f);
      expect(invalid.status).toBe(1);
      expect(invalid.stderr).toStartWith(`${f.input}:1: missing fields`);
      write(f.input, [candidate("a.py")]);
      mkdirSync(f.output);
      const collision = run(f);
      expect(collision.status).toBe(1);
      expect(collision.stderr).toMatch(/\\(?:x1b|u001b)\[2J/);
      expect(collision.stderr).not.toContain("\x1b");
      rmSync(f.output, { recursive: true });
      const success = run(f);
      expect(success.status).toBe(0);
      expect(success.stdout).toBe(`Copied 1 rows into ${f.output}\n`);
      rmSync(f.input);
      rmSync(f.output);
    },
  );
  test.skipIf(process.platform === "win32")(
    "follows existing input/output symlinks and preserves existing output permissions",
    () => {
      const f = fixture();
      const target = join(f.root, "target.jsonl");
      writeFileSync(target, "existing", { mode: 0o640 });
      chmodSync(target, 0o640);
      symlinkSync(target, f.output);
      write(f.input, [candidate("a.py")]);
      const inputLink = join(f.root, "input-link");
      symlinkSync(f.input, inputLink);
      expect(run({ ...f, input: inputLink }).status).toBe(0);
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
      write(input, [candidate("right.py")]);
      const result = run({
        ...f,
        input: "link/../input.jsonl/.",
        output: "link/../output.jsonl/.",
      });
      expect(result.status, result.stderr).toBe(0);
      expect(read(join(child, "output.jsonl"))).toEqual([
        { path: "right.py", area: "src" },
      ]);
      expect(readFileSync(f.output, "utf8")).toBe("output sentinel");
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

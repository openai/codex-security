import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  symlinkSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { delimiter, dirname, join, parse, relative, sep } from "node:path";
import { createTemporaryDirectoriesSync } from "./support/temporary-directories.js";
import { nodeCommand } from "./support/shell.js";
import { git } from "./git-fixture.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { resolveCodexCommand } from "../src/runtime.js";
import { bundledCodexSdkEnvironment } from "../src/codex-sdk-environment.js";

const temporary = createTemporaryDirectoriesSync(true);
const node = nodeCommand().command;
// APFS requires valid UTF-8 names; Linux also permits undecodable bytes.
const pathNameBytes =
  process.platform === "darwin" ? Buffer.from("雪") : Buffer.from([0xff]);
afterEach(temporary.cleanup);

function fixture() {
  const root = temporary.create("codex-security-inventory-"),
    repo = join(root, "repository"),
    out = join(root, "output");
  mkdirSync(repo);
  git(repo, "init", "-q");
  const toolEnvironment = bundledCodexSdkEnvironment(
    resolveCodexCommand({}).command,
    Object.fromEntries(
      Object.entries(process.env).filter(
        (entry): entry is [string, string] => entry[1] !== undefined,
      ),
    ),
  );
  const write = (path: string, data: string | Buffer = "value = 1\n") => {
    const file = join(repo, path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, data);
    return file;
  };
  const run = (
    command: string,
    args: string[] = [],
    env: NodeJS.ProcessEnv = toolEnvironment,
  ) => {
    const arguments_ = [
      join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
      command,
      "--repo",
      repo,
      "--out",
      out,
      ...args,
    ];
    const home = env["HOME"];
    if (process.platform === "win32" && home && !home.isWellFormed()) {
      const binding = join(
        PLUGIN_ROOT,
        "mcp",
        "native",
        `win32-${process.arch}`,
        "windows.node",
      );
      const check = join(root, "raw-home-check.cjs");
      writeFileSync(
        check,
        `require("node:assert/strict").equal(require(${JSON.stringify(binding)}).windowsEnvironment(Buffer.from("HOME", "utf16le"))?.toString("utf16le"), ${JSON.stringify(home)});`,
      );
      // The native launch preserves HOME before the helper reads its environment.
      const script = `
const native = require(${JSON.stringify(binding)});
const wide = value => Buffer.from(value, "utf16le");
const result = native.runWindowsProcess(wide(process.execPath), ["--require", ${JSON.stringify(check)}, ...process.argv.slice(1)].map(wide), undefined, [{ name: wide("HOME"), value: wide(${JSON.stringify(home)}) }]);
if (result.error) throw Object.assign(new Error(result.message), { errno: result.error });
process.exitCode = result.status;
`;
      return spawnSync(node, ["-e", script, ...arguments_], {
        env,
        encoding: "utf8",
      });
    }
    return spawnSync(node, arguments_, { env, encoding: "utf8" });
  };
  const success = (command: string, args: string[] = []) => {
    const result = run(command, args);
    expect(result.status, result.stderr).toBe(0);
    return readFileSync(out, "utf8");
  };
  const rows = (command = "make-repo-rank-input", args: string[] = []) =>
    success(command, args)
      .split(/\r?\n/u)
      .filter(Boolean)
      .map(
        (line) =>
          JSON.parse(line) as { path: string; area?: string; preview?: string },
      );
  const commit = () => {
    git(repo, "add", ".");
    git(repo, "commit", "-qm", "Fixture revision");
    return git(repo, "rev-parse", "HEAD");
  };
  return {
    root,
    repo,
    out,
    write,
    run,
    success,
    rows,
    commit,
    toolEnvironment,
  };
}

test("revision previews retain blobs with Git's input-only NUL batch protocol", () => {
  const f = fixture();
  f.write("deleted.py", "deleted source\n");
  f.write("changed.py", "old source\n");
  const base = f.commit();
  rmSync(join(f.repo, "deleted.py"));
  f.write("changed.py", "new source\n");
  f.write("empty.py", "");
  f.write("binary", Buffer.from([0, 1, 2]));
  f.commit();
  const preload = join(f.root, "old-git.cjs");
  const calls = join(f.root, "batch-arguments.jsonl");
  writeFileSync(
    preload,
    `
const cp = require("node:child_process");
const spawn = cp.spawn;
cp.spawn = (command, args, options) => {
  if (args.includes("cat-file")) {
    require("node:fs").appendFileSync(${JSON.stringify(calls)}, JSON.stringify(args) + "\\n");
    args = args.map(arg => arg === "-Z" ? "--unsupported-batch-zero" : arg);
  }
  return spawn(command, args, options);
};
require("node:module").syncBuiltinESMExports();
`,
  );
  const result = f.run(
    "make-diff-rank-input",
    ["--base", base, "--mode", "revisions"],
    {
      ...f.toolEnvironment,
      NODE_OPTIONS: `${f.toolEnvironment["NODE_OPTIONS"] ?? ""} --require ${JSON.stringify(preload)}`,
    },
  );
  expect(result.status, result.stderr).toBe(0);
  const rows = readFileSync(f.out, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(rows.find((row) => row.path === "deleted.py")?.preview).toBe("");
  expect(rows.find((row) => row.path === "changed.py")?.preview).toBe(
    "new source",
  );
  expect(rows.find((row) => row.path === "empty.py")?.preview).toBe("");
  expect(rows.some((row) => row.path === "binary")).toBe(false);
  const batches = readFileSync(calls, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(batches.length).toBeGreaterThan(0);
  for (const args of batches) {
    expect(args).toContain("-z");
    expect(args).not.toContain("-Z");
  }
});

for (const command of [
  "generate-in-scope-files",
  "make-repo-scope-input",
  "make-repo-rank-input",
]) {
  for (const rawWindowsHome of [false, true]) {
    test.skipIf(process.platform !== "win32")(
      `${command} selects trusted ripgrep outside the repository${rawWindowsHome ? " through the UTF-16 bridge" : ""}`,
      () => {
        const f = fixture();
        f.write("scope/visible.py");
        const hostile = join(f.repo, "rg.exe");
        copyFileSync(node, hostile);
        const scopes = join(f.root, "scopes.json");
        writeFileSync(scopes, '["scope"]');
        const preload = join(f.root, "tool-launch.cjs");
        const calls = join(f.root, "tool-launch.jsonl");
        writeFileSync(
          preload,
          `
const cp = require("node:child_process");
const spawn = cp.spawn;
const record = command => {
  if (/(^|[\\\\/])rg(?:\\.exe|\\.com)?$/i.test(command))
    require("node:fs").appendFileSync(${JSON.stringify(calls)}, JSON.stringify(command) + "\\n");
};
cp.spawn = (command, args, options) => {
  record(command);
  const child = spawn(command, args, options);
  if (child.send) {
    const send = child.send.bind(child);
    child.send = (payload, ...rest) => {
      if (payload.executable) record(Buffer.from(payload.executable, "base64").toString("utf16le"));
      return send(payload, ...rest);
    };
  }
  return child;
};
require("node:module").syncBuiltinESMExports();
`,
        );
        const env = { ...f.toolEnvironment };
        const pathKey =
          Object.keys(env).find((key) => key.toUpperCase() === "PATH") ??
          "PATH";
        // The bridge case also checks Windows' implicit current-directory lookup.
        if (!rawWindowsHome)
          env[pathKey] = `${f.repo}${delimiter}${env[pathKey] ?? ""}`;
        if (rawWindowsHome) {
          env["HOME"] = `${f.root}${sep}home-\ud800`;
          expect(env["HOME"].isWellFormed()).toBe(false);
        }
        env["CODEX_SECURITY_GIT"] = "";
        env["NODE_OPTIONS"] =
          `${env["NODE_OPTIONS"] ?? ""} --require ${JSON.stringify(preload)}`;
        const result = f.run(
          command,
          command === "generate-in-scope-files"
            ? ["--scope", "scope"]
            : ["--scopes-file", scopes],
          env,
        );
        expect(result.status, result.stderr).toBe(0);
        const contents = readFileSync(f.out, "utf8");
        expect(
          command === "generate-in-scope-files"
            ? contents.trim()
            : JSON.parse(contents).path,
        ).toBe("scope/visible.py");
        const launched = readFileSync(calls, "utf8")
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line));
        expect(launched.length).toBeGreaterThan(0);
        for (const executable of launched) {
          expect(parse(executable).root).not.toBe("");
          expect(executable).not.toBe(hostile);
        }
      },
    );
  }
}

for (const command of [
  "generate-in-scope-files",
  "make-repo-scope-input",
  "make-repo-rank-input",
]) {
  for (const location of [
    "relative",
    "symlink parent",
    "Windows bridge",
  ] as const) {
    test.skipIf(
      location === "symlink parent"
        ? process.platform === "win32"
        : location === "Windows bridge" && process.platform !== "win32",
    )(
      `${command} resolves ${location} ripgrep PATH entries from the repository`,
      () => {
        const f = fixture();
        f.write("scope/visible.py");
        const env = { ...f.toolEnvironment };
        const pathKey =
          Object.keys(env).find((key) => key.toUpperCase() === "PATH") ??
          "PATH";
        const executable = Bun.which("rg", { PATH: env[pathKey] });
        expect(executable).not.toBeNull();
        const tools = join(
          f.root,
          ...(location === "symlink parent" ? ["physical"] : []),
          "tools",
        );
        mkdirSync(tools, { recursive: true });
        copyFileSync(
          executable!,
          join(tools, process.platform === "win32" ? "rg.exe" : "rg"),
        );
        if (location === "symlink parent") {
          const child = join(f.root, "physical", "child");
          mkdirSync(child);
          symlinkSync(child, join(f.root, "link"), "dir");
        }
        env[pathKey] =
          location === "symlink parent" ? "../link/../tools" : "../tools";
        if (location === "Windows bridge") {
          env["HOME"] = `${f.root}${sep}home-\ud800`;
          expect(env["HOME"].isWellFormed()).toBe(false);
        }
        env["CODEX_SECURITY_GIT"] = "";
        const scopes = join(f.root, "scopes.json");
        writeFileSync(scopes, '["scope"]');
        const result = f.run(
          command,
          command === "generate-in-scope-files"
            ? ["--scope", "scope"]
            : ["--scopes-file", scopes],
          env,
        );
        expect(result.status, result.stderr).toBe(0);
        const output = readFileSync(f.out, "utf8");
        expect(
          command === "generate-in-scope-files"
            ? output.trim()
            : JSON.parse(output).path,
        ).toBe("scope/visible.py");
      },
    );
  }
}

function runPathInventory(
  f: ReturnType<typeof fixture>,
  command: string,
  env: NodeJS.ProcessEnv,
  rawHome = false,
) {
  const scopes = join(f.root, "scopes.json");
  writeFileSync(scopes, '["scope"]');
  const args =
    command === "generate-in-scope-files"
      ? ["--scope", "scope"]
      : ["--scopes-file", scopes];
  if (!rawHome) return f.run(command, args, env);
  return spawnSync(
    "/bin/sh",
    [
      "-c",
      'HOME=$(printf "%s/\\377" "$1"); export HOME; shift; exec "$@"',
      "inventory-raw-home",
      f.root,
      node,
      join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
      command,
      "--repo",
      f.repo,
      "--out",
      f.out,
      ...args,
    ],
    { env, encoding: "utf8" },
  );
}

for (const command of [
  "generate-in-scope-files",
  "make-repo-scope-input",
  "make-repo-rank-input",
]) {
  test.skipIf(process.platform === "win32")(
    `${command} continues PATH lookup after a missing ripgrep interpreter`,
    () => {
      const f = fixture();
      f.write("scope/visible.py");
      const env = { ...f.toolEnvironment };
      const first = join(f.root, "first");
      mkdirSync(first);
      writeFileSync(
        join(first, "rg"),
        `#!${join(f.root, "missing-interpreter")}\n`,
        { mode: 0o700 },
      );
      env["PATH"] = `${first}${delimiter}${env["PATH"] ?? ""}`;
      env["CODEX_SECURITY_GIT"] = "";
      const result = runPathInventory(f, command, env);
      expect(result.status, result.stderr).toBe(0);
      const output = readFileSync(f.out, "utf8");
      expect(
        command === "generate-in-scope-files"
          ? output.trim()
          : JSON.parse(output).path,
      ).toBe("scope/visible.py");
    },
  );
  for (const lookup of [
    "double-quoted semicolon",
    "single-quoted semicolon",
    "extension precedence",
  ] as const) {
    for (const bridge of lookup === "single-quoted semicolon"
      ? [false]
      : [false, true]) {
      test.skipIf(process.platform !== "win32")(
        `${command} retains Windows ${lookup} lookup${bridge ? " through the UTF-16 bridge" : ""}`,
        () => {
          const f = fixture();
          f.write("scope/visible.py");
          const env = { ...f.toolEnvironment };
          const pathKey =
            Object.keys(env).find((key) => key.toUpperCase() === "PATH") ??
            "PATH";
          const executable = Bun.which("rg", { PATH: env[pathKey] });
          expect(executable).not.toBeNull();
          const quoted = lookup !== "extension precedence";
          const tools = join(f.root, quoted ? "tools;version" : "tools");
          mkdirSync(tools);
          // Ordinary Node lookup prefers COM; the existing raw bridge prefers EXE.
          const extension = !quoted && !bridge ? "com" : "exe";
          copyFileSync(executable!, join(tools, `rg.${extension}`));
          if (!quoted)
            copyFileSync(
              node,
              join(tools, `rg.${extension === "com" ? "exe" : "com"}`),
            );
          const quote = lookup === "single-quoted semicolon" ? "'" : '"';
          env[pathKey] = quoted ? `${quote}${tools}${quote}` : tools;
          if (bridge) {
            env["HOME"] = `${f.root}${sep}home-\ud800`;
            expect(env["HOME"].isWellFormed()).toBe(false);
          }
          env["CODEX_SECURITY_GIT"] = "";
          const result = runPathInventory(f, command, env);
          expect(result.status, result.stderr).toBe(0);
          const output = readFileSync(f.out, "utf8");
          expect(
            command === "generate-in-scope-files"
              ? output.trim()
              : JSON.parse(output).path,
          ).toBe("scope/visible.py");
        },
      );
    }
  }
}

for (const rawHome of [false, true]) {
  test.skipIf(process.platform === "win32")(
    `inventory preserves a launched ripgrep wrapper's exit127${rawHome ? " with raw HOME" : ""}`,
    () => {
      const f = fixture();
      f.write("scope/visible.py");
      const first = join(f.root, "first");
      mkdirSync(first);
      writeFileSync(
        join(first, "rg"),
        '#!/bin/sh\nprintf "synthetic tool failure\\n" >&2\nexit 127\n',
        { mode: 0o700 },
      );
      writeFileSync(f.out, "previous\n");
      const result = runPathInventory(
        f,
        "generate-in-scope-files",
        {
          ...f.toolEnvironment,
          PATH: `${first}${delimiter}${f.toolEnvironment["PATH"] ?? ""}`,
          CODEX_SECURITY_GIT: "",
        },
        rawHome,
      );
      expect(result.status).toBe(2);
      expect(result.stderr).toContain("synthetic tool failure");
      expect(readFileSync(f.out, "utf8")).toBe("previous\n");
    },
  );
}

for (const scope of [".", "src", "./src", "src/résumé.py"]) {
  test(`path inventory preserves ripgrep spelling and byte order for ${scope}`, () => {
    const f = fixture();
    f.write("src/résumé.py");
    f.write("src/alpha.py");
    f.write("src/binary", Buffer.from([0]));
    f.write(".hidden/source.py");
    f.write(".gitignore", "ignored/\n");
    f.write("ignored/untracked.py");
    f.write("ignored/tracked.py");
    git(f.repo, "add", "--force", "ignored/tracked.py");
    const args = [
      "--files",
      "--null",
      "--hidden",
      "--path-separator",
      "/",
      "--glob",
      "!**/.git",
      "--glob",
      "!**/.git/**",
      "--",
      scope,
    ];
    const rg = spawnSync("rg", args, { cwd: f.repo, env: f.toolEnvironment });
    expect(rg.status, rg.error?.message ?? rg.stderr?.toString()).toBe(0);
    const expected = rg.stdout.toString().split("\0").filter(Boolean);
    if (scope === ".") expected.push("./ignored/tracked.py");
    expect(f.success("generate-in-scope-files", ["--scope", scope])).toBe(
      expected
        .map((path) => Buffer.from(path + "\n"))
        .sort(Buffer.compare)
        .map(String)
        .join(""),
    );
    expect(readdirSync(f.root).filter((name) => name.endsWith(".tmp"))).toEqual(
      [],
    );
  });
}

for (const command of ["make-repo-rank-input", "make-repo-scope-input"]) {
  test(`${command} retains explicit and ignored tracked files without widening directory scope`, () => {
    const f = fixture();
    f.write("src/source.py");
    f.write("src/entrypoint", "run\n");
    f.write("outside.py");
    f.write(".gitignore", "src/ignored*\n");
    f.write("src/ignored-tracked.py");
    f.write("src/ignored-untracked.py");
    f.write("src/binary", Buffer.from([0]));
    f.write("direct.bin", Buffer.from([0]));
    git(f.repo, "add", "--force", "src/ignored-tracked.py");
    const scopes = join(f.root, "scopes.json");
    writeFileSync(
      scopes,
      JSON.stringify(["src", "direct.bin", "src/source.py"]),
    );
    const rows = f.rows(command, ["--scopes-file", scopes]);
    expect(rows.map((row) => row.path)).toEqual([
      "direct.bin",
      ...(command === "make-repo-scope-input" ? ["src/binary"] : []),
      "src/entrypoint",
      "src/ignored-tracked.py",
      "src/source.py",
    ]);
    if (command === "make-repo-rank-input") expect(rows[0]!.preview).toBe("");
  });
}

for (const encoding of ["utf8", "utf16le", "utf16be"] as const) {
  for (const mode of ["repo", "revisions", "local-patch"]) {
    test(`${mode} previews decode ${encoding} and detect binary bytes beyond the prefix`, () => {
      const f = fixture();
      f.write("existing.py");
      const base = f.commit();
      const source = "    value = 'café 😀  literal'  \n\n    return value  \n";
      const bytes =
        encoding === "utf8"
          ? Buffer.from(source)
          : Buffer.concat([
              Buffer.from([0xff, 0xfe]),
              Buffer.from(source, "utf16le"),
            ]);
      if (encoding === "utf16be") bytes.swap16();
      f.write("text", bytes);
      const lateBinary =
        encoding === "utf8"
          ? Buffer.concat([Buffer.alloc(96 * 1024, 120), Buffer.from([0])])
          : Buffer.concat([
              Buffer.from([0xff, 0xfe]),
              Buffer.from("x".repeat(96 * 1024) + "\0", "utf16le"),
            ]);
      if (encoding === "utf16be") lateBinary.swap16();
      f.write("encoded-binary", lateBinary);
      f.write(
        "late-binary",
        Buffer.concat([Buffer.alloc(96 * 1024, 120), Buffer.from([0])]),
      );
      for (const bom of [
        [0xff, 0xfe],
        [0xfe, 0xff],
      ])
        f.write(
          `late-bom-${bom[0]}`,
          Buffer.concat([
            Buffer.alloc(64 * 1024, 120),
            Buffer.from([...bom, 104, 0, 105, 0]),
          ]),
        );
      if (mode === "revisions") f.commit();
      const rows =
        mode === "repo"
          ? f.rows()
          : f.rows("make-diff-rank-input", ["--base", base, "--mode", mode]);
      expect(rows.find((row) => row.path === "text")?.preview).toBe(
        source.slice(0, -1),
      );
      expect(
        rows.some(
          (row) =>
            row.path === "late-binary" ||
            row.path === "encoded-binary" ||
            row.path.startsWith("late-bom-"),
        ),
      ).toBe(false);
    });
  }
}

for (const budget of [0, -1, 2, 30, 220, 1024]) {
  test(`preview budget ${budget} preserves source and complete UTF-8 units`, () => {
    const f = fixture(),
      source = Array.from(
        { length: 40 },
        (_, index) =>
          `line_${String(index).padStart(2, "0")} ${"😀".repeat(20)}`,
      ).join("\n");
    f.write("source", source);
    const preview = f.rows("make-repo-rank-input", [
      "--preview-bytes",
      String(budget),
    ])[0]!.preview!;
    expect(Buffer.byteLength(preview)).toBeLessThanOrEqual(Math.max(0, budget));
    expect(preview).not.toContain("\ufffd");
    if (budget <= 0) expect(preview).toBe("");
    else if (budget <= 30) expect(source.startsWith(preview)).toBe(true);
    else {
      expect(preview).toContain("line_39");
      expect(preview).toContain("...");
    }
  });
}

test("small previews retain complete bodies, literal replacement characters, and line whitespace", () => {
  const f = fixture();
  f.write(
    "source",
    "\n \t\n    text = 'two  spaces\tand\u0085a separator �'  \r\n    return text  \r\n\n",
  );
  expect(f.rows()[0]!.preview).toBe(
    "    text = 'two  spaces\tand\u0085a separator �'  \n    return text  ",
  );
});

test("explicit scope names are literal and JSONL escapes Unicode separators", () => {
  const f = fixture(),
    name = "audit\u0085line\u2028paragraph\u2029.py";
  f.write(name);
  f.write("~literal/file");
  const scopes = join(f.root, "scopes.json");
  writeFileSync(scopes, JSON.stringify([name, "~literal"]));
  const text = f.success("make-repo-rank-input", ["--scopes-file", scopes]);
  expect(text).not.toMatch(/[\u0085\u2028\u2029]/u);
  expect(
    text
      .split(/\r?\n/u)
      .filter(Boolean)
      .map((line) => JSON.parse(line).path),
  ).toEqual([name, "~literal/file"]);
});

for (const mode of ["revisions", "local-patch"]) {
  test(`${mode} selects added, changed, deleted, and renamed regular files`, () => {
    const f = fixture();
    f.write("changed.py", "old\n");
    f.write("deleted.py", "delete\n");
    f.write("renamed.py", "rename\n");
    const base = f.commit();
    f.write("changed.py", "new\n");
    rmSync(join(f.repo, "deleted.py"));
    git(f.repo, "mv", "renamed.py", "moved.py");
    f.write("new-file", "added\n");
    git(f.repo, "add", ".");
    f.write("unstaged.py", "unstaged\n");
    if (mode === "revisions") {
      f.commit();
      f.write("changed.py", "worktree must not leak\n");
    }
    const args = ["--base", base, "--mode", mode];
    const rows = f.rows("make-diff-rank-input", args);
    expect(rows.find((row) => row.path === "changed.py")?.preview).toBe("new");
    expect(rows.find((row) => row.path === "deleted.py")?.preview).toBe("");
    expect(rows.map((row) => row.path)).toEqual([
      "changed.py",
      "deleted.py",
      "moved.py",
      "new-file",
      "unstaged.py",
    ]);
    expect(
      f.success("generate-in-scope-files", [
        "--scope",
        ".",
        "--diff-base",
        base,
        "--diff-mode",
        mode,
      ]),
    ).toBe(rows.map((row) => row.path + "\n").join(""));
  });
}

for (const [mode, undoStagedChange] of [
  ["revisions", false],
  ["local-patch", false],
  ["local-patch", true],
] as const) {
  test(`${mode} inventories type changes with staged change undone ${undoStagedChange}`, () => {
    const f = fixture();
    f.write("routes.py");
    const changed = join(f.repo, "changed.py");
    symlinkSync("routes.py", changed, "file");
    const base = f.commit();
    rmSync(changed);
    f.write("changed.py", "changed = True\n");
    if (undoStagedChange) {
      git(f.repo, "add", ".");
      rmSync(changed);
      symlinkSync("routes.py", changed, "file");
    } else if (mode === "revisions") f.commit();
    const inventory = f
      .success("generate-in-scope-files", [
        "--scope",
        ".",
        "--diff-base",
        base,
        "--diff-mode",
        mode,
      ])
      .split("\n");
    const ranked = f.rows("make-diff-rank-input", [
      "--base",
      base,
      "--mode",
      mode,
    ]);
    expect(inventory.includes("changed.py")).toBe(!undoStagedChange);
    expect(ranked.some(({ path }) => path === "changed.py")).toBe(
      !undoStagedChange,
    );
  });
}

for (const mode of ["revisions", "local-patch"] as const) {
  for (const replacement of ["symlink", "gitlink"] as const) {
    test(`${mode} inventories exclude files replaced by ${replacement}`, () => {
      const f = fixture();
      f.write("README.md", "fixture\n");
      const source = f.write("replaced.py", "old source\n");
      const base = f.commit();
      if (replacement === "symlink") {
        rmSync(source);
        symlinkSync("README.md", source, "file");
      } else {
        const origin = join(f.root, "origin");
        mkdirSync(origin);
        git(origin, "init", "-q");
        writeFileSync(join(origin, "README.md"), "fixture\n");
        git(origin, "add", ".");
        git(origin, "commit", "-qm", "Source fixture");
        git(f.repo, "rm", "-f", "replaced.py");
        git(
          f.repo,
          "-c",
          "protocol.file.allow=always",
          "submodule",
          "add",
          origin,
          "replaced.py",
        );
      }
      f.write("visible.py");
      git(f.repo, "add", ".");
      if (mode === "revisions") f.commit();
      const expected =
        replacement === "gitlink"
          ? [".gitmodules", "visible.py"]
          : ["visible.py"];
      expect(
        f
          .success("generate-in-scope-files", [
            "--scope",
            ".",
            "--diff-base",
            base,
            "--diff-mode",
            mode,
          ])
          .trim()
          .split("\n"),
      ).toEqual(expected);
      expect(
        f
          .rows("make-diff-rank-input", ["--base", base, "--mode", mode])
          .map(({ path }) => path),
      ).toEqual(expected);
    });
  }
}

test("local diff inventory skips unreadable files", () => {
  const f = fixture();
  f.write("tracked.py");
  const base = f.commit();
  f.write("unreadable.py");
  f.write("readable.py");
  const preload = join(f.root, "read-error.cjs");
  writeFileSync(
    preload,
    `
const failure = () => { throw Object.assign(new Error("Synthetic unreadable file"), { code: "EACCES" }); };
const fs = require("node:fs");
const open = fs.openSync;
fs.openSync = (path, ...args) => String(path).endsWith("unreadable.py") ? failure() : open(path, ...args);
require("node:module").syncBuiltinESMExports();
const Module = require("node:module");
const native = Module._extensions[".node"];
Module._extensions[".node"] = (loaded, path) => {
  native(loaded, path);
  if (!path.endsWith("windows.node")) return;
  loaded.exports = new Proxy(loaded.exports, { get(exports, key) {
    const value = Reflect.get(exports, key);
    if (key !== "openWindowsFile") return value;
    return (path, ...args) => {
      const result = value(path, ...args);
      if (path.toString("utf16le").endsWith("unreadable.py") && result.handle) {
        return { ...result, handle: new Proxy(result.handle, { get(handle, key) {
          if (key === "read") return failure;
          const member = Reflect.get(handle, key);
          return typeof member === "function" ? member.bind(handle) : member;
        }}) };
      }
      return result;
    };
  }});
};
`,
  );
  const result = f.run(
    "generate-in-scope-files",
    ["--scope", ".", "--diff-base", base, "--diff-mode", "local-patch"],
    {
      ...f.toolEnvironment,
      NODE_OPTIONS: `${f.toolEnvironment["NODE_OPTIONS"] ?? ""} --require ${JSON.stringify(preload)}`,
    },
  );
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(f.out, "utf8")).toBe("readable.py\n");
});

test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
  "ignored tracked access errors preserve the existing inventory",
  () => {
    const f = fixture();
    f.write(".gitignore", "ignored/\n");
    f.write("ignored/tracked.py");
    f.write("visible.py");
    git(f.repo, "add", "--force", "ignored/tracked.py");
    writeFileSync(f.out, "previous\n");
    const directory = join(f.repo, "ignored");
    chmodSync(directory, 0);
    try {
      const result = f.run("generate-in-scope-files", ["--scope", "."]);
      expect(result.status).toBe(2);
      expect(result.stderr).toMatch(/EACCES|permission denied/iu);
      expect(readFileSync(f.out, "utf8")).toBe("previous\n");
    } finally {
      chmodSync(directory, 0o700);
    }
  },
);

for (const command of ["make-repo-rank-input", "make-repo-scope-input"])
  test.skipIf(process.platform === "win32")(
    `${command} skips candidates that become inaccessible after enumeration`,
    () => {
      const f = fixture();
      const blocked = f.write("blocked.py");
      f.write("visible.py");
      git(f.repo, "add", ".");
      const scopes = join(f.root, "scopes.json");
      writeFileSync(scopes, '["."]');
      const preload = join(f.root, "stat-error.cjs");
      writeFileSync(
        preload,
        `const fs = require("node:fs");
const original = fs.statSync;
fs.statSync = (path, ...args) => {
  if (String(path) === ${JSON.stringify(blocked)})
    throw Object.assign(new Error("Synthetic access denial"), {code: "EACCES"});
  return original(path, ...args);
};
require("node:module").syncBuiltinESMExports();
`,
      );
      const result = f.run(command, ["--scopes-file", scopes], {
        ...f.toolEnvironment,
        NODE_OPTIONS: `${f.toolEnvironment["NODE_OPTIONS"] ?? ""} --require ${JSON.stringify(preload)}`,
      });
      expect(result.status, result.stderr).toBe(0);
      expect(
        readFileSync(f.out, "utf8")
          .trim()
          .split("\n")
          .map((row) => JSON.parse(row).path),
      ).toEqual(["visible.py"]);
    },
  );

test("failed inventory generation preserves the existing file", () => {
  const f = fixture();
  f.write("source");
  writeFileSync(f.out, "previous\n");
  for (const args of [
    ["--scope", "missing"],
    ["--scope", ".."],
    ["--scope", ".", "--diff-base", "missing-revision"],
  ]) {
    expect(f.run("generate-in-scope-files", args).status).toBe(2);
    expect(readFileSync(f.out, "utf8")).toBe("previous\n");
  }
  const absent = f.run("generate-in-scope-files", ["--scope", "."], {
    ...process.env,
    PATH: f.root,
  });
  expect(absent.status).toBe(2);
  expect(readFileSync(f.out, "utf8")).toBe("previous\n");
});

for (const command of ["make-repo-scope-input", "make-repo-rank-input"]) {
  test(`${command} ignores tracked descendants replaced by symlinks`, () => {
    const f = fixture();
    f.write("src/nested/source");
    f.commit();
    rmSync(join(f.repo, "src", "nested"), { recursive: true });
    const outside = join(f.root, "outside");
    mkdirSync(outside);
    writeFileSync(join(outside, "source"), "external\n");
    symlinkSync(outside, join(f.repo, "src", "nested"), "junction");
    const scopes = join(f.root, "scopes.json");
    writeFileSync(scopes, JSON.stringify(["src"]));
    expect(f.rows(command, ["--scopes-file", scopes])).toEqual([]);
    if (command === "make-repo-scope-input") {
      writeFileSync(scopes, JSON.stringify(["src/nested/../source"]));
      expect(f.run(command, ["--scopes-file", scopes]).status).not.toBe(0);
    }
  });
}

test.skipIf(process.platform === "win32")(
  "line-breaking and non-UTF8 diff paths fail without replacing inventory",
  () => {
    const f = fixture();
    f.write("source");
    const base = f.commit();
    for (const name of ["line\nname", "line\rname"]) {
      f.write(name);
      writeFileSync(f.out, "previous\n");
      expect(f.run("generate-in-scope-files", ["--scope", "."]).status).toBe(2);
      expect(readFileSync(f.out, "utf8")).toBe("previous\n");
      rmSync(join(f.repo, name));
    }
    // APFS cannot create the invalid-UTF8 filename below.
    if (process.platform === "darwin") return;
    const path = Buffer.concat([
      Buffer.from(f.repo + "/"),
      Buffer.from([0xff]),
    ]);
    writeFileSync(path, "text");
    expect(
      f.run("generate-in-scope-files", [
        "--scope",
        ".",
        "--diff-base",
        base,
        "--diff-mode",
        "local-patch",
      ]).status,
    ).toBe(2);
    expect(readFileSync(f.out, "utf8")).toBe("previous\n");
  },
);

test("inventory excludes nested Git metadata and handles long destination names", () => {
  const f = fixture();
  f.write("nested/source");
  git(join(f.repo, "nested"), "init", "-q");
  const out = join(f.root, "a".repeat(251) + ".txt");
  const result = f.run("generate-in-scope-files", [
    "--scope",
    ".",
    "--out",
    out,
  ]);
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(out, "utf8")).toBe("./nested/source\n");
});

test("scope inventory rejects symbolic-link components before lexical parent traversal", () => {
  const f = fixture();
  f.write("src/source");
  symlinkSync(join(f.repo, "src"), join(f.repo, "alias"), "junction");
  const scopes = join(f.root, "scopes.json");
  for (const scope of [
    "alias/source",
    "alias/../src/source",
    `${f.root}${sep}.${sep}repository${sep}alias${sep}..${sep}src${sep}source`,
  ]) {
    writeFileSync(scopes, JSON.stringify([scope]));
    const result = f.run("make-repo-scope-input", ["--scopes-file", scopes]);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("symbolic links");
  }
});

test.skipIf(process.platform === "win32")(
  "path inventory refuses output symlinks and creates private replacement files",
  () => {
    const f = fixture();
    f.write("source");
    const target = join(f.root, "existing");
    writeFileSync(target, "untouched\n");
    symlinkSync(target, f.out);
    const rejected = f.run("generate-in-scope-files", ["--scope", "."]);
    expect(rejected.status).toBe(2);
    expect(rejected.stderr).toContain("symbolic link");
    expect(readFileSync(target, "utf8")).toBe("untouched\n");
    rmSync(f.out);
    f.success("generate-in-scope-files", ["--scope", "."]);
    expect(statSync(f.out).mode & 0o777).toBe(0o600);
  },
);

for (const ending of ["\n", "\r"])
  test.skipIf(process.platform === "win32")(
    `launchers preserve POSIX roots ending ${JSON.stringify(ending)} and scoped names through Git and ripgrep`,
    () => {
      const f = fixture();
      f.write("source", "selected revision\n");
      const base = f.commit();
      f.write("source", "current revision\n");
      f.commit();
      const rawRoot = Buffer.concat([
        Buffer.from(f.root + "/raw-"),
        pathNameBytes,
        Buffer.from("'`$" + ending),
      ]);
      renameSync(f.repo, rawRoot);
      const rawScope = Buffer.concat([
        Buffer.from("scope-"),
        pathNameBytes,
        Buffer.from("'`$"),
      ]);
      mkdirSync(Buffer.concat([rawRoot, Buffer.from("/"), rawScope]));
      writeFileSync(
        Buffer.concat([
          rawRoot,
          Buffer.from("/"),
          rawScope,
          Buffer.from("/entry"),
        ]),
        "scoped source\n",
      );
      const literal = (bytes: Buffer) =>
        [...bytes]
          .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
          .join("");
      const launcher = join(
        PLUGIN_ROOT,
        "scripts",
        "launch_codex_security_mcp",
      );
      const run = (command: string, scoped: boolean) =>
        spawnSync(
          "/bin/sh",
          [
            "-c",
            [
              `repository=$(printf '%b.' '${literal(rawRoot)}'); repository=\${repository%.}`,
              `scope=$(printf '%b.' '${literal(rawScope)}'); scope=\${scope%.}`,
              `exec "$1" --helper "$2" --repo "$repository" --out "$3" ${scoped ? '--scope "$scope"' : '--base "$4" --head HEAD'}`,
            ].join("\n"),
            "inventory-fixture",
            launcher,
            command,
            f.out,
            base,
          ],
          { encoding: "utf8", env: f.toolEnvironment },
        );
      const diff = run("make-diff-rank-input", false);
      expect(diff.status, diff.stderr).toBe(0);
      expect(JSON.parse(readFileSync(f.out, "utf8")).preview).toBe(
        "current revision",
      );
      const inventory = run("generate-in-scope-files", true);
      expect(inventory.status, inventory.stderr).toBe(0);
      expect(readFileSync(f.out)).toEqual(
        Buffer.concat([rawScope, Buffer.from("/entry\n")]),
      );
    },
  );

test("Git inventory clears inherited repository selection and keeps forced tracked files", () => {
  const f = fixture();
  f.write(".gitignore", "tracked.py\n");
  f.write("tracked.py");
  git(f.repo, "add", "--force", "tracked.py");
  const env = {
    ...process.env,
    [process.platform === "win32" ? "gIt_DiR" : "GIT_DIR"]: join(
      f.root,
      "missing-git",
    ),
    [process.platform === "win32" ? "gIt_WoRk_TrEe" : "GIT_WORK_TREE"]: f.root,
  };
  const result = f.run("make-repo-rank-input", [], env);
  expect(result.status, result.stderr).toBe(0);
  expect(
    readFileSync(f.out, "utf8")
      .trim()
      .split(/\r?\n/u)
      .map((line) => JSON.parse(line).path),
  ).toEqual([".gitignore", "tracked.py"]);
});

test.skipIf(process.platform === "win32")(
  "path inventories exceed the default execFile output buffer",
  () => {
    const f = fixture(),
      bin = join(f.root, "bin");
    mkdirSync(bin);
    const command = join(bin, "rg"),
      count = 20_000,
      prefix = "source-".repeat(15);
    writeFileSync(
      command,
      `#!${node}\nfor(let index=0;index<${count};index++) process.stdout.write(${JSON.stringify(prefix)}+String(index).padStart(5,'0')+'\\0');\n`,
      { mode: 0o700 },
    );
    const result = f.run("generate-in-scope-files", ["--scope", "."], {
      ...process.env,
      PATH: bin,
      CODEX_SECURITY_GIT: "",
    });
    expect(result.status, result.stderr).toBe(0);
    const rows = readFileSync(f.out, "utf8").trimEnd().split("\n");
    expect(rows.length).toBe(count);
    expect(rows[0]).toBe(prefix + "00000");
    expect(rows.at(-1)).toBe(prefix + "19999");
  },
);

test("explicit scopes preserve literal glob, tilde and colon filenames", () => {
  const f = fixture();
  const files =
    process.platform === "win32"
      ? ["src/[slug]/page.tsx", "~/example.ts"]
      : [
          "src/[slug]/page.tsx",
          "src/star*file.ts",
          "src/question?file.ts",
          "~/example.ts",
          "module:handler.ts",
        ];
  for (const path of [
    ...files,
    "src/s/page.tsx",
    "src/l/page.tsx",
    "src/starOtherfile.ts",
    "src/questionXfile.ts",
  ])
    f.write(path);
  f.commit();
  const scopes = join(f.root, "scopes.json");
  writeFileSync(scopes, JSON.stringify(["src/[slug]", ...files.slice(1)]));
  expect(
    f
      .rows("make-repo-scope-input", ["--scopes-file", scopes])
      .map((row) => row.path),
  ).toEqual([...files].sort());
});

for (const rawExecutable of [false, true])
  test.skipIf(process.platform === "win32")(
    `Git children retain raw HOME/PATH and explicit Git filters (raw executable: ${rawExecutable})`,
    () => {
      const f = fixture();
      f.write("visible.py");
      f.write("hidden.py");
      const home = Buffer.concat([
        Buffer.from(f.root + "/home-"),
        pathNameBytes,
      ]);
      const bin = Buffer.concat([Buffer.from(f.root + "/bin-"), pathNameBytes]);
      mkdirSync(home);
      mkdirSync(bin);
      writeFileSync(
        Buffer.concat([home, Buffer.from("/.gitconfig")]),
        "[core]\nexcludesFile = ~/.gitignore_global\n",
      );
      writeFileSync(
        Buffer.concat([home, Buffer.from("/.gitignore_global")]),
        "hidden.py\n",
      );
      writeFileSync(
        Buffer.concat([bin, Buffer.from("/inventory-child-tool")]),
        '#!/bin/sh\nprintf executed > "$INVENTORY_CHILD_MARKER"\n',
        { mode: 0o700 },
      );
      const gitPath = Buffer.concat([
        Buffer.from(f.root + "/git-"),
        rawExecutable ? pathNameBytes : Buffer.from("wrapper"),
      ]);
      const hostGit = Bun.which("git")!;
      const quote = (value: string) =>
        "'" + value.replaceAll("'", "'\\''") + "'";
      writeFileSync(
        gitPath,
        `#!/bin/sh\nset -e\ntest "$GIT_LITERAL_PATHSPECS" = 1\ntest -z "\${GIT_DIR+x}"\ninventory-child-tool\nexec ${quote(hostGit)} "$@"\n`,
        { mode: 0o700 },
      );
      const octal = (bytes: Buffer) =>
        [...bytes]
          .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
          .join("");
      const marker = join(f.root, "child-ran");
      const script = [
        `HOME=$(printf '%b' '${octal(home)}'); export HOME`,
        `raw_bin=$(printf '%b' '${octal(bin)}'); PATH="$raw_bin"; export PATH`,
        `CODEX_SECURITY_GIT=$(printf '%b' '${octal(gitPath)}'); export CODEX_SECURITY_GIT`,
        'exec "$1" "$2" make-repo-rank-input --repo "$3" --out "$4"',
      ].join("\n");
      const result = spawnSync(
        "/bin/sh",
        [
          "-c",
          script,
          "inventory-env",
          node,
          join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
          f.repo,
          f.out,
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            GIT_CONFIG_GLOBAL: undefined,
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_DIR: join(f.root, "wrong-git"),
            GIT_LITERAL_PATHSPECS: "0",
            INVENTORY_CHILD_MARKER: marker,
          },
        },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(
        readFileSync(f.out, "utf8")
          .trim()
          .split(/\r?\n/u)
          .map((line) => JSON.parse(line).path),
      ).toEqual(["visible.py"]);
      expect(readFileSync(marker, "utf8")).toBe("executed");
    },
  );

test.skipIf(process.platform === "win32")(
  "ripgrep children retain raw HOME and PATH",
  () => {
    const f = fixture();
    f.write("visible.py");
    const home = Buffer.concat([Buffer.from(f.root + "/home-"), pathNameBytes]);
    const bin = Buffer.concat([Buffer.from(f.root + "/bin-"), pathNameBytes]);
    mkdirSync(home);
    mkdirSync(bin);
    writeFileSync(Buffer.concat([home, Buffer.from("/marker")]), "raw-home\n");
    writeFileSync(
      Buffer.concat([bin, Buffer.from("/rg")]),
      '#!/bin/sh\nset -e\nIFS= read -r value < "$HOME/marker"\ntest "$value" = raw-home\nprintf "./visible.py\\0"\n',
      { mode: 0o700 },
    );
    const octal = (bytes: Buffer) =>
      [...bytes]
        .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
        .join("");
    const script = [
      `HOME=$(printf '%b' '${octal(home)}'); export HOME`,
      `PATH=$(printf '%b' '${octal(bin)}'); export PATH`,
      'exec "$1" "$2" generate-in-scope-files --repo "$3" --scope . --out "$4"',
    ].join("\n");
    const result = spawnSync(
      "/bin/sh",
      [
        "-c",
        script,
        "inventory-env",
        node,
        join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
        f.repo,
        f.out,
      ],
      { encoding: "utf8", env: { ...process.env, CODEX_SECURITY_GIT: "" } },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(f.out, "utf8")).toBe("./visible.py\n");
  },
);

test.skipIf(process.platform === "win32")(
  "Git discovery distinguishes absent and empty PATH",
  () => {
    const f = fixture();
    f.write(".gitignore", "retained.txt\n");
    f.write("retained.txt");
    git(f.repo, "add", "--force", "retained.txt");
    const env = {
      ...process.env,
      CODEX_SECURITY_GIT: undefined,
      PATH: undefined,
    };
    const result = f.run("make-repo-rank-input", [], env);
    expect(result.status, result.stderr).toBe(0);
    expect(
      readFileSync(f.out, "utf8")
        .split("\n")
        .filter(Boolean)
        .map((line) => JSON.parse(line).path),
    ).toContain("retained.txt");
    expect(
      f.run("make-repo-rank-input", [], { ...env, PATH: "" }).status,
    ).not.toBe(0);
  },
);

for (const setting of [
  "GIT_CONFIG_GLOBAL",
  "GIT_CONFIG_SYSTEM",
  "XDG_CONFIG_HOME",
  "GIT_CONFIG_PARAMETERS",
  "GIT_CONFIG_VALUE_0",
  "RIPGREP_CONFIG_PATH",
])
  test.skipIf(process.platform === "win32")(
    `inventory tools retain raw ${setting} configuration`,
    () => {
      const f = fixture();
      f.write("visible.py");
      f.write("hidden.py");
      const rawPath = Buffer.concat([
        Buffer.from(f.root + "/configuration-"),
        pathNameBytes,
      ]);
      const ignore = join(f.root, "ignore");
      writeFileSync(ignore, "hidden.py\n");
      let value = rawPath;
      if (
        setting === "GIT_CONFIG_PARAMETERS" ||
        setting === "GIT_CONFIG_VALUE_0"
      ) {
        writeFileSync(rawPath, "hidden.py\n");
        if (setting === "GIT_CONFIG_PARAMETERS")
          value = Buffer.concat([
            Buffer.from("'core.excludesFile="),
            rawPath,
            Buffer.from("'"),
          ]);
      } else {
        let config = rawPath;
        if (setting === "XDG_CONFIG_HOME") {
          mkdirSync(Buffer.concat([rawPath, Buffer.from("/git")]), {
            recursive: true,
          });
          config = Buffer.concat([rawPath, Buffer.from("/git/config")]);
        }
        writeFileSync(
          config,
          setting === "RIPGREP_CONFIG_PATH"
            ? "--glob\n!hidden.py\n"
            : `[core]\nexcludesFile = ${JSON.stringify(ignore)}\n`,
        );
      }
      const octal = [...value]
        .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
        .join("");
      const command =
        setting === "RIPGREP_CONFIG_PATH"
          ? "generate-in-scope-files"
          : "make-repo-rank-input";
      const result = spawnSync(
        "/bin/sh",
        [
          "-c",
          `${setting}=$(printf '%b' '${octal}'); export ${setting}\nexec "$1" "$2" "$3" --repo "$4" --out "$5" --scope .`,
          "inventory-config",
          node,
          join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
          command,
          f.repo,
          f.out,
        ],
        {
          encoding: "utf8",
          env: {
            ...f.toolEnvironment,
            ...(setting === "RIPGREP_CONFIG_PATH" ? {} : { HOME: f.root }),
            CODEX_SECURITY_GIT: Bun.which("git")!,
            GIT_CONFIG_GLOBAL:
              setting === "XDG_CONFIG_HOME" ? undefined : "/dev/null",
            GIT_CONFIG_SYSTEM: "/dev/null",
            GIT_CONFIG_PARAMETERS: undefined,
            GIT_CONFIG_COUNT:
              setting === "GIT_CONFIG_VALUE_0" ? "1" : undefined,
            GIT_CONFIG_KEY_0: "core.excludesFile",
            GIT_CONFIG_VALUE_0: undefined,
            GIT_CONFIG_NOSYSTEM: undefined,
            XDG_CONFIG_HOME: undefined,
            RIPGREP_CONFIG_PATH: undefined,
          },
        },
      );
      expect(result.status, result.stderr).toBe(0);
      const lines = readFileSync(f.out, "utf8").trim().split("\n");
      expect(
        setting === "RIPGREP_CONFIG_PATH"
          ? lines
          : lines.map((line) => JSON.parse(line).path),
      ).toEqual([
        setting === "RIPGREP_CONFIG_PATH" ? "./visible.py" : "visible.py",
      ]);
    },
  );

test("absolute file scopes work when the repository is a filesystem root", () => {
  const f = fixture();
  const source = f.write("source.py");
  const scopes = join(f.root, "scopes.json");
  writeFileSync(scopes, JSON.stringify([source]));
  const root = parse(f.repo).root;
  const result = f.run("make-repo-scope-input", [
    "--repo",
    root,
    "--scopes-file",
    scopes,
  ]);
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(readFileSync(f.out, "utf8")).path).toBe(
    relative(root, source).split(sep).join("/"),
  );
});

test.skipIf(process.platform !== "win32")(
  "drive-relative scopes stay anchored to the repository",
  () => {
    const f = fixture();
    f.write("src/source.py");
    const scope = `${parse(f.repo).root.slice(0, 2)}src`;
    expect(
      f.rows("make-repo-rank-input", ["--scope", scope]).map((row) => row.path),
    ).toEqual(["src/source.py"]);
    const scopes = join(f.root, "scopes.json");
    writeFileSync(scopes, JSON.stringify([scope]));
    expect(
      f
        .rows("make-repo-scope-input", ["--scopes-file", scopes])
        .map((row) => row.path),
    ).toEqual(["src/source.py"]);
  },
);

test("preview trimming handles a full sample of leading blank lines", () => {
  const f = fixture();
  f.write("source.py", "\n".repeat(64_000) + "kept\n");
  expect(f.rows()[0]!.preview).toBe("kept");
});

for (const command of ["make-repo-rank-input", "make-repo-scope-input"])
  test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    `${command} reports unreadable tracked directories without replacing output`,
    () => {
      const f = fixture();
      f.write("private/source.py");
      git(f.repo, "add", ".");
      const scopes = join(f.root, "scopes.json");
      writeFileSync(scopes, JSON.stringify(["."]));
      writeFileSync(f.out, "previous\n");
      const directory = join(f.repo, "private");
      chmodSync(directory, 0);
      try {
        const result = f.run(command, ["--scopes-file", scopes]);
        expect(result.status).toBe(1);
        expect(result.stderr).toMatch(/EACCES|permission denied/iu);
        expect(readFileSync(f.out, "utf8")).toBe("previous\n");
      } finally {
        chmodSync(directory, 0o700);
      }
    },
  );

test("inventory skips stale tracked entries after deletion and directory replacement", () => {
  const f = fixture();
  f.write("deleted.py");
  f.write("replaced/source.py");
  git(f.repo, "add", ".");
  rmSync(join(f.repo, "deleted.py"));
  rmSync(join(f.repo, "replaced"), { recursive: true });
  f.write("replaced");
  expect(f.rows().map((row) => row.path)).toEqual(["replaced"]);
});

test.skipIf(process.platform !== "win32")(
  "tracked files replaced by a junction to the repository are not traversed",
  () => {
    const f = fixture();
    f.write("cycle");
    f.write("visible.py");
    git(f.repo, "add", ".");
    const junction = join(f.repo, "cycle");
    rmSync(junction);
    symlinkSync(f.repo, junction, "junction");
    const scopes = join(f.root, "scopes.json");
    writeFileSync(scopes, '["."]');
    try {
      for (const command of ["make-repo-rank-input", "make-repo-scope-input"])
        expect(
          f.rows(command, ["--scopes-file", scopes]).map((row) => row.path),
        ).toEqual(["visible.py"]);
    } finally {
      rmSync(junction, { recursive: true, force: true });
    }
  },
);

test("absolute explicit scopes ignore dot and empty components before the repo", () => {
  const f = fixture();
  f.write("src/source.py");
  const scopes = join(f.root, "scopes.json");
  writeFileSync(
    scopes,
    JSON.stringify([
      `${f.root}${sep}.${sep}repository${sep}src${sep}source.py`,
      `${f.root}${sep}${sep}repository${sep}src${sep}source.py`,
    ]),
  );
  expect(
    f
      .rows("make-repo-scope-input", ["--scopes-file", scopes])
      .map((row) => row.path),
  ).toEqual(["src/source.py"]);
});

test("diff inventory expands a home-relative repository scope", () => {
  const f = fixture();
  f.write("source.py", "before\n");
  const base = f.commit();
  f.write("source.py", "after\n");
  const result = f.run(
    "generate-in-scope-files",
    [
      "--scope",
      "~/repository",
      "--diff-base",
      base,
      "--diff-mode",
      "local-patch",
    ],
    { ...process.env, HOME: f.root, USERPROFILE: f.root },
  );
  expect(result.status, result.stderr).toBe(0);
  expect(readFileSync(f.out, "utf8")).toBe("source.py\n");
});

test.skipIf(process.platform === "win32")(
  "inventory falls back to ripgrep when selected Git's interpreter is missing",
  () => {
    const f = fixture();
    f.write("source.py");
    const selectedGit = join(f.root, "git");
    writeFileSync(selectedGit, `#!${join(f.root, "missing-interpreter")}\n`, {
      mode: 0o700,
    });
    const result = f.run("make-repo-rank-input", [], {
      ...f.toolEnvironment,
      CODEX_SECURITY_GIT: selectedGit,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(f.out, "utf8")).path).toBe("source.py");
  },
);

test("inventory preserves scoped names beneath dotted-I repository names", () => {
  const f = fixture();
  f.write("scope/source.py", "kept\n");
  const repository = join(f.root, "İrepository");
  renameSync(f.repo, repository);
  const scopes = join(f.root, "scopes.json");
  writeFileSync(scopes, JSON.stringify(["scope"]));
  for (const command of ["make-repo-scope-input", "make-repo-rank-input"]) {
    const rows = f.rows(command, [
      "--repo",
      repository,
      "--scopes-file",
      scopes,
    ]);
    expect(rows.map((row) => row.path)).toEqual(["scope/source.py"]);
    if (command === "make-repo-rank-input")
      expect(rows[0]).toMatchObject({ area: "scope", preview: "kept" });
  }
});

test.skipIf(process.platform !== "win32")(
  "Windows Git inventories and revision previews retain indexed lone UTF-16 names",
  () => {
    const f = fixture();
    f.write("base.py");
    const base = f.commit();
    const names = ["high-\ud800.py", "low-\udfff.py"];
    f.write(".gitignore", "high-*\nlow-*\n");
    git(f.repo, "add", ".gitignore");
    try {
      const blob = spawnSync(
        "git",
        ["-C", f.repo, "hash-object", "-w", "--stdin"],
        { input: "kept\n", encoding: "utf8" },
      );
      expect(blob.status, blob.stderr).toBe(0);
      const rawNames = [
        Buffer.concat([
          Buffer.from("high-"),
          Buffer.from([0xed, 0xa0, 0x80]),
          Buffer.from(".py"),
        ]),
        Buffer.concat([
          Buffer.from("low-"),
          Buffer.from([0xed, 0xbf, 0xbf]),
          Buffer.from(".py"),
        ]),
      ];
      const index = Buffer.concat(
        rawNames.map((name) =>
          Buffer.concat([
            Buffer.from(`100644 ${blob.stdout.trim()}\t`),
            name,
            Buffer.from([0]),
          ]),
        ),
      );
      const updated = spawnSync(
        "git",
        ["-C", f.repo, "update-index", "-z", "--index-info"],
        { input: index },
      );
      expect(updated.status, updated.stderr.toString()).toBe(0);
      git(f.repo, "checkout-index", "--all", "--force");
      git(f.repo, "commit", "-qm", "Indexed path fixture");
      const inventory = f.run("generate-in-scope-files", ["--scope", "."]);
      expect(inventory.status, inventory.stderr).toBe(0);
      for (const name of rawNames)
        expect(
          readFileSync(f.out).includes(
            Buffer.concat([Buffer.from("./"), name, Buffer.from("\n")]),
          ),
        ).toBe(true);
      const scopes = join(f.root, "scopes.json");
      writeFileSync(scopes, '["."]');
      for (const command of [
        "make-repo-rank-input",
        "make-repo-scope-input",
        "make-diff-rank-input",
      ]) {
        const rows = f.rows(
          command,
          command === "make-diff-rank-input"
            ? ["--base", base]
            : ["--scopes-file", scopes],
        );
        expect(
          rows
            .filter((row) => /^(high|low)-/u.test(row.path))
            .map((row) => row.path),
        ).toEqual(names);
        if (command !== "make-repo-scope-input")
          for (const name of names)
            expect(rows.find((row) => row.path === name)?.preview).toBe("kept");
      }
    } finally {
      git(f.repo, "reset", "--hard", base);
    }
  },
);

for (const command of ["make-repo-scope-input", "make-repo-rank-input"])
  for (const raw of ["ordinary", "HOME", "PATH", "repository"])
    for (const tool of ["missing", "non-executable"])
      test.skipIf(process.platform === "win32")(
        `${command} safely falls back with ${tool} ripgrep for ${raw} POSIX paths`,
        () => {
          const f = fixture();
          rmSync(join(f.repo, ".git"), { recursive: true });
          f.write("scope/visible.py", "source\n");
          f.write("outside.py");
          const repo =
            raw === "repository"
              ? Buffer.concat([Buffer.from(f.root + "/repo-"), pathNameBytes])
              : Buffer.from(f.repo);
          if (raw === "repository") renameSync(f.repo, repo);
          const home = Buffer.concat([
            Buffer.from(f.root + "/home-"),
            raw === "HOME" ? Buffer.from([0xff]) : Buffer.from("plain"),
          ]);
          const bin = join(f.root, "bin");
          mkdirSync(bin);
          if (tool === "non-executable")
            writeFileSync(join(bin, "rg"), "#!/bin/sh\nexit 0\n", {
              mode: 0o600,
            });
          const path = Buffer.concat([
            Buffer.from(bin),
            raw === "PATH" ? Buffer.from([58, 47, 0xff]) : Buffer.alloc(0),
          ]);
          const scopes = join(f.root, "scopes.json");
          writeFileSync(scopes, '["scope"]');
          const octal = (bytes: Buffer) =>
            [...bytes]
              .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
              .join("");
          const script = [
            `HOME=$(printf '%b' '${octal(home)}'); export HOME`,
            `PATH=$(printf '%b' '${octal(path)}'); export PATH`,
            'exec "$1" "$2" --helper 3<&0 0</dev/null',
          ].join("\n");
          const input = Buffer.concat([
            Buffer.from("1\0"),
            home,
            Buffer.from(`\0${command}\0--repo\0`),
            repo,
            Buffer.from(`\0--out\0${f.out}\0--scopes-file\0${scopes}\0`),
          ]).toString("hex");
          const run = () =>
            spawnSync(
              "/bin/sh",
              [
                "-c",
                script,
                "inventory-env",
                node,
                join(PLUGIN_ROOT, "mcp", "helpers.mjs"),
              ],
              {
                encoding: "utf8",
                input,
                env: { ...process.env, CODEX_SECURITY_GIT: "" },
              },
            );
          const result = run();
          expect(result.status, result.stderr).toBe(0);
          expect(JSON.parse(readFileSync(f.out, "utf8"))).toEqual(
            command === "make-repo-scope-input"
              ? { path: "scope/visible.py" }
              : { path: "scope/visible.py", area: "scope", preview: "source" },
          );
          writeFileSync(
            Buffer.concat([repo, Buffer.from("/scope/.ignore")]),
            "visible.py\n",
          );
          writeFileSync(f.out, "previous\n");
          const ignored = run();
          expect(ignored.status).toBe(1);
          expect(ignored.stderr).toContain("without Git or ripgrep");
          expect(readFileSync(f.out, "utf8")).toBe("previous\n");
        },
      );

for (const name of [".gitignore", ".ignore", ".rgignore"])
  for (const location of ["ancestor", "descendant"])
    test.skipIf(process.platform === "win32")(
      `missing-tool fallback notices ${location} symlinked ${name}`,
      () => {
        const f = fixture();
        rmSync(join(f.repo, ".git"), { recursive: true });
        f.write("scope/nested/source.py");
        const rules = join(f.root, "ignore-rules");
        writeFileSync(rules, "source.py\n");
        symlinkSync(
          rules,
          join(f.repo, location === "ancestor" ? name : `scope/nested/${name}`),
        );
        writeFileSync(f.out, "previous\n");
        const result = f.run("make-repo-rank-input", ["--scope", "scope"], {
          ...process.env,
          CODEX_SECURITY_GIT: "",
          PATH: f.root,
        });
        expect(result.status).toBe(1);
        expect(result.stderr).toContain("without Git or ripgrep");
        expect(readFileSync(f.out, "utf8")).toBe("previous\n");
      },
    );

for (const marker of [".git", ".gitignore"])
  test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    `missing-tool fallback rejects ${marker} before reading descendants`,
    () => {
      const f = fixture();
      const scope = marker === ".git" ? "." : "scope";
      const blocked =
        marker === ".git"
          ? join(f.repo, ".git", "objects")
          : join(f.repo, scope, "unreadable");
      if (marker === ".gitignore") {
        rmSync(join(f.repo, ".git"), { recursive: true });
        f.write(".gitignore", "ignored.py\n");
        f.write("scope/unreadable/source.py");
      }
      writeFileSync(f.out, "previous\n");
      chmodSync(blocked, 0);
      try {
        const result = f.run("make-repo-rank-input", ["--scope", scope], {
          ...process.env,
          CODEX_SECURITY_GIT: "",
          PATH: f.root,
        });
        expect(result.status).toBe(1);
        expect(result.stderr.trim()).toBe(
          "Could not safely enumerate ignored scoped files without Git or ripgrep.",
        );
        expect(readFileSync(f.out, "utf8")).toBe("previous\n");
      } finally {
        chmodSync(blocked, 0o700);
      }
    },
  );

for (const name of [".gitignore", ".ignore", ".rgignore"])
  test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    `missing-tool fallback finds descendant ${name} before entering sibling directories`,
    () => {
      const f = fixture();
      rmSync(join(f.repo, ".git"), { recursive: true });
      f.write(`nested/${name}`, "ignored.py\n");
      f.write("nested/!unreadable/source.py");
      const blocked = join(f.repo, "nested", "!unreadable");
      writeFileSync(f.out, "previous\n");
      chmodSync(blocked, 0);
      try {
        const result = f.run("make-repo-rank-input", [], {
          ...process.env,
          CODEX_SECURITY_GIT: "",
          PATH: f.root,
        });
        expect(result.status).toBe(1);
        expect(result.stderr.trim()).toBe(
          "Could not safely enumerate ignored scoped files without Git or ripgrep.",
        );
        expect(readFileSync(f.out, "utf8")).toBe("previous\n");
      } finally {
        chmodSync(blocked, 0o700);
      }
    },
  );

test("file and Git previews retain empty files and incomplete final UTF-16 units", () => {
  const f = fixture();
  f.write("base.py");
  const base = f.commit();
  f.write("empty.py", "");
  f.write("utf16.py", Buffer.from([0xff, 0xfe, 0]));
  f.commit();
  for (const rows of [
    f.rows(),
    f.rows("make-diff-rank-input", ["--base", base]),
  ]) {
    expect(rows.find((row) => row.path === "empty.py")?.preview).toBe("");
    expect(rows.find((row) => row.path === "utf16.py")?.preview).toBe("");
  }
});

for (const signal of ["TERM", "KILL"])
  for (const command of [
    "generate-in-scope-files",
    "make-repo-rank-input",
    "make-repo-scope-input",
  ])
    test.skipIf(process.platform === "win32")(
      `${command} preserves output when ripgrep is terminated by SIG${signal}`,
      () => {
        const f = fixture();
        f.write("partial.py");
        f.write("omitted.py");
        const bin = join(f.root, "bin");
        mkdirSync(bin);
        writeFileSync(
          join(bin, "rg"),
          `#!/bin/sh\nprintf './partial.py\\0'\nkill -${signal} $$\n`,
          { mode: 0o700 },
        );
        const scopes = join(f.root, "scopes.json");
        writeFileSync(scopes, JSON.stringify(["."]));
        writeFileSync(f.out, "previous\n");
        const result = f.run(
          command,
          command === "make-repo-scope-input"
            ? ["--scopes-file", scopes]
            : ["--scope", "."],
          { ...process.env, CODEX_SECURITY_GIT: "", PATH: bin },
        );
        expect(result.status).not.toBe(0);
        expect(result.stderr).toContain(`SIG${signal}`);
        expect(readFileSync(f.out, "utf8")).toBe("previous\n");
      },
    );

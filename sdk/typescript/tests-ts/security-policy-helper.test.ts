import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { dirname, join, relative, sep, win32 } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const temporaryDirectories: string[] = [];

function fixture(name = "repository") {
  const directory = mkdtempSync(join(tmpdir(), "security-policy-helper-"));
  temporaryDirectories.push(directory);
  const root = join(directory, name);
  const output = join(directory, "output");
  mkdirSync(root);
  return { root, output };
}

function write(root: string, path: string, content: string | Buffer): void {
  const target = join(root, path);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

function run(args: string[], env = process.env, cwd?: string) {
  return spawnSync("node", [helper, "resolve-security-md", ...args], {
    encoding: "utf8",
    env,
    maxBuffer: Infinity,
    cwd,
  });
}

function inventory(root: string) {
  return run(["--repo", root, "--list"]);
}

function resolve(root: string, scope: string, output = "-") {
  return run(["--repo", root, "--scope", scope, "--out", output]);
}

function expectGuidance(text: string, policies: [string, string][]): void {
  const headings = [
    ...text.matchAll(/^## [^\r\n]*: ("(?:[^"\\]|\\.)*")\r?$/gm),
  ];
  const sections = headings.map((heading, index) => [
    JSON.parse(heading[1]!) as string,
    text
      .slice(heading.index! + heading[0].length, headings[index + 1]?.index)
      .replace(/^[\r\n]+|[\r\n]+$/gu, ""),
  ]);
  expect(sections).toEqual(
    policies.map(([source, content]) => [
      source,
      content.replace(/^[\r\n]+|[\r\n]+$/gu, ""),
    ]),
  );
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("built SECURITY.md helper", () => {
  test("accepts negative-number paths and unique long-option prefixes", () => {
    const { root } = fixture();
    const cases: [string, string, string][] = [
      ["-1", "-2", "-3"],
      ["-١", "-.5", "-1.5"],
    ];
    if (process.platform !== "win32") cases.push(["-4", "-1\n", "-3\n"]);
    for (const [repo, scope, output] of cases) {
      write(root, `${repo}/${scope}/SECURITY.md`, "negative path policy\n");
      const result = run(
        ["--r", repo, "--s", scope, "--o", output],
        process.env,
        root,
      );
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe("");
      expect(readFileSync(join(root, output), "utf8")).toContain(
        "negative path policy",
      );
    }
  });

  test("accepts dash-prefixed paths containing spaces after option matching", () => {
    const { root } = fixture();
    for (const [repo, scope, output] of [
      ["- repository", "- archived", "- guidance"],
      ["--repo space", "--special space", "--other= output"],
    ] as const) {
      write(root, `${repo}/${scope}/SECURITY.md`, "space path policy\n");
      const result = run(
        ["--repo", repo, "--scope", scope, "--out", output],
        process.env,
        root,
      );
      expect(result.status, result.stderr).toBe(0);
      expect(readFileSync(join(root, output), "utf8")).toContain(
        "space path policy",
      );
    }
    for (const value of [
      "-hello world",
      "--help=some text",
      "--s=some text",
      "--unsupported",
      "-tab\tvalue",
    ]) {
      const result = run(["--repo", root, "--scope", value]);
      expect(result.status, result.stderr).toBe(2);
      expect(result.stdout).toBe("");
    }
  });

  test.skipIf(process.platform !== "win32")(
    "preserves Windows home-variable precedence and drive-relative homes",
    () => {
      const { root } = fixture();
      const home = join(root, "current");
      write(home, "project/SECURITY.md", "home-variable policy\n");
      const drive = win32.parse(home).root.slice(0, 2);
      const hook = join(root, "home-env.cjs");
      function homeEnv(variables: NodeJS.ProcessEnv) {
        // libuv restores omitted Windows home variables when spawning a child.
        writeFileSync(
          hook,
          `
          for (const name of ["USERPROFILE", "HOMEDRIVE", "HOMEPATH"]) delete process.env[name];
          Object.assign(process.env, ${JSON.stringify(variables)});
        `,
        );
        return {
          ...process.env,
          NODE_OPTIONS: `${process.env["NODE_OPTIONS"] ?? ""} --require ${JSON.stringify(hook)}`,
        };
      }
      const variants: [NodeJS.ProcessEnv, string, string][] = [
        [
          { HOMEDRIVE: drive, HOMEPATH: home.slice(drive.length) },
          "~/project",
          root,
        ],
        [{ HOMEPATH: home }, "~/project", root],
        [
          { USERPROFILE: home, HOMEDRIVE: "Z:", HOMEPATH: "\\missing" },
          "~/project",
          root,
        ],
        [{ HOMEDRIVE: drive, HOMEPATH: "current" }, "~/project", root],
        [{ USERPROFILE: `${drive}current` }, "~/project", root],
        [{ USERPROFILE: "" }, "~", join(home, "project")],
        [{ HOMEDRIVE: drive, HOMEPATH: "" }, "~", join(home, "project")],
      ];
      for (const [variables, repo, cwd] of variants) {
        const result = run(
          ["--repo", repo, "--scope", "."],
          homeEnv(variables),
          cwd,
        );
        expect(result.status, result.stderr).toBe(0);
        expect(result.stdout).toContain("home-variable policy");
      }
      expect(run(["--repo", root, "--scope", "~"], homeEnv({})).status).toBe(1);
      const other = homeEnv({ USERPROFILE: `${home}\\`, USERNAME: "current" });
      expect(run(["--repo", "~other", "--scope", "."], other).status).toBe(1);
    },
  );

  test("inventories sorted hidden, regular, and file-linked policies without Git metadata", () => {
    const { root } = fixture();
    write(root, "SECURITY.md", "root policy\n");
    write(root, ".hidden/SECURITY.md", "hidden policy\n");
    write(root, ".git/objects/SECURITY.md", "not a policy\n");
    write(root, "shared-policy.md", "shared policy\n");
    mkdirSync(join(root, "services", "api"), { recursive: true });
    symlinkSync(
      join(root, "shared-policy.md"),
      join(root, "services", "api", "SECURITY.md"),
      "file",
    );
    const result = inventory(root);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe(
      '[".hidden/SECURITY.md", "SECURITY.md", "services/api/SECURITY.md"]\n',
    );
    expect(result.stderr).toBe("");
  });

  test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "inventories unrelated files without requiring directory search permission",
    () => {
      const { root } = fixture();
      write(root, "SECURITY.md", "root policy\n");
      write(root, "readable/other.txt", "unrelated\n");
      mkdirSync(join(root, "readable", ".git"));
      const directory = join(root, "readable");
      chmodSync(directory, 0o400);
      try {
        const result = inventory(root);
        expect(result.status, result.stderr).toBe(0);
        expect(result.stdout).toBe('["SECURITY.md"]\n');
      } finally {
        chmodSync(directory, 0o700);
      }
    },
  );

  test("ignores files and directory links replaced after enumeration", () => {
    const { root, output } = fixture();
    write(root, "SECURITY.md", "root policy\n");
    write(root, "nested/SECURITY.md", "nested policy\n");
    write(root, "temporary.tmp", "temporary file");
    write(root, "unrelated.txt", "unrelated file");
    write(root, "changed-directory/placeholder", "temporary directory");
    write(output, "outside/SECURITY.md", "outside policy\n");
    const hook = join(output, "remove-after-readdir.cjs");
    write(
      output,
      "remove-after-readdir.cjs",
      `
      const fs = require("node:fs");
      const { join } = require("node:path");
      const windows = process.platform === "win32";
      const backend = windows
        ? require(join(${JSON.stringify(dirname(helper))}, "native", "win32-" + process.arch, "windows.node"))
        : fs;
      const method = windows ? "windowsDirectoryEntries" : "readdirSync";
      const directory = fs.realpathSync.native(${JSON.stringify(root)});
      const original = backend[method];
      if (windows) {
        const openFile = backend.openWindowsFile;
        backend.openWindowsFile = (path, ...args) => {
          if (require("node:path").basename(path.toString("utf16le")) === "unrelated.txt") throw new Error("unrelated file must not be opened");
          return openFile(path, ...args);
        };
      }
      backend[method] = (path, ...options) => {
        const entries = original(path, ...options);
        const text = path.toString(windows ? "utf16le" : "utf8");
        if (fs.realpathSync.native(text) === directory) {
          fs.unlinkSync(${JSON.stringify(join(root, "temporary.tmp"))});
          fs.rmSync(${JSON.stringify(join(root, "changed-directory"))}, { recursive: true });
          fs.symlinkSync(${JSON.stringify(join(output, "outside"))}, ${JSON.stringify(join(root, "changed-directory"))}, windows ? "junction" : "dir");
        }
        return entries;
      };
      require("node:module").syncBuiltinESMExports();
    `,
    );
    const result = run(["--repo", root, "--list"], {
      ...process.env,
      NODE_OPTIONS: `${process.env["NODE_OPTIONS"] ?? ""} --require ${JSON.stringify(hook)}`,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe('["SECURITY.md", "nested/SECURITY.md"]\n');
    expect(result.stderr).toBe("");
    expect(existsSync(join(root, "temporary.tmp"))).toBe(false);
  });

  test("frames Unicode paths as ASCII JSON in codepoint order", () => {
    const { root } = fixture();
    for (const name of ["\u{10000}", "\ue000", "\u0080", "\u007f"]) {
      write(root, `${name}/SECURITY.md`, "policy\n");
    }
    const result = inventory(root);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe(
      '["\\u007f/SECURITY.md", "\\u0080/SECURITY.md", "\\ue000/SECURITY.md", "\\ud800\\udc00/SECURITY.md"]\n',
    );
    const guidance = resolve(root, "\u{10000}").stdout;
    expectGuidance(guidance, [["\u{10000}/SECURITY.md", "policy"]]);
    expect(guidance.split("\n", 1)[0]).toMatch(
      /"\\ud800\\udc00\/SECURITY\.md"$/u,
    );
  });

  test.skipIf(process.platform !== "linux")(
    "traverses undecodable filenames and frames policy paths with surrogate escapes",
    () => {
      const { root } = fixture();
      write(root, "SECURITY.md", "root policy\n");
      writeFileSync(
        Buffer.concat([
          Buffer.from(join(root, "legacy-")),
          Buffer.from([0xff]),
          Buffer.from(".txt"),
        ]),
        "unrelated file",
      );
      const directory = Buffer.concat([
        Buffer.from(join(root, "é")),
        Buffer.from([0xff]),
      ]);
      mkdirSync(directory);
      writeFileSync(
        Buffer.concat([directory, Buffer.from("/SECURITY.md")]),
        "byte-name policy\n",
      );
      write(root, "é\ue000/SECURITY.md", "BMP policy\n");
      write(root, "é\u{10000}/SECURITY.md", "supplementary policy\n");
      const result = inventory(root);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe(
        '["SECURITY.md", "\\u00e9\\udcff/SECURITY.md", "\\u00e9\\ue000/SECURITY.md", "\\u00e9\\ud800\\udc00/SECURITY.md"]\n',
      );
      expect(result.stderr).toBe("");
    },
  );

  test.skipIf(process.platform === "win32")(
    "escapes newlines and terminal controls in inventory paths",
    () => {
      const { root } = fixture();
      write(root, "service\n\u001b[31mname/SECURITY.md", "policy\n");
      const result = inventory(root);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe('["service\\n\\u001b[31mname/SECURITY.md"]\n');
    },
  );

  test.skipIf(process.platform !== "linux")(
    "reads a raw-byte policy target without following its replacement-character sibling",
    () => {
      const { root, output } = fixture();
      const target = Buffer.concat([
        Buffer.from(join(root, "policy-")),
        Buffer.from([0xff]),
      ]);
      writeFileSync(target, "inside policy\n");
      write(output, "outside.md", "outside policy\n");
      symlinkSync(join(output, "outside.md"), join(root, "policy-\ufffd"));
      symlinkSync(target, join(root, "SECURITY.md"));
      const result = resolve(root, ".");
      expect(result.status, result.stderr).toBe(0);
      expectGuidance(result.stdout, [["SECURITY.md", "inside policy"]]);
    },
  );

  test.skipIf(process.platform !== "linux")(
    "resolves repository and scope aliases into raw-byte directories",
    () => {
      const { root, output } = fixture();
      const directory = Buffer.concat([
        Buffer.from(join(root, "component-")),
        Buffer.from([0xff]),
      ]);
      mkdirSync(directory);
      writeFileSync(
        Buffer.concat([directory, Buffer.from("/SECURITY.md")]),
        "component policy\n",
      );
      write(root, "SECURITY.md", "root policy\n");
      write(output, "SECURITY.md", "outside policy\n");
      symlinkSync(output, join(root, "component-\ufffd"));
      const alias = join(root, "alias");
      symlinkSync(directory, alias);
      const scoped = resolve(root, "alias");
      expect(scoped.status, scoped.stderr).toBe(0);
      expectGuidance(scoped.stdout, [
        ["SECURITY.md", "root policy"],
        ["component-\udcff/SECURITY.md", "component policy"],
      ]);
      const rooted = resolve(alias, ".");
      expect(rooted.status, rooted.stderr).toBe(0);
      expectGuidance(rooted.stdout, [["SECURITY.md", "component policy"]]);
      const listed = inventory(alias);
      expect(listed.status, listed.stderr).toBe(0);
      expect(listed.stdout).toBe('["SECURITY.md"]\n');
    },
  );

  test.skipIf(process.platform !== "linux")(
    "preserves actual POSIX argv bytes for repository, scope, and output paths",
    () => {
      const { root, output } = fixture();
      const repository = Buffer.concat([
        Buffer.from(join(root, "repo-")),
        Buffer.from([0xff]),
      ]);
      const scope = Buffer.concat([
        repository,
        Buffer.from("/scope-"),
        Buffer.from([0xfe]),
      ]);
      mkdirSync(scope, { recursive: true });
      writeFileSync(
        Buffer.concat([scope, Buffer.from("/SECURITY.md")]),
        "raw argument policy\n",
      );
      write(root, "repo-\ufffd/scope-\ufffd/SECURITY.md", "wrong policy\n");
      const result = spawnSync(
        "/bin/sh",
        [
          "-c",
          'exec "$1" --helper resolve-security-md --repo "$2/repo-$(printf \'\\377\')" --scope "scope-$(printf \'\\376\')" --out "$3/out-$(printf \'\\375\')/guidance.md"',
          "helper-test",
          join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
          root,
          output,
        ],
        { encoding: "utf8" },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe("");
      const destination = Buffer.concat([
        Buffer.from(join(output, "out-")),
        Buffer.from([0xfd]),
        Buffer.from("/guidance.md"),
      ]);
      expectGuidance(readFileSync(destination, "utf8"), [
        ["scope-\udcfe/SECURITY.md", "raw argument policy"],
      ]);
    },
  );

  test("does not inventory or follow directory links, even when named SECURITY.md", () => {
    for (const linkType of ["dir", "junction"] as const) {
      if (linkType === "junction" && process.platform !== "win32") continue;
      const { root, output } = fixture();
      write(output, "SECURITY.md", "outside policy\n");
      symlinkSync(output, join(root, "outside-link"), linkType);
      symlinkSync(output, join(root, "SECURITY.md"), linkType);
      const result = inventory(root);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe("[]\n");
    }
  });

  test.each(["file", "dir"] as const)(
    "inventories broken %s links and outside file links without reading their contents",
    (linkType) => {
      const { root, output } = fixture();
      write(output, "outside.md", "outside policy\n");
      mkdirSync(join(root, "broken"));
      symlinkSync(
        join(root, "missing.md"),
        join(root, "broken", "SECURITY.md"),
        linkType,
      );
      symlinkSync(
        join(output, "outside.md"),
        join(root, "SECURITY.md"),
        "file",
      );
      const result = inventory(root);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe('["SECURITY.md", "broken/SECURITY.md"]\n');
    },
  );

  test("concatenates plain-folder guidance from root to leaf", () => {
    const { root } = fixture();
    write(root, "SECURITY.md", "root policy\n");
    write(root, "services/SECURITY.md", "service policy\n");
    write(root, "services/api/SECURITY.md", "api policy");
    write(root, "services/api/handler.ts", "export {};\n");
    const result = resolve(root, join(root, "services", "api", "handler.ts"));
    expect(result.status, result.stderr).toBe(0);
    expectGuidance(result.stdout, [
      ["SECURITY.md", "root policy"],
      ["services/SECURITY.md", "service policy"],
      ["services/api/SECURITY.md", "api policy"],
    ]);
    expect(result.stdout).toEndWith("api policy\n");
  });

  test("uses a file's parent, skips whitespace-only guidance, and preserves a BOM", () => {
    const { root } = fixture();
    write(root, "SECURITY.md", "\ufeff");
    write(root, "src/SECURITY.md", " \n\t\u0085\u001c");
    write(root, "src/app.ts", "export {};\n");
    const result = resolve(root, "src/app.ts");
    expect(result.status, result.stderr).toBe(0);
    expectGuidance(result.stdout, [["SECURITY.md", "\ufeff"]]);
  });

  test("preserves path parsing for file scopes and output destinations", () => {
    const { root, output } = fixture();
    write(root, "src/SECURITY.md", "source policy\n");
    write(root, "src/app.ts", "export {};\n");
    const expected: [string, string][] = [["src/SECURITY.md", "source policy"]];
    for (const scope of ["src/app.ts/", "./src//app.ts/./"]) {
      const result = resolve(`${root}/./`, scope, "./-/");
      expect(result.status, result.stderr).toBe(0);
      expectGuidance(result.stdout, expected);
    }
    const destination = `${output}/guidance.md/./`;
    const result = resolve(root, "src/app.ts", destination);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
    expectGuidance(readFileSync(join(output, "guidance.md"), "utf8"), expected);
  });

  test("resolves parent components after existing files and symbolic links", () => {
    const { root } = fixture();
    write(root, "nested/SECURITY.md", "nested policy\n");
    write(root, "nested/file.ts", "export {};\n");
    const expected: [string, string][] = [
      ["nested/SECURITY.md", "nested policy"],
    ];
    for (const scope of ["nested/file.ts/..", "nested/SECURITY.md/../."]) {
      const result = resolve(root, scope);
      expect(result.status, result.stderr).toBe(0);
      expectGuidance(result.stdout, expected);
    }
    const result = resolve(`${root}/nested/file.ts/..`, ".");
    expect(result.status, result.stderr).toBe(0);
    expectGuidance(result.stdout, [["SECURITY.md", "nested policy"]]);
    symlinkSync("nested/file.ts/..", join(root, "alias"), "dir");
    const linked = resolve(root, "alias");
    expect(linked.status, linked.stderr).toBe(0);
    expectGuidance(linked.stdout, expected);
    const missing = resolve(root, "missing/../nested");
    expect(missing.status, missing.stderr).toBe(
      process.platform === "win32" ? 0 : 2,
    );
    if (process.platform === "win32") expectGuidance(missing.stdout, expected);
    else expect(missing.stdout).toBe("");
  });

  test.skipIf(process.platform === "win32")(
    "returns the existing failure status for scope link cycles",
    () => {
      const { root } = fixture();
      symlinkSync("second", join(root, "first"), "dir");
      symlinkSync("first", join(root, "second"), "dir");
      const result = resolve(root, "first");
      expect(result.status).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("Symlink loop");
    },
  );

  test("creates output directories and writes empty guidance when no policy exists", () => {
    const { root, output } = fixture();
    const destination = join(output, "artifacts", "guidance.md");
    const result = resolve(root, ".", destination);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("");
    expect(readFileSync(destination, "utf8")).toBe("");
  });

  test("writes UTF-8 guidance independently of the console locale", () => {
    const { root, output } = fixture();
    const content = "Unicode policy: 🔐 東京\n";
    write(root, "SECURITY.md", content);
    const args = ["--repo", root, "--scope", "."];
    const result = run(args, { ...process.env, LANG: "C", LC_ALL: "C" });
    expect(result.status, result.stderr).toBe(0);
    expectGuidance(result.stdout, [["SECURITY.md", content]]);
    const destination = join(output, "guidance.md");
    expect(resolve(root, ".", destination).status).toBe(0);
    expect(readFileSync(destination, "utf8")).toBe(
      process.platform === "win32"
        ? result.stdout.replace(/\n/g, "\r\n")
        : result.stdout,
    );
  });

  test("expands the current home directory for repository and scope paths", () => {
    const { root } = fixture();
    write(root, "SECURITY.md", "home policy\n");
    const result = run(["--repo", "~", "--scope", "~"], {
      ...process.env,
      HOME: root,
      USERPROFILE: root,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("home policy\n");
  });

  test.skipIf(process.platform !== "linux")(
    "preserves raw HOME bytes for tilde expansion and keeps output tildes literal",
    () => {
      const { root } = fixture();
      const home = Buffer.concat([
        Buffer.from(join(root, "home-")),
        Buffer.from([0xff]),
      ]);
      mkdirSync(Buffer.concat([home, Buffer.from("/project")]), {
        recursive: true,
      });
      writeFileSync(
        Buffer.concat([home, Buffer.from("/SECURITY.md")]),
        "raw home policy\n",
      );
      writeFileSync(
        Buffer.concat([home, Buffer.from("/project/SECURITY.md")]),
        "project policy\n",
      );
      write(root, "home-\ufffd/SECURITY.md", "replacement sibling\n");
      write(root, "home-\ufffd/project/SECURITY.md", "replacement project\n");
      const result = spawnSync(
        "/bin/sh",
        [
          "-c",
          'HOME="$2/home-$(printf \'\\377\')"; export HOME; exec "$1" --helper resolve-security-md --repo "~" --scope "~/project" --out "~/guidance.md"',
          "helper-test",
          join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
          root,
        ],
        { cwd: root, encoding: "utf8" },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe("");
      expectGuidance(readFileSync(join(root, "~", "guidance.md"), "utf8"), [
        ["SECURITY.md", "raw home policy"],
        ["project/SECURITY.md", "project policy"],
      ]);
    },
  );

  test.skipIf(process.platform === "win32")(
    "distinguishes ordinary, unset, and empty HOME for quoted tilde paths",
    () => {
      const { root } = fixture();
      write(root, "project/SECURITY.md", "project policy\n");
      const project = join(root, "project");
      for (const [home, path] of [
        [root, "~/project"],
        [undefined, `~/${relative(userInfo().homedir, project)}`],
        ["", `~${project}`],
      ] as const) {
        const result = spawnSync(
          join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
          ["--helper", "resolve-security-md", "--repo", path, "--scope", path],
          { encoding: "utf8", env: { ...process.env, HOME: home } },
        );
        expect(result.status, result.stderr).toBe(0);
        expectGuidance(result.stdout, [["SECURITY.md", "project policy"]]);
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "expands named homes with quoted and control characters in the remaining path",
    () => {
      const { root } = fixture();
      const info = userInfo();
      const directory = 'space "quote" back\\slash\nline\ttab\b';
      write(root, `${directory}/SECURITY.md`, "named-home policy\n");
      const path = `~${info.username}/${relative(info.homedir, join(root, directory))}`;
      const result = run(["--repo", path, "--scope", path], {
        ...process.env,
        HOME: join(root, "unused home"),
      });
      expect(result.status, result.stderr).toBe(0);
      expectGuidance(result.stdout, [["SECURITY.md", "named-home policy"]]);
    },
  );

  test.skipIf(process.platform === "win32")(
    "expands named homes without invoking Git or Python",
    () => {
      const { root, output } = fixture();
      write(root, "SECURITY.md", "independent policy\n");
      const tools = join(output, "tools");
      const marker = join(output, "tool-invoked");
      for (const name of ["git", "python", "python3"]) {
        write(
          tools,
          name,
          '#!/bin/sh\nprintf invoked > "$HELPER_TOOL_MARKER"\nexit 99\n',
        );
        chmodSync(join(tools, name), 0o755);
      }
      const info = userInfo();
      const path = `~${info.username}/${relative(info.homedir, root)}`;
      const result = spawnSync(
        "/bin/sh",
        [
          join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
          "--helper",
          "resolve-security-md",
          "--repo",
          path,
          "--scope",
          path,
        ],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            PATH: tools,
            CODEX_MCP_NODE_PATH: Bun.which("node") ?? undefined,
            HELPER_TOOL_MARKER: marker,
          },
        },
      );
      expect(result.status, result.stderr).toBe(0);
      expectGuidance(result.stdout, [["SECURITY.md", "independent policy"]]);
      expect(result.stderr).toBe("");
      expect(existsSync(marker)).toBe(false);
    },
  );

  test.skipIf(process.platform !== "win32")(
    "expands named Windows profiles beside the current profile",
    () => {
      const { root } = fixture();
      const profiles = join(root, "profiles");
      write(profiles, "current/SECURITY.md", "current policy\n");
      write(profiles, "sibling/SECURITY.md", "sibling policy\n");
      const result = run(["--repo", "~sibling", "--scope", "~sibling"], {
        ...process.env,
        USERPROFILE: join(profiles, "current"),
        USERNAME: "current",
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain("sibling policy\n");
    },
  );

  test("resolves repository-local file and directory links", () => {
    const { root } = fixture();
    write(root, "policies/shared.md", "shared policy\n");
    symlinkSync(
      join(root, "policies", "shared.md"),
      join(root, "SECURITY.md"),
      "file",
    );
    write(root, "components/SECURITY.md", "component policy\n");
    write(root, "components/app.ts", "export {};\n");
    mkdirSync(join(root, "components", "leaf"));
    symlinkSync(
      join(root, "components", "leaf"),
      join(root, "alias"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const scope =
      process.platform === "win32" ? "alias" : `alias${sep}..${sep}app.ts`;
    const result = resolve(root, scope);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("shared policy\n");
    expect(result.stdout).toContain("component policy\n");
  });

  test("rejects missing, non-directory, or outside repository and scope paths", () => {
    const { root, output } = fixture();
    mkdirSync(output);
    write(root, "file.ts", "export {};\n");
    for (const [result, message] of [
      [inventory(join(root, "missing")), "scan root does not exist"],
      [inventory(join(root, "file.ts")), "scan root is not a directory"],
      [resolve(root, "missing"), "scan scope does not exist"],
      [resolve(root, output), "scan scope is outside the scan root"],
    ] as const) {
      expect(result.status, result.stderr).toBe(2);
      expect(result.stderr).toContain(message);
      expect(result.stdout).toBe("");
    }
  });

  test.skipIf(process.platform !== "win32")(
    "resolves drive-relative and rooted scopes using the repository drive",
    () => {
      const { root } = fixture("İrepository");
      write(root, "src/SECURITY.md", "component policy\n");
      write(root, "src/app.ts", "export {};\n");
      const drive = root.slice(0, 2);
      for (const scope of [
        `${drive}src\\app.ts`,
        join(root, "src", "app.ts").slice(2),
      ]) {
        const result = run(
          ["--repo", root, "--scope", scope],
          process.env,
          process.env["SystemRoot"] ?? dirname(root),
        );
        expect(result.status, result.stderr).toBe(0);
        expectGuidance(result.stdout, [
          ["src/SECURITY.md", "component policy"],
        ]);
      }
    },
  );

  test("rejects scope and policy links outside the repository", () => {
    const { root, output } = fixture();
    write(output, "outside.md", "outside policy\n");
    symlinkSync(join(output, "outside.md"), join(root, "SECURITY.md"), "file");
    symlinkSync(
      output,
      join(root, "outside"),
      process.platform === "win32" ? "junction" : "dir",
    );
    for (const [scope, message] of [
      [".", "SECURITY.md is outside the scan root"],
      ["outside", "scan scope is outside the scan root"],
    ]) {
      const result = resolve(root, scope!);
      expect(result.status, result.stderr).toBe(2);
      expect(result.stderr).toContain(message!);
      expect(result.stdout).toBe("");
    }
  });

  test("rejects non-UTF-8 and oversized regular or linked policies", () => {
    for (const kind of ["non-utf8", "oversized", "linked"]) {
      const { root } = fixture();
      const content =
        kind === "non-utf8"
          ? Buffer.from([0xff])
          : Buffer.alloc(1024 * 1024 + 1, "a");
      write(root, kind === "linked" ? "large.md" : "SECURITY.md", content);
      if (kind === "linked")
        symlinkSync(join(root, "large.md"), join(root, "SECURITY.md"), "file");
      const result = resolve(root, ".");
      expect(result.status, result.stderr).toBe(2);
      expect(result.stderr).toContain(
        kind === "non-utf8" ? "not valid UTF-8" : "exceeds 1 MiB",
      );
      expect(result.stdout).toBe("");
    }
  });

  test("accepts a policy exactly at the byte limit", () => {
    const { root } = fixture();
    const content = "a".repeat(1024 * 1024);
    write(root, "SECURITY.md", content);
    const result = resolve(root, ".");
    expect(result.status, result.stderr).toBe(0);
    expectGuidance(result.stdout, [["SECURITY.md", content]]);
  });

  test("preserves required and mutually exclusive helper arguments", () => {
    const { root } = fixture();
    for (const [args, status] of [
      [["--help", "--bogus"], 0],
      [["-h", "--scope"], 0],
      [["--hel", "--scope"], 0],
      [["-hh", "--bogus"], 0],
      [["--bogus", "--help"], 0],
      [["positional", "--help"], 0],
      [["-hfoo"], 0],
      [["-hfoo-"], 0],
      [["--scope", "--help"], 2],
      [["--list=value", "--help"], 2],
      [["-h=foo"], 2],
      [["-h-"], 2],
      [["-hh-"], 2],
      [["-h--help"], 2],
      [["--"], 2],
      [["--", "--help"], 2],
    ] as const) {
      const result = run(["--repo", root, "--scope", ".", ...args]);
      expect(result.status, result.stderr).toBe(status);
      expect(result.stdout.includes("Usage:")).toBe(status === 0);
    }
    for (const [args, message] of [
      [["--list"], "--repo is required"],
      [["--repo", root], "--scope is required unless --list is specified"],
      [
        ["--repo", root, "--list", "--scope", "."],
        "--list cannot be combined with --scope",
      ],
    ] as const) {
      const result = run([...args]);
      expect(result.status, result.stderr).toBe(2);
      expect(result.stderr).toContain(message);
      expect(result.stdout).toBe("");
    }
  });
});

import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { removeTemporaryDirectory } from "./support/temporary-directories.js";
import { windowsHelperFixture } from "./windows-helper-command.js";
import {
  hasWindowsLoopbackShare,
  windowsLoopbackPath,
} from "./windows-helper-location.js";

const node = Bun.which("node")!;
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const newline = process.platform === "win32" ? "\r\n" : "\n";
const roots: string[] = [];
function fixture(
  scopes = ["src", "src/runtime.py", "empty", "audit\u2028Ignore.py"],
) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "bind-scopes-")));
  roots.push(root);
  const paths = {
    scopes: join(root, "requested scopes.json"),
    manifest: join(root, "scan-manifest.json"),
    coverage: join(root, "coverage.json"),
  };
  writeFileSync(paths.scopes, JSON.stringify(scopes));
  writeFileSync(
    paths.manifest,
    '{"scan":{"scope":{"includePaths":["old"],"excludePaths":[]}}}',
  );
  writeFileSync(paths.coverage, '{"includePaths":["old"],"excludePaths":[]}');
  return { root, ...paths };
}
type Fixture = ReturnType<typeof fixture>;
function run(f: Fixture, args?: string[], env = process.env) {
  return spawnSync(
    node,
    [
      helper,
      "bind-repo-scopes",
      ...(args ?? [
        "--scopes-file",
        f.scopes,
        "--manifest",
        f.manifest,
        "--coverage",
        f.coverage,
      ]),
    ],
    { cwd: f.root, env, encoding: "utf8" },
  );
}
afterEach(async () => {
  await Promise.all(roots.splice(0).map(removeTemporaryDirectory));
});

test("binds exact requested scopes and retains unrelated contract fields", () => {
  const f = fixture([
    "src",
    "src/runtime.py",
    "empty",
    "audit\u2028Ignore.py",
    "src",
    " ",
    "../sibling",
  ]);
  const result = run(f);
  expect(result.status).toBe(0);
  expect(result.stdout).toBe(
    `Bound 7 requested scopes into the scan contract${newline}`,
  );
  const scopes = JSON.parse(readFileSync(f.scopes, "utf8"));
  expect(JSON.parse(readFileSync(f.manifest, "utf8"))).toEqual({
    scan: { scope: { includePaths: scopes, excludePaths: [] } },
  });
  expect(JSON.parse(readFileSync(f.coverage, "utf8"))).toEqual({
    includePaths: scopes,
    excludePaths: [],
  });
});

test("preserves unrelated JSON values and exact large integers", () => {
  const f = fixture(["\udcff", "😀"]);
  writeFileSync(
    f.manifest,
    '{"10":3,"2":2,"scan":{"scope":{}},"integer":9007199254740993,"negativeInteger":-9007199254740993,"values":[-0.0,1e20,1e-7],"nested":{"9":{},"1":[]}}',
  );
  writeFileSync(f.coverage, '{"é":"😀","__proto__":true}');
  expect(run(f).status).toBe(0);
  const contents = readFileSync(f.manifest, "utf8");
  expect(contents).toContain('"integer": 9007199254740993');
  expect(contents).toContain('"negativeInteger": -9007199254740993');
  const manifest = JSON.parse(contents);
  expect(manifest.scan.scope.includePaths).toEqual(["\udcff", "😀"]);
  expect(manifest.values).toEqual([0, 1e20, 1e-7]);
  expect(manifest.nested).toEqual({ "9": {}, "1": [] });
  const coverage = JSON.parse(readFileSync(f.coverage, "utf8"));
  expect(coverage["é"]).toBe("😀");
  expect(Object.hasOwn(coverage, "__proto__")).toBe(true);
  expect(coverage["__proto__"]).toBe(true);
  expect(coverage.includePaths).toEqual(["\udcff", "😀"]);
});

for (const [label, contents, message] of [
  [
    "empty array",
    "[]",
    "Scopes file must contain a non-empty JSON string array",
  ],
  [
    "empty scope",
    '[""]',
    "Scopes file must contain a non-empty JSON string array",
  ],
  [
    "wrong element",
    '["src",1]',
    "Scopes file must contain a non-empty JSON string array",
  ],
  [
    "wrong container",
    "{}",
    "Scopes file must contain a non-empty JSON string array",
  ],
  ["malformed JSON", "[", "Unable to read scopes file"],
  ["UTF-8 BOM", '\ufeff["src"]', "Unable to read scopes file"],
] as const) {
  test(`rejects ${label} before changing either document`, () => {
    const f = fixture();
    const before = [readFileSync(f.manifest), readFileSync(f.coverage)];
    writeFileSync(f.scopes, contents);
    const result = run(f);
    expect(result.status).toBe(1);
    expect(result.stderr).toBe(`${message}: ${f.scopes}${newline}`);
    expect([readFileSync(f.manifest), readFileSync(f.coverage)]).toEqual(
      before,
    );
  });
}

for (const [target, contents] of [
  ["manifest", "[]"],
  ["manifest", "{}"],
  ["manifest", '{"scan":[]}'],
  ["manifest", '{"scan":{"scope":null}}'],
  ["coverage", "null"],
  ["coverage", "{"],
  ["coverage", Buffer.from([0xff])],
] as const) {
  const label = typeof contents === "string" ? contents : "UTF-8";
  test(`rejects invalid ${target} ${label} before writing`, () => {
    const f = fixture();
    writeFileSync(f[target], contents);
    const before = [readFileSync(f.manifest), readFileSync(f.coverage)];
    const result = run(f);
    expect(result.status).toBe(1);
    expect(result.stderr).toBe(
      `Unable to bind requested scopes into the scan contract${newline}`,
    );
    expect([readFileSync(f.manifest), readFileSync(f.coverage)]).toEqual(
      before,
    );
  });
}

test("reads both aliased documents before the ordered writes", () => {
  const f = fixture(["new"]);
  f.coverage = f.manifest;
  expect(run(f).status).toBe(0);
  expect(JSON.parse(readFileSync(f.manifest, "utf8"))).toEqual({
    scan: { scope: { includePaths: ["old"], excludePaths: [] } },
    includePaths: ["new"],
  });
});

test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
  "escapes terminal controls only in filesystem errors",
  () => {
    const f = fixture();
    const manifest = join(f.root, "manifest-\u001b[2J.json");
    renameSync(f.manifest, manifest);
    f.manifest = manifest;
    const before = [readFileSync(f.manifest), readFileSync(f.coverage)];
    chmodSync(f.manifest, 0o444);
    try {
      const result = run(f);
      expect(result.status).toBe(1);
      expect(result.stdout).toBe("");
      expect(result.stderr).toContain("manifest-\\u001b[2J.json");
      expect(result.stderr).not.toContain("\u001b");
      expect([readFileSync(f.manifest), readFileSync(f.coverage)]).toEqual(
        before,
      );
    } finally {
      chmodSync(f.manifest, 0o644);
    }

    const scopes = join(f.root, "scopes-\u001b[2J.json");
    renameSync(f.scopes, scopes);
    f.scopes = scopes;
    writeFileSync(scopes, "[]");
    const invalid = run(f);
    expect(invalid.status).toBe(1);
    expect(invalid.stderr).toBe(
      `Scopes file must contain a non-empty JSON string array: ${scopes}\n`,
    );
  },
);

test("expands home and relative paths through the existing helper arguments", () => {
  const f = fixture();
  const result = run(
    f,
    [
      "--scopes-file=~/requested scopes.json",
      "--manifest=./scan-manifest.json",
      "--coverage=coverage.json",
    ],
    { ...process.env, HOME: f.root, USERPROFILE: f.root },
  );
  expect(result.status).toBe(0);
});

test.skipIf(process.platform !== "linux")(
  "launcher preserves raw scope and contract path bytes",
  () => {
    const f = fixture();
    const raw = (name: string, byte: number) =>
      Buffer.concat([
        Buffer.from(join(f.root, name + "-")),
        Buffer.from([byte]),
      ]);
    const scopes = raw("scopes", 0xff);
    const manifest = raw("manifest", 0xfe);
    const coverage = raw("coverage", 0xfd);
    for (const [key, path] of [
      ["scopes", scopes],
      ["manifest", manifest],
      ["coverage", coverage],
    ] as const) {
      renameSync(f[key], path);
      writeFileSync(join(f.root, key + "-\ufffd"), "replacement sentinel");
    }
    const result = spawnSync(
      "/bin/sh",
      [
        "-c",
        'exec "$1" --helper bind-repo-scopes --scopes-file "$2/scopes-$(printf \'\\377\')" --manifest "$2/manifest-$(printf \'\\376\')" --coverage "$2/coverage-$(printf \'\\375\')"',
        "sh",
        join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
        f.root,
      ],
      { encoding: "utf8" },
    );
    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    const requested = JSON.parse(readFileSync(scopes, "utf8"));
    expect(
      JSON.parse(readFileSync(manifest, "utf8")).scan.scope.includePaths,
    ).toEqual(requested);
    expect(JSON.parse(readFileSync(coverage, "utf8")).includePaths).toEqual(
      requested,
    );
    for (const key of ["scopes", "manifest", "coverage"])
      expect(readFileSync(join(f.root, key + "-\ufffd"), "utf8")).toBe(
        "replacement sentinel",
      );
  },
);

test.skipIf(process.platform === "win32")(
  "preserves output symlinks and file modes",
  () => {
    const f = fixture();
    const target = join(f.root, "coverage-target.json");
    writeFileSync(target, "{}", { mode: 0o640 });
    rmSync(f.coverage);
    symlinkSync(target, f.coverage);
    expect(run(f).status).toBe(0);
    expect(realpathSync(f.coverage)).toBe(target);
    expect(statSync(target).mode & 0o777).toBe(0o640);
  },
);

for (const location of ["absolute", "relative", "unc"] as const)
  test.skipIf(
    process.platform !== "win32" ||
      (location === "unc" && !hasWindowsLoopbackShare),
  )(
    `documented PowerShell scope generation and binding preserve ${location} literal paths`,
    async () => {
      const requested = ["caf\u00e9/\u96ea.py", "src", "src"];
      const f = fixture(requested);
      const scopes = join(
        f.root,
        "scopes %USERNAME% !EXPAND! caf\u00e9's.json",
      );
      renameSync(f.scopes, scopes);
      const expandedScopes = scopes.replace("%USERNAME%", "expanded-user");
      writeFileSync(expandedScopes, '["wrong"]');
      const caller = join(f.root, "caller");
      mkdirSync(caller);
      const workingDirectory =
        location === "unc" ? windowsLoopbackPath(caller) : caller;
      const argument = (path: string) =>
        location === "absolute" ? path : relative(caller, path);
      const launcher = windowsHelperFixture(f.root, {
        CODEX_SECURITY_TARGET_PATHS_FILE: argument(scopes),
      });
      const repository = join(f.root, "repository %USERNAME% !EXPAND! café's");
      mkdirSync(join(repository, "café"), { recursive: true });
      mkdirSync(join(repository, "src"));
      writeFileSync(join(repository, "café", "雪.py"), "source\n");
      writeFileSync(join(repository, "src", "source.py"), "source\n");
      const scanDir = join(f.root, "scan %USERNAME% !EXPAND! \u96ea's");
      const expandedScanDir = scanDir.replace("%USERNAME%", "expanded-user");
      for (const directory of [scanDir, expandedScanDir]) mkdirSync(directory);
      const initial = {
        "scan-manifest.json": readFileSync(f.manifest),
        "coverage.json": readFileSync(f.coverage),
      };
      for (const powershell of launcher.powershells) {
        const generated = await launcher.run(
          powershell,
          "skills/security-scan/SKILL.md",
          {
            "<plugin_dir>": argument(launcher.plugin),
            "<repo_root>": argument(repository),
            "<scan_dir>": argument(scanDir),
          },
          undefined,
          workingDirectory,
          undefined,
          1,
        );
        expect(generated.status, generated.diagnostics).toBe(0);
        expect(
          readFileSync(join(scanDir, "scoped-source-input.jsonl"), "utf8")
            .trim()
            .split(/\r?\n/u)
            .map((line) => JSON.parse(line).path),
          generated.diagnostics,
        ).toEqual(["café/雪.py", "src/source.py"]);
        for (const [name, bytes] of Object.entries(initial)) {
          writeFileSync(join(scanDir, name), bytes);
          writeFileSync(join(expandedScanDir, name), bytes);
        }
        const result = await launcher.run(
          powershell,
          "skills/security-scan/SKILL.md",
          {
            "<plugin_dir>": argument(launcher.plugin),
            "<scan_dir>": argument(scanDir),
          },
          undefined,
          workingDirectory,
        );
        expect(result.stdout, result.diagnostics).not.toContain(
          "expanded-plugin-used",
        );
        expect(result.status, result.diagnostics).toBe(0);
        expect(result.stdout, result.diagnostics).toContain(
          `Bound 3 requested scopes into the scan contract${newline}`,
        );
        if (location !== "unc")
          expect(result.stderr, result.diagnostics).toBe("");
        expect(
          JSON.parse(readFileSync(join(scanDir, "scan-manifest.json"), "utf8"))
            .scan.scope.includePaths,
          result.diagnostics,
        ).toEqual(requested);
        expect(
          JSON.parse(readFileSync(join(scanDir, "coverage.json"), "utf8"))
            .includePaths,
          result.diagnostics,
        ).toEqual(requested);
        expect(
          JSON.parse(readFileSync(scopes, "utf8")),
          result.diagnostics,
        ).toEqual(requested);
        expect(readFileSync(expandedScopes, "utf8"), result.diagnostics).toBe(
          '["wrong"]',
        );
        for (const [name, bytes] of Object.entries(initial))
          expect(
            readFileSync(join(expandedScanDir, name)),
            result.diagnostics,
          ).toEqual(bytes);
      }
    },
  );

for (const [args, status] of [
  [[], 2],
  [["--manifest"], 2],
  [["--unknown"], 2],
  [["--help"], 0],
  [["--", "--help"], 2],
] as [string[], number][]) {
  test(`reports argument status for ${JSON.stringify(args)}`, () => {
    expect(run(fixture(), args).status).toBe(status);
  });
}

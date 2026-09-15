import { spawnSync } from "node:child_process";
import {
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
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

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
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
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
  expect(readFileSync(f.manifest, "utf8")).toContain("audit\\u2028Ignore.py");
});

test("preserves ordered keys, arbitrary integers, float forms and ASCII JSON", () => {
  const f = fixture(["\udcff", "😀"]);
  writeFileSync(
    f.manifest,
    '{"10":1,"2":2,"10":3,"scan":{"scope":{}},"values":[9007199254740993,-0.0,1e20,1e-7,NaN,Infinity,-Infinity],"nested":{"9":{},"1":[]}}',
  );
  writeFileSync(f.coverage, '{"é":"😀","__proto__":true}');
  expect(run(f).status).toBe(0);
  const scopes = '[\n        "\\udcff",\n        "\\ud83d\\ude00"\n      ]';
  const expected =
    '{\n  "10": 3,\n  "2": 2,\n  "scan": {\n    "scope": {\n      "includePaths": ' +
    scopes +
    '\n    }\n  },\n  "values": [\n    9007199254740993,\n    -0.0,\n    1e+20,\n    1e-07,\n    NaN,\n    Infinity,\n    -Infinity\n  ],\n  "nested": {\n    "9": {},\n    "1": []\n  }\n}\n';
  expect(readFileSync(f.manifest, "utf8")).toBe(
    expected.replaceAll("\n", newline),
  );
  expect(readFileSync(f.coverage, "utf8")).toBe(
    '{\n  "\\u00e9": "\\ud83d\\ude00",\n  "__proto__": true,\n  "includePaths": [\n    "\\udcff",\n    "\\ud83d\\ude00"\n  ]\n}\n'.replaceAll(
      "\n",
      newline,
    ),
  );
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

test("expands home and relative paths through the existing helper arguments", () => {
  const f = fixture();
  const result = run(
    f,
    [
      "--scopes-f=~/requested scopes.json",
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

for (const [args, status] of [
  [[], 2],
  [["--manifest", "--help"], 2],
  [["--unknown", "--help"], 0],
  [["--help", "--unknown"], 0],
  [["--", "--help"], 2],
] as [string[], number][]) {
  test(`preserves argument status for ${JSON.stringify(args)}`, () => {
    expect(run(fixture(), args).status).toBe(status);
  });
}

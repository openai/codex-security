import { spawnSync } from "node:child_process";
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
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const node = Bun.which("node")!;
const helper = join(PLUGIN_ROOT, "mcp", "helpers.mjs");
const roots: string[] = [];
type Row = Record<string, unknown>;
interface Fixture {
  root: string;
  repo: string;
  scope: string;
  output: string;
}
const location = (
  path = "app/routes.py",
  start_line = 2,
  role = "entrypoint",
) => ({ path, start_line, role });
const candidate = (locations: Row[] = [location()], extra: Row = {}) => ({
  cwe_ids: ["CWE-89"],
  locations,
  summary: "Request input reaches an unsafe operation",
  evidence: "The input reaches the operation without a check",
  ...extra,
});
function write(path: string, data: string | Buffer): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, data);
}
function fixture(): Fixture {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "candidate-normalizer-")),
  );
  roots.push(root);
  const repo = join(root, "İrepository");
  for (const path of [
    "app/routes.py",
    "app/query.py",
    "app/export.py",
    "helpers/shared.py",
  ])
    write(join(repo, path), "one\ntwo\nthree\nfour\nfive\n");
  const scope = join(root, "in-scope.txt");
  write(scope, "app/routes.py\napp/query.py\napp/export.py\n");
  return { root, repo, scope, output: join(root, "combined.jsonl") };
}
function run(
  f: Fixture,
  groups: Row[][],
  extra: string[] = [],
  env = process.env,
) {
  const inputs = groups.map((rows, index) => {
    const input = join(f.root, `candidates-${index}.jsonl`);
    write(input, rows.map((row) => JSON.stringify(row)).join("\n") + "\n");
    return input;
  });
  return invoke(f, inputs, extra, env);
}
function invoke(
  f: Fixture,
  inputs: string[],
  extra: string[] = [],
  env = process.env,
) {
  return spawnSync(
    node,
    [
      helper,
      "normalize-candidates",
      "--input",
      ...inputs,
      "--out",
      f.output,
      "--repo-root",
      f.repo,
      "--in-scope-files",
      f.scope,
      ...extra,
    ],
    {
      encoding: "utf8",
      env,
      cwd: f.root,
      maxBuffer: Infinity,
    },
  );
}
function ledger(f: Fixture): Row[] {
  return readFileSync(f.output, "utf8")
    .split(/\r?\n/u)
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Row);
}
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe("built candidate normalizer", () => {
  test.skipIf(process.platform !== "linux")(
    "accepts many input paths through the packaged launcher",
    () => {
      const f = fixture();
      const row = `${JSON.stringify(candidate())}\n`;
      const inputs = Array.from({ length: 700 }, (_, index) => {
        const path = join(
          f.root,
          `worker-${index}-${"input".repeat(16)}.jsonl`,
        );
        write(path, row);
        return path;
      });
      const result = spawnSync(
        join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
        [
          "--helper",
          "normalize-candidates",
          "--input",
          ...inputs,
          "--out",
          f.output,
          "--repo-root",
          f.repo,
          "--in-scope-files",
          f.scope,
        ],
        {
          cwd: f.root,
          env: { ...process.env, CODEX_MCP_NODE_PATH: node },
          encoding: "utf8",
        },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe(
        `Combined 700 candidate rows into 1 rows in ${f.output}\n`,
      );
      expect(ledger(f)).toHaveLength(1);
    },
  );

  test("combines canonical code paths without Python and preserves separate instances", () => {
    const f = fixture();
    const locations = [
      location("app/query.py", 4, "sink"),
      location(),
      location("app/query.py", 3, "root_control"),
    ];
    const first = candidate(locations, {
      cwe_ids: ["cwe-089", "CWE-89"],
      summary: "Z: request reaches SQL\nA: query runs",
      evidence: "First trace",
      context: "First review",
    });
    const second = candidate(
      [...locations].reverse().concat(location("app/query.py", 4, "sink")),
      {
        summary: "A second review",
        evidence: "Second trace",
        context: "Second review",
      },
    );
    const result = run(
      f,
      [[first], [second, candidate(locations, { instance: "sort parameter" })]],
      [],
      { ...process.env, PATH: "" },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.replaceAll("\r\n", "\n")).toBe(
      `Combined 3 candidate rows into 2 rows in ${f.output}\n`,
    );
    const rows = ledger(f);
    expect(rows).toHaveLength(2);
    const merged = rows.find((row) => row["instance"] === undefined)!;
    expect(merged["cwe_ids"]).toEqual(["CWE-89"]);
    expect(merged["locations"]).toEqual([
      { path: "app/routes.py", start_line: 2, end_line: 2, role: "entrypoint" },
      {
        path: "app/query.py",
        start_line: 3,
        end_line: 3,
        role: "root_control",
      },
      { path: "app/query.py", start_line: 4, end_line: 4, role: "sink" },
    ]);
    expect(merged["summary"]).toBe(
      "A second review\nZ: request reaches SQL\nA: query runs",
    );
    expect(merged["evidence"]).toBe("First trace\nSecond trace");
    expect(merged["context"]).toBe("First review\nSecond review");
    expect(rows.some((row) => row["instance"] === "sort parameter")).toBe(true);
    if (process.platform !== "win32")
      expect(statSync(f.output).mode & 0o777).toBe(0o600);
  });

  test("is byte-stable across input order, duplicate aliases, and recombination", () => {
    const f = fixture();
    const first = candidate([location(), location("app/query.py", 4, "sink")], {
      evidence: "First trace",
    });
    const second = candidate([...first["locations"]].reverse(), {
      evidence: "Second trace",
    });
    const separate = candidate(
      [location("app/export.py", 2), location("app/export.py", 4, "sink")],
      { cwe_ids: ["CWE-22"] },
    );
    expect(run(f, [[first, separate], [second]]).status).toBe(0);
    const expected = readFileSync(f.output);
    expect(run(f, [[second], [separate, first]]).status).toBe(0);
    expect(readFileSync(f.output)).toEqual(expected);
    const input = join(f.root, "previous.jsonl");
    write(input, expected);
    expect(invoke(f, [input, input]).status).toBe(0);
    expect(readFileSync(f.output)).toEqual(expected);
    if (process.platform !== "win32") {
      const alias = join(f.root, "input-alias.jsonl");
      symlinkSync(input, alias);
      const result = invoke(f, [input, alias]);
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toContain("Combined 2 candidate rows into 2 rows");
      expect(readFileSync(f.output)).toEqual(expected);
    }
  });

  test("keeps different entrypoints and sinks and allows supporting files outside scope", () => {
    const f = fixture();
    const shared = location("helpers/shared.py", 3, "root_control");
    const rows = [
      candidate([location(), shared, location("app/query.py", 4, "sink")], {
        cwe_ids: [],
      }),
      candidate([location(), shared, location("app/export.py", 4, "sink")], {
        cwe_ids: [],
      }),
      candidate(
        [
          location("app/export.py", 2),
          shared,
          location("app/query.py", 4, "sink"),
        ],
        { cwe_ids: [] },
      ),
    ];
    expect(run(f, [rows]).status).toBe(0);
    expect(ledger(f)).toHaveLength(3);
    expect(
      ledger(f).every((row) => (row["cwe_ids"] as unknown[]).length === 0),
    ).toBe(true);
    const rejected = run(f, [[candidate([shared])]]);
    expect(rejected.status).toBe(2);
    expect(rejected.stderr).toContain("expected at least one in-scope file");
  });

  test("sorts Unicode code points, normalizes Unicode and large CWE integers, and retains BOM text", () => {
    const f = fixture();
    const names = ["app/\u{10000}.py", "app/\ue000.py"];
    for (const name of names) write(join(f.repo, name), "line\n");
    write(f.scope, names.join("\n") + "\n");
    const row = candidate(
      names.map((name) => location(name, 1, "evidence")),
      {
        cwe_ids: ["CWE-٢", "cwe-００８９", "CWE-89", "CWE-9007199254740993"],
        summary: "\u001c\ufeffSummary\u0085",
        evidence: "\u{10000}",
      },
    );
    const result = run(f, [[row, { ...row, evidence: "\ue000" }]]);
    expect(result.status, result.stderr).toBe(0);
    const value = ledger(f)[0]!;
    expect(value["cwe_ids"]).toEqual([
      "CWE-2",
      "CWE-89",
      "CWE-9007199254740993",
    ]);
    expect((value["locations"] as Row[]).map((item) => item["path"])).toEqual(
      [...names].reverse(),
    );
    expect(value["summary"]).toBe("\ufeffSummary");
    expect(value["evidence"]).toBe("\ue000\n\u{10000}");
    expect(value["candidate_id"]).toBe("candidate-cc5ebd3ebd732a50");
    expect(readFileSync(f.output, "utf8").startsWith('{"candidate_id":')).toBe(
      true,
    );
  });

  test("counts source lines as bytes separated by CR, LF, or CRLF", () => {
    const f = fixture();
    for (const [contents, count] of [
      [Buffer.from("a\rb\r\nc\n"), 3],
      [Buffer.from("a\vb\fc\u0085d\u2028e"), 1],
      [Buffer.from("unterminated"), 1],
      [Buffer.alloc(0), 0],
      [Buffer.from([0xff, 0x0a, 0xfe]), 2],
    ] as const) {
      write(join(f.repo, "app/routes.py"), contents);
      if (count > 0)
        expect(
          run(f, [[candidate([location("app/routes.py", count)])]]).status,
        ).toBe(0);
      const result = run(f, [
        [candidate([location("app/routes.py", count + 1)])],
      ]);
      expect(result.status).toBe(2);
      expect(result.stderr).toContain(`exceeds app/routes.py:${count}`);
    }
  });

  test.each(["1.0", "1e0"])(
    "normalizes integral line spelling %s",
    (spelling) => {
      const f = fixture();
      const input = join(f.root, "raw.jsonl");
      const row = JSON.stringify(candidate([location("app/routes.py", 1)]));
      write(input, row + "\n");
      expect(invoke(f, [input]).status).toBe(0);
      const expected = readFileSync(f.output);
      write(
        input,
        row.replace('"start_line":1', `"start_line":${spelling}`) + "\n",
      );
      expect(invoke(f, [input]).status).toBe(0);
      expect(readFileSync(f.output)).toEqual(expected);
    },
  );

  test("rejects invalid line values, malformed rows, and invalid UTF-8 atomically", () => {
    const f = fixture();
    const input = join(f.root, "raw.jsonl");
    for (const number of [
      "1.5",
      "true",
      "0",
      "-1",
      "NaN",
      "Infinity",
      "1e9999",
      '"1"',
    ]) {
      write(
        input,
        JSON.stringify(candidate([location("app/routes.py", 1)])).replace(
          '"start_line":1',
          `"start_line":${number}`,
        ) + "\n",
      );
      write(f.output, "previous output\n");
      const result = invoke(f, [input]);
      expect(result.status).toBe(2);
      expect(result.stderr).toContain("row 1:");
      expect(readFileSync(f.output, "utf8")).toBe("previous output\n");
    }
    const prefix = Buffer.from(
      JSON.stringify(
        candidate(undefined, { cwe_ids: [], summary: "s", evidence: "" }),
      ).slice(0, -2),
    );
    const invalidLongJson = Buffer.concat([
      prefix,
      Buffer.alloc(191 - prefix.length, 0x61),
      Buffer.from([0xff]),
      Buffer.from('"}'),
    ]);
    for (const invalid of [
      invalidLongJson,
      "not-json",
      "[]",
      "null",
      '{"locations":',
      "\ufeff{}",
      Buffer.from([0xff]),
      JSON.stringify(candidate([], { summary: "\ud800" })),
    ]) {
      write(input, invalid);
      const result = invoke(f, [input]);
      expect(result.status).toBe(2);
      expect(readFileSync(f.output, "utf8")).toBe("previous output\n");
    }
    write(input, JSON.stringify(candidate()) + "\r\n\rnot-json\n");
    expect(invoke(f, [input]).stderr).toContain("raw.jsonl row 3:");
    write(
      input,
      JSON.stringify(candidate(undefined, { evidence: "\ud800" })) + "\n",
    );
    expect(invoke(f, [input]).status).toBe(2);
    expect(readFileSync(f.output, "utf8")).toBe("previous output\n");
    expect(readdirSync(f.root).some((name) => name.endsWith(".tmp"))).toBe(
      false,
    );
  });

  test("reports invalid fields with the input row and preserves existing output", () => {
    const f = fixture();
    const cases: [Row, string][] = [
      [candidate(undefined, { cwe_ids: null }), "cwe_ids: expected an array"],
      [
        candidate(undefined, { cwe_ids: [12] }),
        "cwe_ids: expected CWE strings",
      ],
      [
        candidate(undefined, { cwe_ids: ["SQL injection"] }),
        "cwe_ids: unsupported value",
      ],
      [
        candidate(undefined, { cwe_ids: ["CWE-0"] }),
        "cwe_ids: unsupported value",
      ],
      [candidate([]), "locations: expected a non-empty array"],
      [
        candidate([null as unknown as Row]),
        "locations: expected location objects",
      ],
      [candidate([location("app/missing.py")]), "missing.py"],
      [
        candidate([location("../outside.py")]),
        "repository-relative path without traversal",
      ],
      [
        candidate([location(f.repo)]),
        "repository-relative path without traversal",
      ],
      [candidate([location("app")]), "path: expected a regular file"],
      [
        candidate([location("app/routes.py", 6)]),
        "line range 6-6 exceeds app/routes.py:5",
      ],
      [candidate([{ ...location(), end_line: 1 }]), "greater than or equal"],
      [
        candidate([location("app/routes.py", 1, "rootControl")]),
        "role: unsupported value",
      ],
      [
        candidate([{ ...location(), line: 2 }]),
        "locations: unsupported fields line",
      ],
      [
        candidate(undefined, { technically_validated: true }),
        "unsupported fields technically_validated",
      ],
      [
        candidate(undefined, { disposition: "reportable" }),
        "unsupported fields disposition",
      ],
      [
        candidate(undefined, { candidate_id: " " }),
        "candidate_id: expected a non-empty string",
      ],
      [
        candidate(undefined, { summary: "\u001c" }),
        "summary: expected a non-empty string",
      ],
      [
        candidate(undefined, { evidence: null }),
        "evidence: expected a non-empty string",
      ],
      [
        candidate(undefined, { context: " " }),
        "context: expected a non-empty string",
      ],
      [
        candidate(undefined, { instance: false }),
        "instance: expected a non-empty string",
      ],
    ];
    for (const [row, message] of cases) {
      write(f.output, "previous output\n");
      const result = run(f, [[candidate(), row]]);
      expect(result.status).toBe(2);
      expect(result.stderr).toContain("candidates-0.jsonl row 2:");
      expect(result.stderr).toContain(message);
      expect(readFileSync(f.output, "utf8")).toBe("previous output\n");
    }
  });

  test.skipIf(process.platform === "win32")(
    "rejects unsupported surrogate paths before replacement-character sibling lookup",
    () => {
      const f = fixture();
      write(join(f.repo, "\ufffd.py"), "replacement sibling\n");
      write(f.scope, "\ufffd.py\n");
      for (const name of ["\ud800.py", "\udc00.py"]) {
        write(f.output, "previous output\n");
        const result = run(f, [[candidate([location(name, 1)])]]);
        expect(result.status).toBe(2);
        expect(result.stderr).toContain("unpaired surrogate");
        expect(readFileSync(f.output, "utf8")).toBe("previous output\n");
      }
    },
  );

  test("writes valid long output basenames through a short exclusive temporary name", () => {
    const f = fixture();
    f.output = join(f.root, `${"x".repeat(220)}.jsonl`);
    const result = run(f, [[candidate()]]);
    expect(result.status, result.stderr).toBe(0);
    expect(ledger(f)).toHaveLength(1);
    expect(readdirSync(f.root).some((name) => name.endsWith(".tmp"))).toBe(
      false,
    );
  });

  test.skipIf(process.platform === "win32")(
    "preserves scope through repeated separators after an unresolved symlink",
    () => {
      const f = fixture();
      symlinkSync("self", join(f.repo, "self"));
      symlinkSync("missing/../self", join(f.repo, "alias"));
      write(f.scope, `alias/${f.repo}/app/routes.py\n`);
      const result = run(f, [[candidate()]], ["--allow-missing-in-scope"]);
      expect(result.status, result.stderr).toBe(1);
      expect(existsSync(f.output)).toBe(false);
    },
  );

  test.skipIf(process.platform === "win32")(
    "normalizes remaining output components after a non-strict symlink cycle",
    () => {
      const f = fixture();
      symlinkSync("loop", join(f.root, "loop"));
      const target = join(f.root, "target.jsonl");
      write(target, "target must remain unchanged\n");
      const output = join(f.root, "from-loop.jsonl");
      symlinkSync(target, output);
      const result = run(
        { ...f, output: `${f.root}/loop/../from-loop.jsonl` },
        [[candidate()]],
      );
      expect(result.status, result.stderr).toBe(0);
      expect(readFileSync(target, "utf8")).toBe(
        "target must remain unchanged\n",
      );
      expect(ledger({ ...f, output })).toHaveLength(1);
      const alias = join(f.root, "nested-output-alias");
      const nestedTarget = join(f.root, "nested-target.jsonl");
      symlinkSync("loop/../nested-target.jsonl", alias);
      const nested = run({ ...f, output: alias }, [[candidate()]]);
      expect(nested.status, nested.stderr).toBe(0);
      expect(ledger({ ...f, output: nestedTarget })).toHaveLength(1);
      expect(
        run({ ...f, output: `${f.root}/loop/still-looped.jsonl` }, [
          [candidate()],
        ]).status,
      ).toBe(1);
    },
  );

  test("handles empty ledgers and protects resolved input and inventory destinations", () => {
    const f = fixture();
    expect(run(f, [[]]).status).toBe(0);
    expect(readFileSync(f.output, "utf8")).toBe("");
    const source = join(f.root, "candidates-0.jsonl");
    expect(invoke({ ...f, output: source }, [source]).stderr).toContain(
      "--out: must not also be an input",
    );
    const scopeBefore = readFileSync(f.scope);
    expect(invoke({ ...f, output: f.scope }, [source]).stderr).toContain(
      "--out: must not replace --in-scope-files",
    );
    expect(readFileSync(f.scope)).toEqual(scopeBefore);
    if (process.platform !== "win32") {
      const alias = join(f.root, "output-alias");
      symlinkSync(source, alias);
      expect(invoke({ ...f, output: alias }, [source]).stderr).toContain(
        "--out: must not also be an input",
      );
    }
    const nested = {
      ...f,
      output: join(f.root, "new", "nested", "ledger.jsonl"),
    };
    expect(run(nested, [[candidate()]]).status).toBe(0);
    expect(ledger(nested)).toHaveLength(1);
  });

  test("allows deleted inventory paths only when requested and keeps candidate files strict", () => {
    const f = fixture();
    write(f.scope, "app/deleted.py\napp/routes.py\n");
    const strict = run(f, [[candidate()]]);
    expect(strict.status).toBe(2);
    expect(strict.stderr).toContain("in-scope file row 1:");
    expect(run(f, [[candidate()]], ["--allow-missing-in-scope"]).status).toBe(
      0,
    );
    expect(
      run(
        f,
        [[candidate([location("app/deleted.py")])]],
        ["--allow-missing-in-scope"],
      ).status,
    ).toBe(2);
    write(f.scope, "../deleted.py\napp/routes.py\n");
    expect(run(f, [[candidate()]], ["--allow-missing-in-scope"]).status).toBe(
      2,
    );
    if (process.platform !== "win32") {
      const outside = join(f.root, "outside");
      mkdirSync(outside);
      symlinkSync(outside, join(f.repo, "outside"), "dir");
      write(f.scope, "outside/deleted.py\napp/routes.py\n");
      const escaped = run(f, [[candidate()]], ["--allow-missing-in-scope"]);
      expect(escaped.status).toBe(2);
      expect(escaped.stderr).toContain("path escapes repository");
    }
  });

  test("accepts CRLF, mixed newline, and unterminated inventories", () => {
    const f = fixture();
    for (const inventory of [
      "\r\napp/routes.py\r\napp/query.py\r\n",
      "app/routes.py\r\napp/query.py\n",
      "app/routes.py\r\napp/query.py",
    ]) {
      write(f.scope, inventory);
      expect(run(f, [[candidate()]]).status).toBe(0);
      expect((ledger(f)[0]!["locations"] as Row[])[0]!["path"]).toBe(
        "app/routes.py",
      );
    }
  });

  test.skipIf(process.platform === "win32")(
    "preserves literal POSIX names and rejects incompatible candidate paths",
    () => {
      const f = fixture();
      for (const name of [
        "app/ leading.py",
        "app/trailing .py",
        "app/ .py",
        "app/   .py",
        "app/carriage\rname.py",
        "app/trailing.py\r",
        "app/vertical\vname.py",
        "app/form\fname.py",
        "app/next\u0085name.py",
        "app/line\u2028name.py",
        "app/paragraph\u2029name.py",
      ]) {
        write(join(f.repo, name), "line\n");
        write(f.scope, name + "\n");
        const result = run(f, [[candidate([location(name, 1)])]]);
        expect(result.status, result.stderr).toBe(0);
        expect((ledger(f)[0]!["locations"] as Row[])[0]!["path"]).toBe(name);
      }
      for (const name of ["app/literal\\name.py", "app/C:foo.py", " ", "   "]) {
        write(join(f.repo, name), "line\n");
        write(f.scope, name + "\n");
        const result = run(f, [[candidate([location(name, 1)])]]);
        expect(result.status).toBe(2);
        expect(result.stderr).toContain("safe repository-relative POSIX path");
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "disambiguates carriage-return collisions from independent inventory evidence",
    () => {
      const cases = [
        {
          inventory: "app/routes.py\r\napp/query.py\r\n",
          files: ["app/routes.py\r"],
          selected: "app/routes.py",
        },
        {
          inventory:
            "app/query.py\napp/query.py\r\napp/routes.py\napp/routes.py\r\n",
          files: ["app/routes.py\r", "app/query.py\r"],
          selected: "app/routes.py\r",
        },
        {
          inventory: "app/query.py\r\napp/routes.py\r",
          files: ["app/routes.py\r"],
          selected: "app/routes.py\r",
        },
        {
          inventory: "app/routes.py\r\napp/literal.py\r\napp/query.py\n",
          files: ["app/routes.py\r", "app/literal.py\r"],
          selected: "app/routes.py\r",
        },
        {
          inventory: "\r\napp/routes.py\r\napp/query.py\r\n",
          files: ["app/routes.py\r", "app/query.py\r"],
          selected: "app/routes.py",
        },
      ];
      for (const item of cases) {
        const f = fixture();
        for (const name of item.files) write(join(f.repo, name), "line\n");
        write(f.scope, item.inventory);
        const result = run(f, [[candidate([location(item.selected, 1)])]]);
        expect(result.status, result.stderr).toBe(0);
        expect((ledger(f)[0]!["locations"] as Row[])[0]!["path"]).toBe(
          item.selected,
        );
      }
      for (const inventory of [
        "app/routes.py\r\napp/query.py\n",
        "app/routes.py\r\napp/query.py\r\n",
      ]) {
        const f = fixture();
        for (const name of ["app/routes.py\r", "app/query.py\r"])
          write(join(f.repo, name), "line\n");
        write(f.scope, inventory);
        for (const selected of ["app/routes.py", "app/routes.py\r"]) {
          const result = run(f, [[candidate([location(selected, 1)])]]);
          expect(result.status).toBe(2);
          expect(result.stderr).toContain("ambiguous carriage-return paths");
          expect(existsSync(f.output)).toBe(false);
        }
      }
    },
  );

  test.skipIf(process.platform !== "win32")(
    "normalizes Windows separators and rejects drive-qualified locations",
    () => {
      const f = fixture();
      write(f.scope, "app\\routes.py\r\n");
      expect(run(f, [[candidate([location("app\\routes.py")])]]).status).toBe(
        0,
      );
      expect((ledger(f)[0]!["locations"] as Row[])[0]!["path"]).toBe(
        "app/routes.py",
      );
      const result = run(f, [[candidate([location("C:routes.py")])]]);
      expect(result.status).toBe(2);
      expect(result.stderr).toContain(
        "repository-relative path without traversal",
      );
    },
  );

  test.skipIf(process.platform !== "linux")(
    "preserves an invalid filename byte near the end of a longer launcher payload",
    () => {
      const f = fixture();
      const input = Buffer.concat([
        Buffer.from(join(f.root, "candidates-")),
        Buffer.from([0xff]),
      ]);
      writeFileSync(input, JSON.stringify(candidate()) + "\n");
      write(join(f.root, "candidates-\ufffd"), "wrong input\n");
      const args = [
        "normalize-candidates",
        "--repo-root",
        "İrepository",
        "--in-scope-files",
        "in-scope.txt",
        "--out",
        "combined.jsonl",
        "--input",
        "candidates-",
      ];
      // The invalid byte sits at offset 191, where Node 20's decoder lost it.
      const padding =
        193 - Buffer.byteLength(["x", "", ...args].join("\0")) - 2;
      const result = spawnSync(
        "/bin/sh",
        [
          "-c",
          'exec "$1" --helper normalize-candidates --repo-root "$2" --in-scope-files in-scope.txt --out combined.jsonl --input "candidates-$(printf \'\\377\')"',
          "helper-test",
          join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
          "İrepository",
        ],
        {
          cwd: f.root,
          env: {
            ...process.env,
            HOME: "h".repeat(padding),
            CODEX_MCP_NODE_PATH: node,
          },
          encoding: "utf8",
        },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(ledger(f)).toHaveLength(1);
      expect(readFileSync(join(f.root, "candidates-\ufffd"), "utf8")).toBe(
        "wrong input\n",
      );
    },
  );

  test.skipIf(process.platform === "win32")(
    "preserves canonical byte paths and rejects links outside the repository",
    () => {
      const f = fixture();
      const raw = Buffer.concat([
        Buffer.from(f.root + "/repository-"),
        process.platform === "darwin" ? Buffer.from("é") : Buffer.from([0xff]),
      ]);
      mkdirSync(raw);
      writeFileSync(Buffer.concat([raw, Buffer.from("/entry.py")]), "one\n");
      const alias = join(f.root, "alias");
      symlinkSync(raw, alias, "dir");
      write(f.scope, "entry.py\n");
      const result = run({ ...f, repo: alias }, [
        [candidate([location("entry.py", 1)])],
      ]);
      expect(result.status, result.stderr).toBe(0);
      expect((ledger(f)[0]!["locations"] as Row[])[0]!["path"]).toBe(
        "entry.py",
      );
      const outside = join(f.root, "outside.py");
      write(outside, "one\n");
      symlinkSync(outside, join(f.repo, "outside.py"));
      write(f.scope, "app/routes.py\n");
      const escaped = run(f, [
        [candidate([location(), location("outside.py", 1, "sink")])],
      ]);
      expect(escaped.status).toBe(2);
      expect(escaped.stderr).toContain("must resolve inside --repo-root");
    },
  );

  test.skipIf(process.platform !== "win32")(
    "keeps Unicode sibling directories outside candidate and deleted-file scope",
    () => {
      const f = fixture();
      const sibling = join(f.root, "i\u0307repository");
      write(join(sibling, "source.py"), "one\n");
      symlinkSync(sibling, join(f.repo, "outside"), "junction");
      const escaped = run(f, [
        [candidate([location(), location("outside/source.py", 1, "sink")])],
      ]);
      expect(escaped.status).toBe(2);
      expect(escaped.stderr).toContain("must resolve inside --repo-root");
      write(f.scope, "app/routes.py\noutside/deleted.py\n");
      const missing = run(f, [[candidate()]], ["--allow-missing-in-scope"]);
      expect(missing.status).toBe(2);
      expect(missing.stderr).toContain("path escapes repository");
      expect(existsSync(f.output)).toBe(false);
    },
  );

  test("keeps argument aliases, multiple inputs, home expansion, and literal dash output", () => {
    const f = fixture();
    run(f, [[candidate()]]);
    const input = join(f.root, "candidates-0.jsonl");
    const result = spawnSync(
      node,
      [
        helper,
        "normalize-candidates",
        "--inp",
        input,
        input,
        "--o",
        "-",
        "--repo-r",
        "./~/İrepository",
        "--in-s",
        "~/in-scope.txt",
      ],
      {
        cwd: f.root,
        env: { ...process.env, HOME: f.root, USERPROFILE: f.root },
        encoding: "utf8",
      },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readFileSync(join(f.root, "-"), "utf8"))).toHaveProperty(
      "candidate_id",
    );
    expect(
      spawnSync(node, [helper, "normalize-candidates", "--help"], {
        encoding: "utf8",
      }).status,
    ).toBe(0);
    for (const args of [
      [],
      ["--input"],
      ["--in", input],
      ["--allow-missing-in-scope=true"],
    ])
      expect(
        spawnSync(node, [helper, "normalize-candidates", ...args]).status,
      ).toBe(2);
  });
});

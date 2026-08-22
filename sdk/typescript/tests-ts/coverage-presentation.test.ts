import { describe, expect, test } from "bun:test";
import {
  formatCoverageScope,
  formatScopePath,
} from "../src/coverage-presentation.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

function projectScope(scope: {
  includePaths: string[];
  excludePaths: string[];
  explicitExclusions: Array<{ pattern: string; reason: string }>;
}): string {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const script = [
    "import json, pathlib, runpy, sys, unicodedata",
    "plugin = pathlib.Path(sys.argv[1])",
    "examples = plugin / 'examples' / 'completed-scan'",
    "manifest, findings, coverage = [json.loads((examples / name).read_text()) for name in ('scan-manifest.json', 'findings.json', 'coverage.json')]",
    "scope = json.loads(sys.argv[2])",
    "manifest['scan']['scope'].update({key: scope[key] for key in ('includePaths', 'excludePaths')})",
    "manifest['scan']['scope']['artifactsReviewed'] = scope['includePaths']",
    "coverage.update(scope)",
    "coverage.update({'mode': 'scoped_path', 'completeness': 'partial', 'surfaces': [], 'deferred': [{'id': 'source-review', 'reason': 'Source review remains unfinished.', 'paths': scope['includePaths']}]})",
    "findings['findings'] = []",
    "unicodedata.category = lambda _character: 'Cn'",
    "projection = runpy.run_path(str(plugin / 'scripts' / 'report_projection.py'))",
    "sys.stdout.buffer.write(projection['generate_report_markdown'](manifest, findings, coverage))",
  ].join("\n");
  const result = Bun.spawnSync(
    [python!, "-I", "-B", "-c", script, PLUGIN_ROOT, JSON.stringify(scope)],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  return new TextDecoder().decode(result.stdout);
}

describe("coverage scope presentation", () => {
  test("distinguishes path text from include and exclusion delimiters", () => {
    const included = formatCoverageScope({
      mode: "scoped_path",
      includePaths: ["src; excluding tests"],
      excludePaths: [],
    });
    const excluded = formatCoverageScope({
      mode: "scoped_path",
      includePaths: ["src"],
      excludePaths: ["tests"],
    });
    expect(included).toBe('scoped paths: "src; excluding tests"');
    expect(excluded).toBe("scoped paths: src; excluding tests");
    expect(included).not.toBe(excluded);
    expect(
      formatCoverageScope({
        mode: "scoped_path",
        includePaths: ["src, tests", "src/parser.ts"],
        excludePaths: [],
      }),
    ).toBe('scoped paths: "src, tests", src/parser.ts');
  });

  test("round-trips ambiguous paths without emitting terminal controls", () => {
    const paths = [
      "src/a  b.ts",
      "src/trailing ",
      'src/"quoted"',
      "src/back\\slash",
      "src/line\nfeed",
      "src/\u001b[31m",
      "src/\u009b31m",
      "src/\u0085\u2028\u2029COVERAGE forged",
      "src/\ufeffname",
    ];
    for (const path of paths) {
      const encoded = formatScopePath(path);
      expect(encoded).not.toMatch(
        /[\u0000-\u001f\u007f-\u009f\u2028\u2029\ufeff]/u,
      );
      expect(JSON.parse(encoded)).toBe(path);
    }
    expect(formatScopePath("src/parser.ts")).toBe("src/parser.ts");
    expect(formatScopePath("src/generated/**")).toBe("src/generated/**");
  });

  test("distinguishes canonically equivalent path spellings", () => {
    for (const [composed, decomposed, encoded] of [
      ["src/café.ts", "src/cafe\u0301.ts", '"src/cafe\\u0301.ts"'],
      ["src/가.ts", "src/\u1100\u1161.ts", '"src/\\u1100\\u1161.ts"'],
    ] as const) {
      expect(composed.normalize("NFC")).toBe(decomposed.normalize("NFC"));
      expect(formatScopePath(composed)).toBe(composed);
      expect(formatScopePath(decomposed)).toBe(encoded);
      expect(JSON.parse(encoded)).toBe(decomposed);
      expect(formatScopePath(composed).normalize("NFC")).not.toBe(
        formatScopePath(decomposed).normalize("NFC"),
      );
    }
  });

  test("escapes invisible Unicode controls independently of Python's Unicode database", () => {
    // Unicode 17 DerivedGeneralCategory.txt, General_Category=Format.
    const formatControls = (
      [
        [0x00ad, 0x00ad],
        [0x0600, 0x0605],
        [0x061c, 0x061c],
        [0x06dd, 0x06dd],
        [0x070f, 0x070f],
        [0x0890, 0x0891],
        [0x08e2, 0x08e2],
        [0x180e, 0x180e],
        [0x200b, 0x200f],
        [0x202a, 0x202e],
        [0x2060, 0x2064],
        [0x2066, 0x206f],
        [0xfeff, 0xfeff],
        [0xfff9, 0xfffb],
        [0x110bd, 0x110bd],
        [0x110cd, 0x110cd],
        [0x13430, 0x1343f],
        [0x1bca0, 0x1bca3],
        [0x1d173, 0x1d17a],
        [0xe0001, 0xe0001],
        [0xe0020, 0xe007f],
      ] as const
    ).flatMap(([start, end]) =>
      Array.from({ length: end - start + 1 }, (_, offset) =>
        String.fromCodePoint(start + offset),
      ),
    );
    expect(formatControls).toHaveLength(170);
    const representativeNonFormatIgnorables =
      "\u034f\u115f\u1160\u17b4\u17b5\u180b\u180f\u3164\ufe00\ufe0f" +
      "\uffa0\ufff0\ufff8\u{e0000}\u{e0100}\u{e0fff}";
    const controls = [...formatControls, ...representativeNonFormatIgnorables];
    const paths = controls.flatMap((control) => [
      `src/${control}name`,
      `src/a ${control}name`,
    ]);
    for (const path of paths) {
      const encoded = formatScopePath(path);
      expect(encoded).not.toMatch(/[\p{Cf}\p{Default_Ignorable_Code_Point}]/u);
      expect(JSON.parse(encoded)).toBe(path);
    }
    const report = projectScope({
      includePaths: paths,
      excludePaths: [],
      explicitExclusions: [],
    });
    expect(report).not.toMatch(/[\p{Cf}\p{Default_Ignorable_Code_Point}]/u);
    const includedLine =
      report.split("\n").find((line) => line.startsWith("- Included paths:")) ??
      "";
    expect(includedLine).toEndWith(
      paths.map((path) => `\`${formatScopePath(path)}\``).join(", "),
    );
  });

  test("preserves exact paths in Markdown scope and deferred work", () => {
    const included = [
      ["src/a  b.ts", '`"src/a  b.ts"`'],
      ["src/trailing ", '`"src/trailing "`'],
      ["src,tests", '`"src,tests"`'],
      ["src/line\nfeed", '`"src/line\\nfeed"`'],
      ["src/\u202eforged", '`"src/\\u202eforged"`'],
      ["src/\ufeffname", '`"src/\\ufeffname"`'],
      ["src/\u2028\u2029next", '`"src/\\u2028\\u2029next"`'],
      ["src/[name]*_<tag>.ts", "`src/[name]*_<tag>.ts`"],
      ["src/a`b.ts", "``src/a`b.ts``"],
      ["`edge`", "`` `edge` ``"],
      ["src/naïve.ts", "`src/naïve.ts`"],
      ["src/café.ts", "`src/café.ts`"],
      ["src/cafe\u0301.ts", '`"src/cafe\\u0301.ts"`'],
      ["src/가.ts", "`src/가.ts`"],
      ["src/\u1100\u1161.ts", '`"src/\\u1100\\u1161.ts"`'],
    ] as const;
    const excluded = [
      ["vendor/a  b", '`"vendor/a  b"`'],
      ["vendor,tests", '`"vendor,tests"`'],
    ] as const;
    const pattern = "generated/\u2066[omitted]*`";
    const report = projectScope({
      includePaths: included.map(([path]) => path),
      excludePaths: excluded.map(([path]) => path),
      explicitExclusions: [{ pattern, reason: "Synthetic exclusion." }],
    });
    const row = (label: string) =>
      report.split("\n").find((line) => line.startsWith(label)) ?? "";
    const expectedIncludes = included.map(([, encoded]) => encoded).join(", ");
    expect(row("- Included paths:")).toEndWith(expectedIncludes);
    expect(row("- Excluded paths:")).toEndWith(
      excluded.map(([, encoded]) => encoded).join(", "),
    );
    expect(row("- Artifacts reviewed:")).toEndWith(expectedIncludes);
    expect(row("  - Paths:")).toEndWith(expectedIncludes);
    expect(report).toContain(
      'Excluded ``"generated/\\u2066[omitted]*`"``: Synthetic exclusion.',
    );
    expect(report).not.toMatch(
      /[\u007f-\u009f\u2028\u2029\p{Cf}\p{Default_Ignorable_Code_Point}]/u,
    );
  });
});

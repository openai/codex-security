import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, test } from "bun:test";
import type { PatternCase } from "./support/python-regex-fixture";
import { runCommand } from "./support/shell";

const directory = realpathSync(mkdtempSync(join(tmpdir(), "python-pattern-")));
const fixture = join(directory, "fixture.cjs"),
  node = Bun.which("node")!;
beforeAll(() =>
  buildSync({
    entryPoints: [
      fileURLToPath(
        new URL("./support/python-regex-fixture.ts", import.meta.url),
      ),
    ],
    outfile: fixture,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node20",
  }),
);
afterAll(() => rmSync(directory, { recursive: true, force: true }));
async function run(cases: PatternCase[]): Promise<Record<string, unknown>[]> {
  const child = await runCommand(node, [fixture], {
    input: JSON.stringify(cases),
    timeout: 15000,
    env: {
      ...process.env,
      PYTHON: join(directory, "missing-python"),
      PATH: "",
    },
  });
  expect(child.status, child.stderr).toBe(0);
  expect(child.stderr).toBe("");
  return JSON.parse(child.stdout) as Record<string, unknown>[];
}
const patterns = (values: string[]) =>
  run(values.map((pattern) => ({ pattern })));
const unlimited = 4294967295,
  widthLimit = "18446744073709551616";

test("retains capture identity, scoped flags and conditional references in typed IR", async () => {
  expect(await patterns(["(?P<word>é+)(?i:(?P=word))(?(word)a|b)"])).toEqual([
    {
      nodes: [
        [
          "SUBPATTERN",
          [1, 0, 0, [["MAX_REPEAT", [1, unlimited, [["LITERAL", 233]]]]]],
        ],
        ["SUBPATTERN", [null, 2, 0, [["GROUPREF", 1]]]],
        ["GROUPREF_EXISTS", [1, [["LITERAL", 97]], [["LITERAL", 98]]]],
      ],
      flags: 32,
      groupNames: [["word", 1]],
      groupWidths: [null, ["1", widthLimit]],
      width: ["3", widthLimit],
      warnings: [],
    },
  ]);
  const scoped = await patterns([
    "(?ai)a",
    "(?a:(?u:\\w+))",
    "(?P<__proto__>a)(?P=__proto__)",
  ]);
  expect(scoped[0]!["flags"]).toBe(258);
  const word = ["IN", [["CATEGORY", "CATEGORY_WORD"]]];
  const unicodeScope = [
    "SUBPATTERN",
    [null, 32, 0, [["MAX_REPEAT", [1, unlimited, [word]]]]],
  ];
  expect(scoped[1]!["nodes"]).toEqual([
    ["SUBPATTERN", [null, 256, 0, [unicodeScope]]],
  ]);
  expect(scoped[2]!["groupNames"]).toEqual([["__proto__", 1]]);
});

test("preserves character-set optimizations without merging separate repeat operands", async () => {
  const results = await patterns([
    "ab|ac|ad",
    "[^a]",
    "[a-a]",
    "(?:a+)|(?:a+)",
    "a|a",
  ]);
  expect(results.map((result) => result["nodes"])).toEqual([
    [
      ["LITERAL", 97],
      [
        "IN",
        [
          ["LITERAL", 98],
          ["LITERAL", 99],
          ["LITERAL", 100],
        ],
      ],
    ],
    [["NOT_LITERAL", 97]],
    [["IN", [["RANGE", [97, 97]]]]],
    [
      [
        "BRANCH",
        [
          null,
          [
            [["MAX_REPEAT", [1, unlimited, [["LITERAL", 97]]]]],
            [["MAX_REPEAT", [1, unlimited, [["LITERAL", 97]]]]],
          ],
        ],
      ],
    ],
    [
      ["LITERAL", 97],
      ["BRANCH", [null, [[], []]]],
    ],
  ]);
});

test("tracks atomic and possessive widths, including original repeat bounds and saturation", async () => {
  const results = await patterns([
    "a{100001}+(b|c)?",
    "(?>(a|ab))b",
    "(a?){2,4}+",
    "a{4294967294}",
    "((a{4294967294}){4294967294}){4294967294}",
    "(?:)*",
  ]);
  expect(results.map((result) => result["width"])).toEqual([
    ["100001", "100002"],
    ["2", "3"],
    ["0", "4"],
    ["4294967294", "4294967294"],
    [widthLimit, widthLimit],
    ["0", "0"],
  ]);
  expect(results[0]!["nodes"]).toEqual([
    ["POSSESSIVE_REPEAT", [100001, 100001, [["LITERAL", 97]]]],
    [
      "MAX_REPEAT",
      [
        0,
        1,
        [
          [
            "SUBPATTERN",
            [
              1,
              0,
              0,
              [
                [
                  "IN",
                  [
                    ["LITERAL", 98],
                    ["LITERAL", 99],
                  ],
                ],
              ],
            ],
          ],
        ],
      ],
    ],
  ]);
  expect(await patterns(["a{4294967295}"])).toEqual([
    { type: "OverflowError", message: "the repetition number is too large" },
  ]);
});

test("resolves Unicode 15 identifiers, canonical names, aliases and algorithmic names", async () => {
  const names = [
    "LF",
    "BOM",
    "latin small letter a",
    "HANGUL SYLLABLE GAG",
    "HANGUL SYLLABLE A",
    "CJK UNIFIED IDEOGRAPH-04E00",
    "CJK UNIFIED IDEOGRAPH-323AF",
  ];
  expect(
    (await patterns(names.map((name) => `\\N{${name}}`))).map(
      (result) => result["nodes"],
    ),
  ).toEqual(
    [10, 65279, 97, 44033, 50500, 19968, 205743].map((code) => [
      ["LITERAL", code],
    ]),
  );
  const groups = await patterns(["(?P<é>a)(?P=é)", "(?P<K>a)", "(?P<𰀀>a)"]);
  expect(groups.map((result) => result["groupNames"])).toEqual([
    [["é", 1]],
    [["K", 1]],
    [["𰀀", 1]],
  ]);
  const invalid = await patterns([
    "\\N{hangul syllable ga}",
    "\\N{CJK UNIFIED IDEOGRAPH-4e00}",
    "\\N{CJK UNIFIED IDEOGRAPH-FA0E}",
    "\\N{KEYCAP DIGIT ONE}",
    "(?P<́>a)",
  ]);
  expect(invalid.map((result) => result["type"])).toEqual(
    Array(5).fill("error"),
  );
});

test("keeps parser width analysis separate from fixed-width lookbehind validation", async () => {
  const pattern = "a(?<=a|ab)b";
  expect((await patterns([pattern]))[0]!["width"]).toEqual(["2", "2"]);
  expect(await run([{ pattern, validateLookbehind: true }])).toEqual([
    {
      type: "error",
      message: "look-behind requires fixed-width pattern",
      msg: "look-behind requires fixed-width pattern",
      pos: null,
      lineno: null,
      colno: null,
    },
  ]);
  expect(
    (
      await run([
        { pattern: "(?<=(?:a{4294967294}){2})", validateLookbehind: true },
      ])
    )[0]!["msg"],
  ).toBe("looks too much behind");
  const boundary = (
    await run([{ pattern: "(?<=\\B)(a)(?<=\\1)", validateLookbehind: true }])
  )[0]!;
  expect(boundary["width"]).toEqual(["1", "1"]);
  expect(boundary["nodes"]).toEqual([
    ["ASSERT", [-1, [["AT", "AT_NON_BOUNDARY"]]]],
    ["SUBPATTERN", [1, 0, 0, [["LITERAL", 97]]]],
    ["ASSERT", [-1, [["GROUPREF", 1]]]],
  ]);
});

test("reports Python error positions in code points and preserves syntax warning messages", async () => {
  const rows = [
    ["😀(", "missing ), unterminated subpattern at position 1", 1],
    [
      "a\n(",
      "missing ), unterminated subpattern at position 2 (line 2, column 1)",
      2,
    ],
    ["(a\\1)", "cannot refer to an open group at position 2", 2],
    ["(?(1)a)", "invalid group reference 1 at position 3", 3],
    ["a{2,1}", "min repeat greater than max repeat at position 2", 2],
    ["(?i-i:a)", "bad inline flags: flag turned on and off at position 5", 5],
    [
      "(?L:a)",
      "bad inline flags: cannot use 'L' flag with a str pattern at position 3",
      3,
    ],
    [
      "(?P<x>a)(?P<x>b)",
      "redefinition of group name 'x' as group 2; was group 1 at position 12",
      12,
    ],
    ["[\\d-z]", "bad character range \\d-z at position 1", 1],
  ] as const;
  const results = await patterns(rows.map(([pattern]) => pattern));
  expect(results.map(({ type, message, pos }) => [type, message, pos])).toEqual(
    rows.map(([, message, pos]) => ["error", message, pos]),
  );
  expect(
    (await patterns(["[[]", "[a&&b]"])).map((result) => result["warnings"]),
  ).toEqual([
    ["Possible nested set at position 1"],
    ["Possible set intersection at position 2"],
  ]);
});

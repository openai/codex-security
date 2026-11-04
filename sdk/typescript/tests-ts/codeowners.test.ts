import { expect, test } from "bun:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { codeownersForPath, parseCodeowners } from "../src/codeowners.js";

test.each([
  ["*.ts", "src/a.ts", true],
  ["/handler.ts", "src/handler.ts", false],
  ["/handler.ts", "handler.ts", true],
  ["apps/", "nested/apps/handler.ts", true],
  ["/apps/", "nested/apps/handler.ts", false],
  ["docs/*", "docs/start.md", true],
  ["docs/*", "docs/nested/start.md", false],
  ["/service*", "services/api.ts", true],
  ["/service*", "nested/services/api.ts", false],
  ["service*", "nested/services/api.ts", true],
  ["docs/service*", "docs/services/api.ts", true],
  ["/api?", "api1/main.ts", true],
  ["/api?", "api12/main.ts", false],
  ["**/logs", "deep/logs/file.txt", true],
  ["src/**/test?.ts", "src/test1.ts", true],
  ["src/**/test?.ts", "src/deep/test1.ts", true],
  ["src/**/test?.ts", "src/deep/test12.ts", false],
  ["src/**", "src/deep/file.ts", true],
  ["/a\\ b.ts", "a b.ts", true],
  ["/app/\\[id\\]/page.ts", "app/[id]/page.ts", true],
  ["/app/\\[id\\]/page.ts", "app/i/page.ts", false],
  ["/\\*\\*\\*/main.rb", "***/main.rb", true],
  ["*.ts", "src/A.TS", false],
  ["**/logs", "logs/file.txt", true],
  ["**/logs", "catalogs/file.txt", false],
  ["a/**/b/**/file?.ts", "a/b/file1.ts", true],
  ["a/**/b/**/file?.ts", "a/x/b/y/z/file1.ts", true],
  ["a/**/b/**/file?.ts", "a/x/b/y/z/file12.ts", false],
  ["/a*b?c", "axbyc/child.ts", true],
  ["/a*b?c", "a/xbyc/child.ts", false],
  ["/literal\\?.ts", "literal?.ts", true],
  ["/literal\\?.ts", "literal1.ts", false],
  ["/src/?.ts", "src/💡.ts", true],
  ["/src/💡*.ts", "src/💡-test.ts", true],
  ["docs/*/", "docs/chapter/start.md", true],
] as const)("matches %s against %s: %p", (pattern, path, matches) => {
  expect(
    codeownersForPath(parseCodeowners(`${pattern} @alex`), path) !== undefined,
  ).toBe(matches);
});

test("matches overlapping wildcards without backtracking", async () => {
  const module = new URL("../src/codeowners.ts", import.meta.url).href;
  // Run in a child so a regression cannot hang the test runner's event loop.
  // The deadline is a watchdog, not a microbenchmark assertion.
  const { stdout } = await promisify(execFile)(
    "node",
    [
      "--experimental-strip-types",
      "--input-type=module",
      "--eval",
      `
      import { parseCodeowners, codeownersForPath } from ${JSON.stringify(module)};
      const cases = [
        ["/" + "*a".repeat(24) + "b", "a".repeat(80)],
        ["/" + "**/".repeat(24) + "b", "a/".repeat(80)],
      ];
      console.log(JSON.stringify(cases.map(([pattern, path]) => {
        const rules = parseCodeowners(pattern + " @owner");
        return ["b", "c"].map(end => codeownersForPath(rules, path + end) !== undefined);
      })));
    `,
    ],
    { timeout: 10_000 },
  );
  expect(JSON.parse(stdout)).toEqual([
    [true, false],
    [true, false],
  ]);
});

test("uses the last matching rule and preserves all owners and ownerless overrides", () => {
  const rules = parseCodeowners(
    "* @default\n/apps/ @example/app-team @alex dev@example.test # review team\n/apps/generated/\n",
  );
  expect(codeownersForPath(rules, "apps/handler.ts")).toMatchObject({
    line: 2,
    owners: [
      { kind: "group", provider: "github", handle: "example/app-team" },
      { kind: "person", provider: "github", handle: "alex" },
      { kind: "person", email: "dev@example.test" },
    ],
  });
  expect(codeownersForPath(rules, "apps/generated/api.ts")?.owners).toEqual([]);
});

test.each([" ", "\t"])(
  "preserves escaped trailing whitespace %j in ownerless rules",
  (whitespace) => {
    const pattern = `/file\\${whitespace}`;
    const rule = `  ${pattern}`;
    const rules = parseCodeowners(`* @default\n${rule}\n`);
    expect(codeownersForPath(rules, `file${whitespace}`)).toMatchObject({
      pattern,
      line: 2,
      rule,
      owners: [],
    });
    for (const path of ["file", "file\\"]) {
      expect(codeownersForPath(rules, path)?.owners).toEqual([
        { kind: "person", provider: "github", handle: "default" },
      ]);
    }
  },
);

test("rejects Unicode case-fold aliases in GitHub handles under Node", async () => {
  const module = new URL("../src/codeowners.ts", import.meta.url).href;
  const { stdout } = await promisify(execFile)("node", [
    "--experimental-strip-types",
    "--input-type=module",
    "--eval",
    `
      import { parseCodeowners, codeownersForPath } from ${JSON.stringify(module)};
      const owners = [
        "@ſam", "@Kai", "@alſ", "@alK", "@org/ſquad", "@org/Kit",
        "@Sam", "@Kai", "@alex_corp", "@Org/Team_1.test-x", "é@example.test",
      ];
      console.log(JSON.stringify(owners.map(owner =>
        codeownersForPath(parseCodeowners("* @default\\n/é.ts " + owner), "é.ts")?.owners
      )));
    `,
  ]);
  expect(JSON.parse(stdout)).toEqual([
    ...Array.from({ length: 6 }, () => [
      { kind: "person", provider: "github", handle: "default" },
    ]),
    [{ kind: "person", provider: "github", handle: "Sam" }],
    [{ kind: "person", provider: "github", handle: "Kai" }],
    [{ kind: "person", provider: "github", handle: "alex_corp" }],
    [{ kind: "group", provider: "github", handle: "Org/Team_1.test-x" }],
    [{ kind: "person", email: "é@example.test" }],
  ]);
});

test.each(["@alex_corp", "@example/app-team @alex_corp"])(
  "preserves a rule containing the managed user: %s",
  (owners) => {
    const rules = parseCodeowners(`* @default\n/apps/ ${owners}\n`);
    expect(codeownersForPath(rules, "apps/handler.ts")).toMatchObject({
      line: 2,
      owners: expect.arrayContaining([
        { kind: "person", provider: "github", handle: "alex_corp" },
      ]),
    });
  },
);

test.each(["***/*.rb", "src/***/main.rb", "/app/[id]/page.ts"])(
  "skips invalid pattern %s without replacing the default owner",
  (pattern) => {
    expect(parseCodeowners(`* @default\n${pattern} @other\n`)).toMatchObject([
      { pattern: "*", owners: [{ handle: "default" }] },
    ]);
  },
);

test("skips unsupported and invalid rules without shadowing a valid owner", () => {
  const rules = parseCodeowners(
    "* @alex\n!*.ts @blair\n[ab].ts @blair\n\\#file @blair\n*.ts invalid-owner\n# comment\n",
  );
  expect(rules).toHaveLength(1);
  expect(codeownersForPath(rules, "a.ts")?.owners).toEqual([
    { kind: "person", provider: "github", handle: "alex" },
  ]);
});

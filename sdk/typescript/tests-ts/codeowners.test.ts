import { expect, test } from "bun:test";
import { codeownersForPath, parseCodeowners } from "../src/codeowners.js";

test.each([
  ["*.ts", "src/a.ts", true],
  ["/handler.ts", "src/handler.ts", false],
  ["/handler.ts", "handler.ts", true],
  ["apps/", "nested/apps/handler.ts", true],
  ["/apps/", "nested/apps/handler.ts", false],
  ["docs/*", "docs/start.md", true],
  ["docs/*", "docs/nested/start.md", false],
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
] as const)("matches %s against %s: %p", (pattern, path, matches) => {
  expect(
    codeownersForPath(parseCodeowners(`${pattern} @alex`), path) !== undefined,
  ).toBe(matches);
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

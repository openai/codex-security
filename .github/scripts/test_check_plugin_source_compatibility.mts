import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import {
  copyFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { fileURLToPath } from "node:url";

const checker = fileURLToPath(
  new URL("./check_plugin_source_compatibility.mts", import.meta.url),
);
const directories: string[] = [];
afterEach(() => {
  for (const root of directories.splice(0))
    rmSync(root, { recursive: true, force: true });
});

function git(root: string, ...args: string[]): void {
  const result = spawnSync("git", ["-C", root, ...args], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
}

function fixture(files: Record<string, string | Buffer> = {}): string {
  const root = mkdtempSync(join(tmpdir(), "plugin-source-check-"));
  directories.push(root);
  git(root, "init", "--quiet");
  for (const [name, content] of Object.entries(files))
    writeFileSync(join(root, name), content);
  if (Object.keys(files).length) git(root, "add", "--", ...Object.keys(files));
  return root;
}

function runChecker(...args: string[]): SpawnSyncReturns<string> {
  return spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      "--disable-warning=ExperimentalWarning",
      checker,
      ...args,
    ],
    { encoding: "utf8" },
  );
}

test("reports tracked source violations in stable order", () => {
  const root = fixture({
    "oversized.py": "x".repeat(150_001),
    "notes.md":
      "This prose continues in the middle of a sentence\nonto another source line.\n",
  });
  const result = runChecker("--plugin-root", root);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(
    result.stderr,
    [
      "notes.md:1: prose is hard-wrapped mid-sentence; use a natural Markdown line",
      "oversized.py: file is 150001 bytes; maximum is 150000 bytes\n",
    ].join("\n"),
  );
});

test("accepts valid source and ignores untracked files", () => {
  const root = fixture({
    "README.md": "A complete sentence.\n",
    "package-lock.json": "x".repeat(150_001),
  });
  writeFileSync(
    join(root, "untracked.md"),
    "This untracked prose continues\nonto another source line.\n",
  );
  const result = runChecker("--plugin-root", root);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "Plugin source compatibility checks passed.\n");
  assert.equal(result.stderr, "");
});

test("checkout preserves source size with autocrlf", () => {
  const root = fixture();
  copyFileSync(
    new URL("../../.gitattributes", import.meta.url),
    join(root, ".gitattributes"),
  );
  git(root, "config", "--local", "core.autocrlf", "true");
  for (const [name, line] of [
    ["module.py", "pass\n"],
    ["module.mts", "null\n"],
  ] as const) {
    const source = join(root, name);
    const content = Buffer.from(line.repeat(30_000));
    writeFileSync(source, content);
    git(root, "add", "--", ".gitattributes", name);
    unlinkSync(source);
    git(root, "checkout-index", "--", name);
    const result = runChecker("--plugin-root", root);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(readFileSync(source), content);
  }
});

test("accepts Markdown structures, natural line endings, and inline markup", () => {
  const root = fixture(
    Object.fromEntries(
      [
        "---\nThis prose continues\nonto another source line.\n",
        "First clause,\ncontinues here.\n",
        "First clause\n**continues** here.\n",
        "---\r\ntitle: Front matter\r\n---\r\nA complete sentence.\r\n",
        "```text\nWrapped code\ncontinues here\n```\n",
        "~~~text\nWrapped code\ncontinues here\n~~~\n",
        "Heading\n---\n# Another heading\n> A quote\n| A table |\n<!-- comment -->\n::directive\n<div>\n    code\n\tmore code\n",
        "A list\n- first\n1. second\n2) third\n",
        "Complete.\nQuestion?\nBang!\nColon:\nSemicolon;\n。\n！\n？\n：\n；\nParen)\nBracket]\nBrace}\nQuote'\nDouble\"\nCode`\nAngle>\nBackslash\\\nBreak  \nhttps://example.invalid/url\nlast\n",
      ].map((content, index) => [`example-${index}.md`, content]),
    ),
  );
  const result = runChecker("--plugin-root", root);
  assert.equal(result.status, 0, result.stderr);
});

test("rejects hard wraps after closed front matter and fences, including CRLF", () => {
  const root = fixture({
    "README.MD":
      "---\r\ntitle: Example\r\n---\r\n```\r\ncode\r\n```\r\nThis continues\r\non another line.\r\n",
  });
  const result = runChecker("--plugin-root", root);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /README\.MD:7: prose is hard-wrapped/u);
});

test("rejects dependency lock files above two megabytes", () => {
  const root = fixture({ "pnpm-lock.yaml": "x".repeat(2_000_001) });
  const result = runChecker("--plugin-root", root);
  assert.equal(result.status, 1);
  assert.equal(
    result.stderr,
    "pnpm-lock.yaml: file is 2000001 bytes; maximum is 2000000 bytes\n",
  );
});

test(
  "does not follow tracked symlinks outside the plugin",
  { skip: process.platform === "win32" },
  () => {
    const outside = fixture({
      "outside.md": "This outside prose continues\nonto another source line.\n",
    });
    const root = fixture();
    symlinkSync(join(outside, "outside.md"), join(root, "linked.md"));
    git(root, "add", "--", "linked.md");
    const result = runChecker("--plugin-root", root);
    assert.equal(result.status, 0, result.stderr);
  },
);

test("reports Git, missing tracked files, and invalid UTF-8 as check failures", () => {
  const root = fixture({ "README.md": Buffer.from([0xff]) });
  for (const action of [
    () => {},
    () => unlinkSync(join(root, "README.md")),
    () => rmSync(join(root, ".git"), { recursive: true }),
  ]) {
    action();
    const result = runChecker("--plugin-root", root);
    assert.equal(result.status, 2);
    assert.match(result.stderr, /^source compatibility check failed:/u);
  }
});

test("help describes the source contract and invalid arguments fail", () => {
  const result = runChecker("--help");
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /tracked plugin source/u);
  assert.equal(runChecker("--plugin-root").status, 2);
  assert.equal(runChecker("--unknown").status, 2);
});

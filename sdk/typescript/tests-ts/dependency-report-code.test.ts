import { expect, test } from "bun:test";
import { renderDependencyCode } from "../src/dependency-report-code.js";

test("keeps numbered, highlighted rows and escapes exact source text", () => {
  const html = renderDependencyCode(
    '\tconst item = "<img src=x onerror=alert(1)> & data";\r\n\nreturn item;\n',
    "src/worker.ts",
    17,
    new Set([19]),
  );

  expect(html).not.toContain("<img");
  expect(html).toContain("&lt;img src=x onerror=alert(1)&gt; &amp; data");
  const rows: Array<[string | null, boolean]> = [];
  const numbers: string[] = [];
  const lines: string[] = [];
  new HTMLRewriter()
    .on(".code-row", {
      element(node) {
        rows.push([
          node.getAttribute("data-line"),
          node.hasAttribute("data-highlighted"),
        ]);
      },
    })
    .on(".code-number", {
      element() {
        numbers.push("");
      },
      text(node) {
        numbers[numbers.length - 1] += node.text;
      },
    })
    .on(".code-text", {
      element() {
        lines.push("");
      },
      text(node) {
        lines[lines.length - 1] += node.text;
      },
    })
    .transform(html);

  expect(rows).toEqual([
    ["17", false],
    ["18", false],
    ["19", true],
    ["20", false],
  ]);
  expect(numbers).toEqual(["17", "18", "19", "20"]);
  expect(lines).toEqual([
    "\tconst item = &quot;&lt;img src=x onerror=alert(1)&gt; &amp; data&quot;;&#13;",
    "",
    "return item;",
    "",
  ]);
});

test.each([
  ["worker.TSX", "const worker = true;", "keyword", "const"],
  ["worker.py", "def worker():", "keyword", "def"],
  ["worker.go", "func worker() {}", "keyword", "func"],
  ["worker.rs", "fn worker() {}", "keyword", "fn"],
  ["worker.cpp", "return 12;", "keyword", "return"],
  ["settings.json", '{"enabled": true}', "literal", "true"],
  ["settings.yaml", "enabled: true", "property", "enabled"],
  [".bashrc", "if test -n x; then", "keyword", "if"],
])("highlights obvious tokens in %s", (path, code, kind, token) => {
  expect(renderDependencyCode(code, path, 1)).toContain(
    `<span class="tok-${kind}">${token}</span>`,
  );
});

test("does not highlight keywords inside multiline comments or strings", () => {
  const html = renderDependencyCode(
    '/* const\nreturn */\nconst s = "if // text";',
    "worker.js",
    1,
  );

  expect(html).toContain('<span class="tok-comment">/* const</span>');
  expect(html).toContain('<span class="tok-comment">return */</span>');
  expect(html).toContain(
    '<span class="tok-string">&quot;if // text&quot;</span>',
  );
  expect(html.match(/class="tok-keyword"/gu)).toHaveLength(1);
});

test("uses escaped plain text for unrecognized file types", () => {
  const html = renderDependencyCode("const a < b & c", "notes.txt", 3);

  expect(html).toContain(
    '<span class="code-text">const a &lt; b &amp; c</span>',
  );
  expect(html).not.toContain("tok-");
});

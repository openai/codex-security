import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";
import type { ThreatModelRenderInput as Input } from "../src/threat-model-render.js";

const pluginRoot = join(import.meta.dirname, "../..");
const { renderThreatModel } = await importSource(
  join(pluginRoot, "mcp-app/src/threat-model-render.ts"),
);
const python = process.env.PYTHON?.trim() || "python3";
function pythonRender(input: Input): string {
  return execFileSync(
    python,
    [
      "-B",
      "-I",
      "-X",
      "utf8",
      join(pluginRoot, "scripts/threat_model_projection.py"),
      "--input-json-stdin",
    ],
    { input: JSON.stringify(input), encoding: "utf8", stdio: "pipe" },
  );
}

function equivalent(
  name: string,
  threatModel: unknown,
  provenance?: Input["provenance"],
) {
  test(`threat model rendering matches Python: ${name}`, () => {
    const input = { threatModel, provenance };
    assert.equal(renderThreatModel(input), pythonRender(input));
  });
}
const markdownModel = { format: "markdown", content: "# Full model\n" };
equivalent("all structured sections and multiline bodies", {
  summary: "A **model**.\n\n```text\nA -> B\n```",
  assets: ["Queue\n  ownership", "Stored records"],
  trustBoundaries: ["API -> queue"],
  attackerCapabilities: ["Send requests"],
  securityObjectives: ["Keep [records] private"],
  assumptions: ["Authenticated callers"],
});
equivalent("whitespace-only structured strings", {
  summary: " \n\t",
  assets: [" \n\t"],
});
equivalent("blank Markdown falls back to the summary", {
  ...markdownModel,
  summary: "Saved summary",
  content: " \n",
});
equivalent("structured metadata bypasses Markdown validation", {
  ...markdownModel,
  summary: " ",
  assets: [" "],
  origin: false,
  scope: { includePaths: ["", "src"], excludePaths: 42, summary: [] },
});
equivalent("Markdown accepts non-structured extensions", {
  ...markdownModel,
  summary: 42,
  assets: false,
});
equivalent(
  "scope formatting and footer truthiness",
  {
    summary: "Model",
    origin: false,
    scope: { includePaths: [], excludePaths: [""], summary: " " },
  },
  {
    source: "",
    scanId: "example-scan",
    target: "",
    revision: "",
    snapshotDigest: "",
    status: " ",
    provisional: false,
  },
);
equivalent(
  "footer escaping preserves inline code",
  {
    ...markdownModel,
    content: "# Authored [model]\n\nKeep **this**.",
    origin: "provided",
    scope: {
      includePaths: ["src/[queue]", "a\\b"],
      excludePaths: ["tmp/*"],
      summary: "## Scope\n`[literal]` <tag>",
    },
  },
  {
    source: "- source",
    scanId: "1. scan",
    target: "> workspace",
    revision: "``revision``",
    snapshotDigest: "| digest",
    status: "```status",
    provisional: true,
    scanScope: {
      includePaths: ["."],
      excludePaths: ["vendor"],
      summary: "Source\tboundary",
    },
  },
);
equivalent(
  "footer entities remain literal in prose and scope paths",
  {
    ...markdownModel,
    origin: "provided",
    scope: {
      includePaths: [
        "docs/&lt;tag&gt;.md",
        "docs/www.example.com/&lt;tag&gt;.md",
        "docs/`&lt;tag&gt;`.md",
        "docs/a,&lt;tag&gt;.md",
        "dir&lt;tag&gt;.example/file.md",
        "dir.example/file&lt;tag&gt;.md",
        "www.example.com/file&amp;.md",
        "`&amp;`",
        "`&amp;.md",
        "file&amp;`",
      ],
      excludePaths: ["tmp/&amp;.md"],
      summary:
        "R&D decodes &#x3C;tag&#x3E; and &amp;lt;. Keep `&amp;` literal.",
    },
  },
  { target: "R&D &lt;workspace&gt;" },
);
for (const url of [
  "https://example.com/?first=1&second=2",
  "http://example.com/?payload=&#x3C;tag&#x3E;&mode=1",
  "ftp://example.com/?first=1&second=2",
  "www.example.com/?payload=&lt;tag&gt;&mode=1",
  "WWW.example.com/?first=1&second=2",
  "WwW.example.com/?first=1&second=2",
  "https://example.com/`a`?first=1&second=2",
  "example.com/?first=1&second=2",
  "//example.com/?first=1&second=2",
  '"example.com/?first=1&second=2"',
  "[example.com/?first=1&second=2]",
  "éxample.com/?first=1&second=2",
  "例子.com/?first=1&second=2",
  "example.com/?payload=&lt;tag&gt;&mode=1",
  "example.com/?first=1&word;=2",
  "//example.com/?first=1&word;=2",
  "user&tag@example.com",
  "mailto:user&tag@example.com",
  "//localhost:8080/?first=1&word;=2",
  "{//example.com/?first=1&word;=2}",
  "?example.com/?first=1&word;=2",
  "mailto:user&tag@localhost",
]) {
  equivalent(`footer URL ampersands ${url}`, markdownModel, {
    target: `${url} then &amp; and \`https://example.com/?a=1&b=2 &amp;\`.`,
  });
}
for (const [paths, expected] of [
  [
    [
      ".",
      "src/",
      "path with space",
      "src/[queue]",
      "tmp/*",
      "Résumé.md",
      "😀.md",
    ],
    String.raw`., src/, path with space, src/\[queue\], tmp/\*, Résumé.md, 😀.md`,
  ],
  [
    ["a,b.ts", "a, b.ts", "a  b", "a b", " ", "  "],
    '`"a,b.ts"`, `"a, b.ts"`, `"a  b"`, a b, `" "`, `"  "`',
  ],
  [
    [" a`b ", "a``b,c", "`literal`"],
    '``" a`b "``, ```"a``b,c"```, \\`literal\\`',
  ],
  [
    [
      "docs/Résumé, final.md",
      "a\u202eb, c.md",
      "a\u00a0b",
      "😀, c.md",
      "\u{1fae9},notes.md",
    ],
    '`"docs/R\\u00e9sum\\u00e9, final.md"`, `"a\\u202eb, c.md"`, `"a\\u00a0b"`, `"\\ud83d\\ude00, c.md"`, `"\\ud83e\\udee9,notes.md"`',
  ],
  [
    ["a\u001bb", "a\u007fb, c.md", "a\nb", "a\tb"],
    '`"a\\u001bb"`, `"a\\u007fb, c.md"`, `"a\\nb"`, `"a\\tb"`',
  ],
] satisfies [string[], string][]) {
  test(`literal scope paths match Python: ${JSON.stringify(paths)}`, () => {
    const scope = { includePaths: paths, excludePaths: paths };
    const input = {
      threatModel: { ...markdownModel, scope },
      provenance: { scanScope: scope },
    };
    const rendered = renderThreatModel(input);
    assert.equal(rendered, pythonRender(input));
    for (const label of ["Model scope", "Scan scope"]) {
      assert.ok(rendered.includes(`- ${label}: ${expected}\n`));
      assert.ok(rendered.includes(`- ${label} exclusions: ${expected}\n`));
    }
  });
}
for (const ending of ["", "\n", "\n\n", "\r\n"]) {
  equivalent(`authored Markdown ending ${JSON.stringify(ending)}`, {
    ...markdownModel,
    content: "# Model\n\n```text\nexact  spacing\n```" + ending,
  });
}
for (const value of ["\ufeff", "\u0085", "\u001c", "\u00a0"]) {
  equivalent(
    `Python whitespace ${JSON.stringify(value)}`,
    { summary: value, assets: [value] },
    { target: `a${value}b` },
  );
}
equivalent("a BOM is authored Markdown", {
  ...markdownModel,
  content: "\ufeff",
});

const invalidCases: [unknown, string][] = [
  [{}, "summary"],
  [{ summary: "" }, "summary"],
  [{ summary: "Model", assets: false }, "assets"],
  [{ summary: "Model", assets: [""] }, "assets"],
  [{ ...markdownModel, content: "\u0085" }, "content"],
  [{ ...markdownModel, origin: false }, "origin"],
  [{ ...markdownModel, scope: [] }, "scope"],
  [{ ...markdownModel, scope: {} }, "scope"],
  [{ ...markdownModel, scope: { includePaths: [""] } }, "scope.includePaths"],
  [
    {
      ...markdownModel,
      scope: { includePaths: [], excludePaths: false },
    },
    "scope.excludePaths",
  ],
  [
    {
      ...markdownModel,
      scope: { includePaths: [], summary: "" },
    },
    "scope.summary",
  ],
];
for (const [threatModel, field] of invalidCases) {
  test(`invalid model identifies ${field}: ${JSON.stringify(threatModel)}`, () => {
    const diagnostic = `threatModel.${field}`;
    assert.throws(
      () => pythonRender({ threatModel }),
      (error: unknown) =>
        String((error as { stderr: unknown }).stderr).includes(diagnostic),
    );
    assert.throws(
      () => renderThreatModel({ threatModel }),
      (error: unknown) =>
        error instanceof Error && error.message.includes(diagnostic),
    );
  });
}
test("non-object models report a threatModel diagnostic", () => {
  for (const threatModel of [null, [], false, "model"]) {
    assert.throws(() => renderThreatModel({ threatModel }), /threatModel/);
  }
});

test("Python finalizer recognizes native renderer bytes as the current projection", () => {
  const scope = {
    includePaths: [
      "src",
      "a,b.ts",
      "a  b",
      "\u{1fae9},notes.md",
      "docs/&lt;tag&gt;.md",
      "docs/a,&lt;tag&gt;.md",
      "dir&lt;tag&gt;.example/file.md",
      "dir.example/file&lt;tag&gt;.md",
      "www.example.com/file&amp;.md",
      "`&amp;`",
    ],
    excludePaths: [" "],
  };
  const threatModel = { summary: "Saved model", assets: ["Queue"], scope };
  const scan = {
    id: "example-scan",
    status: "running",
    threatModel,
    target: {
      displayName: "R&D &lt;workspace&gt;",
      revision: "example-revision",
    },
    scope,
  };
  const markdown = renderThreatModel({
    threatModel,
    provenance: {
      source: "scan",
      scanId: scan.id,
      target: scan.target.displayName,
      revision: scan.target.revision,
      status: scan.status,
      provisional: true,
      scanScope: scan.scope,
    },
  });
  const result = execFileSync(
    python,
    [
      "-B",
      "-I",
      "-X",
      "utf8",
      "-c",
      `
import json, pathlib, sys, tempfile
sys.path.insert(0, sys.argv[1])
import finalize_scan_contract as finalizer
payload = json.load(sys.stdin)
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory).resolve()
    (root / "scan-manifest.json").write_text(json.dumps({"scan": payload["scan"]}))
    (root / "threatmodel.md").write_bytes(payload["markdown"].encode("utf-8"))
    print(finalizer.describe_threat_model(root)["path"] == str(root / "threatmodel.md"))
`,
      join(pluginRoot, "scripts"),
    ],
    {
      input: JSON.stringify({ scan, markdown }),
      encoding: "utf8",
      stdio: "pipe",
    },
  );
  assert.equal(result.trim(), "True");
});

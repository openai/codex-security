import { expect, test } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  discoverDependencyRepository,
  sourceReferences,
} from "../src/dependency-discovery.js";
import { gitText } from "./support/shell.js";
import {
  temporaryDirectory,
  removeTemporaryDirectory,
} from "./support/temporary-directories.js";

const pkg = { ecosystem: "npm", name: "sample-codec" };

function commitFixture(repo: string) {
  const git = (...args: string[]) => gitText(args, { cwd: repo }).trim();
  git("init", "--quiet");
  git("add", ".");
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "-qm",
    "Fixture",
  );
  return git;
}

test("caller ownership and installed versions come from the same committed workspace", async () => {
  const repo = await temporaryDirectory("dependency-workspace-");
  try {
    const entries: Record<string, unknown> = { "": { workspaces: ["apps/*"] } };
    for (const [service, version] of [
      ["alpha", "1.0.0"],
      ["beta", "2.0.0"],
      ["inconsistent", "1.0.0"],
      ["unlocked", "3.0.0"],
    ] as const) {
      const dir = "apps/" + service;
      const manifest = {
        name: service,
        dependencies: { [pkg.name]: "^" + version },
      };
      await mkdir(join(repo, dir), { recursive: true });
      await writeFile(
        join(repo, dir, "package.json"),
        JSON.stringify(manifest),
      );
      await writeFile(
        join(repo, dir, "main.js"),
        "// entry point\nimport codec\nfrom 'sample-codec';\ncodec.decode('file');\n",
      );
      if (service !== "unlocked") {
        entries[dir] = manifest;
        entries[
          service === "alpha"
            ? "node_modules/sample-codec"
            : dir + "/node_modules/sample-codec"
        ] = { version: service === "inconsistent" ? "7.0.0" : version };
      }
    }
    await writeFile(
      join(repo, "package.json"),
      JSON.stringify({ private: true, workspaces: ["apps/*"] }),
    );
    await writeFile(
      join(repo, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages: entries }, null, 2),
    );
    await writeFile(join(repo, "Dockerfile"), "FROM node:22\n");
    await writeFile(
      join(repo, "apps/alpha/ambient.d.ts"),
      "import { Codec } from 'sample-codec';",
    );
    await writeFile(
      join(repo, "apps/alpha/types.ts"),
      [
        "// import { decode } from 'sample-codec';",
        "const example = \"import codec from 'sample-codec'\";",
        "import type { CodecOptions } from 'sample-codec';",
        "export type { CodecOptions } from 'sample-codec';",
      ].join("\n"),
    );
    const git = commitFixture(repo);
    const revision = git("rev-parse", "HEAD");
    await writeFile(
      join(repo, "apps/alpha/main.js"),
      "// dirty working copy\n",
    );
    await writeFile(join(repo, "package-lock.json"), "{}\n");
    // The database may have a local replacement object for the same tracked file.
    git(
      "replace",
      git("rev-parse", "HEAD:package-lock.json"),
      git("hash-object", "-w", "package-lock.json"),
    );
    const result = await discoverDependencyRepository({
      repository: repo,
      package: pkg,
      environment: { PATH: "" },
    });
    expect(result.revision).toBe(revision);
    expect(result.sourceLeads).toEqual([
      "apps/alpha/ambient.d.ts",
      "apps/alpha/types.ts",
    ]);
    expect(
      result.callers.map(({ path, line, version }) => [path, line, version]),
    ).toEqual([
      ["apps/alpha/main.js", 2, "1.0.0"],
      ["apps/beta/main.js", 2, "2.0.0"],
      ["apps/inconsistent/main.js", 2, undefined],
      ["apps/unlocked/main.js", 2, undefined],
    ]);
    expect(result.manifests.map((m) => m.selection?.packagePath)).toEqual([
      "node_modules/sample-codec",
      "apps/beta/node_modules/sample-codec",
      undefined,
      undefined,
    ]);
    const lockLines = git(
      "--no-replace-objects",
      "show",
      "HEAD:package-lock.json",
    ).split("\n");
    for (const m of result.manifests.filter((m) => m.selection)) {
      const selection = m.selection!;
      expect(lockLines[selection.line - 1]).toContain(
        '"version": "' + selection.version + '"',
      );
    }
    expect(result.buildFiles).toEqual(["Dockerfile"]);
    expect(result.runtime).toEqual([]);
    expect(result.coverage.status).toBe("partial");
    expect(result.coverage.gaps.join("\n")).toMatch(/OpenGrep is unavailable/);
    expect(result.coverage.gaps.join("\n")).toMatch(/unlocked/);
    expect(result.coverage.gaps).toContain(
      "No runtime observations were supplied.",
    );
  } finally {
    await removeTemporaryDirectory(repo);
  }
});

test("Python pins and module aliases require scoped source evidence", async () => {
  const repo = await temporaryDirectory("python-package-");
  try {
    for (const [project, requirement] of [
      ["worker", "sample_image==2.3.4"],
      ["preview", 'sample-image==2.5.0; python_version < "3.12"'],
    ] as const) {
      await mkdir(join(repo, project));
      await writeFile(
        join(repo, project, "requirements.txt"),
        requirement + "\n",
      );
      await writeFile(
        join(repo, project, "main.py"),
        "from decoder import (\n    load,\n)\nload('sample')\n",
      );
    }
    commitFixture(repo);
    const args = {
      repository: repo,
      package: { ecosystem: "PyPI", name: "sample-image" },
      environment: { PATH: "" },
    };
    const evidence = await discoverDependencyRepository({
      ...args,
      symbols: ["decoder.load"],
    });
    expect(
      evidence.callers.map(({ path, version }) => [path, version]),
    ).toEqual([
      ["preview/main.py", undefined],
      ["worker/main.py", "2.3.4"],
    ]);
    expect(evidence.manifests[1]!.selection).toEqual({
      kind: "requirements-pin",
      version: "2.3.4",
      lockfile: "worker/requirements.txt",
      packagePath: "sample-image",
      line: 1,
    });
    const withoutAlias = await discoverDependencyRepository(args);
    expect(withoutAlias.callers).toEqual([]);
    expect(withoutAlias.coverage.gaps.join("\n")).toContain(
      "No direct importing caller",
    );
  } finally {
    await removeTemporaryDirectory(repo);
  }
});

test("reports a nested build-only package in the active caller boundary", async () => {
  const repo = await temporaryDirectory("dependency-docker-build-");
  try {
    for (const directory of [
      "services/renderer",
      "tests/fixtures",
      "tests/owned",
    ]) {
      await mkdir(join(repo, directory), { recursive: true });
      await writeFile(
        join(repo, directory, "Dockerfile"),
        "FROM scratch\nRUN apt-get install -y libwebp7\n",
      );
    }
    await writeFile(
      join(repo, "tests/owned/SECURITY.md"),
      "This renderer is deployed.\n",
    );
    commitFixture(repo);
    const result = await discoverDependencyRepository({
      repository: repo,
      package: { ecosystem: "Debian", name: "libwebp7" },
      callerBoundary: { productionOnly: true, excludePaths: [] },
    });
    expect(result.coverage.status).toBe("unknown");
    expect(result.buildFiles.sort()).toEqual([
      "services/renderer/Dockerfile",
      "tests/owned/Dockerfile",
    ]);
  } finally {
    await removeTemporaryDirectory(repo);
  }
});

test("extracts JavaScript, TypeScript, and Python import bindings across multi-line and aliased forms", () => {
  const tsRefs = sourceReferences(
    "src/service.ts",
    [
      "const fence = /`/g;",
      "import type DefaultType from 'sample-codec';",
      "import type * as NamespaceType from 'sample-codec';",
      "import { type Options, type Output as Out } from 'sample-codec';",
      "import codec, {",
      "  // active decoder",
      "  type InlineType,",
      "  decode,",
      "  encode as encodeSample,",
      "} from 'sample-codec';",
      "import type from 'sample-codec/type-value';",
      "import { type as runtimeType } from 'sample-codec/type-value';",
      "const {",
      "  parse,",
      "  format: formatSample = fallback,",
      "  ...restCodec",
      "} = require(",
      "  'sample-codec'",
      ");",
      "const load = require('sample-codec').load;",
      "const result = require('sample-codec').decode(payload);",
      "const ratio = stats.return / 2; const inlineSub = require('sample-codec/sub');",
      "const fs = require('node:fs'),",
      "  chained = require('sample-codec');",
      "export * from 'sample-codec/reexport';",
    ].join("\n"),
    pkg,
    [],
  );
  expect(tsRefs.lines).toEqual([5, 11, 12, 13, 20, 21, 22, 24, 25]);
  expect(tsRefs.bindings).toEqual([
    "codec",
    "decode",
    "encodeSample",
    "type",
    "runtimeType",
    "parse",
    "formatSample",
    "restCodec",
    "load",
    "inlineSub",
    "chained",
  ]);

  const pyRefs = sourceReferences(
    "src/service.py",
    [
      "from sample_image import (",
      "    # primary entrypoints",
      "    load,",
      "    open as open_image,",
      ")",
      "from sample_image.ops import resize, crop as crop_image",
      "from sample_image \\",
      "    import stream",
      "import sample_image.codec as codec",
      "import os, sample_image as img",
    ].join("\n"),
    { ecosystem: "PyPI", name: "sample-image" },
    [],
  );
  expect(pyRefs.lines).toEqual([1, 6, 7, 9, 10]);
  expect(pyRefs.bindings).toEqual([
    "load",
    "open_image",
    "resize",
    "crop_image",
    "stream",
    "codec",
    "img",
  ]);
});

test("preserves minified imports, template expressions, and escaped newlines", () => {
  const text = [
    'const line = "first\\',
    'second"',
    'import{decode}from"sample-codec"',
    'const codec = require("sample-codec")',
    'const result = `raw require("sample-codec") ${require("sample-codec")}`',
    'const data = await import("sample-codec/data.json", { with: { type: "json" } })',
    'const promise = import("sample-codec")',
    'type Options = import("sample-codec").Options',
    'const { type : alias } = require("sample-codec")',
    'const { type = fallback } = await import("sample-codec")',
  ].join("\r\n");
  expect(sourceReferences("test.ts", text, pkg, [])).toEqual({
    lines: [3, 4, 5, 6, 7, 9, 10],
    bindings: ["decode", "codec", "data", "alias", "type"],
  });
});

test("keeps the runtime branch after a Python typing guard and skips unfinished docstrings", () => {
  const text = [
    "from typing import TYPE_CHECKING",
    "if TYPE_CHECKING:",
    "    from sample_image import Type",
    "else:",
    "    from sample_image import(load)",
    '"""' + "\\".repeat(64),
    "import sample_image",
  ].join("\n");
  expect(
    sourceReferences(
      "test.py",
      text,
      { ecosystem: "PyPI", name: "sample-image" },
      [],
    ),
  ).toEqual({
    lines: [5],
    bindings: ["load"],
  });
});

test("a truncated literal ends at the newline without exposing its contents", () => {
  const prefix = "'" + "\\'".repeat(512) + "; ";
  for (const [path, ecosystem, statement] of [
    ["x.py", "PyPI", "import codec"],
    ["x.js", "npm", 'import "codec"'],
  ] as const) {
    const text = prefix + statement + "\n" + statement;
    expect(
      sourceReferences(path, text, { ecosystem, name: "codec" }, []).lines,
    ).toEqual([2]);
  }
});

test("ignores member calls and regex literals while preserving later runtime imports", () => {
  const text = [
    'obj. /* method */ require("sample-codec")',
    'obj?.\nimport("sample-codec")',
    'const re = /[/]require("sample-codec")/g;',
    'const ratio = 1 / /require("sample-codec")/.test(input);',
    "const broken = " + "/[".repeat(512) + 'require("sample-codec")',
    'const copy = {...require("sample-codec")};',
    'const value = require("sample-codec");',
    "const other = /[" + "\\\\/[".repeat(512) + 'require("sample-codec")]',
  ].join("\n");
  expect(sourceReferences("service.js", text, pkg, [])).toEqual({
    lines: [7, 8],
    bindings: ["value"],
  });
});

test("distinguishes regex statement bodies from division after a call", () => {
  const text = [
    'if (ok) /require("sample-codec")/.test(input);',
    'while (check(`flag:${flag}`)) /import("sample-codec")/.test(input);',
    'obj.if(ok) / require("sample-codec");',
    'if (check(ok) / require("sample-codec")) proceed();',
    'else /require("sample-codec")/.test(input);',
    'do /import("sample-codec")/.test(input); while (false);',
    'for await (const item of items) /require("sample-codec")/.test(item);',
  ].join("\n");
  expect(sourceReferences("service.js", text, pkg, []).lines).toEqual([3, 4]);
});

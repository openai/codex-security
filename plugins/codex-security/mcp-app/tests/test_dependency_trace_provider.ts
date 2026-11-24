import {
  available,
  nativeRules,
  sourceEvidence,
  sourceStep,
} from "./support/native-trace-rules.ts";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  findProjectReferences,
  localProvider,
} from "../src/dependency-trace/provider.ts";
import { traceResponse } from "../src/dependency-trace/response.ts";
import { createDependencyTracer } from "../src/dependency-trace/trace.ts";
import type { TraceScope } from "../src/dependency-trace/types.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const signal = new AbortController().signal;
const file: TraceScope = {
  kind: "file",
  package: "image_lib",
  symbol: "decode",
  rules: nativeRules("decode"),
  path: "example.py",
};
const search: TraceScope = { ...file, kind: "search", path: "." };

test("project references cite launch and CI records without assigning ownership", async (t) => {
  if (!(await available("rg"))) return t.skip("rg required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("project-references-");
  await mkdir(join(root, "modules", "render"), { recursive: true });
  await mkdir(join(root, "runtime"));
  await mkdir(join(root, ".github", "workflows"), { recursive: true });
  await writeFile(join(root, "modules/render/Dockerfile"), "FROM scratch\n");
  await writeFile(
    join(root, "runtime", "launch.yaml"),
    [
      "services:",
      "  gallery:",
      "    build: ../modules/render/Dockerfile",
      "  successor:",
      "    build: ../modules/render-next/Dockerfile",
    ].join("\n"),
  );
  await writeFile(
    join(root, ".github", "workflows", "test.yaml"),
    "run: test -d modules/render\n",
  );
  assert.deepEqual(
    await findProjectReferences(root, "modules/render/Dockerfile"),
    {
      references: [{ path: "runtime/launch.yaml", line: 3 }],
      complete: true,
    },
  );
  const result = await findProjectReferences(root, "modules/render");
  assert.equal(result.complete, true, result.reason ?? "incomplete search");
  assert.deepEqual(
    result.references.sort((a, b) => a.path.localeCompare(b.path)),
    [
      { path: ".github/workflows/test.yaml", line: 1 },
      { path: "runtime/launch.yaml", line: 3 },
    ],
  );
  await writeFile(
    join(root, "runtime", "launch.yaml"),
    ("# modules/render " + "x".repeat(512) + "\n").repeat(700),
  );
  const all = await findProjectReferences(root, "modules/render");
  assert.equal(all.complete, true, all.reason ?? "incomplete references");
  assert.equal(all.references.length, 701);
  const launchReferences = all.references.filter(
    ({ path }) => path === "runtime/launch.yaml",
  );
  assert.equal(launchReferences.length, 700);
  assert.equal(launchReferences.at(-1)?.line, 700);
  await assert.rejects(
    findProjectReferences(root, "modules/render", AbortSignal.abort()),
  );
});

test("trace scopes stay inside the checkout and avoid large files", async (t) => {
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-provider-");
  const external = await dirs.create("outside-trace-");
  await writeFile(join(root, "example.py"), Buffer.alloc(1024 * 1024 + 1));
  const provider = localProvider(root);
  assert.match((await provider.run(file, signal)).reason ?? "", /exceeds/);
  assert.equal(
    (await provider.run({ ...search, path: external }, signal)).complete,
    false,
  );
  await symlink(
    external,
    join(root, "linked"),
    process.platform === "win32" ? "junction" : "dir",
  );
  assert.match(
    (await provider.run({ ...search, path: "linked" }, signal)).reason ?? "",
    /symlink/,
  );
  await assert.rejects(provider.run(file, AbortSignal.abort()));
});

test("literal discovery recurses in scope and observes dirty and added files", async (t) => {
  if (!(await available("rg"))) return t.skip("rg required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-discovery-");
  const provider = localProvider(root);
  await mkdir(join(root, "sub", "deep"), { recursive: true });
  await writeFile(join(root, "excluded"), "image_lib\n");
  await writeFile(join(root, "sub", "deep", "uses.ts"), "use image_lib\n");
  const scope: TraceScope = {
    kind: "search",
    package: "image_lib",
    path: "sub",
  };
  assert.equal(await provider.fingerprint!(scope, signal), undefined);
  const result = await provider.run(scope, signal);
  assert.equal(result.complete, true, result.reason ?? "incomplete scope");
  assert.deepEqual(result.next, []);
  assert.deepEqual(result.textMatches, [
    { source: "sub/deep/uses.ts", text: "image_lib" },
  ]);
  await writeFile(join(root, "sub", "BUILD.bazel"), 'deps = ["image_lib"]');
  const manifests = await provider.run(
    { ...scope, kind: "manifests", symbol: "decode" },
    signal,
  );
  assert.deepEqual(manifests.next, []);
  assert.deepEqual(manifests.textMatches, [
    { source: "sub/BUILD.bazel", text: "image_lib" },
  ]);
  // A subsequent lookup sees the current worktree, including untracked files.
  await writeFile(join(root, "sub", "BUILD.bazel"), "");
  await writeFile(join(root, "sub", "deep", "uses.ts"), "different\n");
  await writeFile(join(root, "sub", "new.ts"), "image_lib\n");
  assert.deepEqual((await provider.run(scope, signal)).textMatches, [
    { source: "sub/new.ts", text: "image_lib" },
  ]);
});

test("manifest fingerprints and declarations need no external tool", async (t) => {
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-manifest-");
  const provider = localProvider(root);
  const originalPath = process.env.PATH;
  process.env.PATH = "";
  t.after(() => {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  });
  const manifest = { ...file, path: "package.json", symbol: undefined };
  await writeFile(
    join(root, manifest.path),
    '{"dependencies":{"image_lib":"1.0.0"}}',
  );
  const fingerprint = await provider.fingerprint!(manifest, signal);
  assert.ok(fingerprint);
  const result = await provider.run(manifest, signal);
  assert.equal(result.complete, true);
  assert.equal(result.fingerprint, fingerprint);
  assert.deepEqual(
    result.evidence.map(({ step }) => step.relation),
    ["depends_on"],
  );
  assert.equal(result.textMatches, undefined);
  await writeFile(join(root, manifest.path), '{"description":"image_lib"}');
  const edited = await provider.run(manifest, signal);
  assert.equal(edited.complete, true);
  assert.notEqual(edited.fingerprint, fingerprint);
  assert.deepEqual(edited.evidence, []);
  for (const [path, symbol] of [
    ["README.md", "decode"],
    ["example.py", undefined],
  ] as const) {
    await writeFile(join(root, path), "image_lib\n");
    const scope = { ...file, path, symbol, rules: undefined };
    assert.equal(await provider.fingerprint!(scope, signal), undefined);
    const skipped = await provider.run(scope, signal);
    assert.deepEqual(skipped.evidence, []);
    assert.equal(skipped.textMatches, undefined);
    assert.match(
      skipped.reason ?? "",
      path.endsWith(".py")
        ? /model-authored rules/
        : /supported source file and sink symbol/,
    );
  }
});

test("OpenGrep follows a same-file caller and records an imported alias as a candidate", async (t) => {
  if (!(await available("opengrep"))) return t.skip("OpenGrep required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-native-");
  const provider = localProvider(root);
  const typescript =
    'import {decode as render} from "image_lib";\nfunction wrapper(x: string) {return render(x);}\nfunction outer(x: string) {return wrapper(x);}\n';
  for (const [path, contents, callerLine] of [
    [
      "example.py",
      "from image_lib import decode as render\n\ndef wrapper(x):\n    return render(x)\n\ndef outer(x):\n    return wrapper(x)\n",
      4,
    ],
    ["example.ts", typescript, 2],
    ["example.mts", typescript, 2],
  ] as const) {
    await writeFile(join(root, path), contents);
    const result = await provider.run(
      {
        ...file,
        path,
        rules: nativeRules(
          "decode",
          path.endsWith(".py") ? "python" : "typescript",
        ),
      },
      signal,
    );
    assert.equal(result.complete, true, result.reason ?? "incomplete scope");
    assert.deepEqual(sourceEvidence(result.evidence), [
      {
        source: path,
        line: callerLine,
        step: {
          from: { kind: "symbol", name: "wrapper", scope: path },
          relation: "candidate_call",
          calleeText: "render",
        },
      },
    ]);
    assert.equal(result.next[0]?.symbol, "wrapper");
    const upstream = await provider.run(
      {
        ...result.next[0]!,
        rules: nativeRules(
          result.next[0]!.symbol!,
          path.endsWith(".py") ? "python" : "typescript",
        ),
      },
      signal,
    );
    assert.equal(upstream.evidence[0]?.step.from.name, "outer");
  }
});

test("Go source batches find bare and package-qualified calls", async (t) => {
  for (const command of ["rg", "opengrep"]) {
    if (!(await available(command))) return t.skip(command + " required");
  }
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-go-calls-");
  await writeFile(
    join(root, "consumer.go"),
    [
      "package consumer",
      'import decoder "example.com/codec"',
      "type Worker struct{}",
      "func helper(data []byte) []byte { return decoder.Decode(data) }",
      "func ordinary() { Decode(nil) }",
      "func (w *Worker) Read() ([]byte, error) { return decoder.Decode(nil), nil }",
      'func example() { _ = "decoder.Decode(nil)" }',
      "// decoder.Decode(nil)",
    ].join("\n"),
  );
  const tracer = createDependencyTracer(root);
  t.after(() => tracer.close());

  const response = traceResponse(
    await tracer.trace({
      package: "example.com/codec",
      source_terms: ["example.com/codec"],
      symbol: "decoder.Decode",
      rules: nativeRules("Decode", "go", undefined, "example.com/codec"),
      paths: ["."],
      source_only: true,
      max_hops: 0,
      time_budget_ms: 15000,
    }),
  );
  assert.equal(response.coverage.complete, true);
  assert.deepEqual(
    response.trace
      .flatMap(({ from, relation, evidence }) =>
        evidence.flatMap(({ source, lines = [] }) =>
          lines.map((line) => [line, source, from.name, relation] as const),
        ),
      )
      .sort(([a], [b]) => a - b),
    [
      [4, "consumer.go", "helper", "candidate_call"],
      [5, "consumer.go", "ordinary", "candidate_call"],
      [6, "consumer.go", "Read", "candidate_call"],
    ],
  );
});

test("dense source files retain every call beyond the old processing cap", async (t) => {
  if (!(await available("opengrep"))) return t.skip("OpenGrep required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-dense-calls-");
  const provider = localProvider(root);
  const path = "consumer.py";
  await writeFile(
    join(root, path),
    "from image_lib import decode\n" +
      Array.from(
        { length: 96 },
        (_, i) => `def wrapper_${i}(data):\n    return decode(data)\n`,
      ).join("\n"),
  );
  const result = await provider.run(
    {
      ...file,
      path,
      rules: nativeRules(
        "decode",
        path.endsWith(".py") ? "python" : "typescript",
      ),
    },
    signal,
  );
  assert.equal(result.complete, true, result.reason ?? "incomplete scope");
  assert.equal(result.evidence.length, 96);
  assert.equal(result.evidence.at(-1)?.step.from.name, "wrapper_95");
  assert.ok(result.next.some(({ symbol }) => symbol === "wrapper_95"));

  await writeFile(
    join(root, path),
    "from image_lib import decode\ndef wrapper(data):\n" +
      "    decode(data)\n".repeat(641),
  );
  const all = await provider.run(
    {
      ...file,
      path,
      rules: nativeRules(
        "decode",
        path.endsWith(".py") ? "python" : "typescript",
      ),
    },
    signal,
  );
  assert.equal(all.complete, true, all.reason ?? "incomplete native scan");
  assert.equal(all.evidence.length, 641);
  assert.equal(all.evidence.at(-1)?.line, 643);
});

test("source batches return inline Python worker operations as original-line text leads", async (t) => {
  for (const command of ["rg", "opengrep"]) {
    if (!(await available(command))) return t.skip(command + " required");
  }
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-inline-worker-");
  await writeFile(
    join(root, "example.py"),
    [
      "import subprocess",
      "import sys",
      "from image_lib import Image",
      "def ordinary(image):",
      '    image.save("normal.png")',
      'EXAMPLE = """',
      "from image_lib import Image",
      'image.save("only-prose.png")',
      '"""',
      'WORKER = r"""',
      "from image_lib import Image",
      '# image.save("only-comment.png")',
      'image.save("named.png")',
      '"""',
      'subprocess.run([sys.executable, "-c", WORKER])',
      'subprocess.run(["python3", "-c", """',
      "from image_lib import Image",
      'image.save("inline.png")',
      '"""])',
      'subprocess.run(["python3", "-c", """',
      'something.save("unrelated.png")',
      '"""])',
    ].join("\n"),
  );

  const tracer = createDependencyTracer(root);
  t.after(() => tracer.close());
  const response = traceResponse(
    await tracer.trace({
      package: "image-package",
      source_terms: ["image_lib"],
      symbol: "save",
      rules: nativeRules("save"),
      paths: ["."],
      source_only: true,
      max_hops: 0,
      time_budget_ms: 15000,
    }),
  );
  assert.equal(response.coverage.complete, true);
  assert.deepEqual(response.textMatches, [
    { source: "example.py", text: "save", lines: [13, 18] },
  ]);
  assert.deepEqual(response.trace.map(sourceStep), [
    {
      from: { kind: "symbol", name: "ordinary", scope: "example.py" },
      relation: "candidate_call",
      calleeText: "save",
      evidence: [{ source: "example.py", lines: [5] }],
    },
  ]);
});

test("optional intrafile taint follows a helper argument and excludes a constant control", async (t) => {
  if (!(await available("opengrep"))) return t.skip("OpenGrep required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-flow-");
  const provider = localProvider(root);
  const query: TraceScope = {
    ...file,
    symbol: "log_item",
    source_symbol: "read_input",
    rules: nativeRules("log_item", "python", "read_input"),
  };
  const py =
    "def format_value(x):\n    log_item(x)\n\ndef process():\n    format_value(read_input())\n    log_item('constant')\n" +
    "log_item(read_input())\ndef constants_only():\n" +
    "    log_item('constant')\n".repeat(500);
  await writeFile(join(root, "example.py"), py);
  const flow = await provider.run(query, signal);
  assert.equal(flow.complete, true, flow.reason ?? "incomplete scope");
  assert.deepEqual(
    flow.evidence.map((hit) => hit.line),
    [2, 7],
  );
  assert.deepEqual(sourceStep(flow.evidence[0]!.step), {
    from: { kind: "symbol", name: "format_value", scope: "example.py" },
    relation: "candidate_flow",
    calleeText: "log_item",
    sourceText: "read_input",
  });
  assert.deepEqual(sourceStep(flow.evidence[1]!.step), {
    from: { kind: "file", name: "example.py" },
    relation: "candidate_flow",
    calleeText: "log_item",
    sourceText: "read_input",
  });
  assert.deepEqual(flow.next, []);
  await writeFile(
    join(root, "example.py"),
    py
      .replace("log_item(x)", "log_item('constant')")
      .replace("log_item(read_input())", "log_item('constant')"),
  );
  const control = await provider.run(query, signal);
  assert.equal(control.complete, true, control.reason ?? "incomplete scope");
  assert.deepEqual(control.evidence, []);
});

test("documentation cannot consume source or manifest scan slots", async (t) => {
  if (!(await available("rg"))) return t.skip("rg required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-file-budget-");
  await mkdir(join(root, "docs"));
  await Promise.all(
    Array.from({ length: 160 }, (_, i) =>
      writeFile(join(root, "docs", `guide-${i}.md`), "image_lib decode\n"),
    ),
  );
  for (const app of ["batch", "preview"]) {
    await mkdir(join(root, app));
    await writeFile(join(root, app, "consumer.js"), "decoder.decode(input);\n");
    await writeFile(
      join(root, app, "package.json"),
      '{"dependencies":{"image_lib":"1"}}\n',
    );
  }
  const provider = localProvider(root);
  for (const [scope, filename] of [
    [search, "consumer.js"],
    [{ ...search, symbol: undefined }, "package.json"],
  ] as const) {
    const result = await provider.run(scope, signal);
    assert.deepEqual(result.next.map(({ path }) => path).sort(), [
      `batch/${filename}`,
      `preview/${filename}`,
    ]);
    assert.equal(result.complete, true, result.reason ?? "incomplete search");
    assert.ok(
      result.textMatches?.every(({ source }) => !source.endsWith(".md")),
    );
  }
});

test("an unsupported symbol returns source leads and incomplete call coverage", async (t) => {
  if (!(await available("rg"))) return t.skip("rg required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-symbol-");
  await writeFile(join(root, "consumer.js"), "fs$rename();\n");
  const result = await localProvider(root).run(
    { ...search, symbol: "fs$rename", rules: undefined },
    signal,
  );
  assert.equal(result.complete, false);
  assert.match(result.reason ?? "", /identifier/);
  assert.deepEqual(result.next, []);
  assert.deepEqual(result.textMatches, [
    { source: "consumer.js", text: "fs$rename" },
  ]);
});

test("Git discovery includes the worktree copy of force-tracked ignored files", async (t) => {
  if (!(await available("rg")) || !(await available("git")))
    return t.skip("rg and git required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-git-");
  const external = await dirs.create("outside-git-");
  const git = (...args: string[]) =>
    promisify(execFile)("git", ["-C", root, ...args]);
  await git("init", "-q");
  await mkdir(join(root, "vendor", "old"), { recursive: true });
  await writeFile(join(root, ".gitignore"), "vendor/\n");
  await writeFile(join(root, "vendor", "lib.py"), "unmodified-on-index\n");
  await writeFile(
    join(root, "vendor", "package.json"),
    "unmodified-on-index\n",
  );
  await writeFile(join(root, "vendor", "old", "untrusted"), "ordinary\n");
  await git(
    "add",
    "-f",
    "vendor/lib.py",
    "vendor/package.json",
    "vendor/old/untrusted",
  );
  await writeFile(join(root, "vendor", "ignored"), "image_lib\n");
  await writeFile(
    join(root, "vendor", "catalog-info.yaml"),
    "kind: Component\n",
  );
  await writeFile(join(root, "vendor", "lib.py"), "image_lib image_lib\n");
  await writeFile(join(root, "vendor", "package.json"), "image_lib\n");
  await writeFile(join(root, "new.txt"), "image_lib\n");
  await writeFile(join(external, "untrusted"), "image_lib\n");
  await rm(join(root, "vendor", "old"), { force: true, recursive: true });
  await symlink(
    external,
    join(root, "vendor", "old"),
    process.platform === "win32" ? "junction" : "dir",
  );
  const provider = localProvider(root);
  const lookup = async (path: string, kind: "search" | "manifests") => {
    const result = await provider.run(
      { kind, package: "image_lib", path },
      signal,
    );
    assert.equal(result.complete, true, result.reason ?? "incomplete");
    return [
      ...new Set([
        ...result.next.map((scope) => scope.path),
        ...(result.textMatches ?? []).map((match) => match.source),
      ]),
    ].sort();
  };
  assert.deepEqual(await lookup(".", "search"), [
    "vendor/lib.py",
    "vendor/package.json",
  ]);
  assert.deepEqual(await lookup("vendor", "search"), [
    "vendor/lib.py",
    "vendor/package.json",
  ]);
  assert.deepEqual(await lookup("vendor", "manifests"), [
    "vendor/package.json",
  ]);
  await git("add", "-f", "vendor/catalog-info.yaml");
  assert.deepEqual(await lookup("vendor", "manifests"), [
    "vendor/catalog-info.yaml",
    "vendor/package.json",
  ]);
});

test("scoped traces return a nearby declared Backstage component and system", async (t) => {
  if (!(await available("rg"))) return t.skip("rg required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-catalog-");
  const service = join(root, "apps", "mail");
  const sibling = join(root, "apps", "other");
  await mkdir(service, { recursive: true });
  await mkdir(sibling);
  const catalog = [
    "apiVersion: backstage.io/v1alpha1",
    "kind: Component",
    "metadata:",
    "  namespace: messaging",
    "  name: delivery",
    "spec:",
    "  type: service",
    "  system: 'System:products/PostOffice'",
  ].join("\n");
  await writeFile(
    join(service, "package.json"),
    '{"dependencies":{"image_lib":"1"}}',
  );
  await writeFile(
    join(service, "another.yaml"),
    catalog.replace("PostOffice", "Incorrect"),
  );
  await writeFile(
    join(sibling, "catalog-info.yaml"),
    catalog.replace("PostOffice", "Unrelated") + "\n# image_lib",
  );
  await writeFile(
    join(root, "catalog-info.yaml"),
    catalog.replace("PostOffice", "Outside"),
  );
  const descriptor = join(service, "catalog-info.yml");
  const tracer = createDependencyTracer(root);
  t.after(() => tracer.close());
  const query = async (max_hops = 1) => {
    const result = await tracer.trace({
      package: "image_lib",
      paths: ["apps"],
      time_budget_ms: 5000,
      max_hops,
    });
    return result.scopes.flatMap(({ evidence }) => evidence);
  };
  const systems = async (max_hops?: number) =>
    (await query(max_hops)).filter(({ step }) => step.relation === "part_of");
  assert.deepEqual(await systems(), []);
  await writeFile(descriptor, catalog);
  assert.deepEqual(await systems(0), []);
  assert.deepEqual(await systems(), [
    {
      source: "apps/mail/catalog-info.yml",
      line: 8,
      step: {
        from: { kind: "component", name: "messaging/delivery" },
        relation: "part_of",
        to: { kind: "system", name: "products/postoffice" },
      },
    },
  ]);
  await writeFile(
    descriptor,
    catalog.replace("System:products/PostOffice", "accounts"),
  );
  assert.deepEqual((await systems())[0]?.step.to, {
    kind: "system",
    name: "messaging/accounts",
  });
  await writeFile(
    descriptor,
    catalog.replace("type: service", "type: library"),
  );
  assert.deepEqual((await systems())[0]?.step.from, {
    kind: "component",
    name: "messaging/delivery",
  });
  await writeFile(descriptor, catalog.split("\n  system:")[0]!);
  const descriptorEvidence = (await query()).filter(
    ({ step }) => step.relation === "declares",
  );
  assert.deepEqual(descriptorEvidence, [
    {
      source: "apps/mail/catalog-info.yml",
      line: 7,
      step: {
        from: { kind: "file", name: "apps/mail/catalog-info.yml" },
        relation: "declares",
        to: { kind: "component", name: "messaging/delivery" },
      },
    },
  ]);
  await writeFile(
    descriptor,
    catalog.replace("System:products/PostOffice", "component:default/other"),
  );
  assert.deepEqual(await systems(), []);
  await writeFile(descriptor, catalog + "\n---\n" + catalog);
  assert.deepEqual(await systems(), []);
  await writeFile(descriptor, "bad: [\nimage_lib\n");
  const observations = await query();
  assert.ok(
    observations.some(({ source }) => source === "apps/mail/package.json"),
  );
  assert.ok(
    !observations.some(({ source }) => source === "apps/mail/catalog-info.yml"),
  );
  assert.ok(!observations.some(({ step }) => step.relation === "part_of"));
});

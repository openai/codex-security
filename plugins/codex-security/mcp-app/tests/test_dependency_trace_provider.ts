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
import { createDependencyTracer } from "../src/dependency-trace/trace.ts";
import type { TraceScope } from "../src/dependency-trace/types.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const signal = new AbortController().signal;
const file: TraceScope = {
  kind: "file",
  package: "image_lib",
  symbol: "decode",
  path: "example.py",
};
const search: TraceScope = { ...file, kind: "search", path: "." };

async function available(command: string) {
  return promisify(execFile)(command, ["--version"]).then(
    () => true,
    () => false,
  );
}

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
    "# modules/render\n".repeat(100),
  );
  const bounded = await findProjectReferences(root, "modules/render");
  assert.equal(bounded.complete, false);
  assert.equal(bounded.references.length, 64);
  assert.ok(bounded.reason);
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
  await writeFile(join(root, "sub", "deep", "config.txt"), "use image_lib\n");
  const scope: TraceScope = {
    kind: "search",
    package: "image_lib",
    path: "sub",
  };
  assert.equal(await provider.fingerprint!(scope, signal), undefined);
  const result = await provider.run(scope, signal);
  assert.equal(result.complete, true, result.reason ?? "incomplete scope");
  assert.deepEqual(
    result.next.map((scope) => scope.path),
    ["sub/deep/config.txt"],
  );
  await writeFile(join(root, "sub", "BUILD.bazel"), 'deps = ["image_lib"]');
  const manifests = await provider.run(
    { ...scope, kind: "manifests", symbol: "decode" },
    signal,
  );
  assert.deepEqual(
    manifests.next.map(({ path, symbol }) => [path, symbol]),
    [["sub/BUILD.bazel", undefined]],
  );
  await writeFile(join(root, "sub", "BUILD.bazel"), "");
  const hit = result.next[0]!;
  const initial = await provider.fingerprint!(hit, signal);
  assert.ok(initial);
  assert.equal(
    (await provider.run(hit, signal)).evidence[0]?.step.relation,
    "references",
  );
  assert.equal((await provider.run(hit, signal)).fingerprint, initial);
  assert.deepEqual(
    (await provider.run(hit, signal)).evidence.map((e) => e.line),
    [1],
  );
  await writeFile(join(root, "sub", "deep", "config.txt"), "different\n");
  assert.notEqual(await provider.fingerprint!(hit, signal), initial);
  await writeFile(join(root, "sub", "new.txt"), "image_lib\n");
  assert.deepEqual(
    (await provider.run(scope, signal)).next.map((scope) => scope.path),
    ["sub/new.txt"],
  );
});

test("OpenGrep follows a same-file caller and records an imported alias as a candidate", async (t) => {
  if (!(await available("opengrep"))) return t.skip("OpenGrep required");
  const dirs = createTemporaryDirectories(true);
  t.after(() => dirs.cleanup());
  const root = await dirs.create("trace-native-");
  const provider = localProvider(root);
  for (const [path, contents, callerLine] of [
    [
      "example.py",
      "from image_lib import decode as render\n\ndef wrapper(x):\n    return render(x)\n\ndef outer(x):\n    return wrapper(x)\n",
      4,
    ],
    [
      "example.ts",
      'import {decode as render} from "image_lib";\nfunction wrapper(x) {return render(x);}\nfunction outer(x) {return wrapper(x);}\n',
      2,
    ],
  ] as const) {
    await writeFile(join(root, path), contents);
    const result = await provider.run({ ...file, path }, signal);
    assert.equal(result.complete, true, result.reason ?? "incomplete scope");
    assert.deepEqual(result.evidence, [
      {
        source: path,
        line: callerLine,
        step: {
          from: { kind: "symbol", name: "wrapper", scope: path },
          relation: "candidate_call",
          to: { kind: "spelling", name: "decode" },
        },
      },
    ]);
    assert.equal(result.next[0]?.symbol, "wrapper");
    const upstream = await provider.run(result.next[0]!, signal);
    assert.equal(upstream.evidence[0]?.step.from.name, "outer");
  }
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
  };
  const py =
    "def format_value(x):\n    log_item(x)\n\ndef process():\n    format_value(read_input())\n    log_item('constant')\n";
  await writeFile(join(root, "example.py"), py);
  const flow = await provider.run(query, signal);
  assert.equal(flow.complete, true, flow.reason ?? "incomplete scope");
  assert.deepEqual(
    flow.evidence.map((hit) => hit.line),
    [2],
  );
  assert.deepEqual(flow.evidence[0]?.step, {
    from: { kind: "spelling", name: "read_input", scope: "example.py" },
    relation: "candidate_flow",
    to: { kind: "spelling", name: "log_item" },
  });
  assert.deepEqual(flow.next, []);
  await writeFile(
    join(root, "example.py"),
    py.replace("log_item(x)", "log_item('constant')"),
  );
  const control = await provider.run(query, signal);
  assert.equal(control.complete, true, control.reason ?? "incomplete scope");
  assert.deepEqual(control.evidence, []);
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
  await writeFile(join(root, "vendor", "lib.py"), "image_lib\n");
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
    return result.next.map((scope) => scope.path).sort();
  };
  assert.deepEqual(await lookup(".", "search"), [
    "new.txt",
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
    observations.some(({ source }) => source === "apps/mail/catalog-info.yml"),
  );
  assert.ok(!observations.some(({ step }) => step.relation === "part_of"));
});

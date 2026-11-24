import {
  available,
  nativeRules,
  sourceStep,
} from "./support/native-trace-rules.ts";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { traceResponse } from "../src/dependency-trace/response.ts";
import type {
  TraceEvidence,
  TraceResult,
} from "../src/dependency-trace/types.ts";
import { buildServer, loadGraphSession } from "./build-server.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

test("operator discovery exclusions preserve nested policy and exact caller follow-ups", async (t) => {
  for (const command of ["rg", "opengrep"]) {
    if (!(await available(command))) return t.skip(command + " required");
  }
  const temps = createTemporaryDirectories(true);
  t.after(() => temps.cleanup());
  const checkout = await temps.create("source-scope-checkout-");
  const runtime = await temps.create("source-scope-session-");
  const { createDependencyGraphSession } = await loadGraphSession(runtime);
  await mkdir(join(checkout, "examples", "runtime"), { recursive: true });
  await mkdir(join(checkout, "tests"));
  await mkdir(join(checkout, "docs"));
  const uncertainPolicyFiles: string[] = [];
  if (process.platform !== "win32") {
    for (const [directory, target] of [
      ["dangling-policy", "missing.md"],
      ["looping-policy", "SECURITY.md"],
    ] as const) {
      await mkdir(join(checkout, "examples", directory));
      await symlink(
        target,
        join(checkout, "examples", directory, "SECURITY.md"),
      );
      uncertainPolicyFiles.push(`examples/${directory}/consumer.py`);
    }
  }
  const allFiles = [
    "examples/already-read.py",
    "examples/demo.py",
    "examples/runtime/consumer.py",
    "examples/worker.py",
    "tests/test_named.py",
    "docs/guide.py",
    "test_fallback.py",
    "app.py",
    ...uncertainPolicyFiles,
  ].sort();
  for (const file of allFiles)
    await writeFile(
      join(checkout, file),
      "from image_lib import decode\ndecode(data)\n",
    );
  await writeFile(
    join(checkout, "SECURITY.md"),
    "Report through the project security team.\n",
  );
  await writeFile(
    join(checkout, "examples/runtime/SECURITY.md"),
    "The executor consumes this code.\n",
  );
  for (const path of ["../outside", ".", checkout, "D:/outside"]) {
    await assert.rejects(
      createDependencyGraphSession(checkout, false, {
        excludedSourcePaths: [path],
      }),
      /expected a safe scan-relative POSIX path/u,
    );
  }
  const baseline = await createDependencyGraphSession(checkout, false, {
    fullTraceReply: true,
  });
  const scoped = await createDependencyGraphSession(checkout, false, {
    fullTraceReply: true,
    excludedSourcePaths: ["examples"],
  });
  const production = await createDependencyGraphSession(checkout, false, {
    fullTraceReply: true,
    productionDiscovery: true,
  });
  t.after(async () => {
    await baseline.close();
    await scoped.close();
    await production.close();
  });
  const request = {
    package: "image-package",
    symbol: "decode",
    rules: nativeRules("decode"),
    source_only: true,
    max_hops: 0,
    time_budget_ms: 60000,
  };
  type Session = Awaited<ReturnType<typeof createDependencyGraphSession>>;
  async function trace(session: Session, targets: object) {
    return (await session.call("trace_codex_security_code", {
      ...request,
      ...targets,
    })) as unknown as ReturnType<typeof traceResponse>;
  }
  function locations(result: ReturnType<typeof traceResponse>) {
    return [
      ...new Set(
        result.trace.flatMap(({ evidence }) =>
          evidence.map(({ source }) => source),
        ),
      ),
    ].sort();
  }
  const broad = { paths: ["."], source_terms: ["image_lib"] };
  assert.deepEqual(locations(await trace(baseline, broad)), allFiles);
  const original = await trace(production, broad);
  assert.deepEqual(
    locations(original),
    ["app.py", "examples/runtime/consumer.py", ...uncertainPolicyFiles].sort(),
  );
  assert.deepEqual(original.coverage.discovery_omissions, [
    { path: "docs/guide.py", excludedBy: "docs", basis: "production_default" },
    {
      path: "examples/already-read.py",
      excludedBy: "examples",
      basis: "production_default",
    },
    {
      path: "examples/demo.py",
      excludedBy: "examples",
      basis: "production_default",
    },
    {
      path: "examples/worker.py",
      excludedBy: "examples",
      basis: "production_default",
    },
    {
      path: "test_fallback.py",
      excludedBy: "test_fallback.py",
      basis: "production_default",
    },
    {
      path: "tests/test_named.py",
      excludedBy: "tests",
      basis: "production_default",
    },
  ]);
  assert.deepEqual(
    locations(await trace(production, { files: ["examples/worker.py"] })),
    ["examples/worker.py"],
  );
  await trace(production, { files: ["tests/test_named.py"] });
  assert.deepEqual(
    locations(await trace(production, broad)),
    [
      "app.py",
      "examples/runtime/consumer.py",
      "examples/worker.py",
      "tests/test_named.py",
      ...uncertainPolicyFiles,
    ].sort(),
  );
  assert.deepEqual(
    locations(await trace(scoped, { files: ["examples/already-read.py"] })),
    ["examples/already-read.py"],
  );
  const first = await trace(scoped, broad);
  assert.equal(first.coverage.complete, true);
  assert.deepEqual(
    locations(first),
    [
      "examples/already-read.py",
      "examples/runtime/consumer.py",
      "tests/test_named.py",
      "docs/guide.py",
      "test_fallback.py",
      "app.py",
      ...uncertainPolicyFiles,
    ].sort(),
  );
  assert.deepEqual(first.coverage.discovery_omissions, [
    { path: "examples/demo.py", excludedBy: "examples" },
    { path: "examples/worker.py", excludedBy: "examples" },
  ]);
  assert.equal(
    scoped.boundTraceResponse(first).coverage.discovery_omissions,
    undefined,
  );
  assert.deepEqual(
    locations(await trace(scoped, { files: ["examples/demo.py"] })),
    ["examples/demo.py"],
  );
  await trace(scoped, { files: ["examples/worker.py"] });
  assert.deepEqual(locations(await trace(scoped, broad)), allFiles);
});

test("filtered directory discovery registers OpenGrep hits without selecting files", async (t) => {
  for (const command of ["rg", "opengrep"]) {
    if (!(await available(command))) return t.skip(command + " required");
  }
  const temps = createTemporaryDirectories(true);
  t.after(() => temps.cleanup());
  const checkout = await temps.create("dependency-batch-checkout-");
  const runtime = await temps.create("dependency-batch-session-");
  const { createDependencyGraphSession } = await loadGraphSession(runtime);
  const session = await createDependencyGraphSession(checkout, true);
  t.after(() => session.close());

  await mkdir(join(checkout, "src"));
  await Promise.all(
    Array.from({ length: 70 }, (_, index) =>
      writeFile(
        join(
          checkout,
          "src",
          "noise-" + String(index).padStart(2, "0") + ".py",
        ),
        "def unrelated(record):\n    return record.save()\n",
      ),
    ),
  );
  await writeFile(join(checkout, "src/import-only.py"), "import image_lib\n");
  const targets = Array.from({ length: 18 }, (_, index) => {
    const suffix = String(index).padStart(2, "0");
    return { path: "src/target-" + suffix + ".py", caller: "write_" + suffix };
  });
  for (const { path, caller } of targets) {
    // Equal-length caller names put both calls at the same native byte offset.
    await writeFile(
      join(checkout, path),
      "from image_lib import Image\n\ndef " +
        caller +
        '(image: Image):\n    return image.save("result.png", format="PNG")\n',
    );
  }

  const result = await session.call("trace_codex_security_code", {
    package: "image-package",
    source_terms: ["image_lib"],
    symbol: "save",
    rules: nativeRules("save"),
    paths: ["src"],
    source_only: true,
    max_hops: 0,
    time_budget_ms: 15000,
  });
  const trace = result.trace as {
    from: { kind: string; name: string; scope?: string };
    relation: string;
    calleeText?: string;
    evidence: { source: string; lines?: number[] }[];
  }[];
  assert.deepEqual(
    trace
      .filter(({ relation }) => relation === "candidate_call")
      .sort((left, right) => left.from.name.localeCompare(right.from.name))
      .map(sourceStep),
    targets.map(({ path, caller }) => ({
      from: { kind: "symbol", name: caller, scope: path },
      relation: "candidate_call",
      calleeText: "save",
      evidence: [{ source: path, lines: [4] }],
    })),
  );
  assert.deepEqual(
    (result.coverage as { source_batches: unknown }).source_batches,
    { scheduled: 2, completed: 2, files: 18 },
  );
  assert.equal(result.service_resolution.pending, 0);
  const graph = await session.call("query_codex_security_graph", {});
  assert.equal(graph.code_paths_found, 18);

  await mkdir(join(checkout, "overflow"));
  const dense =
    "from image_lib import Image\n" +
    Array.from(
      { length: 100 },
      (_, index) =>
        `def render_${index}(image: Image):\n    image.save("${"x".repeat(8500)}.png", format="PNG")\n`,
    ).join("\n");
  // OpenGrep skips targets over 1,000,000 bytes by default. Exercise its
  // output limit with multiple matches, keeping the input below that threshold.
  assert.ok(Buffer.byteLength(dense) < 1_000_000);
  await writeFile(join(checkout, "overflow/dense.py"), dense);
  await writeFile(
    join(checkout, "overflow/sparse.py"),
    "from image_lib import Image\n\ndef render_one(image: Image):\n" +
      '    image.save("result.png", format="PNG")\n',
  );
  const overflow = await session.call("trace_codex_security_code", {
    package: "image-package",
    source_terms: ["image_lib"],
    symbol: "save",
    rules: ["first", "second", "third", "fourth"].flatMap((suffix) =>
      nativeRules("save").map((rule) => ({
        ...rule,
        id: String(rule.id) + "-" + suffix,
      })),
    ),
    paths: ["overflow"],
    source_only: true,
    max_hops: 0,
    time_budget_ms: 60000,
  });
  const overflowCoverage = overflow.coverage as {
    complete: boolean;
    partial: { reason: string }[];
    source_batches: { scheduled: number; completed: number; files: number };
  };
  assert.equal(overflowCoverage.complete, false);
  assert.deepEqual(overflowCoverage.source_batches, {
    scheduled: 1,
    completed: 0,
    files: 2,
  });
  assert.match(
    overflowCoverage.partial.map(({ reason }) => reason).join("\n"),
    /OpenGrep response exceeded the byte limit/u,
  );
  assert.deepEqual(
    sourceStep(
      (overflow.trace as typeof trace).find(
        ({ from }) => from.scope === "overflow/sparse.py",
      )!,
    ),
    {
      from: {
        kind: "symbol",
        name: "render_one",
        scope: "overflow/sparse.py",
      },
      relation: "candidate_call",
      calleeText: "save",
      evidence: [{ source: "overflow/sparse.py", lines: [4] }],
    },
  );

  // Append inside the existing real-session source batch test.
  await mkdir(join(checkout, "wide"));
  const files = 12;
  const callsPerFile = 14;
  const totalCalls = files * callsPerFile;
  for (let index = 0; index < files; index++) {
    const name = "consumer-" + index + "-" + "source".repeat(18) + ".py";
    const callers = Array.from(
      { length: callsPerFile },
      (_, caller) =>
        "def render_" +
        caller +
        '(image: Image):\n    return image.save("result.png", format="PNG")\n\n',
    ).join("");
    await writeFile(
      join(checkout, "wide", name),
      "from image_lib import Image\n\n" + callers,
    );
  }

  const wideRequest = {
    package: "image-package",
    source_terms: ["image_lib"],
    symbol: "save",
    rules: nativeRules("save"),
    paths: ["wide"],
    source_only: true,
    max_hops: 0,
    time_budget_ms: 600_000,
  };
  const host = await createDependencyGraphSession(checkout, true, {
    fullTraceReply: true,
  });
  t.after(() => host.close());
  const raw = await host.call("trace_codex_security_code", wideRequest);
  const rawTrace = raw.trace as typeof trace;
  assert.equal(rawTrace.length, totalCalls);
  assert.equal((raw.coverage as { complete: boolean }).complete, true);
  assert.equal(
    (await host.call("query_codex_security_graph", {})).code_paths_found,
    totalCalls,
  );

  // Include the extra candidate list that the SDK adds after observing raw.
  const candidates = rawTrace.map(({ evidence }, index) => ({
    id: "candidate-" + (index + 1),
    path: evidence[0].source,
    line: evidence[0].lines?.[0],
  }));
  const model = host.boundTraceResponse({ ...raw, candidates });
  assert.ok(Buffer.byteLength(JSON.stringify(model)) <= 32 * 1024);
  assert.ok(
    Buffer.byteLength(JSON.stringify(model)) <
      Buffer.byteLength(JSON.stringify(raw)),
  );

  const summaryBefore = await session.call("query_codex_security_graph", {});
  const standalone = await session.call(
    "trace_codex_security_code",
    wideRequest,
  );
  assert.ok(Buffer.byteLength(JSON.stringify(standalone)) <= 32 * 1024);
  assert.ok((standalone.trace as typeof trace).length < totalCalls);
  assert.equal((standalone.coverage as { complete: boolean }).complete, true);
  assert.equal(
    (await session.call("query_codex_security_graph", {})).code_paths_found,
    Number(summaryBefore.code_paths_found) + totalCalls,
  );
});

test("standalone dependency tools preserve source evidence with no service catalog", async (t) => {
  const temps = createTemporaryDirectories(true);
  t.after(() => temps.cleanup());
  const checkout = await temps.create("dependency-trace-checkout-");
  const runtime = await temps.create("dependency-trace-server-");
  const bundle = join(runtime, "server.cjs");
  await buildServer(bundle);
  await mkdir(join(checkout, "src"));
  await writeFile(join(checkout, "src/uses.js"), "example\nother\nexample\n");
  await assert.rejects(
    promisify(execFile)(
      process.execPath,
      [bundle, "--dependency-trace", checkout],
      {
        env: {
          ...process.env,
          CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY: "0",
        },
      },
    ),
    /Dependency tracing is disabled/u,
  );
  const client = new Client({ name: "dependency-test", version: "1" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [bundle, "--dependency-trace", checkout],
      env: { CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY: "1" },
    }),
  );
  try {
    const { tools } = await client.listTools();
    const name = "trace_codex_security_code";
    const resolve = "resolve_codex_security_services";
    const inspect = "query_codex_security_graph";
    assert.deepEqual(tools.map((tool) => tool.name).sort(), [
      inspect,
      resolve,
      name,
    ]);
    assert.equal(
      tools.find((tool) => tool.name === inspect)?.annotations?.readOnlyHint,
      true,
    );
    const emptyQueue = {
      catalog_configured: false,
      pending: 0,
      checked: 0,
      unresolved: 0,
      paths: [] as string[],
      unresolved_paths: [],
      revision: 0,
    };
    const emptyGraph = {
      code_paths_found: 0,
      services_found: 0,
      services: [],
      service_resolution: emptyQueue,
    };
    assert.deepEqual(
      (await client.callTool({ name: inspect, arguments: {} }))
        .structuredContent,
      emptyGraph,
    );
    const query = { package: "example", time_budget_ms: 5000, max_hops: 0 };
    const response = await client.callTool({
      name,
      arguments: { ...query, paths: ["src"] },
    });
    assert.equal(response.isError, undefined);
    const content = response.content as { type: string; text: string }[];
    const result = JSON.parse(content[0].text);
    assert.deepEqual(result, response.structuredContent);
    assert.deepEqual(result, {
      trace: [],
      textMatches: [{ source: "src/uses.js", text: "example", lines: [] }],
      service_resolution: emptyQueue,
      coverage: {
        complete: true,
        limits: [],
        searched_paths: ["src"],
        partial: [],
        frontier: [],
      },
    });
    const detail = await client.callTool({
      name: inspect,
      arguments: { node: "src/uses.js" },
    });
    assert.deepEqual(detail.structuredContent, {
      matches: [],
      service_resolution: emptyQueue,
    });
    await writeFile(
      join(checkout, "src/main.js"),
      "import 'reader-package';\n",
    );
    await writeFile(
      join(checkout, "src/package.json"),
      '{"name":"example-reader","dependencies":{"reader-package":"1.0.0"}}\n',
    );
    await writeFile(
      join(checkout, "src/catalog-info.yaml"),
      "apiVersion: backstage.io/v1alpha1\nkind: Component\nmetadata:\n  name: example-reader\nspec:\n  type: service\n",
    );
    const traced = await client.callTool({
      name,
      arguments: {
        ...query,
        package: "reader-package",
        paths: ["src"],
        max_hops: 2,
      },
    });
    assert.equal(traced.isError, undefined);
    const trace = traced.structuredContent as {
      service_resolution: typeof emptyQueue;
      trace: { from: { kind: string }; to?: { kind: string; name: string } }[];
    };
    assert.deepEqual(trace.service_resolution, emptyQueue);
    assert.ok(
      trace.trace.some(
        ({ to }) =>
          to?.kind === "component" && to.name === "default/example-reader",
      ),
    );
    assert.ok(
      trace.trace.every(
        ({ from, to }) => from.kind !== "service" && to?.kind !== "service",
      ),
    );
    assert.deepEqual(
      (
        await client.callTool({
          name: resolve,
          arguments: { paths: ["src/main.js"], project: "src" },
        })
      ).structuredContent,
      emptyGraph,
    );
    await mkdir(join(checkout, "config"));
    await writeFile(
      join(checkout, "config/run.yaml"),
      "application: portal\nproject: src\n",
    );
    const references = await client.callTool({
      name: resolve,
      arguments: { project: "src" },
    });
    assert.equal(references.isError, undefined);
    assert.deepEqual(references.structuredContent, {
      project: "src",
      references: [{ path: "config/run.yaml", line: 2 }],
      complete: true,
      service_resolution: emptyQueue,
    });
    for (const arguments_ of [
      { project: "../outside" },
      {
        paths: ["src/main.js"],
        observations: [{ service: "reader", source: "catalog:reader" }],
      },
      {
        paths: ["src/main.js"],
        resolutions: [
          {
            path: "src/main.js",
            services: [{ name: "example-reader" }],
            source: "src/package.json",
          },
        ],
      },
    ]) {
      const rejected = await client.callTool({
        name: resolve,
        arguments: arguments_,
      });
      assert.equal(rejected.isError, true);
    }
    assert.deepEqual(
      (await client.callTool({ name: inspect, arguments: {} }))
        .structuredContent,
      emptyGraph,
    );

    const second = new Client({ name: "second-check", version: "1" });
    try {
      await second.connect(
        new StdioClientTransport({
          command: process.execPath,
          args: [bundle, "--dependency-trace", checkout],
          env: { CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY: "1" },
        }),
      );
      assert.deepEqual(
        (await second.callTool({ name: inspect, arguments: {} }))
          .structuredContent,
        emptyGraph,
      );
    } finally {
      await second.close();
    }
    for (const args of [
      { ...query, paths: ["../outside"] },
      { ...query, paths: [checkout] },
      { ...query, max_hops: -1 },
      { package: "example", max_hops: 1 },
    ]) {
      const rejected = await client.callTool({ name, arguments: args });
      assert.equal(rejected.isError, true);
    }
    const outside = await temps.create("dependency-trace-outside-");
    await writeFile(join(outside, "manifest.txt"), "example\n");
    await symlink(outside, join(checkout, "linked"), "junction");
    const escaped = await client.callTool({
      name,
      arguments: { ...query, paths: ["linked"], max_hops: 1 },
    });
    const [report] = escaped.content as { text: string }[];
    const denied = JSON.parse(report.text);
    assert.equal(denied.coverage.complete, false);
    assert.deepEqual(denied.trace, []);
    assert.deepEqual(denied.coverage.searched_paths, []);
    assert.equal(denied.coverage.partial.length, 1);
    assert.equal(denied.coverage.partial[0].path, "linked");
    assert.match(denied.coverage.partial[0].reason, /symlink/u);
  } finally {
    await client.close();
  }
});

test("only host catalog results settle requested service lookups", async (t) => {
  const temps = createTemporaryDirectories(true);
  t.after(() => temps.cleanup());
  const checkout = await temps.create("dependency-catalog-checkout-");
  const runtime = await temps.create("dependency-catalog-session-");
  const { createDependencyGraphSession } = await loadGraphSession(runtime);
  const session = await createDependencyGraphSession(checkout, true);
  t.after(() => session.close());
  const resolve = "resolve_codex_security_services";
  const query = "query_codex_security_graph";
  await writeFile(join(checkout, "README.md"), "A note about example.\n");
  const search = {
    package: "example",
    time_budget_ms: 5000,
    max_hops: 1,
  };
  const prose = await session.call("trace_codex_security_code", search);
  assert.deepEqual(prose.textMatches, []);
  assert.deepEqual(prose.trace, []);
  await writeFile(join(checkout, "package.json"), '{"description":"example"}');
  const raw = await session.call("trace_codex_security_code", search);
  assert.deepEqual(raw.trace, []);
  assert.deepEqual(raw.textMatches, [
    { source: "package.json", text: "example", lines: [] },
  ]);
  assert.equal(raw.service_resolution.pending, 0);
  assert.deepEqual(
    (await session.call(query, { node: "example" })).matches,
    [],
  );
  assert.deepEqual(
    (await session.call(query, { node: "package.json" })).matches,
    [],
  );
  await session.call(resolve, { paths: ["package.json"] });
  assert.equal(
    (await session.call(query, { node: "package.json" })).service_lookup,
    "pending",
  );
  await mkdir(join(checkout, "discovery"));
  await writeFile(
    join(checkout, "discovery/package.json"),
    '{"dependencies":{"example":"1.0.0"}}',
  );
  const source = await session.call("trace_codex_security_code", {
    ...search,
    files: ["discovery/package.json"],
    source_only: true,
    max_hops: 0,
  });
  assert.equal(source.service_resolution.pending, 1);
  assert.deepEqual(source.service_resolution.paths, ["package.json"]);
  assert.deepEqual(source.trace, [
    {
      from: { kind: "file", name: "discovery/package.json" },
      relation: "depends_on",
      to: { kind: "package", name: "example", scope: "discovery/package.json" },
      evidence: [{ source: "discovery/package.json", lines: [1] }],
    },
  ]);
  const reason = "No catalog record for this manifest.";
  session.recordCatalogResolution({
    path: "package.json",
    status: "unresolved",
    reason,
  });
  const unresolved = await session.call(query, { node: "package.json" });
  assert.equal(unresolved.service_lookup, "unresolved");
  assert.deepEqual(unresolved.evidence, []);
  assert.deepEqual(unresolved.service_lookup_detail, {
    reason,
    source: "configured service catalog",
  });
  const args = {
    paths: ["src/./main.js", "src/main.js", "lib/standalone.js"],
    project: ".",
  };
  const queued = await session.call(resolve, args);
  assert.deepEqual(queued.service_resolution.paths, [
    "src/main.js",
    "lib/standalone.js",
  ]);
  await assert.rejects(
    session.call(resolve, { ...args, resolutions: [{ path: "src/main.js" }] }),
    /Unrecognized key/u,
  );

  const lookup = {
    path: "lib/standalone.js",
    services: [],
    source: "catalog:lookup/empty",
  };
  // A file-only miss cannot settle a pending question about a specific project.
  const pending = session.recordCatalogResolution(lookup);
  assert.deepEqual(
    pending.service_resolution.paths,
    queued.service_resolution.paths,
  );
  session.recordCatalogResolution({
    path: "src/main.js",
    project: ".",
    services: [
      {
        name: "portal",
        scope: "production",
        source: "catalog:service/portal",
      },
      {
        name: "preview",
        scope: "staging",
        source: "catalog:service/preview",
      },
    ],
  });
  const resolved = session.recordCatalogResolution({ ...lookup, project: "." });
  assert.equal(resolved.services_found, 2);
  assert.equal(resolved.service_resolution.pending, 0);
  assert.equal(resolved.service_resolution.checked, 2);
  const file = await session.call(query, { node: "src/main.js" });
  assert.deepEqual(
    (file.evidence as { source: string; relation?: string }[])
      .filter(({ relation }) => relation === "uses")
      .map(({ source }) => source),
    ["catalog:service/portal", "catalog:service/preview"],
  );
});

test("trace groups citations and keeps linked and similarly named endpoints distinct", () => {
  const worker = { kind: "service", name: "worker", scope: "production" };
  const first = {
    from: { kind: "queue", name: "jobs" },
    relation: "consumed_by",
    to: worker,
  };
  const second = {
    from: worker,
    relation: "built_from",
    to: { kind: "target", name: "worker", scope: "workspace" },
  };
  const scope = {
    kind: "file" as const,
    path: "app.js",
    package: "library",
    symbol: "library.sink",
    source_symbol: "read",
  };
  const call = (file: string): TraceEvidence => ({
    source: file,
    line: 2,
    step: {
      from: { kind: "symbol", name: "run", scope: file },
      relation: "candidate_call",
      calleeText: "sink",
    },
  });
  const items: TraceEvidence[] = [
    { step: first, source: "catalog:jobs" },
    { step: second, source: "build.yml", line: 8 },
    call("app.js"),
  ];
  const result: TraceResult = {
    complete: true,
    limits: [],
    frontier: [],
    scopes: [
      {
        scope,
        id: 0,
        hops: 0,
        complete: true,
        evidence: items,
        textMatches: [{ source: "leads.js", text: "sink" }],
      },
      {
        scope: { ...scope, path: "other.js" },
        id: 1,
        hops: 1,
        complete: true,
        textMatches: [9, 3, 9].map((line) => ({
          source: "leads.js",
          text: "sink",
          line,
        })),
        evidence: [
          ...items,
          {
            step: second,
            source: "build.yml",
            line: 3,
          },
          call("other.js"),
          {
            ...call("app.js"),
            step: { ...call("app.js").step, calleeText: "alias" },
          },
        ],
      },
      {
        scope: {
          kind: "catalog",
          package: "library",
          path: "catalog-info.yaml",
        },
        id: 2,
        hops: 1,
        complete: true,
        evidence: [],
      },
    ],
  };
  const response = traceResponse(result);
  assert.deepEqual(response.coverage.searched_paths, []);
  assert.deepEqual(response.textMatches, [
    { source: "leads.js", text: "sink", lines: [3, 9] },
  ]);
  assert.deepEqual(response.trace, [
    { ...first, evidence: [{ source: "catalog:jobs" }] },
    { ...second, evidence: [{ source: "build.yml", lines: [3, 8] }] },
    {
      from: { kind: "symbol", name: "run", scope: "app.js" },
      relation: "candidate_call",
      calleeText: "sink",
      evidence: [{ source: "app.js", lines: [2] }],
    },
    {
      from: { kind: "symbol", name: "run", scope: "other.js" },
      relation: "candidate_call",
      calleeText: "sink",
      evidence: [{ source: "other.js", lines: [2] }],
    },
    {
      from: { kind: "symbol", name: "run", scope: "app.js" },
      relation: "candidate_call",
      calleeText: "alias",
      evidence: [{ source: "app.js", lines: [2] }],
    },
  ]);
});

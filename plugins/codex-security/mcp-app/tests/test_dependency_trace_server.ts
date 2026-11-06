import assert from "node:assert/strict";
import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { traceResponse } from "../src/dependency-trace/response.ts";
import type {
  TraceEvidence,
  TraceResult,
} from "../src/dependency-trace/types.ts";
import { applicationRoot, buildServer } from "./build-server.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

test("standalone dependency tools preserve source evidence with no service catalog", async (t) => {
  const temps = createTemporaryDirectories(true);
  t.after(() => temps.cleanup());
  const checkout = await temps.create("dependency-trace-checkout-");
  const runtime = await temps.create("dependency-trace-server-");
  const bundle = join(runtime, "server.cjs");
  await buildServer(bundle);
  await mkdir(join(checkout, "src"));
  await writeFile(join(checkout, "src/uses.js"), "example\nother\nexample\n");
  const client = new Client({ name: "dependency-test", version: "1" });
  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [bundle, "--dependency-trace", checkout],
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
  const bundle = join(runtime, "session.cjs");
  await buildServer(bundle, {
    entryPoints: [join(applicationRoot, "src/dependency-trace/session.ts")],
  });
  const { createDependencyGraphSession } = (
    (await import(pathToFileURL(bundle).href)) as {
      default: typeof import("../src/dependency-trace/session.ts");
    }
  ).default;
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
  const reason = "No catalog record for this manifest.";
  session.recordCatalogResolutions([
    { path: "package.json", status: "unresolved", reason },
  ]);
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
  assert.deepEqual(session.pendingCatalogRequests(args), [
    { path: "src/main.js", project: "." },
    { path: "lib/standalone.js", project: "." },
  ]);
  await assert.rejects(
    session.call(resolve, { ...args, resolutions: [{ path: "src/main.js" }] }),
    /Unrecognized key/u,
  );

  const resolved = session.recordCatalogResolutions([
    {
      path: "src/main.js",
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
    },
    { path: "lib/standalone.js", services: [], source: "catalog:lookup/empty" },
  ]);
  assert.equal(resolved.services_found, 2);
  assert.equal(resolved.service_resolution.pending, 0);
  assert.equal(resolved.service_resolution.checked, 2);
  assert.deepEqual(session.pendingCatalogRequests(args), []);
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
    expansions: [{ from: 0, to: 1 }],
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

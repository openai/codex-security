import assert from "node:assert/strict";
import { test } from "node:test";
import { EvidenceGraph } from "../src/dependency-trace/graph.ts";
import type {
  TraceEvidence,
  TraceResult,
} from "../src/dependency-trace/types.ts";

const file = { kind: "file", name: "src/preview.ts" };
const caller = { kind: "symbol", name: "makePreview", scope: file.name };
const target = { kind: "spelling", name: "decode" };
const call: TraceEvidence = {
  source: file.name,
  line: 12,
  step: { from: caller, relation: "candidate_call", to: target },
};
function trace(...evidence: TraceEvidence[]): TraceResult {
  return {
    complete: true,
    limits: [],
    scopes: [
      {
        id: 0,
        hops: 1,
        scope: { kind: "file", package: "decoder", path: file.name },
        complete: true,
        evidence,
      },
    ],
    expansions: [],
    frontier: [],
  };
}

function summaryFor(graph: EvidenceGraph) {
  const result = graph.query();
  assert("services" in result);
  return result;
}

function detailFor(graph: EvidenceGraph, node: string) {
  const result = graph.query(node);
  assert("node" in result);
  return result;
}

function matchesFor(graph: EvidenceGraph, node: string) {
  const result = graph.query(node);
  assert("matches" in result);
  return result.matches;
}

test("counts distinct candidate calls and flows, including different source lines", () => {
  const graph = new EvidenceGraph();
  const result = trace(
    call,
    { ...call, line: 22 },
    { ...call, step: { ...call.step, relation: "candidate_flow" } },
    { ...call, step: { from: file, relation: "references", to: target } },
  );
  graph.addTrace(result);
  graph.addTrace(result);
  assert.deepEqual(summaryFor(graph), {
    code_paths_found: 3,
    services_found: 0,
    services: [],
  });
  const detail = detailFor(graph, file.name);
  assert.deepEqual(
    detail.paths.map(({ line }) => line),
    [12, 22, 12],
  );
  assert.equal(detail.evidence[0]?.relation, "references");
  assert.equal(detail.paths[0]?.relation, "candidate_call");
  assert.equal(detail.paths[0]?.source, file.name);
  assert.deepEqual(new EvidenceGraph().query(), {
    code_paths_found: 0,
    services_found: 0,
    services: [],
  });
});

test("a service exposes only its directly linked code and cited relationships", () => {
  const graph = new EvidenceGraph();
  const uploadPath = "src/upload.ts";
  graph.addTrace(trace(call, { ...call, source: uploadPath }));
  const answers = [
    {
      path: file.name,
      services: [{ name: "preview-job", source: "catalog#preview" }],
    },
    {
      path: uploadPath,
      services: [{ name: "upload-api", source: "catalog#upload" }],
    },
  ];
  graph.resolveServices(answers);
  const services = summaryFor(graph).services;
  assert.deepEqual(
    services.map(({ name }) => name),
    ["preview-job", "upload-api"],
  );
  const preview = detailFor(graph, services[0]!.id);
  assert.deepEqual(detailFor(graph, "preview-job"), preview);
  assert.deepEqual(
    preview.paths.map(({ source }) => source),
    [file.name],
  );
  assert.equal(preview.evidence.length, 1);
  assert.equal(preview.evidence[0]?.source, "catalog#preview");
  const upload = detailFor(graph, "upload-api");
  assert.deepEqual(
    upload.paths.map(({ source }) => source),
    [uploadPath],
  );
  assert.deepEqual(
    upload.evidence.map(({ from, relation, to, source }) => [
      from.name,
      relation,
      to?.name,
      source,
    ]),
    [["upload-api", "uses", uploadPath, "catalog#upload"]],
  );
  const { revision, pending } = graph.serviceResolution();
  graph.resolveServices(answers);
  assert.equal(detailFor(graph, "preview-job").evidence.length, 1);
  assert.deepEqual(summaryFor(graph).services, services);
  assert.equal(graph.serviceResolution().revision, revision);
  assert.equal(graph.serviceResolution().pending, pending);
});

test("file links include local candidates without merging unrelated names or catalog neighbors", () => {
  const graph = new EvidenceGraph();
  graph.addTrace(
    trace(
      call,
      {
        ...call,
        source: "tools/preview.ts",
        step: { ...call.step, from: { ...caller, scope: "tools/preview.ts" } },
      },
      {
        source: "src/catalog-info.yaml",
        step: {
          from: { kind: "component", name: "media/library" },
          relation: "part_of",
          to: { kind: "system", name: "media" },
        },
      },
    ),
  );
  assert.equal(summaryFor(graph).services_found, 0);
  graph.resolveServices([
    {
      path: file.name,
      services: [{ name: "preview-job" }],
      source: "catalog",
    },
  ]);
  assert.deepEqual(
    detailFor(graph, "preview-job").paths.map(({ source }) => source),
    [file.name],
  );
  const candidates = matchesFor(graph, "makePreview");
  assert.deepEqual(
    candidates.map(({ scope }) => scope),
    [file.name, "tools/preview.ts"],
  );
  assert.equal(
    detailFor(graph, candidates[1]!.id).paths[0]?.source,
    "tools/preview.ts",
  );
  assert.deepEqual(detailFor(graph, "media").paths, []);
  assert.deepEqual(graph.query("missing"), { matches: [] });
});

test("retention limit preserves existing IDs and evidence and reports dropped observations", () => {
  const graph = new EvidenceGraph(4096);
  graph.requestServices(["first.ts", "oversized.ts"]);
  graph.resolveServices([
    { path: "first.ts", services: [{ name: "first" }], source: "catalog" },
  ]);
  const first = summaryFor(graph).services[0]!;
  graph.resolveServices([
    {
      path: "oversized.ts",
      services: [{ name: "oversized" }],
      source: "a".repeat(8192),
    },
  ]);
  const report = summaryFor(graph);
  assert.deepEqual(report.services, [first]);
  assert.equal(report.truncated, true);
  assert.deepEqual(matchesFor(graph, "oversized"), []);
  assert.equal(detailFor(graph, first.id).evidence[0]?.source, "catalog");
});

test("a lookup stays pending if the graph drops one of its catalog matches", () => {
  const graph = new EvidenceGraph(4096);
  graph.requestServices([file.name]);
  graph.resolveServices([
    {
      path: file.name,
      services: [
        { name: "retained", source: "catalog#retained" },
        { name: "dropped", source: "x".repeat(8192) },
      ],
    },
  ]);
  assert.equal(summaryFor(graph).services_found, 1);
  assert.equal(graph.serviceResolution().pending, 1);
  assert.equal(graph.serviceResolution().truncated, true);
});

test("a summary counts all retained services and marks a shortened list", () => {
  const graph = new EvidenceGraph();
  const answers = Array.from({ length: 130 }, (_, i) => ({
    path: "file-" + i + ".ts",
    services: [{ name: "workload-" + i }],
    source: "registry",
  }));
  graph.requestServices(answers.map(({ path }) => path));
  graph.resolveServices(answers);
  const summary = summaryFor(graph);
  assert.equal(summary.services_found, 130);
  assert.equal(summary.services.length, 128);
  assert.equal(summary.truncated, true);
  assert.equal(detailFor(graph, "workload-129").node.name, "workload-129");
});

test("a candidate's cited file can be queried without a separate file reference", () => {
  const graph = new EvidenceGraph();
  graph.addTrace(trace(call));
  const result = detailFor(graph, file.name);
  assert.equal(result.node.kind, "file");
  assert.deepEqual(
    result.paths.map(({ line }) => line),
    [12],
  );
});

test("static trace endpoints cannot create named services", () => {
  const graph = new EvidenceGraph();
  graph.addTrace(
    trace({
      ...call,
      step: {
        ...call.step,
        from: { kind: "service", name: "runner" },
        to: { kind: "service", name: "decoder" },
      },
    }),
  );
  assert.equal(summaryFor(graph).services_found, 0);
  assert.equal(summaryFor(graph).code_paths_found, 1);
  assert.equal(detailFor(graph, file.name).paths.length, 1);
  assert.equal(detailFor(graph, "runner").node.kind, "component");
  assert.equal(detailFor(graph, "decoder").node.kind, "component");
  graph.resolveServices([
    {
      path: file.name,
      services: [{ name: "runner" }],
      source: "catalog#runner",
    },
  ]);
  assert.deepEqual(
    matchesFor(graph, "runner").map(({ kind }) => kind),
    ["component", "service"],
  );
});

test("repeated traces share file questions and retain what was checked on a miss", () => {
  const graph = new EvidenceGraph();
  const reference = (path: string): TraceEvidence => ({
    step: {
      from: { kind: "file", name: path },
      relation: "references",
      to: target,
    },
    source: path,
  });
  const result = trace(
    call,
    reference(file.name),
    reference("README.md"),
    reference("package.json"),
    reference("src/parse.js"),
  );
  graph.addTrace(result);
  graph.addTrace(result);
  graph.requestServices([file.name, "src/parse.js"]);
  assert.deepEqual(graph.serviceResolution(), {
    revision: 2,
    pending: 2,
    checked: 0,
    paths: [file.name, "src/parse.js"],
  });
  const miss = { path: file.name, services: [], source: "registry/query-3" };
  graph.resolveServices([miss]);
  graph.resolveServices([miss]);
  assert.deepEqual(graph.serviceResolution(), {
    revision: 3,
    pending: 1,
    checked: 1,
    paths: ["src/parse.js"],
  });
  const record = detailFor(graph, file.name).evidence.find(
    (f) => f.relation === "no_service_found",
  );
  assert.equal(record?.source, miss.source);
});

test("cited directory answers cover past and future files while retaining overlapping applications", () => {
  const graph = new EvidenceGraph();
  const paths = ["src/a.js", "src/nested/b.js", "src2/c.js"];
  graph.addTrace(trace(...paths.map((source) => ({ ...call, source }))));
  const first = {
    path: paths[0],
    directory: "src",
    services: [{ name: "worker", scope: "one" }],
    source: "catalog#one",
  };
  const second = {
    path: paths[1],
    directory: "src/nested",
    services: [{ name: "worker", scope: "two" }],
    source: "catalog#two",
  };
  graph.resolveServices([first, second]);
  graph.requestServices(["src/nested/new.js"]);
  assert.deepEqual(graph.serviceResolution().paths, ["src2/c.js"]);
  assert.equal(graph.serviceResolution().checked, 3);
  assert.deepEqual(
    detailFor(graph, "src/nested/new.js").evidence.map((f) => [
      f.source,
      f.to?.name,
    ]),
    [
      ["catalog#one", "src"],
      ["catalog#two", "src/nested"],
    ],
  );
  const workers = matchesFor(graph, "worker");
  assert.deepEqual(
    workers.map((n) => n.scope),
    ["one", "two"],
  );
  assert.deepEqual(
    detailFor(graph, workers[0]!.id).paths.map((p) => p.source),
    paths.slice(0, 2),
  );
  assert.deepEqual(
    detailFor(graph, workers[1]!.id).paths.map((p) => p.source),
    [paths[1]],
  );
  const revision = graph.serviceResolution().revision;
  graph.resolveServices([first, second]);
  assert.equal(graph.serviceResolution().revision, revision);
});

test("invalid answers leave the whole batch pending and a truncated graph reports incomplete coverage", () => {
  const graph = new EvidenceGraph();
  graph.requestServices([file.name, "src/other.ts"]);
  const miss = { path: file.name, services: [], source: "catalog" };
  const initial = graph.serviceResolution();
  assert.throws(
    () => graph.resolveServices([miss, { ...miss, path: "not-queued.ts" }]),
    /No service question/,
  );
  assert.throws(
    () => graph.resolveServices([{ ...miss, directory: "src" }]),
    /directory mapping/,
  );
  assert.throws(
    () =>
      graph.resolveServices([
        { ...miss, directory: "sr", services: [{ name: "reader" }] },
      ]),
    /directory mapping/,
  );
  assert.deepEqual(graph.serviceResolution(), initial);
  const tiny = new EvidenceGraph(900);
  tiny.requestServices([file.name]);
  tiny.resolveServices([{ ...miss, source: "x".repeat(2048) }]);
  assert.equal(tiny.serviceResolution().pending, 1);
  assert.equal(tiny.serviceResolution().truncated, true);
});

test("a file outside the pending page exposes its lookup state directly", () => {
  const graph = new EvidenceGraph();
  const paths = Array.from({ length: 130 }, (_, i) => `src/file-${i}.ts`);
  graph.requestServices(paths);
  const last = paths[129];
  assert.ok(!graph.serviceResolution().paths.includes(last));
  assert.equal(detailFor(graph, last).service_lookup, "pending");
  graph.resolveServices([
    {
      path: paths[0],
      directory: "src",
      services: [{ name: "backend" }],
      source: "catalog#backend",
    },
  ]);
  assert.equal(detailFor(graph, last).service_lookup, "checked");
  assert.equal(detailFor(graph, "backend").service_lookup, undefined);
  graph.requestServices(["other.ts"]);
  graph.resolveServices([
    { path: "other.ts", services: [], source: "catalog" },
  ]);
  assert.equal(detailFor(graph, "other.ts").service_lookup, "checked");
});

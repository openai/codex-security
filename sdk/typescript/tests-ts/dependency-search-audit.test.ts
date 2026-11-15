import { expect, test } from "bun:test";
import { DependencySearchAudit } from "../src/dependency-search-audit.js";

test("audits source scope, truncation, errors and registered tools that never ran", () => {
  const audit = new DependencySearchAudit();
  const trace = {
    tool: "trace_codex_security_code",
    id: "trace-1",
    arguments: {
      paths: ["sources"],
      package: "sample-codec",
      rules: [{ id: "find-wrapper" }],
      source_only: true,
    },
  };
  audit.observeGraph("item/started", trace);
  audit.observeGraph("item/completed", {
    ...trace,
    status: "completed",
    result: {
      structuredContent: {
        coverage: {
          complete: false,
          searched_paths: ["sources"],
          partial: [{ path: "sources/extra", reason: "Time limit" }],
          frontier: [{ path: "sources/later" }],
          discovery_omissions: [
            { path: "examples/demo.py", excludedBy: "examples" },
          ],
        },
        trace: [{ source: "sources/worker.ts" }],
        ruleExecutions: [{ id: "rule-1" }],
      },
    },
  });
  audit.observeGraph("item/completed", {
    ...trace,
    id: "trace-2",
    status: "failed",
    error: "Timed out",
  });
  const searches = audit.snapshot(["fixture_tools"]);
  expect(searches).toMatchObject([
    {
      startedAt: expect.any(String),
      finishedAt: expect.any(String),
      result: "matches",
      completeness: "partial",
      evidenceReferences: ["rule-1"],
    },
    {
      startedAt: null,
      result: "unknown",
      completeness: "error",
      details: expect.arrayContaining(["Timed out"]),
    },
    { source: "fixture_tools", result: "not_run", completeness: "skipped" },
  ]);
  expect(searches[0]!.scope).toContain('rules=["find-wrapper"]');
  expect(searches[0]!.details).toContain(
    "Incomplete: path=sources/extra · Time limit",
  );
  expect(searches[0]!.details).toContain("Not visited: path=sources/later");
  expect(searches[0]!.details).toContain(
    'Broad discovery omitted "examples/demo.py" under operator exclusion "examples".',
  );
});

test("observes partial no-match and treats an empty payload as unknown coverage", () => {
  const audit = new DependencySearchAudit();
  const metadata = {
    tool: "find_job",
    arguments: {
      run_id: "run-a",
      environment: "prod",
      token: "fixture-secret",
    },
    startedAt: "2026-01-01T10:00:00Z",
    finishedAt: "2026-01-01T10:00:01Z",
  };
  audit.recordInventory(
    "inventory-1",
    "jobs",
    {
      structuredContent: {
        outcome: "no_match",
        coverage: { complete: true, truncated: true },
      },
    },
    metadata,
  );
  audit.recordInventory("inventory-2", "jobs", null, {
    ...metadata,
    outcome: "empty",
  });
  audit.recordInventory("inventory-3", "other", {}, { outcome: "unavailable" });
  const searches = audit.snapshot([]);
  expect(searches).toMatchObject([
    {
      source: "jobs",
      result: "no_match",
      completeness: "partial",
      startedAt: metadata.startedAt,
      finishedAt: metadata.finishedAt,
      evidenceReferences: ["inventory-1"],
    },
    {
      source: "jobs",
      result: "unknown",
      completeness: "unknown",
      evidenceReferences: ["inventory-2"],
    },
    {
      source: "other",
      result: "not_run",
      completeness: "unavailable",
      evidenceReferences: ["inventory-3"],
    },
  ]);
  expect(searches[0]!.scope).toContain("run_id=run-a");
  expect(JSON.stringify(searches)).not.toContain("fixture-secret");
});

test("preserves partial inventory when the native MCP envelope also carries a neutral structured projection", () => {
  const audit = new DependencySearchAudit();
  const payload = {
    data: {
      footprints: [],
      serviceName: "fixture-worker",
      metadata: {
        partial: true,
        clusters_queried: 19,
        unavailableClusters: ["fixture-remote"],
      },
    },
  };
  const args = { service_name: "fixture-worker" };
  for (const [index, result] of [
    { content: [{ type: "text", text: JSON.stringify(payload) }] },
    {
      structuredContent: {},
      content: [{ type: "text", text: JSON.stringify(payload) }],
    },
    {
      structured_content: { complete: true },
      content: [
        { type: "text", text: "Additional transport information" },
        { type: "text", text: JSON.stringify(payload) },
      ],
    },
    {
      structured_content: {
        content: [{ type: "text", text: JSON.stringify(payload) }],
      },
    },
  ].entries()) {
    audit.recordInventory(`inventory-${index}`, "fixture_catalog", result, {
      tool: "inventory_footprint",
      arguments: args,
    });
  }
  const completed = {
    data: {
      ...payload.data,
      footprints: [{ workload: "fixture-id" }],
      metadata: { complete: true },
    },
  };
  audit.recordInventory(
    "inventory-4",
    "fixture_catalog",
    { structuredContent: completed },
    { tool: "inventory_footprint", arguments: args },
  );
  const output = audit.snapshot([]);
  expect(output).toHaveLength(5);
  for (const row of output.slice(0, 4)) {
    expect(row).toMatchObject({
      result: "no_match",
      completeness: "partial",
      scope: expect.arrayContaining(["service_name=fixture-worker"]),
      details: [
        "0 footprints returned for fixture-worker.",
        "19 clusters queried.",
        "Unavailable clusters: fixture-remote.",
        "No match was observed within this lookup's reported scope.",
      ],
    });
  }
  expect(output[4]).toMatchObject({
    result: "matches",
    completeness: "complete",
  });
});

const podQueryArgs = {
  query:
    'pods\n| where cluster in ("fixture-a", "fixture-b") and namespace == "fixture-ns" and servicename in ("api", "worker")\n| project cluster, namespace\n| take 50',
  mode: "partial",
};
const snapshotTime = "2026-01-01T01:00:10.123456789Z";
const archiveTime = "2026-01-01T02:00:45.567Z";
const completionTime = "2026-02-01T02:01:00.000Z";

function table(snapshot: unknown = snapshotTime) {
  return {
    columns: [{ name: "cluster", type: "string" }],
    coverage: [
      { cluster: "fixture-a", resource: "pods", snapshotAt: snapshot },
    ],
    rows: [{ secret: "opaque-do-not-emit" }],
    stats: { truncated: false },
  };
}

const textEnvelope = (text: string) => ({ content: [{ type: "text", text }] });

test("detects transport text truncation despite parseable results and preserves returned matches", () => {
  const truncated = '{"rows":[…13 chars truncated…';
  const complete = { complete: true, status: "matched" };
  const audit = new DependencySearchAudit();
  for (const [index, result] of [
    textEnvelope(truncated),
    textEnvelope(
      JSON.stringify({
        content: [
          { type: "text", text: JSON.stringify(complete) },
          { type: "text", text: truncated },
        ],
      }),
    ),
    textEnvelope(
      JSON.stringify({ ...complete, rows: ["head…13 chars truncated…tail"] }),
    ),
  ].entries()) {
    audit.recordInventory(`inventory-${index}`, "fixture", result, {
      tool: "fixture_query",
      arguments: {},
    });
  }
  expect(audit.snapshot([])).toMatchObject([
    { completeness: "partial", result: "returned" },
    { completeness: "partial", result: "matches" },
    { completeness: "partial", result: "matches" },
  ]);
});

test("keeps plain text and structured row values distinct from a transport omission marker", () => {
  const audit = new DependencySearchAudit();
  audit.recordInventory(
    "inventory-1",
    "fixture",
    {
      ...textEnvelope("Output may be truncated."),
      structuredContent: {
        complete: true,
        status: "matched",
        rows: ["Example notation: …13 chars truncated…"],
      },
    },
    { tool: "fixture_query", arguments: {} },
  );
  expect(audit.snapshot([])[0]).toMatchObject({
    completeness: "complete",
    result: "matches",
  });
});

function stagedPodAudit(value: unknown, args = podQueryArgs) {
  const audit = new DependencySearchAudit();
  audit.recordInventory("inventory-1", "fixture", value, {
    tool: "kube-lens-query",
    arguments: args,
    finishedAt: completionTime,
  });
  return audit.snapshot([])[0]!;
}

test("exposes compressed exact pod selectors and separates saved, snapshot and completion clocks", () => {
  const raw = JSON.stringify(table()).replace(
    '"opaque-do-not-emit"',
    '"opa…150 chars truncated…em',
  );
  const nested = {
    ...textEnvelope(JSON.stringify(textEnvelope(raw))),
    structuredContent: null,
    _meta: {
      offlineReplay: {
        original_recorded_at: archiveTime,
        artifact: "opaque-source",
      },
    },
  };
  const audit = stagedPodAudit(nested);
  expect(audit).toMatchObject({
    completeness: "partial",
    result: "returned",
    startedAt: null,
    finishedAt: completionTime,
    scope: expect.arrayContaining([
      "mode=partial",
      "resource=pods",
      'cluster=["fixture-a","fixture-b"]',
      "namespace=fixture-ns",
      'service=["api","worker"]',
    ]),
    details: [
      "The inventory query requested partial coverage.",
      `Archived response originally recorded at ${archiveTime}.`,
      `Pod inventory snapshot for fixture-a at ${snapshotTime}.`,
    ],
  });
  expect(JSON.stringify(audit)).not.toContain("opaque");
  expect(JSON.stringify(audit)).not.toContain("project cluster");
});

test("reports conflicting native coverage timestamps and does not guess absent dates", () => {
  const withoutDates = stagedPodAudit({ structuredContent: table(null) });
  expect(withoutDates.details).toEqual([
    "The inventory query requested partial coverage.",
  ]);
  const later = "2026-01-01T04:00:12.111Z";
  const conflict = stagedPodAudit({
    structuredContent: table(later),
    ...textEnvelope(JSON.stringify(table())),
  });
  expect(conflict.details).toContain(
    "Pod inventory snapshot for fixture-a at: conflicting captured timestamps.",
  );
  expect(conflict.details.join()).not.toContain(snapshotTime);
  expect(conflict.details.join()).not.toContain(later);
  const ambiguous = stagedPodAudit(
    textEnvelope(
      JSON.stringify(table()).replace('"opaque-do-not-emit"', '"malformed'),
    ),
    { ...podQueryArgs, mode: "strict" },
  );
  expect(ambiguous.completeness).toBe("unknown");
  expect(ambiguous.details).toEqual([]);
});

test("partial scope stays neutral payload evidence, while complete JSON may explicitly mark truncation", () => {
  expect(
    stagedPodAudit({ structuredContent: { complete: true } }),
  ).toMatchObject({ completeness: "partial", result: "returned" });
  const truncated = stagedPodAudit(
    { structuredContent: { ...table(), stats: { truncated: true } } },
    { ...podQueryArgs, mode: "strict" },
  );
  expect(truncated).toMatchObject({
    completeness: "partial",
    result: "returned",
  });
  const malformedHeader =
    '{"columns":[],"coverage":[{"cluster":"fixture-a","resource":"pods"}],"rows":[{} …150 chars truncated…';
  expect(
    stagedPodAudit(textEnvelope(malformedHeader), {
      ...podQueryArgs,
      mode: "strict",
    }).details,
  ).toEqual([]);
  const queryWithUnsupportedPredicate = stagedPodAudit(
    {},
    {
      ...podQueryArgs,
      query: 'pods\n| where namespace == "fixture-ns" or name == "hidden"',
    },
  );
  expect(queryWithUnsupportedPredicate.scope).not.toContain(
    "namespace=fixture-ns",
  );
  expect(JSON.stringify(queryWithUnsupportedPredicate)).not.toContain("hidden");
});

test("bound registry provenance identifies its exact image and timestamp without inferring deployment", () => {
  const uri = "example.invalid/api@sha256:aa";
  const metadata = {
    status: "verified",
    image: uri,
    environment: "prod",
    observed_at: archiveTime,
    complete: true,
  };
  const audit = new DependencySearchAudit();
  const mcp = {
    tool: "images.provenance",
    arguments: { image_ref: uri, environment: "prod" },
    finishedAt: completionTime,
  };
  audit.recordInventory(
    "inventory-1",
    "fixture",
    { structuredContent: metadata },
    mcp,
  );
  audit.recordInventory(
    "inventory-2",
    "fixture",
    { structuredContent: { ...metadata, image: "example.invalid/other" } },
    mcp,
  );
  expect(audit.snapshot([])).toMatchObject([
    {
      finishedAt: completionTime,
      completeness: "complete",
      result: "returned",
      scope: expect.arrayContaining([`image_ref=${uri}`, "environment=prod"]),
      details: [`Image provenance observed at ${archiveTime}.`],
    },
    { finishedAt: completionTime, details: [] },
  ]);
});

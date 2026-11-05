import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { importSource } from "./import-module.ts";
import { after, test } from "node:test";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import {
  coordinatorFixture,
  promptContext,
  runCoordinator,
  standardScanDraft,
  temporaryDirectories,
} from "./deep_scan_coordinator_fixture.ts";

const { recordCodexSecurityWorkerScanDraft } = await importSource(
  join(import.meta.dirname, "../src/artifact-scan-draft.ts"),
);
after(() => temporaryDirectories.cleanup());
const base = standardScanDraft("fixture", "one", "worker").findings[0]!;
const lookup = {
  ...base,
  codeEvidence: [
    {
      id: "lookup",
      label: "Lookup",
      explanation: "Lookup site",
      path: "fixture.py",
      startLine: 1,
      code: "lookup(id)",
    },
  ],
};
type Report = {
  id: number;
  title: string;
  locations: [string, ...unknown[]][];
  evidence: unknown[];
};
type PairCheck = {
  pairs: { id: number; left: number; right: number }[];
  reports: {
    id: number;
    primary: { title: string; evidence: unknown[] };
    attached: { title: string }[];
  }[];
};

function samePair(pair: number) {
  return {
    pair,
    decision: "same",
    reason: "One fix",
    leftEvidence: 0,
    rightEvidence: 0,
  };
}

function approvePairs({ pairs }: PairCheck) {
  return { reviews: pairs.map(({ id }) => samePair(id)) };
}

async function scanLoop(
  observations: ScanDraftInput["findings"][],
  config: {
    workers?: number;
    maxDiscoveryRuns: number;
    stopAfterNoNew: number;
    comparisons?: (number[][] | ((input: Report[]) => unknown))[];
    sameFix?: (input: PairCheck) => unknown;
    sameSource?: (a: string, b: string) => boolean;
  },
  finish?: (index: number) => Promise<void>,
) {
  const { comparisons = [], sameFix, sameSource, ...limits } = config;
  const { fixture, store } = await coordinatorFixture(limits);
  let comparisonsRun = 0;
  let draft: ScanDraftInput | undefined;
  const started: number[] = [];
  const previousByPass: string[][] = [];
  const terminal = await runCoordinator(
    fixture,
    store,
    {
      async compareFindings(prompt, _cwd, _signal, schema) {
        if ("sources" in (schema.properties as object)) {
          const rows: {
            id: number;
            A: { title: string };
            B: { title: string };
          }[] = JSON.parse(prompt.split("\n").at(-1)!);
          return JSON.stringify({
            sources: rows.map(({ id, A, B }) => ({
              id,
              same: sameSource?.(A.title, B.title) ?? true,
              survivingPaths: [],
            })),
          });
        }
        if ("reviews" in (schema.properties as object)) {
          const input = JSON.parse(prompt.split("\n").at(-1)!) as PairCheck;
          return JSON.stringify(sameFix?.(input) ?? { reviews: [] });
        }
        const input = JSON.parse(prompt.split("\n").at(-1)!) as Report[];
        const groups = comparisons[comparisonsRun++]!;
        if (typeof groups === "function") return JSON.stringify(groups(input));
        return JSON.stringify({
          uncertain: [],
          defects: groups.map((group, index) => ({
            operation: String(index),
            failure: "fixture defect",
            path: input[group[0]].locations[0][0],
            reports: group.map((id) => ({ id, evidence: 0 })),
          })),
        });
      },
      async run(request) {
        assert.equal(request.kind, "discovery");
        const { workerLabel, previousFindings } = await promptContext(
          request.promptPath,
        );
        const index = Number(workerLabel.split("-")[1]) - 1;
        previousByPass[index] = previousFindings ?? [];
        started.push(index);
        assert.ok(observations[index], "unexpected additional scan");
        await finish?.(index);
        await recordCodexSecurityWorkerScanDraft(
          {
            root: request.workingDirectory,
            repoRoot: fixture.run.targetPath,
            layout: "worker",
            scanId: fixture.run.scanId,
          },
          {
            ...standardScanDraft(fixture.run.scanId, undefined, workerLabel),
            findings: observations[index],
          },
        );
        return {};
      },
    },
    {
      onComplete: async (result) => {
        draft = result;
      },
    },
  );
  assert.equal(terminal?.status, "succeeded", terminal?.error);
  assert.ok(draft);
  assert.equal(comparisonsRun, comparisons.length);
  return { terminal, draft, started, previousByPass };
}

test("a duplicate stops the loop and every observation survives", async () => {
  const alias = {
    ...base,
    title: "A different description",
    severity: { level: "critical" as const },
    provenance: { source: "local_plugin" },
  };
  const { terminal, draft, started } = await scanLoop([[base], [alias]], {
    maxDiscoveryRuns: 8,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1]]],
  });
  assert.deepEqual(started, [0, 1]);
  assert.equal(terminal.terminalReason, "saturated");
  assert.equal(draft.findings.length, 1);
  assert.deepEqual(draft.findings[0].severity, base.severity);
  assert.deepEqual(
    draft.findings[0].provenance.sourceFindings?.map((x) => x.finding.title),
    [base.title, alias.title],
  );
  assert.deepEqual(
    draft.findings[0].provenance.sourceFindings?.map((x) => x.finding.severity),
    [base.severity, alias.severity],
  );
});

test("an exact repeat of a merged source saturates without another comparison", async () => {
  const alias = {
    ...base,
    title: "Another description of the same sink",
    severity: { level: "medium" as const },
    locations: [...base.locations, { path: "caller.py", startLine: 12 }],
  };
  const { terminal, draft } = await scanLoop([[base, alias], [alias]], {
    maxDiscoveryRuns: 4,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1]]],
  });
  assert.equal(terminal.terminalReason, "saturated");
  assert.equal(draft.findings.length, 1);
  assert.deepEqual(draft.findings[0].severity, base.severity);
  assert.deepEqual(
    draft.findings[0].provenance.sourceFindings?.map((x) => x.finding.severity),
    [base.severity, alias.severity, alias.severity],
  );
});

test("reordered extension fields do not spend a comparison or restart the no-new streak", async () => {
  const first = {
    ...base,
    extensions: { observed: { input: "request", operation: "lookup" } },
  };
  const repeat = {
    ...base,
    extensions: { observed: { operation: "lookup", input: "request" } },
  };
  const { terminal, draft } = await scanLoop([[first], [repeat]], {
    maxDiscoveryRuns: 2,
    stopAfterNoNew: 1,
  });
  assert.equal(terminal.terminalReason, "saturated");
  assert.equal(draft.findings.length, 1);
  assert.equal(draft.findings[0].provenance.sourceFindings?.length, 2);
});

test("one scan's distinct rule and anchor survive a cross-scan alias", async () => {
  const extract = {
    ...base,
    codeEvidence: [
      {
        id: "destination",
        label: "Destination",
        explanation: "Both operations call this helper.",
        path: "fixture.py",
        startLine: 1,
        code: "remove(path)",
      },
    ],
    ruleId: "archive.extract",
    identity: { anchor: "extract.destination" },
  };
  const remove = {
    ...extract,
    ruleId: "plugin.delete",
    identity: { anchor: "delete.plugin" },
  };
  const alias = {
    ...extract,
    ruleId: "archive.write",
    identity: { anchor: "archive.destination" },
  };
  const { draft } = await scanLoop([[extract, remove], [alias]], {
    maxDiscoveryRuns: 2,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1]], [[0, 2], [1]]],
    sameFix: () => ({ reviews: [samePair(0)] }),
  });
  assert.deepEqual(
    draft.findings.map((f) => f.provenance.sourceFindings?.length),
    [2, 1],
  );
});

test("a concrete named input unique to one report survives a shared helper", async () => {
  const keys = {
    ...base,
    title: "Iterator entries are skipped",
    ruleId: "object.entries",
    identity: { anchor: "object.walk", instance: "non-enumerated-entries" },
  };
  const packet = {
    ...base,
    title: "Packet bytes pass through unchanged",
    ruleId: "object.bytes",
    identity: { anchor: "object.dispatch", instance: "packet" },
  };
  const { draft } = await scanLoop([[keys], [packet]], {
    maxDiscoveryRuns: 2,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1]]],
  });
  assert.equal(draft.findings.length, 2);
});

test("an additional affected endpoint survives a narrower report with a different weakness", async () => {
  const disclosure = {
    ...base,
    title: "Debug endpoint returns secrets",
    taxonomy: { category: "Disclosure", cwe: ["CWE-200"] },
    locations: [{ path: "debug.ts", startLine: 3, role: "sink" }],
  };
  const access = {
    ...disclosure,
    title: "Service accounts can read debug output and stop the server",
    taxonomy: { category: "Authorization", cwe: ["CWE-862"] },
    locations: [
      ...disclosure.locations,
      { path: "stop.ts", startLine: 8, role: "impact_sink" },
    ],
  };
  const alias = {
    ...disclosure,
    title: "Debug endpoint exposes passwords",
    taxonomy: { category: "Disclosure", cwe: ["CWE-201"] },
  };
  const { draft } = await scanLoop([[access], [disclosure], [alias]], {
    workers: 3,
    maxDiscoveryRuns: 3,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1, 2]]],
  });
  assert.deepEqual(
    draft.findings.map((f) =>
      f.provenance.sourceFindings?.map((x) => x.finding.title),
    ),
    [[access.title], [disclosure.title, alias.title]],
  );
});

test("overlapping lists of affected endpoints retain the additional fix", async () => {
  const sink = (path: string) => ({ path, startLine: 1, role: "sink" });
  const routes = {
    ...base,
    title: "Unprivileged users may deregister routes and fail directories",
    locations: [sink("deregister.ts"), sink("fail.ts")],
  };
  const admin = {
    ...routes,
    title: "The same users can also stop the service",
    locations: [...routes.locations, sink("stop.ts")],
  };
  const { draft } = await scanLoop([[routes], [admin]], {
    workers: 2,
    maxDiscoveryRuns: 2,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1]]],
  });
  assert.deepEqual(
    draft.findings.map((f) => f.title),
    [routes.title, admin.title],
  );
});

test("a new instance extends the loop and an unfinished final batch respects the cap", async () => {
  const other = {
    ...base,
    locations: [
      { path: "fixture.py", startLine: 22, role: "entrypoint" },
      { path: "fixture.py", startLine: 35, role: "root_control" },
    ],
  };
  const gate = Promise.withResolvers<void>();
  const { terminal, draft, started, previousByPass } = await scanLoop(
    [[base], [other], [base]],
    {
      maxDiscoveryRuns: 3,
      stopAfterNoNew: 3,
      workers: 2,
      comparisons: [[[0], [1]]],
    },
    async (index) => {
      if (index === 0) await gate.promise;
      if (index === 1) gate.resolve();
    },
  );
  assert.deepEqual(started.sort(), [0, 1, 2]);
  assert.deepEqual(previousByPass, [
    [],
    [],
    [`fixture.py:1 ${base.title}`, `fixture.py:35 ${other.title}`],
  ]);
  assert.equal(terminal.terminalReason, "capped");
  assert.deepEqual(
    draft.findings.map((f) => f.locations[0].startLine),
    [1, 22],
  );
  assert.ok(Array.isArray(draft.reviewState.reviews));
  assert.equal(draft.reviewState.reviews.length, 3);
});

test("an empty first scan is a completed scan with no new findings", async () => {
  const { started, terminal, draft } = await scanLoop([[]], {
    maxDiscoveryRuns: 5,
    stopAfterNoNew: 1,
  });
  assert.deepEqual(started, [0]);
  assert.equal(terminal.terminalReason, "saturated");
  assert.deepEqual(draft.findings, []);
});

test("distinct operations on the same line stay separate when a matching report is relabeled", async () => {
  const at = (code: string) => ({
    id: "sink",
    label: "Operation",
    explanation: "The query executes here.",
    path: "fixture.py",
    startLine: 1,
    code,
  });
  const identity = { anchor: "query" };
  const read = { ...base, identity, codeEvidence: [at("query(read)")] };
  const write = { ...base, identity, codeEvidence: [at("query(write)")] };
  const alias = {
    ...read,
    ruleId: "sql-injection.alias",
    title: "Unescaped read query",
  };
  const { draft } = await scanLoop([[read], [write], [alias]], {
    maxDiscoveryRuns: 3,
    stopAfterNoNew: 1,
    comparisons: [
      [[0], [1]],
      [[0, 2], [1]],
    ],
  });
  assert.deepEqual(
    draft.findings.map((f) => f.provenance.sourceFindings?.length),
    [2, 1],
  );
});

test("distinct named siblings survive an unnamed representative", async () => {
  const first = {
    ...base,
    identity: { anchor: "db.query", instance: "tenant" },
  };
  const second = {
    ...base,
    identity: { anchor: "db.query", instance: "account" },
  };
  const { draft } = await scanLoop([[base], [first], [second], [first]], {
    maxDiscoveryRuns: 4,
    stopAfterNoNew: 2,
    comparisons: [[[0, 1]], [[0, 1]]],
  });
  assert.deepEqual(
    draft.findings.map((finding) => finding.provenance.sourceFindings?.length),
    [3, 1],
  );
});

test("matching source excerpts distinguish different bugs and tolerate a different entry point", async () => {
  const location = { path: "fixture.py", startLine: 2, endLine: 3 };
  const code = {
    ...location,
    id: "control",
    label: "Object traversal",
    explanation: "The middleware cleans each value.",
    code: "for name in fields:\n  clean(fields[name])",
  };
  const keys = {
    ...base,
    ruleId: "unfiltered.keys",
    identity: { anchor: "sanitize.fields", instance: "key-not-value" },
    title: "Unfiltered property names reach the renderer",
    rootCause:
      "The traversal sanitizes values but preserves unfiltered property names.",
    locations: [location],
    codeEvidence: [code],
  };
  const other = {
    ...keys,
    ruleId: "unsupported.container",
    title: "A map retains executable markup",
    rootCause: "A map exposes entries outside enumerable fields.",
  };
  const alias = {
    ...keys,
    ruleId: "unsafe.property.names",
    identity: { anchor: "sanitize.property.names", instance: "key-not-value" },
    title: "Property names escape sanitization",
    locations: [
      { path: "fixture.py", startLine: 1, role: "entrypoint" },
      { ...location, role: "root_control" },
    ],
    codeEvidence: [{ ...code, startLine: 3, code: "clean(fields[name])" }],
  };
  const { draft } = await scanLoop([[keys], [other], [alias]], {
    maxDiscoveryRuns: 3,
    stopAfterNoNew: 1,
    comparisons: [
      [[0], [1]],
      [[0, 2], [1]],
    ],
  });
  assert.deepEqual(
    draft.findings[0].locations.map((l) => l.startLine),
    [2, 1],
  );
  assert.deepEqual(
    draft.findings.map((f) => f.provenance.sourceFindings?.length),
    [2, 1],
  );
});

test("a report requiring both repairs stays separate from reports covering either one", async () => {
  const left = { ...base, title: "Upload accepts another user's object" };
  const broad = {
    ...base,
    title: "Upload and delete accept another user's object",
  };
  const right = { ...base, title: "Delete accepts another user's object" };
  const alias = {
    ...left,
    title: "Foreign object accepted during upload",
    ruleId: "object.ownership",
    taxonomy: { category: "authorization", cwe: ["CWE-862"] },
    locations: [...base.locations, { path: "upload.py", startLine: 18 }],
  };
  const { draft } = await scanLoop([[left], [broad], [right], [alias]], {
    workers: 4,
    maxDiscoveryRuns: 4,
    stopAfterNoNew: 1,
    comparisons: [
      [
        [0, 1, 3],
        [1, 2],
      ],
    ],
  });
  assert.deepEqual(
    draft.findings.map((f) =>
      f.provenance.sourceFindings?.map((s) => s.finding.title),
    ),
    [[left.title, alias.title], [broad.title], [right.title]],
  );
  assert.deepEqual(
    draft.findings[0].locations.map((l) => l.path),
    ["fixture.py", "upload.py"],
  );
});

test("an incomplete comparison keeps unlisted reports and merges supported duplicates", async () => {
  const other = { ...base, title: "Another defect" };
  const alias = { ...base, title: "Another observation of the first defect" };
  const { draft } = await scanLoop([[base, alias], [other]], {
    workers: 2,
    maxDiscoveryRuns: 2,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1]]],
  });
  assert.deepEqual(
    draft.findings.map((f) => f.title),
    [base.title, other.title],
  );
  assert.match(draft.scope?.limitations?.[0] ?? "", /omitted 1 of 3 reports/);
});

test("a failed comparison keeps both reports and records why", async () => {
  const other = { ...base, title: "Another defect" };
  const { draft } = await scanLoop([[base, other]], {
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 1,
    comparisons: [
      () => {
        throw new Error("comparison unavailable");
      },
    ],
  });
  assert.equal(draft.findings.length, 2);
  assert.match(draft.scope?.limitations?.[0] ?? "", /comparison unavailable/);
});

test("a repair citing evidence absent from its report cannot absorb it", async () => {
  const other = { ...base, title: "Independent operation" };
  const { draft } = await scanLoop([[base], [other]], {
    workers: 2,
    maxDiscoveryRuns: 2,
    stopAfterNoNew: 1,
    comparisons: [
      (rows) => ({
        uncertain: [],
        defects: [
          {
            operation: "query",
            failure: "missing check",
            path: base.locations[0].path,
            reports: rows.map(({ id, evidence }) => ({
              id,
              evidence: id === 0 ? 0 : evidence.length,
            })),
          },
        ],
      }),
    ],
  });
  assert.deepEqual(
    draft.findings.map((f) => f.title),
    [base.title, other.title],
  );
});

test("one code-supported edit merges a disputed pair and keeps the broader report visible", async () => {
  const code = {
    id: "read",
    label: "Read",
    explanation: "Unchecked read",
    path: "fixture.py",
    startLine: 1,
    code: "load(id)",
  };
  const read = { ...base, codeEvidence: [code] };
  const broad = { ...read, title: "Read and delete lack ownership checks" };
  const alias = { ...read, title: "Another user's object can be read" };
  const { draft, terminal } = await scanLoop([[read], [broad], [alias]], {
    workers: 3,
    maxDiscoveryRuns: 3,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1, 2], [1], [2]]],
    sameFix({ pairs }) {
      return {
        reviews: pairs
          .filter(({ left, right }) => left === 0 && right === 2)
          .map(({ id }) => samePair(id)),
      };
    },
  });
  assert.equal(terminal.terminalReason, "saturated");
  assert.deepEqual(
    draft.findings.map((f) =>
      f.provenance.sourceFindings?.map((s) => s.finding.title),
    ),
    [[read.title, alias.title], [broad.title]],
  );
});

test("missing assignments can merge on cited code, without chaining through a discarded report", async () => {
  const records = ["A", "B", "C"].map((title) => ({ ...lookup, title }));
  const { draft } = await scanLoop([records], {
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 1,
    comparisons: [() => ({ uncertain: [0, 1, 2], defects: [] })],
    sameFix({ pairs }) {
      assert.deepEqual(
        pairs.map(({ left, right }) => [left, right]),
        [
          [0, 1],
          [0, 2],
          [1, 2],
        ],
      );
      return {
        reviews: pairs.map(({ id }) => ({
          ...samePair(id),
          leftEvidence: id === 1 ? 99 : 0,
        })),
      };
    },
  });
  assert.deepEqual(
    draft.findings.map((f) =>
      f.provenance.sourceFindings?.map((s) => s.finding.title),
    ),
    [["A", "B"], ["C"]],
  );
});

test("a surviving path in an attached original vetoes a proposed match", async () => {
  const [read, detail, both] = [
    "Read lacks an owner check",
    "Read leaks an attachment",
    "Read and delete lack owner checks",
  ].map((title) => ({ ...lookup, title }));
  let checked = false;
  const { draft } = await scanLoop([[read, detail, both]], {
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1, 2], [2]]],
    sameFix({ pairs, reports }) {
      assert.deepEqual(
        reports.find((r) => r.id === 0)?.attached.map((s) => s.title),
        [detail.title],
      );
      return { reviews: [samePair(pairs[0].id)] };
    },
    sameSource(a, b) {
      if ([a, b].includes(detail.title)) {
        checked = true;
        return false;
      }
      return true;
    },
  });
  assert.ok(checked);
  assert.deepEqual(
    draft.findings.map((f) => f.title),
    [read.title, both.title],
  );
});

test("a source listing additional affected handlers stays separate even when the comparison approves", async () => {
  const sink = (path: string) => ({ path, startLine: 1, role: "sink" });
  const code = {
    id: "body",
    label: "Body read",
    explanation: "The handler reads the entire body.",
    path: "first.py",
    startLine: 1,
    code: "read_body()",
  };
  const first = {
    ...base,
    codeEvidence: [code],
    locations: [sink("first.py")],
  };
  const two = {
    ...first,
    title: "Two handlers read unbounded bodies",
    locations: [...first.locations, sink("second.py")],
  };
  const three = {
    ...two,
    title: "A third handler also reads unbounded bodies",
    locations: [...two.locations, sink("third.py")],
  };
  const { draft } = await scanLoop([[first, three, two]], {
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1, 2], [2]]],
    sameFix: approvePairs,
  });
  assert.deepEqual(
    draft.findings.map((f) => f.provenance.sourceFindingIds?.length),
    [2, 1],
  );
});

test("fixing login cannot hide a separately cited permissive action policy", async () => {
  const login = {
    ...base,
    title: "Admin routes allow anonymous access",
    taxonomy: { category: "authentication", cwe: ["CWE-306"] },
    locations: [{ path: "login.py", startLine: 1, role: "root_control" }],
    codeEvidence: [
      {
        id: "login",
        label: "Login callback",
        explanation: "The callback is empty.",
        path: "login.py",
        startLine: 1,
        code: "def login(): pass",
      },
    ],
  };
  const policy = {
    ...login,
    title: "Any signed-in user can also administer records",
    taxonomy: { category: "access control", cwe: ["CWE-306", "CWE-862"] },
    locations: [
      ...login.locations,
      { path: "policy.py", startLine: 2, role: "control" },
    ],
  };
  // The primary comparison can agree on a single repair or send the pair to confirmation.
  for (const assignments of [[[0, 1]], [[0, 1], [1]]]) {
    const { draft } = await scanLoop([[login, policy]], {
      maxDiscoveryRuns: 1,
      stopAfterNoNew: 1,
      comparisons: [assignments],
      sameFix: approvePairs,
    });
    assert.deepEqual(
      draft.findings.map((f) => f.title),
      [login.title, policy.title],
    );
  }
});

test("a later source with a surviving path reopens the merge and counts as new", async () => {
  const [left, alias, broad] = [
    "Unchecked lookup",
    "Another lookup caller",
    "Lookup also lacks a deadline",
  ].map((title) => ({ ...lookup, title }));
  const { draft, terminal } = await scanLoop([[left, alias], [broad]], {
    workers: 1,
    maxDiscoveryRuns: 2,
    stopAfterNoNew: 1,
    comparisons: [
      [[0, 1], [1]],
      [[0, 2], [1]],
    ],
    sameFix: approvePairs,
    sameSource: (a, b) => ![a, b].includes(broad.title),
  });
  assert.equal(terminal.terminalReason, "capped");
  assert.deepEqual(
    draft.findings.map((f) =>
      f.provenance.sourceFindings?.map((s) => s.finding.title),
    ),
    [[left.title, broad.title], [alias.title]],
  );
});

test("a context fallback rechecks a prior consolidation before counting it as new", async () => {
  const [left, alias, clarification] = [
    "Unchecked lookup",
    "Another lookup caller",
    "More detail on the lookup",
  ].map((title) => ({ ...lookup, title }));
  const { draft, terminal } = await scanLoop([[left, alias], [clarification]], {
    workers: 1,
    maxDiscoveryRuns: 2,
    stopAfterNoNew: 1,
    comparisons: [
      [[0, 1], [1]],
      () => {
        throw new Error("Codex ran out of room in the model's context window.");
      },
      [[0, 1], [2]],
    ],
    sameFix: approvePairs,
  });
  assert.equal(draft.findings.length, 1);
  assert.equal(draft.findings[0]!.provenance.sourceFindings?.length, 3);
  assert.equal(terminal.terminalReason, "saturated");
});

test("a failed comparison waits for every started worker batch", async () => {
  const { checkSameFix } = await importSource(
    join(import.meta.dirname, "../src/deep-scan/same-fix.ts"),
  );
  const groups = [0, 1, 2].map((id) => ({ id, worker: id }));
  const records = groups.map(() => ({
    locations: [["fixture.py", 1, 1]],
    evidence: [["fixture.py", "lookup(id)"]],
  }));
  const release = Promise.withResolvers<void>();
  let started = 0;
  let finished = false;
  const check = checkSameFix(
    groups,
    [],
    records,
    new Map(),
    new Map(groups.map(({ id }) => [id, [lookup]])),
    async () => {
      if (++started === 1) throw new Error("comparison failed");
      await release.promise;
      return JSON.stringify({ reviews: [] });
    },
    (error: unknown) => {
      throw error;
    },
  );
  const rejected = assert.rejects(check, /comparison failed/).then(() => {
    finished = true;
  });
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(started, 2);
  assert.equal(finished, false);
  release.resolve();
  await rejected;
});

test("a saved same-fix merge keeps both original comparison inputs on resume", async () => {
  const { mergeBatch } = await importSource(
    join(import.meta.dirname, "../src/deep-scan/iteration.ts"),
  );
  const { parseScanUnion, persistedScanUnion, scanUnionToDraft } =
    await importSource(
      join(import.meta.dirname, "../src/deep-scan/artifact-validation.ts"),
    );
  const [left, alias, unrelated] = [
    "Unchecked lookup",
    "Same lookup through a caller",
    "Different operation",
  ].map((title) => ({ ...lookup, title }));
  const worker = (id: string, findings: ScanDraftInput["findings"]) => ({
    id,
    resultPath: join("/tmp", id, "result.json"),
    result: {
      ...standardScanDraft("fixture", undefined, id),
      findings,
      scope: {
        summary: `Review by ${id}`,
        artifactsReviewed: ["common.py", `${id}.py`],
        limitations: ["Static review only", `${id} dependency unavailable`],
      },
    },
  });
  const before = { scanId: randomUUID(), findings: [] };
  const defects = (members: number[][]) =>
    JSON.stringify({
      uncertain: [],
      defects: members.map((reports) => ({
        operation: "lookup",
        failure: "check",
        path: "fixture.py",
        reports: reports.map((id) => ({ id, evidence: 0 })),
      })),
    });
  const fail = (err: unknown) => {
    throw err;
  };
  const counts = await mergeBatch(
    before,
    [worker("w1", [left]), worker("w2", [alias])],
    "/tmp",
    async (
      _prompt: string,
      schema: { properties: Record<string, unknown> },
    ) => {
      if ("sources" in schema.properties)
        return JSON.stringify({
          sources: [{ id: 0, same: true, survivingPaths: [] }],
        });
      if ("reviews" in schema.properties)
        return JSON.stringify({ reviews: [samePair(0)] });
      return defects([[0, 1], [1]]);
    },
    fail,
  );
  assert.deepEqual(counts, [1, 0]);
  const restored = parseScanUnion(
    JSON.parse(JSON.stringify(persistedScanUnion(before))),
  );
  assert.equal(restored.findings.length, 1);
  assert.deepEqual(
    await mergeBatch(
      restored,
      [worker("w3", [unrelated])],
      "/tmp",
      async (prompt: string) => {
        const rows: Report[] = JSON.parse(prompt.split("\n").at(-1)!);
        assert.deepEqual(
          rows.map((r) => r.title),
          [left.title, alias.title, unrelated.title],
        );
        return defects([[0], [1], [2]]);
      },
      fail,
    ),
    [1],
  );
  // Both workers amend the prior visible group, but the second worker adds
  // the independently fixable path to its secondary repair group.
  const split = parseScanUnion(
    JSON.parse(JSON.stringify(persistedScanUnion(before))),
  );
  const splitCounts = await mergeBatch(
    split,
    [
      worker("w3", [{ ...left, title: "Left clarification" }]),
      worker("w4", [{ ...alias, title: "Alias with a separate repair" }]),
    ],
    "/tmp",
    async (
      _prompt: string,
      schema: { properties: Record<string, unknown> },
    ) => {
      if ("reviews" in schema.properties)
        return JSON.stringify({ reviews: [] });
      return defects([
        [0, 2],
        [1, 3],
      ]);
    },
    fail,
  );
  assert.deepEqual(splitCounts, [0, 1]);
  const legacy = {
    scanId: before.scanId,
    findings: [
      {
        ...left,
        title: "Accepted combined report",
        summary: "The previous reducer combined the validated explanations.",
        locations: [...left.locations, { path: "combined.py", startLine: 3 }],
        provenance: {
          ...left.provenance,
          sourceFindingIds: ["old:0"],
          sourceFindings: [{ id: "old:0", finding: left }],
        },
      },
    ],
  };
  const singleton = legacy.findings[0]!;
  const representative = { ...singleton, provenance: left.provenance };
  Object.assign(singleton.provenance, {
    deepScanRepairGroups: [{ order: 0, sources: ["old:0"], representative }],
  });
  await mergeBatch(
    legacy,
    [worker("next", [alias])],
    "/tmp",
    async (_p: string, schema: { properties: Record<string, unknown> }) => {
      if ("reviews" in schema.properties)
        return JSON.stringify({ reviews: [samePair(0)] });
      if ("sources" in schema.properties)
        return JSON.stringify({
          sources: [{ id: 0, same: true, survivingPaths: [] }],
        });
      return defects([[0, 1], [1]]);
    },
    fail,
  );
  const legacyRestored = parseScanUnion(
    JSON.parse(JSON.stringify(persistedScanUnion(legacy))),
  );
  await mergeBatch(
    legacyRestored,
    [worker("last", [unrelated])],
    "/tmp",
    async () => defects([[0], [1], [2]]),
    fail,
  );
  assert.equal(legacyRestored.findings[0].title, "Accepted combined report");
  assert.match(legacyRestored.findings[0].summary, /combined the validated/);
  assert.ok(
    legacyRestored.findings[0].locations.some(
      ({ path }: { path: string }) => path === "combined.py",
    ),
  );
  const draft = scanUnionToDraft(restored);
  assert.deepEqual(draft.scope, {
    summary: "Review by w1",
    artifactsReviewed: ["common.py", "w1.py", "w2.py", "w3.py"],
    limitations: [
      "Static review only",
      "w1 dependency unavailable",
      "w2 dependency unavailable",
      "w3 dependency unavailable",
    ],
  });
  assert.deepEqual(
    draft.findings.map(
      (f: ScanDraftInput["findings"][number]) => f.provenance.sourceFindingIds,
    ),
    [["w1:0", "w2:0"], ["w3:0"]],
  );
  assert.equal(draft.findings[0].provenance.deepScanRepairGroups, undefined);
});

test("the same proposed mitigation is insufficient evidence of a shared defect", async () => {
  const remediation = "Restrict the input to supported types.";
  const skipped = {
    ...base,
    title: "Collection entries are not visited",
    remediation,
  };
  const bytes = {
    ...base,
    title: "Visited bytes are returned unchanged",
    remediation,
  };
  const { draft } = await scanLoop([[skipped, bytes]], {
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 1,
    comparisons: [
      (rows) => {
        assert.ok(
          rows.every(
            (row) => !JSON.stringify(row.evidence).includes(remediation),
          ),
        );
        return { defects: [], uncertain: rows.map(({ id }) => id) };
      },
    ],
  });
  assert.deepEqual(
    draft.findings.map((f) => f.title),
    [skipped.title, bytes.title],
  );
});

test("independent handlers requiring the same change stay separate", async () => {
  const read = { ...base, locations: [{ path: "read.py", startLine: 3 }] };
  const write = { ...base, locations: [{ path: "write.py", startLine: 9 }] };
  const { draft } = await scanLoop([[read, write]], {
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1]]],
  });
  assert.deepEqual(
    draft.findings.map((f) => f.locations[0].path),
    ["read.py", "write.py"],
  );
});

test("an excerpt in a caller can support a fix in a different cited file", async () => {
  const alias = {
    ...base,
    title: "Caller reaches the unchecked operation",
    codeEvidence: [
      {
        id: "call",
        label: "Call site",
        explanation: "Calls the unchecked function.",
        path: "caller.py",
        startLine: 4,
        code: "run_query(input)",
      },
    ],
  };
  const path = base.locations[0].path;
  const { draft } = await scanLoop([[base, alias]], {
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 1,
    comparisons: [
      (rows) => ({
        uncertain: [],
        defects: [
          {
            operation: "query",
            failure: "missing check",
            path,
            reports: rows.map(({ id, evidence }) => ({
              id,
              evidence: id ? evidence.length - 1 : 0,
            })),
          },
        ],
      }),
    ],
  });
  assert.equal(draft.findings.length, 1);
});

test("a merged report cannot lend its extra citation to a later comparison", async () => {
  const alias = {
    ...base,
    title: "The same defect through another caller",
    locations: [...base.locations, { path: "caller.py", startLine: 8 }],
  };
  const other = {
    ...base,
    title: "The caller omits its own check",
    locations: [alias.locations[1]],
  };
  const { draft } = await scanLoop([[base, alias], [other]], {
    maxDiscoveryRuns: 2,
    stopAfterNoNew: 1,
    comparisons: [
      [[0, 1]],
      (rows) => ({
        uncertain: [],
        defects: [
          {
            operation: "caller",
            failure: "missing check",
            path: "caller.py",
            reports: rows.map(({ id }) => ({ id, evidence: 0 })),
          },
        ],
      }),
    ],
  });
  assert.deepEqual(
    draft.findings.map((f) => f.provenance.sourceFindings?.length),
    [2, 1],
  );
});

test("a context-sized report does not prevent comparison of later observations", async () => {
  const tooLarge = () => {
    throw new Error(
      "Codex ran out of room in the model's context window. Start a new thread or clear earlier history before retrying.",
    );
  };
  const separate = { ...base, title: "Oversized report" };
  const alias = { ...base, title: "Second description" };
  const { draft } = await scanLoop([[separate, base, alias]], {
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 1,
    comparisons: [
      tooLarge,
      tooLarge,
      tooLarge,
      tooLarge,
      (rows) => {
        assert.deepEqual(
          rows.map(({ title }) => title),
          [alias.title, base.title],
        );
        return {
          uncertain: [],
          defects: [
            {
              operation: "check",
              failure: "fixture",
              path: "fixture.py",
              reports: rows.map(({ id }) => ({ id, evidence: 0 })),
            },
          ],
        };
      },
    ],
  });
  assert.deepEqual(
    draft.findings.map((f) => f.provenance.sourceFindings?.length),
    [1, 2],
  );
  assert.match(draft.scope?.limitations?.join(" ") ?? "", /context window/);
});

test("same-worker identities and independently cited controls survive an identical repair assignment", async () => {
  const root = {
    ...lookup,
    identity: { anchor: "lookup.owner" },
    taxonomy: { category: "authorization", cwe: ["CWE-862"] },
  };
  const second = {
    ...root,
    title: "Different instance",
    identity: { anchor: "lookup.other" },
  };
  const authorization = {
    ...root,
    title: "Also missing the caller check",
    taxonomy: { category: "authorization", cwe: ["CWE-862", "CWE-306"] },
    locations: [
      ...root.locations,
      { path: "caller.py", startLine: 4, role: "control" },
    ],
  };
  const { draft } = await scanLoop([[root, second, authorization]], {
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 1,
    comparisons: [[[0, 1, 2]]],
    sameFix: approvePairs,
  });
  assert.deepEqual(
    draft.findings.map((f) => f.title),
    [root.title, second.title, authorization.title],
  );
});

test("repair assignment includes validated attack paths and a shared range retains its root role", async () => {
  const first = {
    ...lookup,
    locations: [{ path: "fixture.py", startLine: 4, role: "entrypoint" }],
  };
  const second = {
    ...first,
    title: "Alias",
    locations: [{ ...first.locations[0], role: "root_control" }],
    validation: { summary: "Verified dispatch." },
    attackPath: { steps: ["Dispatch calls the helper."] },
  };
  const { draft } = await scanLoop([[first, second]], {
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 1,
    comparisons: [
      (rows) => {
        const record = rows[1] as unknown as typeof second;
        assert.deepEqual(record.validation, second.validation);
        assert.deepEqual(record.attackPath, second.attackPath);
        return {
          uncertain: [],
          defects: [
            {
              operation: "repair",
              failure: "fixture",
              path: "fixture.py",
              reports: rows.map(({ id }) => ({ id, evidence: 0 })),
            },
          ],
        };
      },
    ],
  });
  assert.deepEqual(
    draft.findings.map((f) => f.locations.map(({ role }) => role)),
    [["entrypoint", "root_control"]],
  );
});

for (const conflict of ["reviews", "sources"]) {
  test(`conflicting ${conflict} cannot hide an independent finding`, async () => {
    const { checkSameFix } = await importSource(
      join(import.meta.dirname, "../src/deep-scan/same-fix.ts"),
    );
    const groups = [
      { id: 0, worker: 0 },
      { id: 1, worker: 0 },
    ];
    const records = groups.map(() => ({
      locations: [["fixture.py", 1, 1]],
      evidence: [["fixture.py", "lookup(id)"]],
    }));
    const matches = await checkSameFix(
      groups,
      [],
      records,
      new Map(),
      new Map(groups.map(({ id }) => [id, [lookup]])),
      async (
        _prompt: string,
        schema: { properties: Record<string, unknown> },
      ) => {
        if ("reviews" in schema.properties) {
          const approve = samePair(0);
          return JSON.stringify({
            reviews:
              conflict === "reviews"
                ? [approve, { ...approve, decision: "keep" }]
                : [approve],
          });
        }
        const approve = {
          id: 0,
          same: true,
          fixA: "validate",
          fixB: "validate",
          survivingPaths: [],
        };
        return JSON.stringify({
          sources:
            conflict === "sources"
              ? [
                  approve,
                  {
                    ...approve,
                    same: false,
                    survivingPaths: ["second handler"],
                  },
                ]
              : [approve],
        });
      },
      (error: unknown) => {
        throw error;
      },
    );
    assert.equal(matches.size, 0);
  });
}

test("repeated original observations require one source comparison", async () => {
  const observations = Array.from({ length: 8 }, () => lookup);
  let sourceChecks = 0;
  const alias = {
    ...lookup,
    title: "Another description of the shared lookup",
  };
  const { draft } = await scanLoop([[...observations, alias]], {
    maxDiscoveryRuns: 1,
    stopAfterNoNew: 1,
    comparisons: [
      (rows) => {
        assert.deepEqual(
          rows.map(({ title }) => title),
          [lookup.title, alias.title],
        );
        return { uncertain: rows.map(({ id }) => id), defects: [] };
      },
    ],
    sameFix: approvePairs,
    sameSource: () => {
      sourceChecks++;
      return true;
    },
  });
  assert.equal(draft.findings.length, 1);
  assert.equal(draft.findings[0]!.provenance.sourceFindings!.length, 9);
  assert.equal(sourceChecks, 1);
});

test("review batches limit pair counts and isolate rejected and stale decisions", async () => {
  const { checkSameFix } = await importSource(
    join(import.meta.dirname, "../src/deep-scan/same-fix.ts"),
  );
  const groups = Array.from({ length: 9 }, (_, id) => ({ id, worker: 0 }));
  const records = groups.map(() => ({
    locations: [["fixture.py", 1, 1]],
    evidence: [["fixture.py", "lookup(id)"]],
  }));
  const sizes: number[] = [];
  const failures: unknown[] = [];
  const expected = new Map<number, Set<number>>();
  const matches = await checkSameFix(
    groups,
    [],
    records,
    new Map(),
    new Map(groups.map(({ id }) => [id, [lookup]])),
    async (prompt: string, schema: { properties: Record<string, unknown> }) => {
      const input = JSON.parse(prompt.split("\n").at(-1)!);
      if ("reviews" in schema.properties) {
        const { pairs } = input as PairCheck;
        sizes.push(pairs.length);
        if (sizes.length === 1) throw new Error("review failed");
        const last = pairs.at(-1)!;
        const earlier = expected.get(last.right) ?? new Set<number>();
        earlier.add(last.left);
        expected.set(last.right, earlier);
        // ID zero belongs to the failed first batch.
        return JSON.stringify({ reviews: [samePair(0), samePair(last.id)] });
      }
      return JSON.stringify({
        sources: input.map(({ id }: { id: number }) => ({
          id,
          same: true,
          survivingPaths: [],
        })),
      });
    },
    (error: unknown) => failures.push(error),
  );
  assert.deepEqual(sizes, [16, 16, 4]);
  assert.deepEqual(matches, expected);
  assert.equal(failures.length, 1);
});

test("legacy provenance cannot drop or overwrite visible findings on resume", async () => {
  const { mergeBatch } = await importSource(
    join(import.meta.dirname, "../src/deep-scan/iteration.ts"),
  );
  const { parseScanUnion } = await importSource(
    join(import.meta.dirname, "../src/deep-scan/artifact-validation.ts"),
  );
  const findings = [lookup, { ...lookup, title: "Independent report" }];
  for (const metadata of [
    "old model annotation",
    [],
    [{ order: 0, sources: ["missing:0"] }],
    [{ order: 2147483647, sources: ["w:0"] }],
    [{ order: 0, sources: ["w:0"] }],
  ]) {
    const restored = parseScanUnion({
      scanId: randomUUID(),
      findings: findings.map((finding, i) => ({
        ...finding,
        provenance: {
          ...finding.provenance,
          sourceFindingIds: [`w:${i}`],
          sourceFindings: [{ id: `w:${i}`, finding }],
          // Older reducers could put arbitrary model-supplied fields here.
          deepScanRepairGroups: i ? [{ order: 0, sources: ["w:1"] }] : metadata,
        },
      })),
    });
    const unexpected = () => {
      throw new Error("unexpected model call");
    };
    await mergeBatch(restored, [], "/tmp", unexpected, unexpected);
    assert.deepEqual(
      restored.findings.map((f: typeof lookup) => f.title),
      findings.map((f) => f.title),
    );
    assert.ok(
      restored.findings.every(
        (f: typeof lookup) => f.provenance.deepScanRepairGroups === undefined,
      ),
    );
  }
});

test("resuming partial source ancestry isolates only the ambiguous finding", async () => {
  const { mergeBatch } = await importSource(
    join(import.meta.dirname, "../src/deep-scan/iteration.ts"),
  );
  const { parseScanUnion, persistedScanUnion, scanUnionToDraft } =
    await importSource(
      join(import.meta.dirname, "../src/deep-scan/artifact-validation.ts"),
    );
  for (const ancestry of [
    {
      sourceFindings: [{ id: "w:0", finding: { title: "old" } }],
      sourceFindingIds: ["w:0"],
    },
    {
      sourceFindings: [
        { id: "w:0", finding: { title: "old", locations: lookup.locations } },
      ],
    },
    { sourceFindingIds: ["w:0"] },
    {},
  ]) {
    const scanId = randomUUID();
    const old = {
      ...lookup,
      title: "Previously visible report",
      provenance: { ...lookup.provenance, ...ancestry },
    };
    let saved = parseScanUnion({ scanId, findings: [old] });
    const titles = ["Current bug", "Alias of current bug"];
    const worker = (id: string, entries: string[]) => ({
      id,
      resultPath: join("/tmp", id, "result.json"),
      result: {
        ...standardScanDraft(scanId, undefined, id),
        findings: entries.map((title) => ({ ...lookup, title })),
      },
    });
    const fail = (error: unknown) => {
      throw error;
    };
    let reviews = 0;
    await mergeBatch(
      saved,
      [worker("second", titles)],
      "/tmp",
      async (
        prompt: string,
        schema: { properties: Record<string, unknown> },
      ) => {
        const input = JSON.parse(prompt.split("\n").at(-1)!);
        if ("reviews" in schema.properties) {
          reviews++;
          assert.deepEqual(
            input.pairs.map((p: { left: number; right: number }) => [
              p.left,
              p.right,
            ]),
            [[1, 2]],
          );
          return JSON.stringify(approvePairs(input));
        }
        if ("sources" in schema.properties)
          return JSON.stringify({
            sources: input.map(({ id }: { id: number }) => ({
              id,
              same: true,
              survivingPaths: [],
            })),
          });
        // The old report and the new primary share a proposed direct assignment;
        // the alias also lists a second assignment and needs same-fix confirmation.
        return JSON.stringify({
          uncertain: [],
          defects: [[0, 1, 2], [2]].map((ids) => ({
            operation: "lookup",
            failure: "check",
            path: "fixture.py",
            reports: ids.map((id) => ({ id, evidence: 0 })),
          })),
        });
      },
      fail,
    );
    assert.equal(reviews, 1);
    saved = parseScanUnion(
      JSON.parse(JSON.stringify(persistedScanUnion(saved))),
    );
    await mergeBatch(
      saved,
      [worker("third", [titles[1]!])],
      "/tmp",
      fail,
      fail,
    );
    const result = scanUnionToDraft(saved);
    assert.deepEqual(
      result.findings.map((f: typeof lookup) => f.title),
      [old.title, titles[0]],
    );
    assert.deepEqual(result.findings[0].provenance, old.provenance);
    assert.deepEqual(result.findings[1].provenance.sourceFindingIds, [
      "second:0",
      "second:1",
      "third:0",
    ]);
  }
});

for (const partialSource of ["primary", "secondary"] as const) {
  test(`an exact repeat stays merged after reloading a partial ${partialSource} source`, async () => {
    const { mergeBatch } = await importSource(
      join(import.meta.dirname, "../src/deep-scan/iteration.ts"),
    );
    const { parseScanUnion, persistedScanUnion, scanUnionToDraft } =
      await importSource(
        join(import.meta.dirname, "../src/deep-scan/artifact-validation.ts"),
      );
    const scanId = randomUUID();
    const sources = [lookup, lookup].map((finding, index) => ({
      id: `old:${index}`,
      finding:
        index === (partialSource === "primary" ? 0 : 1)
          ? { title: finding.title }
          : finding,
    }));
    const checkpoint = {
      scanId,
      findings: [
        {
          ...lookup,
          provenance: { ...lookup.provenance, sourceFindings: sources },
        },
      ],
    };
    const result = parseScanUnion(
      JSON.parse(JSON.stringify(persistedScanUnion(checkpoint))),
    );
    const worker = {
      id: "new",
      resultPath: "/tmp/new/result.json",
      result: {
        ...standardScanDraft(scanId, undefined, "new"),
        findings: parseScanUnion({ scanId, findings: [lookup] }).findings,
      },
    };
    let comparisons = 0;
    const compare = async () => {
      comparisons++;
      return JSON.stringify({ uncertain: [0, 1], defects: [] });
    };
    assert.deepEqual(
      await mergeBatch(result, [worker], "/tmp", compare, () => {}),
      [0],
    );
    const published = scanUnionToDraft(result).findings;
    assert.equal(published.length, 1);
    assert.equal(comparisons, 0);
    assert.equal(published[0].title, lookup.title);
    assert.deepEqual(published[0].provenance.sourceFindingIds, [
      "old:0",
      "old:1",
      "new:0",
    ]);
    assert.deepEqual(
      published[0].provenance.sourceFindings.slice(0, 2),
      sources,
    );
  });
}

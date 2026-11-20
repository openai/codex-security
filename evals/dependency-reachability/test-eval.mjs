import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import {
  commitFixture,
  git,
  jsonFile,
  mixedFixture,
  mixedServiceVersions,
  reviewedCve,
  sha256,
  summaryFixtures,
} from "./fixtures.mjs";
import {
  approvedCitations,
  gradeEvidenceSource,
  gradeMixed,
} from "./grade.mjs";

let root;
before(async () => {
  root = await mkdtemp(join(tmpdir(), "dependency-eval-test-"));
});
after(async () => {
  await rm(root, { recursive: true, force: true });
});

test("a failed investigation keeps its stdout diagnostic in the case directory", async () => {
  const cli = join(root, "failed-check.mjs");
  const diagnostic = '{\n  "error": "fixture investigation stopped"\n}\n';
  await writeFile(
    cli,
    `if (process.env.CODEX_SECURITY_ENABLE_DEPENDENCY_EXPLOITABILITY !== "1") process.exit(2);
process.stdout.write(${JSON.stringify(diagnostic)});
process.exitCode = 7;\n`,
  );
  const out = join(root, "failed-run");
  const run = spawnSync(
    process.execPath,
    [
      join(import.meta.dirname, "run.mjs"),
      "live",
      "--case",
      "mixed-services",
      "--cli",
      cli,
      "--out",
      out,
    ],
    { encoding: "utf8" },
  );
  assert.ifError(run.error);
  assert.equal(run.status, 1, run.stderr);
  const summary = await readFile(join(out, "results.json"), "utf8");
  const [result] = JSON.parse(summary).results;
  assert.equal(result.status, "execution_error");
  assert.equal(result.exitCode, 7);
  const log = join(out, "mixed-services", "stdout.log");
  assert.equal(await readFile(log, "utf8"), diagnostic);
  if (process.platform !== "win32")
    assert.equal((await stat(log)).mode & 0o777, 0o600);
  assert.doesNotMatch(
    run.stdout + run.stderr + summary,
    /fixture investigation stopped/,
  );
});

test("the probe measures the affected and fixed releases and withholds exactly one binding field", async () => {
  const { fixtures, outcomes } = await summaryFixtures(root);
  assert.deepEqual(
    outcomes.map(({ after }) => after),
    ["process exited", "healthy"],
  );
  const { positive, unbound, fixed } = fixtures;
  assert.equal(positive.target.sha, unbound.target.sha);
  assert.notEqual(positive.target.sha, fixed.target.sha);
  assert.notEqual(positive.repo, unbound.repo);
  assert.deepEqual(positive.files.sinks, unbound.files.sinks);
  assert.deepEqual(positive.files.sources, unbound.files.sources);
  const full = structuredClone(positive.docs.stacks);
  delete full.queries[0].groups[0].observations[0].bindings[0].sourceSha;
  assert.deepEqual(full, unbound.docs.stacks);
  assert.equal(
    positive.observation.frames[positive.observation.sourceIndex].name,
    "parseBatch",
  );
  assert.equal(
    positive.observation.frames[positive.observation.sinkIndex].name,
    "sum",
  );
  assert.deepEqual(git(positive.repo, "ls-files").split("\n"), [
    "sample-summary/index.cjs",
    "sample-summary/package.json",
    "server.cjs",
  ]);
});

function approvedUseClaim(use, sources) {
  const evidence = structuredClone(use.evidence);
  use.decidingEvidence = evidence.map((ref) => ({ kind: "source", ...ref }));
  const sourceIds = evidence.map((source) => {
    const id = sha256(JSON.stringify(source, Object.keys(source).sort()));
    sources[id] = source;
    return id;
  });
  return {
    ...use.conclusionClaim,
    state: "approved",
    decision: { accepted: true, evidenceKeys: [...sourceIds] },
    payload: { kind: "use", use: { ...use, evidence } },
    evidence: { sourceIds },
  };
}

test("the repository grader binds each service's verdict to its own checkout evidence and approved revision", async () => {
  const fixture = await mixedFixture(root);
  const citation = (path, needle) => {
    const line =
      git(fixture.repo, "show", fixture.sha + ":" + path)
        .split("\n")
        .findIndex((s) => s.includes(needle)) + 1;
    assert(line > 0, needle);
    return { path, startLine: line, endLine: line, commit: fixture.sha };
  };
  const report = {
    schemaVersion: 2,
    cve: reviewedCve,
    claims: [],
    uses: [],
    claimEvidence: { sources: {} },
  };
  for (const [service, verdict] of [
    ["notes", "potentially_exploitable"],
    ["reviews", "ruled_out"],
  ]) {
    const version = mixedServiceVersions[service];
    const ref = { id: service, revision: 1, hash: sha256(service) };
    report.uses.push({
      location: service,
      component: "linkify-it",
      version,
      verdict,
      reason: "Fixture evidence",
      deployment: "configured",
      conclusionClaim: ref,
      evidence: [
        citation(
          service + "/package-lock.json",
          '"version": "' + version + '"',
        ),
        citation("compose.yaml", "SERVICE: " + service),
        citation("Dockerfile", "COPY ${SERVICE}/package*.json"),
        citation("Dockerfile", "RUN npm ci"),
        citation("server.mjs", "links.match(await text(request))"),
      ],
    });
    report.claims.push(
      approvedUseClaim(report.uses.at(-1), report.claimEvidence.sources),
    );
  }
  assert.equal(gradeMixed(report, fixture).outcomes.length, 2);
  const context = structuredClone(report);
  const row = context.uses[0];
  // Context was approved with this exact claim, but the reviewer did not use
  // this unrelated path as the reason for the reported verdict.
  row.evidence.push(citation("server.mjs", "import"));
  context.claims[0] = approvedUseClaim(row, context.claimEvidence.sources);
  context.claims[0].decision.evidenceKeys.pop();
  assert.throws(
    () => gradeMixed(context, fixture),
    /source selected by the reviewer/u,
  );
  row.decidingEvidence.pop();
  assert.equal(gradeMixed(context, fixture).outcomes.length, 2);
  const premise = structuredClone(context);
  const leaf = premise.claims[0];
  const source = leaf.payload.use.evidence.at(-1);
  const id = leaf.evidence.sourceIds.at(-1);
  const ref = { id: "premise:binding", revision: 1, hash: sha256("binding") };
  const dep = {
    ...ref,
    state: "approved",
    payload: { kind: "premise", sources: [source] },
    dependencies: [],
    decision: { accepted: true, evidenceKeys: [id] },
    evidence: { sourceIds: [id], receiptIds: [] },
  };
  leaf.dependencies = [ref];
  leaf.decision.evidenceKeys.push(
    "claim:" + JSON.stringify([ref.id, ref.revision, ref.hash]),
  );
  premise.claims.push(dep);
  premise.uses[0].decidingEvidence.push({ kind: "source", ...source });
  assert.equal(gradeMixed(premise, fixture).outcomes.length, 2);
  const flattened = structuredClone(premise);
  const rootClaim = flattened.claims[0];
  rootClaim.payload.use.premises = [ref];
  const childRef = { id: "premise:entry", revision: 1, hash: sha256("entry") };
  const child = structuredClone(dep);
  Object.assign(child, childRef);
  const extra = citation("server.mjs", "createServer(async");
  const extraId = sha256(JSON.stringify(extra, Object.keys(extra).sort()));
  flattened.claimEvidence.sources[extraId] = extra;
  child.payload.sources = [extra];
  child.evidence.sourceIds = [extraId];
  child.decision.evidenceKeys = [extraId];
  flattened.claims.push(child);
  const parent = flattened.claims.find((c) => c.id === ref.id);
  parent.dependencies = parent.payload.dependencies = [childRef];
  parent.decision.evidenceKeys.push(
    "claim:" + JSON.stringify([childRef.id, childRef.revision, childRef.hash]),
  );
  const view = flattened.uses[0];
  view.supportingClaims = [ref, childRef];
  view.decidingEvidence.push({ kind: "source", ...extra });
  assert.throws(() => gradeMixed(flattened, fixture), /reported ranges match/u);
  view.evidence.push(extra);
  assert.equal(gradeMixed(flattened, fixture).outcomes.length, 2);
  view.evidence.push(citation("server.mjs", "response.writeHead(404)"));
  assert.throws(() => gradeMixed(flattened, fixture), /reported ranges match/u);
  view.evidence.pop();
  view.supportingClaims.pop();
  assert.throws(
    () => gradeMixed(flattened, fixture),
    /every reviewer-selected premise/u,
  );
  view.supportingClaims.push({ ...childRef, revision: 2 });
  assert.throws(
    () => gradeMixed(flattened, fixture),
    /every reviewer-selected premise/u,
  );
  view.supportingClaims = [ref, childRef];
  parent.payload.dependencies = [];
  assert.throws(() => gradeMixed(flattened, fixture), /approved payload/u);
  parent.payload.dependencies = [childRef];
  parent.decision.evidenceKeys.pop();
  assert.throws(
    () => gradeMixed(flattened, fixture),
    /every reviewer-selected premise/u,
  );
  dep.state = "rejected";
  assert.throws(() => gradeMixed(premise, fixture), /approved premise/u);
  const compact = structuredClone(report);
  for (const use of compact.uses) {
    use.place = { revision: fixture.sha };
    for (const evidence of use.evidence) delete evidence.commit;
  }
  assert.equal(gradeMixed(compact, fixture).outcomes.length, 2);
  compact.uses[0].place.revision = "wrong";
  assert.throws(() => gradeMixed(compact, fixture), /cited revision/u);
  assert.equal(
    gradeMixed(
      {
        package: { name: "linkify-it" },
        checks: [{ ...report, advisoryId: reviewedCve }],
      },
      fixture,
      true,
    ).outcomes.length,
    2,
  );
  const stale = structuredClone(report);
  stale.uses[0].conclusionClaim.revision++;
  assert.throws(() => gradeMixed(stale, fixture), /one exact claim revision/u);
  const missing = structuredClone(report);
  missing.claims[0].payload.use.evidence = [];
  missing.claims[0].evidence.sourceIds = [];
  missing.claims[0].decision.evidenceKeys = [];
  assert.throws(
    () => gradeMixed(missing, fixture),
    /reported ranges match approved/u,
  );
  delete missing.claims[0].payload.use.evidence;
  assert.throws(
    () => gradeMixed(missing, fixture),
    /approved source evidence/u,
  );
  const unrelated = structuredClone(report);
  unrelated.claims[0].evidence.sourceIds =
    unrelated.claims[1].evidence.sourceIds;
  assert.throws(
    () => gradeMixed(unrelated, fixture),
    /approved source reference/u,
  );
  unrelated.claims[0].application = { assessmentId: "notes" };
  assert.throws(
    () => gradeMixed(unrelated, fixture),
    /legacy application claim/u,
  );
  const reordered = structuredClone(report);
  reordered.uses[0].evidence.reverse();
  assert.equal(gradeMixed(reordered, fixture).outcomes.length, 2);
  const wrongService = structuredClone(report);
  wrongService.uses[1].evidence[0] = report.uses[0].evidence[0];
  assert.throws(
    () => gradeMixed(wrongService, fixture),
    /reported ranges match approved/u,
  );
  wrongService.claims[1] = approvedUseClaim(
    wrongService.uses[1],
    wrongService.claimEvidence.sources,
  );
  assert.throws(
    () => gradeMixed(wrongService, fixture),
    /installed version evidence for reviews/u,
  );
  const outside = structuredClone(report);
  outside.uses[0].evidence[0].path = "../outside";
  outside.claims[0] = approvedUseClaim(
    outside.uses[0],
    outside.claimEvidence.sources,
  );
  assert.throws(() => gradeMixed(outside, fixture), /fixture checkout/u);
});

test("the evidence grader checks citations against the stdio server's original replies", async () => {
  const records = join(root, "records.json");
  const transcript = join(root, "calls.jsonl");
  await jsonFile(records, {
    notes: {
      release_record: "Build 1 ran in service notes.",
      request_record: "A guest reached service notes.",
    },
  });
  const queries = [
    {
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-03-26",
        capabilities: {},
        clientInfo: { name: "test", version: "1" },
      },
    },
    { method: "notifications/initialized" },
    { id: 2, method: "tools/list" },
    ...["release_record", "request_record"].map((name, i) => ({
      id: i + 3,
      method: "tools/call",
      params: { name, arguments: { service: "notes" } },
    })),
  ];
  const cli = spawnSync(
    process.execPath,
    [
      join(import.meta.dirname, "fixtures", "evidence-server.mjs"),
      records,
      transcript,
    ],
    {
      input:
        queries
          .map((q) => JSON.stringify({ jsonrpc: "2.0", ...q }))
          .join("\n") + "\n",
      encoding: "utf8",
    },
  );
  assert.ifError(cli.error);
  assert.equal(cli.status, 0, cli.stderr);
  const replies = cli.stdout
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line).result);
  assert.deepEqual(
    replies[1].tools.map((t) => t.name),
    ["release_record", "request_record"],
  );
  const calls = (await readFile(transcript, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.deepEqual(
    calls.map((c) => c.result),
    replies.slice(2),
  );
  const conclusion = { id: "notes", revision: 1, hash: sha256("notes") };
  const use = {
    observations: [],
    decidingEvidence: [],
    conclusionClaim: conclusion,
  };
  const claim = {
    ...conclusion,
    state: "approved",
    evidence: { receiptIds: [] },
    decision: { accepted: true, evidenceKeys: [] },
    payload: { use: { observations: [] } },
  };
  const report = { claimEvidence: { receipts: {} }, claims: [claim] };
  for (const [i, c] of calls.entries()) {
    const key = sha256(
      JSON.stringify({
        arguments: c.arguments,
        result: {
          content: c.result.content.map(({ text, type }) => ({ text, type })),
        },
        server: "service_records",
        tool: c.tool,
      }),
    );
    report.claimEvidence.receipts[key] = {
      server: "service_records",
      ...structuredClone(c),
    };
    use.observations.push({
      server: "service_records",
      tool: c.tool,
      sha256: key,
      record: c.result.content[0].text,
      supports: [i === 0 ? "running" : "access"],
    });
    const ref = use.observations.at(-1);
    const payloadSha = sha256(
      JSON.stringify({
        content: c.result.content.map(({ text, type }) => ({ text, type })),
      }),
    );
    use.decidingEvidence.push({
      kind: "receipt",
      receiptId: key,
      originalPayloadSha256: payloadSha,
    });
    claim.decision.evidenceKeys.push(key);
    claim.evidence.receiptIds.push(key);
    claim.payload.use.observations.push({
      server: ref.server,
      tool: ref.tool,
      sha256: key,
      quote: ref.record,
      supports: ref.supports,
    });
  }
  gradeEvidenceSource(report, use, { calls, withAccess: true });
  const compact = structuredClone(use);
  for (const ref of compact.observations) {
    delete ref.sha256;
    delete ref.tool;
  }
  gradeEvidenceSource(report, compact, { calls, withAccess: true });
  const unreviewed = structuredClone(report);
  unreviewed.claims[0].decision.evidenceKeys.pop();
  assert.throws(
    () => gradeEvidenceSource(unreviewed, compact, { calls, withAccess: true }),
    /actual request_record/u,
  );
  const access = use.observations[1];
  report.claimEvidence.receipts[access.sha256].result.content[0].text =
    claim.payload.use.observations[1].quote =
    access.record =
      "An invented request.";
  assert.throws(
    () => gradeEvidenceSource(report, use, { calls, withAccess: true }),
    /actual request_record response|receipt identity/u,
  );
});

test("the optional suite grades a caller's actual route and config in the same assessed use", async () => {
  const { cases } = await import("./upstream/cases.mjs");
  const { gradeSnapshot, validateSnapshot } =
    await import("./upstream/grade.mjs");
  assert.equal(cases.length, 23);
  assert.equal(new Set(cases.map((c) => c.id)).size, 23);
  const scenario = cases.find((c) => c.id === "unmounted-route");
  const repo = await mkdtemp(join(root, "route-"));
  await mkdir(join(repo, "service"));
  for (const file of scenario.stage) {
    const destination = join(repo, file.destination);
    if (file.kind === "json") await jsonFile(destination, file.value);
    else
      await cp(join(import.meta.dirname, "upstream", file.source), destination);
  }
  const commit = commitFixture(repo);
  assert.deepEqual(validateSnapshot(scenario, repo, commit), {
    identityGroups: 2,
    decidingGroups: 3,
  });
  const ref = { id: "caller", revision: 1, hash: sha256("caller") };
  const use = {
    component: "linkify-it",
    location: "inbox",
    version: null,
    verdict: "ruled_out",
    reason: "Route is unmounted",
    place: { revision: commit },
    conclusionClaim: ref,
    evidence: ["service/server.cjs", "service/deploy.json"].map((path) => ({
      path,
      commit,
      startLine: 1,
      endLine: git(repo, "show", commit + ":" + path).split("\n").length,
    })),
  };
  const sources = {};
  const report = {
    cve: scenario.cve,
    searches: [
      {
        source: "Checkout trace graph",
        tool: "trace_codex_security_code",
        scope: ["package=" + scenario.component, "paths=service"],
        startedAt: null,
        finishedAt: new Date().toISOString(),
        result: "matches",
        completeness: "partial",
        details: [],
        evidenceReferences: [],
      },
    ],
    schemaVersion: 2,
    claimEvidence: { sources },
    claims: [approvedUseClaim(use, sources)],
    uses: [use],
  };
  assert.equal(gradeSnapshot(report, scenario, repo, commit).pass, true);
  const untraced = gradeSnapshot(
    { ...report, searches: [] },
    scenario,
    repo,
    commit,
  );
  assert.equal(untraced.pass, false);
  assert.match(untraced.errors.join(" "), /checkout tracer outcome/u);
  assert.equal(untraced.verdictLabelCorrect, true);
  const partial = structuredClone(report);
  partial.uses[0].evidence.pop();
  partial.claims[0] = approvedUseClaim(
    partial.uses[0],
    partial.claimEvidence.sources,
  );
  const other = {
    ...use,
    location: "second",
    evidence: [use.evidence.at(-1)],
    conclusionClaim: { id: "second", revision: 1, hash: sha256("second") },
  };
  partial.uses.push(other);
  partial.claims.push(approvedUseClaim(other, partial.claimEvidence.sources));
  assert.equal(gradeSnapshot(partial, scenario, repo, commit).pass, false);
});

test("the skill and standalone adapter use the same 23 blind questions and verify exact source lines", async () => {
  const { runAdapter } = await import("./upstream/adapter.mjs");
  const { runBaseline } = await import("./upstream/skill-baseline.mjs");
  const { questions } = await import("./upstream/skill-questions.mjs");
  const { cases } = await import("./upstream/cases.mjs");
  assert.deepEqual([...questions.keys()].sort(), cases.map((c) => c.id).sort());
  const repo = join(root, "skill-baseline");
  await mkdir(repo);
  await writeFile(join(repo, "source.js"), "export const version = '2';\n");
  const sha = commitFixture(repo);
  const scenario = {
    id: "address-backport",
    version: "2",
    verdict: "ruled_out",
    evidenceGroups: [
      [{ path: "source.js", contains: "version", completeFile: true }],
    ],
  };
  const fixture = {
    verdict: "ruled_out",
    dependency_version: "2",
    reason: "The fixed version is installed.",
    evidence: [
      {
        path: "source.js",
        startLine: 1,
        endLine: 1,
        code: "export const version = '2';",
      },
    ],
  };
  const adapter = join(root, "baseline-adapter.mjs");
  await writeFile(
    adapter,
    `import fs from "node:fs";
    if (!fs.readFileSync(0,"utf8").includes("CVE-2025-14874")) process.exit(2);
    if (!fs.existsSync("source.js")) process.exit(3);
    console.log(JSON.stringify(${JSON.stringify(fixture)}));`,
  );
  const { grade, usage } = await runBaseline(
    (cwd, prompt) => runAdapter([process.execPath, adapter], cwd, prompt),
    scenario,
    repo,
    sha,
  );
  assert.equal(grade.pass, true);
  assert.equal(usage, null);
  fixture.evidence[0].code = "inexact citation";
  const negative = await runBaseline(
    async () => ({ answer: fixture, usage: null }),
    scenario,
    repo,
    sha,
  );
  assert.equal(negative.grade.pass, false);
  assert.equal(negative.grade.evidenceCorrect, false);
  const missing = await runBaseline(
    async () => ({ answer: null, usage: null }),
    scenario,
    repo,
    sha,
  );
  assert.equal(missing.grade.pass, false);
  assert.equal(missing.grade.verdictCorrect, false);
  assert(missing.grade.errors.includes("Missing verified source citation"));
});

test("a reviewer-selected row verifies its linked reply, origin, exact selection and displayed record", () => {
  const raw = {
    server: "catalog",
    tool: "read_mcp_resource",
    arguments: { server: "catalog", uri: "fixture:services" },
    result: {
      contents: [
        {
          uri: "fixture:services",
          text: '{"services":[{"name":"one"},{"name":"two"}]}',
        },
      ],
    },
    linkedFrom:
      "7777777777777777777777777777777777777777777777777777777777777777",
    originThreadId: "host",
    originCallId: "fixture-1",
    contentSha256: [
      "5575802f2adae1be43d65b482ee44f5568d35c0feecb3024f218076e2588ee4e",
    ],
  };
  const id = "92b85bb735e04dd12e34f0fbdceddaa012963470f37e0808e45c6cdc46c72313",
    originalPayloadSha256 =
      "9772b6fced00a9d09e0ceff9832e93e931553aab3af6dde1ed399ff6e1c92de8";
  const selection = { record: ["services", 1], textBlock: 0 };
  const origin = {
    arguments: raw.arguments,
    parentReceiptId: raw.linkedFrom,
    tool: raw.tool,
  };
  const key = sha256(
    JSON.stringify({
      origin,
      payloadSha256: originalPayloadSha256,
      selection,
      server: raw.server,
    }),
  );
  const shown = {
    kind: "receipt",
    receiptId: id,
    originalPayloadSha256,
    selection,
  };
  const chosen = {
    key,
    receiptId: id,
    originalPayloadSha256,
    server: "catalog",
    origin,
    selection,
    result: { name: "two" },
  };
  const conclusionClaim = { id: "use", revision: 1, hash: "1".repeat(64) };
  const use = {
    conclusionClaim,
    location: "sample",
    component: "sample",
    version: "1",
    verdict: "ruled_out",
    evidence: [],
    decidingEvidence: [shown],
  };
  const selectedKey = "receipt:" + key;
  const claim = {
    ...conclusionClaim,
    payload: { kind: "use", use },
    state: "approved",
    decision: { accepted: true, evidenceKeys: [selectedKey] },
    evidence: { sourceIds: [], receiptIds: [selectedKey] },
  };
  const report = {
    claims: [claim],
    claimEvidence: {
      sources: {},
      receipts: { [id]: { ...raw, sha256: id }, [selectedKey]: chosen },
    },
  };
  const verify = () =>
    approvedCitations(report, use, () => assert.fail("unexpected source"), "");
  assert.deepEqual(verify(), []);
  chosen.result = { name: "one" };
  assert.throws(verify, /selected value in original reply/);
  chosen.result = { name: "two" };
  use.decidingEvidence = [
    { ...shown, selection: { textBlock: 0, record: ["services", 0] } },
  ];
  assert.throws(verify, /receipt selected by the reviewer/);
  use.decidingEvidence = [shown];
  report.claimEvidence.receipts[id].originCallId = "different";
  assert.throws(verify, /receipt identity/);
});

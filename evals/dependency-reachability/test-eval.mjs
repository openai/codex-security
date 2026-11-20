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
import { checkoutOf } from "./upstream/checkout.mjs";
import { compareRuns } from "./upstream/compare.mjs";
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
import { scoreRating } from "./report-rubric.mjs";
import { buildReportPacket } from "./report-packet.mjs";
import { mixedReportReference } from "./report-runtime.mjs";

test("the report score gives equal weight to accuracy and comprehensiveness", () => {
  const packet = {
    report: { limitations: ["Worker A’s deployed copy is unknown."] },
    reference: { targets: ["Worker A", "Worker B"] },
  };
  const sound = {
    score: 2,
    reason: "Worker A’s exposure is accurately qualified.",
    reportPointer: "/report/limitations/0",
    referencePointer: "/reference/targets/0",
  };
  const partial = {
    ...sound,
    score: 1,
    reason: "The report leaves Worker B unassessed.",
    referencePointer: "/reference/targets/1",
  };
  const rating = {
    factualAccuracy: sound,
    evidentiarySupport: sound,
    calibration: sound,
    targets: [sound, { ...partial, score: 0 }],
    pathCoverage: partial,
    uncertaintyCoverage: partial,
  };
  assert.deepEqual(scoreRating(rating, packet), {
    accuracy: 100,
    comprehensiveness: 50,
    blended: 75,
  });
  const checkTargets = (targets) => scoreRating({ ...rating, targets }, packet);
  assert.throws(
    () => checkTargets([sound]),
    /one judgment per reference target/u,
  );
  assert.throws(() => checkTargets([sound, sound]), /expected target pointer/u);
  const check = (change) =>
    scoreRating({ ...rating, pathCoverage: { ...partial, ...change } }, packet);
  assert.throws(() => check({ score: 3 }), /invalid score/u);
  assert.throws(() => check({ reason: " " }), /missing reason/u);
  assert.throws(
    () => check({ reportPointer: partial.referencePointer }),
    /pointer into report/u,
  );
  assert.throws(
    () => check({ referencePointer: "/reference/targets/2" }),
    /unresolved pointer/u,
  );
});

let root;
before(async () => {
  root = await mkdtemp(join(tmpdir(), "dependency-eval-test-"));
});
after(async () => {
  await rm(root, { recursive: true, force: true });
});

test("the report rater sees the same published evidence in both reviewer modes", async () => {
  const repo = await mkdtemp(join(root, "cited-"));
  await writeFile(join(repo, "route.js"), "parse(request.body)\n");
  const sha = commitFixture(repo);
  await writeFile(join(repo, "route.js"), "return null\n");
  const citation = { path: "route.js", startLine: 1, endLine: 1, commit: sha };
  const use = {
    reason: "The route passes caller input to parse.",
    evidence: [citation],
    observations: [{ record: "Release A is active." }],
  };
  const lead = "Unassessed caller in route.js:1.";
  const receipt = {
    arguments: {},
    result: { observation: "Build A is active." },
    server: "records",
    tool: "release",
  };
  const receiptId = sha256(JSON.stringify(receipt));
  const limitation =
    "Receipt " +
    receiptId +
    " identifies the build. Caller access remains unverified.";
  const reference = { question: "Can an anonymous caller reach parse?" };
  function packet(reviewer) {
    const enabled = reviewer === "enabled";
    const check = {
      advisoryId: "test-advisory",
      claimEvidence: { receipts: { [receiptId]: receipt } },
      reviewer,
      uses: [
        {
          ...use,
          conclusionClaim: { id: reviewer },
          decidingEvidence: enabled ? [] : [citation],
        },
      ],
      coverage: [
        { kind: "unresolved", reason: lead },
        { kind: "dismissed", reason: "The test imports a different parser." },
      ],
      limitations: [
        lead,
        enabled
          ? limitation
          : "Independent grading was disabled. " + limitation,
      ],
    };
    return buildReportPacket({
      report: { checks: [check] },
      reference,
      repo,
      sha,
    });
  }
  const on = packet("enabled");
  assert.deepEqual(on, packet("disabled"));
  const [report] = on.report.checks;
  assert.deepEqual(report.uses[0], { ...use, evidence: ["route.js:1"] });
  assert.equal(report.sources["route.js:1"], "parse(request.body)");
  assert.deepEqual(report.unassessedLeads, [lead]);
  assert.deepEqual(report.limitations, [limitation]);
  assert.equal(report.receipts[0].id, receiptId);
  assert.deepEqual(report.receipts[0].result, receipt.result);
  assert.equal(
    report.coverage[0].reason,
    "The test imports a different parser.",
  );
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

test("service references distinguish an available sibling request from what the investigator saw", async () => {
  const fixture = await mixedFixture(root);
  const sibling = mixedReportReference("mixed-evidence-sibling", fixture);
  assert.match(
    sibling.availableRecords.notes.request_record,
    /on service reviews/u,
  );
  assert.deepEqual(sibling.recordedReplies, []);
  const call = {
    tool: "release_record",
    arguments: { service: "notes" },
    result: {
      content: [
        {
          type: "text",
          text: "Record 1: " + sibling.availableRecords.notes.release_record,
        },
      ],
    },
  };
  const partial = mixedReportReference("mixed-evidence-sibling", fixture, [
    call,
  ]);
  assert.deepEqual(partial.recordedReplies, [call]);
  assert.deepEqual(partial.availableRecords, sibling.availableRecords);
  const pkg = mixedReportReference("mixed-package", fixture);
  assert.deepEqual(pkg.availableRecords, {});
  assert.equal(pkg.targets.length, 4);
  assert.deepEqual(
    pkg.advisories.map((a) => a.cve),
    [reviewedCve, "CVE-2026-59887"],
  );
  for (const service of ["notes", "reviews"])
    assert(pkg.sources.some((s) => s.path === service + "/package-lock.json"));
});

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
  const disabled = structuredClone(report);
  disabled.reviewer = "disabled";
  for (const claim of disabled.claims) {
    claim.state = "unreviewed";
    delete claim.decision;
  }
  assert.deepEqual(
    gradeMixed(disabled, fixture, false, undefined, "disabled"),
    gradeMixed(report, fixture),
  );
  assert.throws(() => gradeMixed(disabled, fixture), /expected reviewer mode/u);
  const context = structuredClone(report);
  const row = context.uses[0];
  // Context was approved with this exact claim, but the reviewer did not use
  // this unrelated path as the reason for the reported verdict.
  row.evidence.push(citation("server.mjs", "import"));
  context.claims[0] = approvedUseClaim(row, context.claimEvidence.sources);
  context.claims[0].decision.evidenceKeys.pop();
  assert.throws(
    () => gradeMixed(context, fixture),
    /source selected for the claim/u,
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
    /every selected premise/u,
  );
  view.supportingClaims.push({ ...childRef, revision: 2 });
  assert.throws(
    () => gradeMixed(flattened, fixture),
    /every selected premise/u,
  );
  view.supportingClaims = [ref, childRef];
  parent.payload.dependencies = [];
  assert.throws(() => gradeMixed(flattened, fixture), /claim payload/u);
  parent.payload.dependencies = [childRef];
  parent.decision.evidenceKeys.pop();
  assert.throws(
    () => gradeMixed(flattened, fixture),
    /every selected premise/u,
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
    /reported ranges match submitted/u,
  );
  delete missing.claims[0].payload.use.evidence;
  assert.throws(
    () => gradeMixed(missing, fixture),
    /submitted source evidence/u,
  );
  const unrelated = structuredClone(report);
  unrelated.claims[0].evidence.sourceIds =
    unrelated.claims[1].evidence.sourceIds;
  assert.throws(
    () => gradeMixed(unrelated, fixture),
    /claim source reference/u,
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
    /reported ranges match submitted/u,
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
  const source = { calls, requestService: "notes" };
  gradeEvidenceSource(report, use, source);
  const compact = structuredClone(use);
  for (const ref of compact.observations) {
    delete ref.sha256;
    delete ref.tool;
  }
  gradeEvidenceSource(report, compact, source);
  const disabled = structuredClone(report);
  disabled.reviewer = "disabled";
  disabled.claims[0].state = "unreviewed";
  delete disabled.claims[0].decision;
  gradeEvidenceSource(disabled, compact, source);
  disabled.claims[0].evidence.receiptIds.pop();
  assert.throws(
    () => gradeEvidenceSource(disabled, compact, source),
    /actual request_record/u,
  );
  const sibling = { calls: structuredClone(calls), requestService: "reviews" };
  sibling.calls[1].result.content[0].text =
    "An anonymous client sent its own text to POST /preview on service reviews at revision abc.";
  assert.throws(
    () => gradeEvidenceSource(report, compact, sibling),
    /unrelated request/u,
  );
  const releaseOnly = structuredClone(report);
  releaseOnly.claims[0].payload.use.observations.pop();
  gradeEvidenceSource(
    releaseOnly,
    {
      ...compact,
      observations: compact.observations.slice(0, 1),
    },
    sibling,
  );
  const unreviewed = structuredClone(report);
  unreviewed.claims[0].decision.evidenceKeys.pop();
  assert.throws(
    () => gradeEvidenceSource(unreviewed, compact, source),
    /actual request_record/u,
  );
  const access = use.observations[1];
  report.claimEvidence.receipts[access.sha256].result.content[0].text =
    claim.payload.use.observations[1].quote =
    access.record =
      "An invented request.";
  assert.throws(
    () => gradeEvidenceSource(report, use, source),
    /actual request_record response|receipt identity/u,
  );
});

test("a local case module can prepare and regrade its large-repo cases across suites", async () => {
  const saved = await mkdtemp(join(root, "saved-"));
  const caseModule = join(saved, "local cases.mjs");
  const scenario = {
    id: "profile",
    suite: "service",
    revision: "v1",
    callerScope: "The upload service",
    cve: reviewedCve,
  };
  await writeFile(
    caseModule,
    `
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
const scenario = ${JSON.stringify(scenario)};
export const cases = [
  { ...scenario, largeRepo: true },
  { ...scenario, id: "batch", suite: "worker", largeRepo: true },
  { ...scenario, id: "focused" },
];
export async function prepare(scenario, repo, commitFixture) {
  await writeFile(join(repo, "handler"), scenario.revision);
  return { repo, sha: commitFixture(repo) };
}
export function validateSnapshot() { return { sites: 1 }; }
export function gradeSnapshot(report, scenario, repo, sha, mode, { sourceReader }) {
  const { excerpt } = sourceReader(repo, sha)(report.citation);
  return { pass: excerpt === scenario.revision && report.reviewer === mode };
}
`,
  );
  const repo = await mkdtemp(join(root, "source-"));
  await writeFile(join(repo, "handler"), scenario.revision);
  const commit = commitFixture(repo);
  for (const mode of ["enabled", "disabled"]) {
    const dir = join(saved, mode, scenario.id);
    await mkdir(dir, { recursive: true });
    await jsonFile(join(dir, "report.json"), {
      grader: mode,
      assumptions: [scenario.callerScope],
      citation: { commit, path: "handler", startLine: 1, endLine: 1 },
    });
  }
  const args = [
    join(import.meta.dirname, "upstream.mjs"),
    "--case-module",
    caseModule,
    "--suite",
    "large-repo",
  ];
  function invoke(...options) {
    return spawnSync(process.execPath, [...args, ...options], {
      encoding: "utf8",
    });
  }
  const help = invoke("--help");
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout.trimEnd(), /Cases: profile, batch$/u);
  const prepared = join(saved, "prepared");
  const prep = invoke("--prepare-only", "--out", prepared);
  assert.equal(prep.status, 0, prep.stderr);
  const manifest = JSON.parse(
    await readFile(join(prepared, "results.json"), "utf8"),
  );
  assert.deepEqual(manifest.selected, ["profile", "batch"]);
  const skipped = invoke("--case", "focused", "--prepare-only");
  assert.equal(skipped.status, 1);
  assert.match(
    skipped.stderr,
    /Cases unavailable for this selection: focused/u,
  );

  const out = join(saved, "regraded");
  const run = invoke(
    "--grade-existing",
    saved,
    "--case",
    scenario.id,
    "--reviewer",
    "both",
    "--jobs",
    "2",
    "--out",
    out,
  );
  assert.ifError(run.error);
  const summary = JSON.parse(await readFile(join(out, "results.json"), "utf8"));
  assert.equal(run.status, 0, JSON.stringify(summary.results));
  assert.deepEqual(summary.selected, [scenario.id]);
  assert.equal(summary.comparison.enabled.passed, 1);
  assert.equal(summary.comparison.disabled.passed, 1);
});

test("checkout provenance follows tracked entry points across worktrees", async () => {
  const source = await mkdtemp(join(root, "source-"));
  await mkdir(join(source, "cases"));
  await writeFile(join(source, "cases/module.mjs"), "");
  await writeFile(join(source, "cli.mjs"), "");
  const commit = commitFixture(source);
  const copy = join(root, "cli-worktree");
  git(source, "worktree", "add", "--quiet", "--detach", copy, commit);
  const cli = join(copy, "cli.mjs");
  const installed = join(copy, "installed.mjs");
  await writeFile(installed, "");
  assert.equal(checkoutOf(installed), null);
  const clean = { commit, trackedDirty: false, dirtyScope: "worktree" };
  assert.deepEqual(checkoutOf(cli), clean);

  await writeFile(cli, "export const changed = true;");
  assert.deepEqual(checkoutOf(cli), { ...clean, trackedDirty: true });
  assert.deepEqual(checkoutOf(join(source, "cli.mjs")), clean);
  const scope = join(copy, "cases/module.mjs");
  assert.deepEqual(checkoutOf(scope, "directory"), {
    ...clean,
    dirtyScope: "directory",
  });
  await writeFile(scope, "export const cases = [];");
  git(copy, "add", "cases/module.mjs");
  assert.equal(checkoutOf(scope, "directory").trackedDirty, true);
});

test("regrading a legacy manifest infers its cases and reviewer mode and can select one side", async () => {
  const saved = await mkdtemp(join(root, "paired-"));
  const selected = ["direct-links", "disabled-links", "queued-links"];
  const failure = {
    id: "direct-links",
    grader: "disabled",
    elapsedMs: 24,
    exitCode: 2,
    error: "investigation stopped",
    status: "execution_error",
  };
  const checkouts = {
    cli: {
      commit: "a".repeat(40),
      trackedDirty: false,
      dirtyScope: "worktree",
    },
  };
  await jsonFile(join(saved, "results.json"), {
    checkouts,
    model: "eval-model",
    grader: "both",
    selected,
    results: [failure],
  });
  async function replay(out, ...args) {
    const run = spawnSync(
      process.execPath,
      [
        join(import.meta.dirname, "upstream.mjs"),
        "--cache",
        ".",
        "--grade-existing",
        saved,
        "--out",
        out,
        ...args,
      ],
      { cwd: root, encoding: "utf8" },
    );
    assert.ifError(run.error);
    assert.equal(run.status, 1, run.stderr);
    return JSON.parse(await readFile(join(root, out, "results.json"), "utf8"));
  }

  const all = await replay("both");
  assert.deepEqual(all.selected, selected);
  assert.deepEqual(all.checkouts, checkouts);
  assert.equal(all.regradeCheckouts.cli, null);
  assert.equal(all.model, "eval-model");
  assert.equal(all.reviewer, "both");
  assert.equal(all.comparison.enabled.executionErrors, 3);
  assert.equal(all.comparison.disabled.executionErrors, 3);

  const subset = await replay(
    "subset",
    "--reviewer",
    "disabled",
    "--case",
    "direct-links",
    "--case",
    "queued-links",
  );
  assert.deepEqual(subset.selected, ["direct-links", "queued-links"]);
  const [stopped, missing] = subset.results;
  assert.equal(stopped.reviewer, "disabled");
  assert.equal(stopped.grader, undefined);
  assert.equal(stopped.error, failure.error);
  assert.equal(stopped.elapsedMs, failure.elapsedMs);
  assert.equal(stopped.exitCode, failure.exitCode);
  assert.equal(missing.reviewer, "disabled");
  assert(
    missing.error.includes(
      join(saved, "disabled", "queued-links", "report.json"),
    ),
  );
});

test("caller scope selects different clip services in an identical checkout", async () => {
  const { cases } = await import("./upstream/cases.mjs");
  const mobile = cases.find((c) => c.id === "clips-mobile-caller");
  const studio = cases.find((c) => c.id === "clips-studio-caller");
  for (const key of ["cve", "repository", "revision", "stage"])
    assert.deepEqual(mobile[key], studio[key]);
  assert.equal(
    mobile.callerScope.replace("mobile", "studio"),
    studio.callerScope,
  );
  assert.equal(mobile.expectedService, "mobile");
  assert.equal(mobile.verdict, "potentially_exploitable");
  assert.equal(studio.expectedService, "studio");
  assert.equal(studio.verdict, "ruled_out");
});

test("the optional suite grades a caller's actual route and config in the same assessed use", async () => {
  const { cases, originalCases } = await import("./upstream/cases.mjs");
  const { gradeSnapshot, validateSnapshot } =
    await import("./upstream/grade.mjs");
  assert.equal(originalCases.length, 23);
  assert.equal(new Set(cases.map((c) => c.id)).size, cases.length);
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
    decidingGroups: 1,
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
  const baseline = gradeSnapshot(report, scenario, repo, commit, "enabled");
  assert.equal(baseline.pass, true);
  assert.equal(baseline.strictPass, true);
  assert.equal(baseline.selectedEvidenceCorrect, true);
  const selected = structuredClone(report);
  selected.claims[0].decision.evidenceKeys.pop();
  selected.uses[0].decidingEvidence.pop();
  const regularOnly = {
    ...baseline,
    strictPass: false,
    selectedEvidenceCorrect: false,
  };
  assert.deepEqual(
    gradeSnapshot(selected, scenario, repo, commit),
    regularOnly,
  );
  // A second use selects every required citation. It must also satisfy all
  // ordinary requirements itself to earn a strict pass.
  for (const [version, strictPass] of [
    ["0.0.0", false],
    [use.version, true],
  ]) {
    const second = {
      ...use,
      version,
      location: "second",
      conclusionClaim: { id: "second", revision: 1, hash: sha256("second") },
    };
    const pair = structuredClone(selected);
    pair.claims.push(approvedUseClaim(second, pair.claimEvidence.sources));
    pair.uses.push(second);
    assert.deepEqual(gradeSnapshot(pair, scenario, repo, commit), {
      ...regularOnly,
      strictPass,
    });
  }
  const disabled = structuredClone(report);
  disabled.reviewer = "disabled";
  disabled.claims[0].state = "unreviewed";
  delete disabled.claims[0].decision;
  const gradeDisabled = () =>
    gradeSnapshot(disabled, scenario, repo, commit, "disabled");
  assert.deepEqual(gradeDisabled(), baseline);
  assert.throws(
    () => gradeSnapshot(disabled, scenario, repo, commit, "enabled"),
    /reviewer mode/u,
  );
  disabled.claims[0].decision = report.claims[0].decision;
  assert.equal(gradeDisabled().claimsCorrect, false);
  delete disabled.claims[0].decision;
  disabled.uses[0].decidingEvidence.pop();
  assert.equal(gradeDisabled().pass, false);
  disabled.uses[0].decidingEvidence = report.uses[0].decidingEvidence;
  disabled.uses[0].evidence[0].commit = "wrong";
  assert.equal(gradeDisabled().pass, false);
  const sibling = gradeSnapshot(
    report,
    { ...scenario, expectedService: "worker" },
    repo,
    commit,
  );
  assert.equal(sibling.verdictLabelCorrect, false);
  assert.equal(sibling.identityCorrect, false);
  const untraced = gradeSnapshot(
    { ...report, searches: [] },
    scenario,
    repo,
    commit,
  );
  assert.equal(untraced.pass, false);
  assert.equal(untraced.strictPass, false);
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
  const { originalCases } = await import("./upstream/cases.mjs");
  assert.deepEqual(
    [...questions.keys()].sort(),
    originalCases.map((c) => c.id).sort(),
  );
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
  assert.throws(verify, /receipt selected for the claim/);
  use.decidingEvidence = [shown];
  report.claimEvidence.receipts[id].originCallId = "different";
  assert.throws(verify, /receipt identity/);
});

test("pairs attempts by case, counts failures, and identifies changed inputs", () => {
  const enabled = {
    reviewer: "enabled",
    sourceSha: "same-source",
    advisorySha256: "same-advisory",
    elapsedMs: 200,
    reviewBatches: 2,
    status: "passed",
    grade: { verdictLabelCorrect: true, evidenceCorrect: true },
  };
  const disabled = {
    ...enabled,
    reviewer: "disabled",
    elapsedMs: 100,
    reviewBatches: 0,
  };
  const score = compareRuns(
    ["gained", "lost", "changed", "unfinished"],
    [
      { ...enabled, id: "gained" },
      { ...disabled, id: "lost" },
      {
        ...disabled,
        id: "gained",
        status: "grade_error",
        grade: { verdictLabelCorrect: true, evidenceCorrect: false },
      },
      {
        ...enabled,
        id: "lost",
        status: "execution_error",
        grade: undefined,
        advisorySha256: undefined,
      },
      { ...disabled, id: "changed", advisorySha256: "new-advisory" },
      { ...enabled, id: "changed" },
      { ...enabled, id: "unfinished" },
    ],
  );
  assert.deepEqual(score.gainedWithReview, ["gained"]);
  assert.deepEqual(score.lostWithReview, ["lost"]);
  assert.deepEqual(score.inputMismatch, ["changed"]);
  assert.deepEqual(score.pending, ["unfinished"]);
  assert.equal(score.matchedAdvisories, 1);
  assert.equal(score.enabled.cases, 2);
  assert.equal(score.enabled.executionErrors, 1);
  assert.equal(score.disabled.passed, 1);
  assert.equal(score.disabled.verdict, 2);
  assert.equal(score.disabled.decidingEvidence, 1);
  assert.equal(score.disabled.reviewBatches, 0);
  assert.equal(score.medianPairedElapsedDeltaMs, 100);
});

test("pairs strict passes independently of ordinary passes and supports earlier modules", () => {
  const on = { reviewer: "enabled", status: "passed" };
  const off = { reviewer: "disabled", status: "passed" };
  const regularOnly = { pass: true, selectedEvidenceCorrect: false };
  const rows = [
    { ...on, id: "a", grade: { ...regularOnly, strictPass: true } },
    { ...off, id: "a", grade: regularOnly },
    { ...on, id: "b", grade: regularOnly },
    { ...off, id: "b", grade: { pass: true, selectedEvidenceCorrect: true } },
  ];
  const score = compareRuns(["a", "b"], rows);
  assert.deepEqual(score.gainedWithReview, []);
  assert.deepEqual(score.lostWithReview, []);
  assert.equal(score.enabled.strictPassed, 1);
  assert.equal(score.disabled.strictPassed, 1);
  assert.deepEqual(score.strictGainedWithReview, ["a"]);
  assert.deepEqual(score.strictLostWithReview, ["b"]);

  rows[1].grade = { pass: true };
  const incomplete = compareRuns(["a"], rows);
  assert.equal(incomplete.disabled.strictPassed, null);
  assert.deepEqual(incomplete.strictGainedWithReview, []);
});

test("blended comparisons separate paired report quality from publication and rating failures", () => {
  const ids = ["gained", "no-report", "changed"];
  const scored = (id, reviewer, accuracy, comprehensiveness) => ({
    id,
    reviewer,
    status: "scored",
    sourceSha: "same",
    reportScore: {
      accuracy,
      comprehensiveness,
      blended: (accuracy + comprehensiveness) / 2,
    },
  });
  const missing = {
    id: "no-report",
    reviewer: "enabled",
    status: "execution_error",
  };
  const rows = [
    scored("gained", "enabled", 100, 100),
    scored("gained", "disabled", 100, 50),
    missing,
    scored("no-report", "disabled", 50, 0),
    scored("changed", "enabled", 0, 0),
    { ...scored("changed", "disabled", 100, 100), sourceSha: "different" },
  ];
  const compare = () => compareRuns(ids, rows, { blended: true });
  const result = compare();
  assert.deepEqual(result.inputMismatch, ["changed"]);
  assert.deepEqual(result.higherWithReview, ["gained"]);
  assert.deepEqual(result.lowerWithReview, []);
  assert.equal(result.enabled.pairedReports, 1);
  assert.equal(result.enabled.blended, 100);
  assert.equal(result.disabled.blended, 75);
  assert.equal(result.disabled.accuracy, 100);
  assert.equal(result.disabled.comprehensiveness, 50);
  assert.equal(result.enabled.blendedPerAttempt, 50);
  assert.equal(result.disabled.blendedPerAttempt, 50);
  missing.status = "rating_error";
  assert.equal(compare().enabled.blendedPerAttempt, null);
});

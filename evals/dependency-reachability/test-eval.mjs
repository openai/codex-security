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
  reviewedCve,
  sha256,
  summaryFixtures,
} from "./fixtures.mjs";
import { gradeMixed } from "./grade.mjs";

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
  const report = { schemaVersion: 2, cve: reviewedCve, claims: [], uses: [] };
  for (const [service, version, verdict] of [
    ["notes", "5.0.0", "potentially_exploitable"],
    ["reviews", "5.0.1", "ruled_out"],
  ]) {
    const ref = { id: service, revision: 1, hash: sha256(service) };
    report.claims.push({
      ...ref,
      state: "approved",
      decision: { accepted: true },
      payload: {
        kind: "use",
        use: { location: service, version, component: "linkify-it", verdict },
      },
    });
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
  }
  assert.equal(gradeMixed(report, fixture).outcomes.length, 2);
  const compact = structuredClone(report);
  for (const use of compact.uses) {
    use.place = { revision: fixture.sha };
    for (const evidence of use.evidence) delete evidence.commit;
  }
  assert.equal(gradeMixed(compact, fixture).outcomes.length, 2);
  compact.uses[0].place.revision = "wrong";
  assert.throws(() => gradeMixed(compact, fixture), /pinned source identity/u);
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
  const wrongService = structuredClone(report);
  wrongService.uses[1].evidence[0] = report.uses[0].evidence[0];
  assert.throws(
    () => gradeMixed(wrongService, fixture),
    /installed version evidence/u,
  );
  const outside = structuredClone(report);
  outside.uses[0].evidence[0].path = "../outside";
  assert.throws(() => gradeMixed(outside, fixture), /fixture checkout/u);
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
  const report = {
    cve: scenario.cve,
    schemaVersion: 2,
    claims: [
      {
        ...ref,
        state: "approved",
        decision: { accepted: true },
        payload: {
          kind: "use",
          use: {
            location: use.location,
            component: use.component,
            version: use.version,
            verdict: use.verdict,
          },
        },
      },
    ],
    uses: [use],
  };
  assert.equal(gradeSnapshot(report, scenario, repo, commit).pass, true);
  const partial = structuredClone(report);
  partial.uses[0].evidence.pop();
  const other = {
    ...use,
    location: "second",
    evidence: [use.evidence.at(-1)],
    conclusionClaim: { id: "second", revision: 1, hash: sha256("second") },
  };
  partial.uses.push(other);
  partial.claims.push({
    ...other.conclusionClaim,
    state: "approved",
    decision: { accepted: true },
    payload: { kind: "use", use: other },
  });
  assert.equal(gradeSnapshot(partial, scenario, repo, commit).pass, false);
});

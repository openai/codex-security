import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  git,
  precondition,
  reviewedCve,
  sha256,
  summaryCve,
} from "./fixtures.mjs";

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
}

// Resolve only tracked paths at the expected revision. A report's path or
// quoted excerpt cannot cause a read from elsewhere on the grading host.
export function sourceReader(repo, sha) {
  const entries = git(repo, "ls-tree", "-r", "--name-only", "-z", sha).split(
    "\0",
  );
  const tracked = new Set(entries);
  const cache = new Map();
  return (citation) => {
    assert(
      tracked.has(citation.path),
      "cited file belongs to the fixture checkout",
    );
    assert.equal(citation.commit, sha, "cited revision");
    if (!cache.has(citation.path)) {
      const key = sha + ":" + citation.path;
      const bytes = execFileSync("git", ["-C", repo, "show", key], {
        maxBuffer: Infinity,
      });
      cache.set(citation.path, {
        lines: bytes
          .toString("utf8")
          .replaceAll("\r\n", "\n")
          .replace(/\n$/u, "")
          .split("\n"),
        blob: git(repo, "rev-parse", key),
        sha256: sha256(bytes),
      });
    }
    const { lines, blob, sha256: hash } = cache.get(citation.path);
    const { startLine, endLine } = citation;
    assert(
      Number.isSafeInteger(startLine) &&
        Number.isSafeInteger(endLine) &&
        startLine > 0 &&
        endLine >= startLine &&
        endLine <= lines.length,
      "valid source range",
    );
    const excerpt = lines.slice(startLine - 1, endLine).join("\n");
    if ("text" in citation)
      assert.equal(citation.text, excerpt, "quoted source");
    if ("blob" in citation) assert.equal(citation.blob, blob, "source blob");
    if ("contentSha256" in citation)
      assert.equal(citation.contentSha256, hash, "source hash");
    return {
      path: citation.path,
      startLine,
      endLine,
      excerpt,
      totalLines: lines.length,
    };
  };
}
export function exactClaim(claims, ref) {
  assert(
    ref &&
      typeof ref.id === "string" &&
      Number.isSafeInteger(ref.revision) &&
      ref.revision > 0 &&
      /^[a-f0-9]{64}$/u.test(ref.hash),
    "valid claim reference",
  );
  const matches = claims.filter(
    (c) =>
      c.id === ref.id && c.revision === ref.revision && c.hash === ref.hash,
  );
  assert.equal(matches.length, 1, "one exact claim revision");
  return matches[0];
}

export function gradeStack(report, fixture) {
  const { variant, target, repo, observation, scope, advisory, files, docs } =
    fixture;
  assert.equal(
    report.schemaVersion,
    "codex-security.pipeline-stacks.report/v1",
  );
  assert.equal(report.reviewPolicy, "single_agent");
  assert.equal(report.cve, summaryCve);
  assert.deepEqual(report.target, target);
  assert(report.runId && report.attemptId && report.toolRevision);
  const material = {
    format: "codex-security.stack-manifest/v1",
    cve: summaryCve,
    target,
    advisory,
    files,
    toolRevision: report.toolRevision,
  };
  assert.equal(
    report.inputDigest,
    sha256(JSON.stringify(canonical(material))),
    "digest of frozen checked inputs",
  );
  assert.deepEqual(report.coverage, {
    total: 1,
    assessed: 1,
    observed: 1,
    outstanding: [],
    noMatch: [],
    noCoverage: [],
    truncated: [],
    truncationUnknown: [],
    scopeConflicts: [],
  });
  assert.equal(report.assessments.length, 1);
  const [a] = report.assessments;
  assert.equal(a.workItemId, "request/service/sample");
  assert.deepEqual(a.scope, scope);
  assert.deepEqual(a.queryScope, scope);
  assert.equal(a.status, "observed");
  assert.equal(a.truncated, false);
  assert.equal(a.observation.stackHash, observation.stackHash);
  assert.equal(a.observation.sinkIndex, observation.sinkIndex);
  assert.equal(a.observation.sourceIndex, observation.sourceIndex);
  assert.deepEqual(a.observation.sinkMatches, [{ sinkId: "sum", rawIndex: 0 }]);
  assert.deepEqual(a.observation.bindings, observation.bindings ?? []);
  const indices = a.observation.frames.map((entry) => {
    assert.deepEqual(
      entry.frame,
      observation.frames[entry.rawIndex],
      "original captured frame",
    );
    return entry.rawIndex;
  });
  assert(
    indices.includes(observation.sourceIndex) &&
      indices.includes(observation.sinkIndex),
  );
  const item = {
    id: a.workItemId,
    queryId: "request",
    groupId: "service",
    scope,
    queryScope: scope,
    scopeConflicts: [],
    origin: docs.stacks.origin,
    selectors: docs.stacks.queries[0].selectors,
    status: "observed",
    truncated: false,
    observation,
  };
  const validate = sourceReader(repo, target.sha);
  const pending = [...a.supportingClaims];
  const selected = new Set();
  const ranges = [];
  const receipts = [];
  while (pending.length) {
    const claim = exactClaim(report.claims, pending.pop());
    if (selected.has(claim.id)) continue;
    selected.add(claim.id);
    pending.push(...claim.dependencies);
    ranges.push(...claim.sources.map(validate));
    for (const receipt of claim.receipts) {
      assert.equal(receipt.server, "stack-packet");
      assert.equal(receipt.originalPayloadSha256, files.stacks.sha256);
      assert.deepEqual(receipt.origin, {
        tool: "read-stacks",
        arguments: {
          inputDigest: report.inputDigest,
          workItemId: item.id,
          queryId: "request",
          groupId: "service",
        },
      });
      let expected = item;
      for (const key of receipt.selection?.record ?? []) {
        assert(
          expected != null && Object.hasOwn(expected, key),
          "capture selector exists",
        );
        expected = expected[key];
      }
      assert.deepEqual(receipt.result, expected, "original capture selection");
      receipts.push(receipt);
    }
  }
  assert.equal(selected.size, report.claims.length, "exact claim closure");
  assert.equal(a.verdict, report.verdict);
  const expected = {
    positive: ["exploitable"],
    fixed: ["ruled_out"],
    unbound: ["unknown", "potentially_exploitable"],
    "missing-version": ["unknown", "potentially_exploitable"],
  };
  assert(
    expected[variant].includes(report.verdict),
    "scoped verdict for " + variant,
  );
  if (variant === "fixed" || variant === "positive") {
    assert(
      receipts.some(
        (r) =>
          JSON.stringify(r.selection?.record) ===
          JSON.stringify(["observation", "bindings", 0]),
      ),
      "cited running package/build binding",
    );
  }
  if (variant === "positive") {
    const control = exactClaim(report.claims, a.attackerControlClaim);
    assert(
      a.supportingClaims.some(
        (ref) => ref.id === control.id && ref.hash === control.hash,
      ),
      "explicit caller-control claim",
    );
    assert(
      control.sources
        .map(validate)
        .some(
          (c) =>
            c.path === "server.cjs" &&
            /JSON\.parse|request\.on|sum\(batch\.samples\)/u.test(c.excerpt),
        ),
      "caller controls request input",
    );
    const condition = a.use?.proof?.conditions?.find(
      (c) => c.label === precondition,
    );
    assert.equal(condition?.status, "met", "cited advisory condition");
    assert(
      condition.citations.some((c) =>
        ranges.some(
          (r) =>
            r.path === c.path && r.startLine <= c.line && c.line <= r.endLine,
        ),
      ),
      "condition cites verified source",
    );
    assert(
      ranges.some(
        (c) =>
          c.path === "server.cjs" && c.excerpt.includes("sum(batch.samples)"),
      ),
      "actual call",
    );
    assert(
      ranges.some(
        (c) =>
          c.path === "sample-summary/index.cjs" &&
          c.excerpt.includes("samples.reduce("),
      ),
      "affected operation",
    );
  }
  if (variant === "unbound" || variant === "missing-version") {
    const questions = a.remainingQuestions.join(" ");
    const missingFact =
      variant === "unbound"
        ? /source|commit|revision|checkout|build|sha/iu
        : /version|release|package|dependency/iu;
    assert.match(questions, missingFact, "question names the missing evidence");
    assert(
      a.remainingQuestions.every((q) => report.remainingQuestions.includes(q)),
    );
  }
  return {
    verdict: report.verdict,
    inputDigest: report.inputDigest,
    toolRevision: report.toolRevision,
    claims: selected.size,
    sourceRanges: ranges.length,
    receipts: receipts.length,
  };
}

// A v2 report can put the revision on the use or in a host-verified source
// envelope. Newer reports can carry it directly on each compact citation.
export function approvedCitations(report, use, read, sha) {
  const claim = exactClaim(report.claims, use.conclusionClaim);
  assert(
    claim.state === "approved" && claim.decision?.accepted === true,
    "independent approval",
  );
  assert.equal(
    claim.payload?.kind,
    "use",
    "conclusion belongs to a dependency use",
  );
  for (const field of ["location", "version", "component", "verdict"])
    assert.equal(claim.payload.use[field], use[field], "approved " + field);
  return use.evidence.map((citation) => {
    if (citation.commit !== undefined) return read(citation);
    if (use.place?.revision === sha) return read({ ...citation, commit: sha });
    const source = Object.values(report.claimEvidence?.sources ?? {}).find(
      (s) =>
        s.path === citation.path &&
        s.startLine <= citation.startLine &&
        s.endLine >= citation.endLine &&
        s.sourceIdentity?.status === "verified" &&
        s.sourceIdentity.commit === sha,
    );
    assert(source, "compact citation has a pinned source identity");
    read({
      ...source,
      commit: sha,
      blob: source.sourceIdentity.blob,
      contentSha256: source.sourceIdentity.contentSha256,
    });
    return read({ ...citation, commit: sha });
  });
}

export function gradeMixed(response, fixture, packageCheck = false) {
  let report = response;
  if (packageCheck) {
    assert.equal(response.package.name, "linkify-it");
    const checks = response.checks.filter(
      (c) =>
        c.advisoryId === reviewedCve ||
        c.advisoryDetails?.some(
          (a) => a.id === reviewedCve || a.aliases?.includes(reviewedCve),
        ),
    );
    assert.equal(
      checks.length,
      1,
      "one package check for the fixture advisory",
    );
    [report] = checks;
  } else {
    assert.equal(report.cve, reviewedCve);
  }
  assert.equal(report.schemaVersion, 2);
  const validate = sourceReader(fixture.repo, fixture.sha);
  assert.equal(report.uses.length, 2, "both services assessed separately");
  const outcomes = [];
  for (const [service, version, verdict] of [
    ["notes", "5.0.0", "potentially_exploitable"],
    ["reviews", "5.0.1", "ruled_out"],
  ]) {
    const uses = report.uses.filter((use) =>
      use.location.split(/[^\w-]+/u).includes(service),
    );
    assert.equal(uses.length, 1, "one use for " + service);
    const [use] = uses;
    assert.equal(use.component, "linkify-it");
    assert.equal(use.version, version);
    assert.equal(use.verdict, verdict);
    assert.equal(use.deployment, "configured");
    assert(use.reason?.trim());
    const cites = approvedCitations(report, use, validate, fixture.sha);
    const lock = service + "/package-lock.json";
    const lines = git(fixture.repo, "show", fixture.sha + ":" + lock).split(
      "\n",
    );
    const installed =
      lines.findIndex((l) => l.includes('"node_modules/linkify-it"')) + 1;
    const versionLine =
      lines.findIndex(
        (l, i) => i >= installed && l.includes('"version": "' + version + '"'),
      ) + 1;
    assert(
      installed &&
        versionLine &&
        cites.some(
          (c) =>
            c.path === lock &&
            c.startLine <= versionLine &&
            versionLine <= c.endLine,
        ),
      "installed version evidence for " + service,
    );
    const has = (path, text) =>
      cites.some((c) => c.path === path && c.excerpt.includes(text));
    assert(
      has("compose.yaml", "SERVICE: " + service),
      "service's build selection",
    );
    assert(
      has("Dockerfile", "COPY ${SERVICE}/package*.json") &&
        has("Dockerfile", "RUN npm ci"),
      "build consumes selected lock",
    );
    if (verdict === "potentially_exploitable")
      assert(
        has("server.mjs", "links.match(await text(request))"),
        "request reaches parser",
      );
    outcomes.push({ service, version, verdict });
  }
  return { outcomes };
}

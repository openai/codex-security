import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { isDeepStrictEqual } from "node:util";
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

// Legacy reports can include deciding excerpts from the conclusion's approved
// premises. Follow only the exact dependency revisions selected by the reviewer.
function legacySources(report, conclusion) {
  assert.equal(
    conclusion.id,
    "application:" + conclusion.application.assessmentId,
    "legacy application claim",
  );
  const dependencies = new Set([conclusion]);
  const byKey = new Map();
  for (const claim of dependencies) {
    for (const ref of claim.dependencies) {
      const premise = exactClaim(report.claims, ref);
      byKey.set(
        "claim:" + JSON.stringify([ref.id, ref.revision, ref.hash]),
        premise,
      );
      dependencies.add(premise);
    }
  }
  const selected = new Set([conclusion]);
  const sources = [];
  const premises = [];
  for (const claim of selected) {
    assert(
      claim.state === "approved" && claim.decision?.accepted === true,
      "approved premise",
    );
    for (const key of claim.decision.evidenceKeys) {
      if (key.startsWith("claim:")) {
        assert(byKey.has(key), "reviewed dependency revision");
        selected.add(byKey.get(key));
      }
    }
    for (const id of claim.evidence.sourceIds) {
      if (!claim.decision.evidenceKeys.includes(id)) continue;
      const source = report.claimEvidence.sources[id];
      assert.equal(
        id,
        "excerpt:" + sha256(JSON.stringify(canonical(source))),
        "original approved excerpt",
      );
      if (source.sourceIdentity?.status !== "verified") continue;
      const { commit, blob, contentSha256 } = source.sourceIdentity;
      const pinned = { ...source, commit, blob, contentSha256 };
      sources.push(pinned);
      if (claim !== conclusion) premises.push(pinned);
    }
  }
  return { sources, premises };
}

function rangeKey({ path, startLine, endLine }) {
  return JSON.stringify([path, startLine, endLine]);
}

const evidenceHash = (value) => sha256(JSON.stringify(canonical(value)));

function receiptKey(ref) {
  return JSON.stringify(canonical(ref));
}

// Resolve each reviewer-selected receipt against the original captured MCP reply.
// A selected row proves only its own returned value, even when its siblings look alike.
function selectedReceipt(table, key) {
  const row = table[key];
  assert(row, "original approved receipt");
  const selected = key.startsWith("receipt:");
  const id = selected ? row.receiptId : key;
  const raw = table[id];
  assert(raw, "original receipt behind selected row");
  const { sha256: recordedHash, ...payload } = raw;
  assert.equal(evidenceHash(payload), id, "receipt identity");
  if (recordedHash !== undefined)
    assert.equal(recordedHash, id, "recorded receipt identity");
  const originalPayloadSha256 = evidenceHash(raw.result);
  const ref = { kind: "receipt", receiptId: id, originalPayloadSha256 };
  if (!selected) return { ref, value: raw.result };
  const origin = {
    tool: raw.tool,
    arguments: raw.arguments,
    ...(raw.linkedFrom && { parentReceiptId: raw.linkedFrom }),
  };
  const { selection } = row;
  const { textBlock, record } = selection;
  assert.deepEqual(row.origin, origin, "original selected row origin");
  assert.equal(row.server, raw.server, "original row server");
  assert.equal(
    row.originalPayloadSha256,
    originalPayloadSha256,
    "whole receipt behind selected row",
  );
  const claimKey = evidenceHash({
    server: raw.server,
    origin,
    payloadSha256: originalPayloadSha256,
    selection,
  });
  assert.equal(key, "receipt:" + claimKey, "reviewer's selected row key");
  assert.equal(row.key, claimKey, "retained selected row key");
  let value;
  if (textBlock === null) {
    value = raw.result.structuredContent ?? raw.result.structured_content;
  } else {
    assert(
      Number.isSafeInteger(textBlock) && textBlock >= 0,
      "valid selected text block",
    );
    const block = (raw.result.content ?? raw.result.contents)?.[textBlock];
    assert(typeof block?.text === "string", "original selected text block");
    value = JSON.parse(block.text);
  }
  for (const field of record) {
    assert(
      value != null && Object.hasOwn(value, field),
      "selected field in original reply",
    );
    value = value[field];
  }
  assert.deepEqual(value, row.result, "selected value in original reply");
  return { ref: { ...ref, selection }, value };
}

function modernDecision(report, conclusion, supportingClaims) {
  const selected = new Set([conclusion]);
  const sources = new Map();
  const receipts = new Map();
  const keyFor = (ref) =>
    "claim:" + JSON.stringify([ref.id, ref.revision, ref.hash]);
  for (const claim of selected) {
    assert(
      claim.state === "approved" && claim.decision?.accepted === true,
      "approved premise",
    );
    const refs = new Map(
      (claim.dependencies ?? []).map((ref) => [keyFor(ref), ref]),
    );
    if (supportingClaims !== undefined) {
      const dependencies =
        claim.payload.kind === "use"
          ? claim.payload.use.premises
          : claim.payload.dependencies;
      assert.deepEqual(
        [...refs.keys()].sort(),
        (dependencies ?? []).map(keyFor).sort(),
        "premise references belong to the approved payload",
      );
    }
    const proposed =
      claim.payload?.kind === "use"
        ? claim.payload.use.evidence
        : claim.payload?.sources;
    assert(Array.isArray(proposed), "approved source evidence");
    const available = new Map(
      proposed.map((source) => [
        sha256(JSON.stringify(canonical(source))),
        source,
      ]),
    );
    for (const [id, source] of available) {
      assert(
        claim.evidence.sourceIds.includes(id),
        "approved source reference",
      );
      assert.deepEqual(
        report.claimEvidence.sources[id],
        source,
        "original approved source",
      );
    }
    for (const id of claim.decision.evidenceKeys) {
      if (refs.has(id)) {
        const premise = exactClaim(report.claims, refs.get(id));
        assert.equal(
          premise.payload?.kind,
          "premise",
          "deciding claim is a premise",
        );
        selected.add(premise);
      } else if (available.has(id)) {
        const source = available.get(id);
        sources.set(rangeKey(source), source);
      } else {
        assert(
          claim.evidence.receiptIds?.includes(id),
          "approved receipt reference",
        );
        const { ref } = selectedReceipt(report.claimEvidence.receipts, id);
        receipts.set(receiptKey(ref), ref);
      }
    }
  }
  if (supportingClaims !== undefined) {
    assert(
      Array.isArray(supportingClaims),
      "supporting claims are exact references",
    );
    assert.deepEqual(
      supportingClaims.map(keyFor).sort(),
      [...selected]
        .filter((c) => c !== conclusion)
        .map(keyFor)
        .sort(),
      "display every reviewer-selected premise",
    );
  }
  return { sources, receipts };
}

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
  const approvedUse = claim.payload.use;
  assert(Array.isArray(approvedUse.evidence), "approved source evidence");
  const legacy = claim.application && legacySources(report, claim);
  const reviewed = new Map();
  const selected =
    !legacy && modernDecision(report, claim, use.supportingClaims);
  for (const source of approvedUse.evidence) {
    let commit = source.commit ?? approvedUse.place?.revision;
    if (!commit && legacy) {
      const envelope = legacy.sources.find(
        (record) =>
          record.commit === sha &&
          record.path === source.path &&
          record.startLine <= source.startLine &&
          record.endLine >= source.endLine,
      );
      assert(envelope, "compact citation has a pinned source identity");
      read(envelope);
      commit = envelope.commit;
    }
    reviewed.set(rangeKey(source), { ...source, commit });
  }
  for (const source of legacy?.premises ?? [])
    reviewed.set(rangeKey(source), source);
  if (selected && use.supportingClaims !== undefined) {
    for (const [key, source] of selected.sources) reviewed.set(key, source);
  }
  const displayed = use.evidence.map(rangeKey);
  assert.deepEqual(
    [...new Set(displayed)].sort(),
    [...reviewed.keys()].sort(),
    "reported ranges match approved source evidence",
  );
  const checked = use.evidence.map((citation) => {
    const source = reviewed.get(rangeKey(citation));
    read(source);
    return read({
      ...citation,
      commit: citation.commit ?? use.place?.revision ?? source.commit,
    });
  });
  if (legacy) return checked;
  const deciding = use.decidingEvidence;
  assert(Array.isArray(deciding), "reported deciding evidence");
  const displayedSources = new Set();
  const displayedReceipts = new Set();
  for (const ref of deciding) {
    if (ref.kind === "source") {
      const key = rangeKey(ref);
      const source = selected.sources.get(key);
      assert(
        source && source.commit === ref.commit,
        "source selected by the reviewer",
      );
      displayedSources.add(key);
    } else {
      assert.equal(ref.kind, "receipt");
      const key = receiptKey(ref);
      assert(selected.receipts.has(key), "receipt selected by the reviewer");
      displayedReceipts.add(key);
    }
  }
  assert.deepEqual(
    displayedSources,
    new Set(selected.sources.keys()),
    "display every selected source",
  );
  assert.deepEqual(
    displayedReceipts,
    new Set(selected.receipts.keys()),
    "display every selected receipt",
  );
  return [...selected.sources.values()].map(read);
}

// Compare report citations with replies recorded by the independent MCP process.
export function gradeEvidenceSource(report, use, { calls, withAccess }) {
  const claim = exactClaim(report.claims, use.conclusionClaim);
  assert(
    claim.state === "approved" && claim.decision.accepted === true,
    "approved runtime observations",
  );
  const records = claim.payload.use.observations;
  const compact = ({ server, record, supports }) => ({
    server,
    record,
    supports,
  });
  assert.deepEqual(
    use.observations.map(compact),
    records.map(({ server, quote, supports }) => ({
      server,
      record: quote,
      supports: supports.filter((s) =>
        ["running", "access", "affected_copy"].includes(s),
      ),
    })),
    "runtime citations belong to the independently approved claim",
  );
  const expected = { running: "release_record", access: "request_record" };
  for (const [support, tool] of Object.entries(expected)) {
    const actual = calls.filter(
      (c) => c.tool === tool && c.arguments.service === "notes",
    );
    assert(actual.length, "investigator requested " + tool + " for notes");
    if (!withAccess && support === "access") {
      assert(
        actual.every((c) =>
          c.result.content[0].text.includes("No observation for notes."),
        ),
      );
      assert(
        !use.observations.some((ref) => ref.supports.includes("access")),
        "missing request record cannot prove access",
      );
      continue;
    }
    assert(
      records.some((ref, index) => {
        const shown = use.observations[index];
        if (
          !ref.supports.includes(support) ||
          ref.server !== "service_records" ||
          ref.tool !== tool ||
          !ref.quote?.trim() ||
          (shown.tool !== undefined && shown.tool !== ref.tool) ||
          (shown.sha256 !== undefined && shown.sha256 !== ref.sha256)
        )
          return false;
        const receipt = report.claimEvidence.receipts[ref.sha256];
        if (
          !receipt ||
          receipt.server !== ref.server ||
          receipt.tool !== tool ||
          !claim.decision.evidenceKeys.some((key) => {
            if (!claim.evidence.receiptIds.includes(key)) return false;
            const selected = selectedReceipt(
              report.claimEvidence.receipts,
              key,
            );
            return (
              selected.ref.receiptId === ref.sha256 &&
              use.decidingEvidence.some(
                (r) => receiptKey(r) === receiptKey(selected.ref),
              ) &&
              (!selected.ref.selection ||
                JSON.stringify(selected.value).includes(ref.quote))
            );
          })
        )
          return false;
        return actual.some(
          (c) =>
            isDeepStrictEqual(receipt.arguments, c.arguments) &&
            isDeepStrictEqual(receipt.result.content, c.result.content) &&
            c.result.content[0].text.includes(ref.quote),
        );
      }),
      "approved use cites the actual " + tool + " response",
    );
  }
}

export function gradeMixed(
  response,
  fixture,
  packageCheck = false,
  evidenceSource,
) {
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
    [
      "notes",
      "5.0.0",
      evidenceSource?.withAccess ? "exploitable" : "potentially_exploitable",
    ],
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
    assert.equal(
      use.deployment,
      service === "notes" && evidenceSource ? "confirmed" : "configured",
    );
    if (service === "notes" && evidenceSource) {
      gradeEvidenceSource(report, use, evidenceSource);
    }
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
    if (service === "notes")
      assert(
        has("server.mjs", "links.match(await text(request))"),
        "request reaches parser",
      );
    outcomes.push({ service, version, verdict });
  }
  return { outcomes };
}

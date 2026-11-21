import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { commitFixture, sha256 } from "../fixtures.mjs";
import { grade } from "./grade.mjs";

const repo = mkdtempSync(join(tmpdir(), "outcome-grade-"));
after(() => rmSync(repo, { recursive: true, force: true }));
const path = "source.txt";
writeFileSync(join(repo, path), "parser 1.2.3\nread()\n");
const revision = commitFixture(repo);
const service = "reader";
const fixture = {
  service,
  revision,
  version: "1.2.3",
  evidence: [
    { path, line: 1 },
    { path, line: 2 },
  ],
};
const digest = "sha256:" + sha256("test artifact");
const expected = { artifactDigest: digest, revision, service };
const primary = "release_record";
const archive = "archived_release_record";
const call = (status, name = primary) => ({
  name,
  status,
  arguments: { service, revision },
  payload: status === "ok" ? expected : {},
});

function sample(scenario = "healthy", calls = [call("ok")], tool = primary) {
  const receipt = {
    result: { structuredContent: expected },
    server: "service_records",
    tool,
  };
  const id = sha256(JSON.stringify(receipt));
  const output = {
    claimEvidence: { receipts: { [id]: receipt } },
    uses: [
      {
        version: fixture.version,
        verdict: "unknown",
        reason:
          "The inventory identifies " +
          digest +
          ". Deployment remains unknown.",
        evidence: [{ path, startLine: 1, endLine: 2, commit: revision }],
      },
    ],
  };
  return { fixture, expected, calls, scenario, repo, output, code: 0 };
}

test("the same evidence requirements apply to a direct lookup, retry and fallback", () => {
  const limited = call("rate_limited");
  assert(grade(sample()).passed);
  assert(grade(sample("transient", [limited, call("ok")])).passed);
  const calls = [limited, call("ok", archive)];
  assert(grade(sample("alternate", calls, archive)).passed);
  assert(!grade(sample("alternate", calls)).passed);
  assert(!grade(sample("transient")).passed);
});

test("receipt, investigator answer, version and both pinned sources are required", () => {
  const wrongScope = sample();
  wrongScope.calls[0].arguments.service = "other";
  assert(!grade(wrongScope).passed);
  for (const change of [
    (r) => {
      r.claimEvidence = {};
    },
    (r) => {
      r.uses[0].reason = "Unknown";
      r.assumptions = [digest];
    },
    (r) => {
      r.uses[0].version = "1.2.30";
    },
    (r) => {
      r.uses[0].evidence[0].endLine = 1;
    },
    (r) => {
      r.uses[0].evidence[0].commit = "wrong";
    },
    (r) => {
      r.uses[0].verdict = "exploitable";
    },
  ]) {
    const slot = sample();
    change(slot.output);
    assert(!grade(slot).passed);
  }
});

test("only a structured block about the missing record after an actual lookup counts", () => {
  const slot = sample("persistent", [call("rate_limited")]);
  assert(!grade(slot).passed);
  const blocked = {
    status: "blocked",
    code: "INVESTIGATION_BLOCKED",
    blockReason: "outcomes_unsatisfied",
    reason: "No record identifies the artifact digest.",
  };
  slot.output = { checks: [blocked] };
  slot.code = 2;
  assert(grade(slot).passed);
  assert(
    grade({ ...slot, scenario: "partial", calls: [call("partial")] }).passed,
  );
  assert(!grade({ ...slot, scenario: "transient" }).passed);
  assert(!grade({ ...slot, calls: [] }).passed);
  blocked.reason = "Missing source citation.";
  assert(!grade(slot).passed);
  blocked.blockReason = "outcome_grader_error";
  blocked.reason = "Parser failed while reading artifact.";
  assert.equal(grade(slot).status, "error");
});

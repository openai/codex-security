import assert from "node:assert/strict";
import { test } from "node:test";

import { API_KEY_VARIABLES, authStatus, describeAuth, withoutApiKeys } from "../src/auth.mjs";
import { orderByCompletion } from "../src/deep.mjs";
import {
  deepDedupPrompt,
  deepDiscoveryPrompt,
  deepTailPrompt,
  scanPrompt,
} from "../src/prompt.mjs";
import { buildClaudeArgs, resolveClaudeCommand, scanSettings } from "../src/runner.mjs";
import { skillNameFor, targetDescription } from "../src/targets.mjs";
import {
  SEVERITY_LEVELS,
  isInside,
  redactMessage,
  safeSegment,
  severityAtLeast,
  stateDirectory,
} from "../src/util.mjs";

test("severity ordering is highest-first and comparisons are inclusive", () => {
  assert.deepEqual(SEVERITY_LEVELS, ["critical", "high", "medium", "low", "informational"]);
  assert.ok(severityAtLeast("critical", "high"));
  assert.ok(severityAtLeast("high", "high"));
  assert.ok(!severityAtLeast("medium", "high"));
  assert.ok(severityAtLeast("informational", "informational"));
});

test("safeSegment produces a filesystem-safe, bounded directory name", () => {
  assert.equal(safeSegment("my repo/name"), "my-repo-name");
  assert.equal(safeSegment("///"), "repository");
  assert.equal(safeSegment("a".repeat(200)).length, 64);
});

test("isInside rejects a path equal to or outside the parent", () => {
  assert.ok(isInside("/a", "/a/b"));
  assert.ok(!isInside("/a", "/a"));
  assert.ok(!isInside("/a", "/b"));
  assert.ok(!isInside("/a/b", "/a"));
});

test("redactMessage strips control characters that could rewrite the terminal", () => {
  const escape = String.fromCharCode(27);
  const redacted = redactMessage(`bad${escape}[2Kvalue\u0007`);
  assert.ok(!redacted.includes(escape));
  assert.ok(!redacted.includes("\u0007"));
  assert.ok(redacted.includes("value"));
});

test("skill routing picks the diff skill for every Git-backed change set", () => {
  assert.equal(skillNameFor({ kind: "repository" }, "standard"), "security-scan");
  assert.equal(skillNameFor({ kind: "paths" }, "standard"), "security-scan");
  assert.equal(skillNameFor({ kind: "repository" }, "deep"), "deep-security-scan");
  assert.equal(skillNameFor({ kind: "refs" }, "standard"), "security-diff-scan");
  assert.equal(skillNameFor({ kind: "working_tree" }, "deep"), "security-diff-scan");
});

test("target descriptions name the resolved scope", () => {
  assert.match(targetDescription({ kind: "paths", paths: ["src", "lib"] }), /src, lib/);
  assert.match(
    targetDescription({ kind: "refs", baseRef: "main", headRef: "HEAD" }),
    /main\.\.HEAD/,
  );
});

test("API key variables are stripped unless the operator opts in", () => {
  const withKeys = { ANTHROPIC_API_KEY: "sk-test", ANTHROPIC_AUTH_TOKEN: "t", PATH: "/bin" };
  const stripped = withoutApiKeys(withKeys);
  for (const name of API_KEY_VARIABLES) assert.equal(stripped[name], undefined);
  assert.equal(stripped.PATH, "/bin");

  const optedIn = withoutApiKeys({ ...withKeys, CLAUDE_SECURITY_ALLOW_API_KEY: "1" });
  assert.equal(optedIn.ANTHROPIC_API_KEY, "sk-test");
});

test("auth status reports an API key as ignored rather than silently honored", async () => {
  const status = await authStatus({
    CLAUDE_CONFIG_DIR: "/nonexistent-claude-config",
    ANTHROPIC_API_KEY: "sk-test",
  });
  assert.deepEqual(status.apiKeyPresent, ["ANTHROPIC_API_KEY"]);
  assert.equal(status.apiKeyIgnored, true);
  assert.match(describeAuth(status), /Ignoring ANTHROPIC_API_KEY/);
});

test("a dead refresh token is the only thing that counts as signed out", async () => {
  const status = await authStatus({ CLAUDE_CONFIG_DIR: "/nonexistent-claude-config" });
  // An unreadable credential store (macOS Keychain, credential helper) must not
  // be reported as signed out, or working setups would be blocked.
  assert.equal(status.authenticated, true);
  assert.equal(status.determined, false);
});

test("scan sessions are isolated from operator settings and cannot write the target", () => {
  const args = buildClaudeArgs({
    model: "claude-opus-5",
    effort: "high",
    settings: scanSettings("C:\\repos\\target"),
    addDirs: ["C:\\repos\\target"],
  });
  assert.ok(args.includes("--print"));
  assert.deepEqual(args.slice(args.indexOf("--output-format"), args.indexOf("--output-format") + 2), [
    "--output-format",
    "stream-json",
  ]);
  assert.equal(args[args.indexOf("--permission-mode") + 1], "bypassPermissions");
  assert.equal(args[args.indexOf("--setting-sources") + 1], "");
  assert.equal(args[args.indexOf("--model") + 1], "claude-opus-5");
  assert.equal(args[args.indexOf("--effort") + 1], "high");

  const settings = JSON.parse(args[args.indexOf("--settings") + 1]);
  assert.ok(settings.permissions.deny.includes("Write(C:/repos/target/**)"));
  assert.ok(settings.permissions.deny.includes("Edit(C:/repos/target/**)"));
});

test("an explicit claude path overrides platform resolution", () => {
  assert.equal(resolveClaudeCommand({ CLAUDE_SECURITY_CLAUDE_PATH: "/opt/claude" }), "/opt/claude");
  assert.match(resolveClaudeCommand({}), /^claude(\.exe)?$/);
});

test("the scan prompt pins identity and forbids sealing", () => {
  const prompt = scanPrompt({ target: { kind: "repository", paths: [] }, mode: "standard" });
  assert.match(prompt, /claude-security:security-scan/);
  assert.match(prompt, /CLAUDE_SECURITY_SCAN_ID/);
  assert.match(prompt, /Omit scan\.sealedAt and scan\.artifacts/);
  assert.match(prompt, /do not run the finalizer/i);
  assert.match(prompt, /never wait for confirmation/i);
});

test("the reducer prompt defines newFindingsCount as the saturation signal", () => {
  const prompt = deepDedupPrompt({
    inputs: [
      {
        workerId: "w1",
        rawCandidatesPath: "/w1/raw.jsonl",
        inScopeFilesPath: "/w1/files.txt",
        threatModelPath: "/w1/tm.md",
        reportPath: "/w1/report.md",
      },
    ],
    canonical: {
      inventory: "/c/inv.jsonl",
      findingReport: "/c/report.md",
      candidates: "/c/candidates.jsonl",
      dedupeReport: "/c/dedupe.md",
      seedResearch: "/c/seed.md",
      workLedger: "/c/ledger.jsonl",
      rawCandidates: "/c/raw.jsonl",
      coverageLedger: "/c/coverage.md",
      findingsDir: "/c/findings",
    },
    resultManifestPath: "/c/result.json",
  });
  assert.match(prompt, /newFindingsCount/);
  assert.match(prompt, /saturated/);
  assert.match(prompt, /first reduction/);
});

test("the state directory stays under the Claude config home", () => {
  const directory = stateDirectory({ CLAUDE_CONFIG_DIR: "/tmp/claude-home" });
  assert.match(directory.split("\\").join("/"), /claude-home\/state\/plugins\/claude-security$/);
  // An explicit override wins; it is resolved to an absolute path, which on
  // Windows means it picks up a drive letter.
  assert.match(
    stateDirectory({ CLAUDE_SECURITY_STATE_DIR: "/tmp/explicit" }).split("\\").join("/"),
    /^([A-Za-z]:)?\/tmp\/explicit$/,
  );
});

test("reduction inputs are ordered by completion, not by launch order", () => {
  // Regression: a deep scan failed with "must claim an ordered prefix of
  // buffered discovery results in completion order" because workers run
  // concurrently and the first one dispatched finished second.
  const launchOrder = [{ workerId: "first-dispatched" }, { workerId: "second-dispatched" }];
  const state = {
    workers: [
      { id: "first-dispatched", completionSequence: 2 },
      { id: "second-dispatched", completionSequence: 1 },
    ],
  };
  assert.deepEqual(
    orderByCompletion(launchOrder, state).map((record) => record.workerId),
    ["second-dispatched", "first-dispatched"],
  );
});

test("a worker with no completion sequence sorts last instead of misclaiming", () => {
  const records = [{ workerId: "unknown" }, { workerId: "sequenced" }];
  const state = { workers: [{ id: "sequenced", completionSequence: 1 }] };
  assert.deepEqual(
    orderByCompletion(records, state).map((record) => record.workerId),
    ["sequenced", "unknown"],
  );
  // Missing worker list must not throw or reorder arbitrarily.
  assert.equal(orderByCompletion(records, {}).length, 2);
});

test("every session is told to delegate synchronously and never poll", () => {
  // Regression: a deep-scan tail spent 56 of its last 80 tool calls polling the
  // filesystem for subagent output, because Task subagents default to running in
  // the background and the session never received their results directly.
  const prompts = [
    scanPrompt({ target: { kind: "repository", paths: [] }, mode: "standard" }),
    deepTailPrompt({
      manifestPath: "/scan/manifest.json",
      target: { kind: "repository", paths: [] },
    }),
    deepDiscoveryPrompt({
      workerId: "w1",
      workerIndex: 1,
      round: 1,
      artifactDir: "/w1",
      resultManifestPath: "/w1/result.json",
    }),
  ];
  for (const prompt of prompts) {
    assert.match(prompt, /run_in_background: false/);
    assert.match(prompt, /[Nn]ever poll the filesystem in a loop/);
  }
});

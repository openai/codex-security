const sha = "a".repeat(40);
const hash = "b".repeat(64);
const range = { path: "src/codec.ts", commit: sha, startLine: 3, endLine: 3 };
const query = {
  window: { start: "2099-02-01T00:00:00Z", end: "2099-02-01T01:00:00Z" },
};
const ref = { id: "copy", revision: 2, hash };
const dep = { id: "call", revision: 1, hash };

export function stackReport() {
  const common = {
    verdict: "unknown",
    supportingClaims: [],
    scopeConflicts: [],
    sinkMatches: [],
    leads: [],
  };
  const stack = {
    ...common,
    workItemId: "captures/0/stacks/0",
    captureIndex: 0,
    stackIndex: 0,
    origin: "debugger backtrace",
    query: { ...query, coverage: "partial" },
    reason: "The decoder ran. Its effective mode is unknown.",
    supportingClaims: [ref],
    remainingQuestions: ["Which decoder mode ran?"],
    questionChecks: [
      {
        question: "Which decoder mode ran?",
        checked: "Inspected the decoder configuration.",
        missingEvidence: "The effective runtime flag.",
        claims: [ref],
      },
    ],
    frameIndices: [0, 4],
    use: {
      location: "decode at the upload handler",
      component: "sample-codec",
      version: "1.0",
      deployment: "unknown",
      verdict: "unknown",
      reason: "The guard is configurable.",
      evidence: [range],
      proof: {
        sink: { function: "decode", callSite: { path: range.path, line: 3 } },
        conditions: [
          {
            label: "Affected mode enabled",
            status: "unknown",
            explanation: "No effective setting in the sample.",
            citations: [],
          },
        ],
      },
    },
    status: "observed",
    sinkMatches: [{ sinkId: "codec", rawIndex: 0 }],
    stack: {
      labels: { process: "uploader", environment: "prod" },
      frames: [
        {
          rawIndex: 0,
          frame: {
            name: "decode",
            type: "native",
            package: {
              name: "sample-codec",
              version: "1.0",
              provenance: "local build record",
            },
          },
        },
        { rawIndex: 4, frame: { name: "upload", type: "function" } },
      ],
    },
  };
  const noMatch = {
    ...common,
    workItemId: "captures/1",
    captureIndex: 1,
    stackIndex: null,
    status: "no_match",
    stack: null,
    reason: "The search returned no matching stacks.",
    remainingQuestions: ["Did the job run?"],
    query: {
      ...query,
      selectors: { process: "scheduled-job" },
      coverage: "complete",
    },
  };
  const source = {
    ...range,
    blob: sha,
    contentSha256: hash,
    text: "return decode(bytes);",
  };
  return {
    schemaVersion: "codex-security.pipeline-stacks.report/v2",
    review: null,
    cve: "CVE-2099-10001",
    runId: "run-a",
    attemptId: "attempt-a",
    inputDigest: hash,
    toolRevision: sha,
    target: { repository: "example", sha },
    verdict: "unknown",
    assessments: [stack, noMatch] as const,
    claims: [
      {
        ...ref,
        scope: { workItemId: stack.workItemId },
        dependencies: [dep],
        payload: { fact: "Sampled copy 1.0", limits: "Mode unverified" },
        sources: [],
        receipts: [
          {
            receiptId: "sample-1",
            server: "stack-packet",
            origin: { arguments: { workItemId: stack.workItemId } },
            originalPayloadSha256: hash,
            result: "RAW_RECEIPT_CONTENT",
          },
        ],
      },
      {
        ...dep,
        scope: {},
        dependencies: [],
        payload: "The upload calls the decoder.",
        sources: [source],
        receipts: [],
      },
    ],
    coverage: {
      total: 2,
      assessed: 2,
      observed: 1,
      outstanding: [],
      noMatch: [noMatch.workItemId],
      noCoverage: [],
      scopeConflicts: [],
      incompleteSearch: [stack.workItemId],
    },
    remainingQuestions: [
      ...stack.remainingQuestions,
      ...noMatch.remainingQuestions,
    ],
  };
}

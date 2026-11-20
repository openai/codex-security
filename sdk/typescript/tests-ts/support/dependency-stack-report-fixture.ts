const sha = "a".repeat(40);
const hash = "b".repeat(64);
const range = { path: "src/codec.ts", commit: sha, startLine: 3, endLine: 3 };
const scope = {
  window: { start: "2099-02-01T00:00:00Z", end: "2099-02-01T01:00:00Z" },
};
const ref = { id: "copy", revision: 2, hash };
const dep = { id: "call", revision: 1, hash };

export function stackReport() {
  const common = {
    verdict: "unknown",
    supportingClaims: [],
    queryId: "query-a",
    groupId: "group-a",
    scopeConflicts: [],
    queryScope: scope,
    scope,
    truncated: null,
  };
  const stack = {
    ...common,
    workItemId: "sample-a",
    reason: "The decoder ran. Its effective mode is unknown.",
    supportingClaims: [ref],
    remainingQuestions: ["Which decoder mode ran?"],
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
    scope: { ...scope, service: "uploader", environment: "prod" },
    truncated: true,
    observation: {
      id: "observation-a",
      stackHash: "stack-a",
      framesTruncated: false,
      sourceIndex: 4,
      sinkIndex: 0,
      sinkMatches: [{ sinkId: "codec", rawIndex: 0 }],
      frames: [
        { rawIndex: 0, frame: { name: "decode", type: "native" } },
        { rawIndex: 4, frame: { name: "upload", type: "function" } },
      ],
      bindings: [
        {
          package: "sample-codec",
          version: "1.0",
          provenance: "sample",
          frameIndices: [0],
        },
      ],
    },
  };
  const noMatch = {
    ...common,
    workItemId: "sample-b",
    groupId: "group-b",
    status: "no_match",
    observation: null,
    reason: "No matching sample in this window.",
    remainingQuestions: ["Did the job run?"],
    queryScope: { ...scope, service: "scheduled-job" },
    scope: { ...scope, service: "scheduled-job" },
  };
  const source = {
    ...range,
    blob: sha,
    contentSha256: hash,
    text: "return decode(bytes);",
  };
  return {
    schemaVersion: "codex-security.pipeline-stacks.report/v1",
    reviewPolicy: "single_agent",
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
      truncated: [stack.workItemId],
      truncationUnknown: [noMatch.workItemId],
    },
    remainingQuestions: [
      ...stack.remainingQuestions,
      ...noMatch.remainingQuestions,
    ],
  };
}

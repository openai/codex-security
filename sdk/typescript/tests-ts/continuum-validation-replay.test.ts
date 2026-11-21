import {
  continuumTestRepository,
  registeredSource,
  creation,
  requestBody,
} from "./support/continuum-validation-fixtures.js";
import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import {
  ContinuumValidationProvider,
  type ContinuumAwsLauncher,
} from "../src/continuum-validation-provider.js";
import type { ValidationItemRecord } from "../src/validation-provider.js";

const recorded = JSON.parse(
  await readFile(
    new URL("./fixtures/continuum-recorded-shape.json", import.meta.url),
    "utf8",
  ),
);
const context = continuumTestRepository();

const finding: Record<string, unknown> & {
  severity: { level: string };
  occurrenceId: string;
} = {
  ...(Object.values(recorded.findings)[0] as Record<string, unknown>),
  severity: { level: "high" },
  occurrenceId: recorded.findings[recorded.issue.findingIds[0]].sourceFindingId,
};

/** Admission and the external producer identity are synthetic. Issue evidence has the recorded shape. */
function transport(fixture = structuredClone(recorded)): ContinuumAwsLauncher {
  return async (operation, args) => {
    const setup = registeredSource(operation, recorded.environmentId);
    if (setup) return setup;
    if (operation === "create-code-finding")
      return creation(
        (Object.values(fixture.findings)[0] as any).findingId,
        recorded.environmentId,
      );
    if (operation === "get-code-finding")
      return {
        ...(Object.values(fixture.findings)[0] as object),
        source: "Codex Security",
        sourceFindingId: finding["occurrenceId"],
      };
    if (operation === "get-code-issue") return structuredClone(fixture.issue);
    if (operation === "list-code-issue-artifacts")
      return structuredClone(fixture.artifactLists[args.at(-1)!]);
    if (operation === "get-code-issue-artifact")
      return structuredClone(fixture.artifacts[args.at(-1)!]);
    throw new Error(`Unexpected fake transport operation: ${operation}`);
  };
}
function provider(launcher = transport()) {
  let elapsed = 0;
  return new ContinuumValidationProvider({
    environmentId: recorded.environmentId,
    launcher,
    now: () => new Date(Date.parse("2026-11-06T15:20:00Z") + elapsed),
    delay: async (ms) => {
      elapsed += ms;
    },
  });
}
function validation(fixture: typeof recorded) {
  const { artifactId } = fixture.artifactLists.VALIDATION_EVIDENCE.items[0];
  return fixture.artifacts[artifactId].body.validationEvidence;
}

function reachability(fixture: typeof recorded) {
  const evidence = Object.values(fixture.artifacts).find(
    (a: any) => a.artifactType === "EVIDENCE",
  ) as any;
  return evidence.body.prevalidationSignals.signals.find(
    (s: any) => s.dimension === "LIKELIHOOD_ASSESSMENT",
  ).preconditions.reachableFromAttacker;
}

// The recorded issue has no finding-specific result. Supply independent
// synthetic AWS PerFindingResult data to exercise the positive path.
const step = {
  step: 1,
  claim: "PRIVATE_CLAIM: Evaluating supplied template text permits injection.",
  source: "src/templates.py:23",
};
const httpProof = {
  httpMethod: "POST",
  targetUrl: "https://example.invalid/PRIVATE_PATH",
  payload: "PRIVATE_PAYLOAD",
  responseStatus: 200,
  responseSnippet: "PRIVATE_RESPONSE",
  effect: "BEHAVIOR_CHANGED",
};

function withObservation(
  proof: Record<string, unknown> = {
    reasoningChain: [step],
    exploitArtifact: httpProof,
  },
) {
  const fixture = structuredClone(recorded);
  validation(fixture).perFindingResults = [
    {
      findingId: finding["findingId"],
      exploitable: "EXPLOITABLE",
      ...structuredClone(proof),
    },
  ];
  return fixture;
}

describe("recorded shape, anonymised replay", () => {
  test("keeps the recorded singleton's verdict, GRAPH exposure and severity on the issue", async () => {
    const result = await provider().validate(finding, context);
    expect(result.report).toContain(
      "Issue reachable from attacker (basis GRAPH)",
    );
    expect(result.report).toContain("likelihood HIGH × impact HIGH");
    expect(result.report).toContain(
      "Deployment source identity is not compared",
    );
    expect(result.record).toMatchObject({
      verdict: "EXPLOITABLE",
      terminalStatus: "COMPLETED",
      severityBefore: "high",
      severityAfter: "high",
      providerSeverity: "critical",
      resultScope: "issue",
      issueFindingCount: 1,
      claimMatch: "unknown",
      reachableFromAttacker: true,
      freshness: { stale: false },
    });
    expect(result.record?.issueUrl).toContain(recorded.issueId);
    expect(result.record?.reasons).toContainEqual(
      expect.objectContaining({
        basis: "GRAPH",
        reason: expect.stringContaining("reachableFromAttacker: true"),
      }),
    );
    expect(result.record?.reasons).toContainEqual(
      expect.objectContaining({
        basis: "FINDING",
        reason: expect.stringContaining("configurationNeeded"),
      }),
    );
    const roundTrip: ValidationItemRecord = JSON.parse(
      JSON.stringify(result.record),
    );
    expect(roundTrip).toEqual(result.record as ValidationItemRecord);
    expect(JSON.stringify(roundTrip)).not.toMatch(
      /executedProof|consoleOutput|payload/u,
    );
  });
});

describe("explicitly fake outcome variations", () => {
  test.each([
    ["FAILED", "UNCERTAIN", true],
    ["NO_SOURCE_AVAILABLE", "UNCERTAIN", true],
    ["PARTIAL", "EXPLOITABLE", false],
    ["COMPLETED", "UNCERTAIN", false],
    ["COMPLETED", undefined, false],
  ] as const)(
    "keeps %s distinct from verdict %s and retains the finding's severity",
    async (terminalStatus, exploitable, failed) => {
      const fake = withObservation();
      validation(fake).terminalStatus = terminalStatus;
      validation(fake).exploitable = exploitable;
      validation(fake).perFindingResults[0].exploitable = exploitable;
      fake.issue.severity = "LOW";
      reachability(fake).value = false;
      const result = await provider(transport(fake)).validate(finding, context);
      expect(result.disposition).toBe("deferred");
      expect(result.record?.proofObservation).toBeUndefined();
      expect(result.record).toMatchObject({
        terminalStatus,
        verdict: exploitable ?? "UNKNOWN",
        severityBefore: "high",
        severityAfter: "high",
        providerSeverity: "low",
        claimMatch: "unknown",
      });
      expect(result.record?.freshness.validatedAt).toBeUndefined();
      expect(result.provenance.validatedAt).toBeUndefined();
      expect(Boolean(result.unavailable)).toBe(failed);
      expect(result.record?.unavailable).toBe(result.unavailable);
      expect(result.report).toContain(terminalStatus);
      expect(result.report).not.toMatch(/validated at|lower priority/iu);
    },
  );

  test("returns a failed bundle immediately with its selected verdict even without scoring", async () => {
    const fake = structuredClone(recorded);
    const id = fake.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId;
    fake.artifacts[id].body.validationEvidence = {
      terminalStatus: "FAILED",
      exploitable: "UNCERTAIN",
      perFindingResults: [
        { findingId: "another-finding", exploitable: "NOT_EXPLOITABLE" },
        {
          findingId: finding["findingId"],
          exploitable: "EXPLOITABLE",
          reasoningChain: [step],
          exploitArtifact: httpProof,
        },
      ],
    };
    fake.artifactLists.EVIDENCE.items = [];
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.unavailable).toContain("FAILED");
    expect(result.report).toContain(id);
    expect(result.report).toContain(
      new Date(fake.artifacts[id].createdAt).toISOString(),
    );
    expect(result.record).toMatchObject({
      terminalStatus: "FAILED",
      verdict: "EXPLOITABLE",
      resultScope: "finding",
      severityAfter: "high",
      claimMatch: "unknown",
    });
    expect(result.record?.freshness.validatedAt).toBeUndefined();
  });

  test("does not synthesize a timestamp when the validation artifact omits it", async () => {
    const fake = structuredClone(recorded);
    const id = fake.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId;
    delete fake.artifacts[id].createdAt;
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record?.verdict).toBe("EXPLOITABLE");
    expect(result.provenance.validatedAt).toBeUndefined();
    expect(result.record?.freshness.validatedAt).toBeUndefined();
    expect(result.report).not.toContain("current at submission");
  });

  test("lowers supplemental severity for a NOT_EXPOSED graph answer", async () => {
    const fake = withObservation();
    fake.issue.severity = "LOW";
    Object.assign(reachability(fake), {
      value: false,
      basis: "GRAPH",
      reason: "NOT_EXPOSED: the observed deployment has no public ingress.",
    });
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record).toMatchObject({
      resultScope: "finding",
      providerSeverity: "low",
      severityAfter: "low",
    });
    expect(result.report).toContain(
      "not reachable from attacker (basis GRAPH)",
    );
    expect(result.report).toContain("lower priority");
    expect(finding.severity.level).toBe("high");
  });

  test.each(["issueId", "issueArn"])(
    "applies linked scoring signals identified by %s",
    async (key) => {
      const fake = withObservation();
      const score =
        fake.artifacts[fake.artifactLists.EVIDENCE.items[0].artifactId];
      for (const signal of score.body.prevalidationSignals.signals)
        signal.subjectRef = fake.issue[key];
      const result = await provider(transport(fake)).validate(finding, context);
      expect(result.record).toMatchObject({
        validationArtifactId:
          fake.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId,
        scoringArtifactId: fake.artifactLists.EVIDENCE.items[0].artifactId,
        reachableFromAttacker: true,
        resultScope: "finding",
        proofObservation: { kind: "execution", effect: "BEHAVIOR_CHANGED" },
        severityAfter: "critical",
        claimMatch: "on_target",
      });
      expect(JSON.stringify(result)).not.toContain("PRIVATE_");
    },
  );

  test.each([
    "related caption",
    "issue-level proof",
    "conflicting entries",
    "missing verdict",
  ])("an issue's %s leaves the finding match unknown", async (scenario) => {
    const fake = structuredClone(recorded);
    if (scenario === "related caption") {
      fake.issue.name = "Resource exhaustion and denial";
      fake.issue.synopsis = "Resource exhaustion in src/templates.py";
    } else if (scenario === "issue-level proof") {
      validation(fake).executedProof = {
        code: {
          proofCode: [{ content: "Template injection in src/templates.py:23" }],
        },
        observedEffect: "BEHAVIOR_CHANGED",
      };
      validation(fake).reasoningChain = [step];
      validation(fake).exploitArtifact = httpProof;
    } else if (scenario === "conflicting entries") {
      validation(fake).perFindingResults = [
        { findingId: finding["findingId"], exploitable: "NOT_EXPLOITABLE" },
        { findingId: finding["findingId"], exploitable: "UNCERTAIN" },
      ];
    } else {
      validation(fake).perFindingResults = [
        { findingId: finding["findingId"] },
      ];
    }
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record).toMatchObject({
      verdict: "EXPLOITABLE",
      resultScope: "issue",
      claimMatch: "unknown",
      severityAfter: "high",
      providerSeverity: "critical",
    });
    expect(result.record?.proofObservation).toBeUndefined();
    expect(result.report).not.toContain("findings false-positive");
  });

  test.each([
    ["another line", [{ ...step, source: "src/templates.py:1" }]],
    [
      "split citation and claim",
      [
        { ...step, claim: "Reads input." },
        { ...step, step: 2, source: "src/another.py:23" },
      ],
    ],
    [
      "citation only in the claim",
      [
        {
          ...step,
          source: "src/another.py:23",
          claim: step.claim + " " + step.source,
        },
      ],
    ],
    [
      "claim only in source",
      [
        {
          ...step,
          source: step.source + " " + step.claim,
          claim: "Reads input.",
        },
      ],
    ],
    ["invalid step", [{ ...step, step: "1" }]],
    ["unstructured reasoning", [step.claim + " " + step.source]],
    ["missing reasoning", undefined],
  ] as const)(
    "does not attribute the HTTP proof with %s",
    async (_, reasoningChain) => {
      const fake = withObservation({
        reasoningChain,
        exploitArtifact: httpProof,
      });
      const result = await provider(transport(fake)).validate(finding, context);
      expect(result.record).toMatchObject({
        resultScope: "finding",
        claimMatch: "unknown",
        severityAfter: "high",
      });
      expect(result.record?.proofObservation).toBeUndefined();
      expect(JSON.stringify(result)).not.toContain("PRIVATE_");
    },
  );

  test.each([
    ["reasoning only", undefined],
    ["no effect", { ...httpProof, effect: "NO_EFFECT" }],
    ["unknown effect", { ...httpProof, effect: "PRIVATE_EFFECT" }],
    ["missing payload", { ...httpProof, payload: undefined }],
    ["missing method", { ...httpProof, httpMethod: undefined }],
    ["invalid method", { ...httpProof, httpMethod: "INVALID" }],
    ["invalid target", { ...httpProof, targetUrl: "not a URL" }],
  ] as const)(
    "matches reasoning without claiming execution for %s",
    async (_, exploitArtifact) => {
      const fake = withObservation({ reasoningChain: [step], exploitArtifact });
      const result = await provider(transport(fake)).validate(finding, context);
      expect(result.record).toMatchObject({
        claimMatch: "on_target",
        severityAfter: "critical",
      });
      expect(result.record?.proofObservation).toBeUndefined();
      expect(JSON.stringify(result)).not.toContain("PRIVATE_");
    },
  );

  test("cannot borrow a sibling's or the issue's HTTP proof", async () => {
    const fake = withObservation({ reasoningChain: [step] });
    validation(fake).exploitArtifact = httpProof;
    validation(fake).perFindingResults.unshift({
      findingId: "another",
      exploitable: "EXPLOITABLE",
      reasoningChain: [step],
      exploitArtifact: httpProof,
    });
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record?.claimMatch).toBe("on_target");
    expect(result.record?.proofObservation).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain("PRIVATE_");
  });

  test("retains matching and scoring for a conclusive legacy verdict without run status", async () => {
    const fake = withObservation();
    const id = fake.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId;
    delete fake.artifacts[id].body.validationEvidence.terminalStatus;
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.disposition).toBe("reportable");
    expect(result.record).toMatchObject({
      verdict: "EXPLOITABLE",
      claimMatch: "on_target",
      severityAfter: "critical",
    });
    expect(result.record?.terminalStatus).toBeUndefined();
    expect(result.record?.proofObservation).toBeUndefined();
  });

  test.each([
    { code: { proofCode: [{ content: "incomplete execution" }] } },
    { observedEffect: "BEHAVIOR_CHANGED" },
    { observedEffect: "BEHAVIOR_CHANGED", code: { proofCode: [] } },
  ])(
    "uses the source analysis when execution is incomplete: %j",
    async (execution) => {
      const summary =
        "In src/templates.py:23, evaluating supplied template text permits injection.";
      const fake = withObservation({
        sourceAnalysis: { summary },
        executedProof: execution,
      });
      const result = await provider(transport(fake)).validate(finding, context);
      expect(result.record?.severityAfter).toBe("critical");
      expect(result.record?.proofObservation).toEqual({
        kind: "source_analysis",
        summary,
      });
      expect(result.report).toContain("using source analysis");
    },
  );

  test("an older linked scorer cannot establish the current issue severity", async () => {
    const fake = withObservation();
    const history = fake.artifactLists.EVIDENCE.items;
    const latest = {
      artifactId: "new-score",
      createdAt: fake.issue.updatedAt,
    };
    const score = {
      ...structuredClone(fake.artifacts[history[0].artifactId]),
      ...latest,
    };
    score.body.prevalidationSignals.signals[0].exploitability.sourceValidationArtifactId =
      "another-proof";
    fake.artifacts[latest.artifactId] = score;
    history.push(latest);
    const linked = fake.artifacts[history[0].artifactId];
    const newestLinked = {
      artifactId: "newest-linked",
      createdAt: "2026-11-06T15:44:00Z",
    };
    const candidate = { ...structuredClone(linked), ...newestLinked };
    for (const signal of candidate.body.prevalidationSignals.signals)
      delete signal.computed;
    fake.artifacts[newestLinked.artifactId] = candidate;
    history.push(newestLinked);
    fake.issue.severityReasoning = "UNRELATED_FACTORS";
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record).toMatchObject({
      claimMatch: "on_target",
      scoringArtifactId: newestLinked.artifactId,
      severityAfter: "high",
      providerSeverity: "critical",
    });
    expect(result.record?.proofObservation?.kind).toBe("execution");
    expect(result.record?.reachableFromAttacker).toBe(true);
    expect(result.report).toContain("latest issue score");
    expect(JSON.stringify(result)).not.toContain("UNRELATED_FACTORS");
  });

  test("returns the executed effect without copying the proof body", async () => {
    const fake = withObservation({
      executedProof: {
        observedEffect: "BEHAVIOR_CHANGED",
        code: {
          proofCode: [
            {
              content:
                "PRIVATE_PROOF: template injection in src/templates.py:23",
            },
          ],
        },
        output: { consoleOutput: "PRIVATE_OUTPUT" },
      },
    });
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record?.proofObservation).toEqual({
      kind: "execution",
      effect: "BEHAVIOR_CHANGED",
    });
    expect(JSON.stringify(result)).not.toMatch(/PRIVATE_PROOF|PRIVATE_OUTPUT/u);
  });

  test("returns a bounded source conclusion from the selected finding in a bundle", async () => {
    const fake = structuredClone(recorded);
    const id = fake.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId;
    const summary =
      "Template injection\n\noccurs in src/templates.py:23. " + "x".repeat(400);
    fake.artifacts[id].body.validationEvidence.perFindingResults = [
      { findingId: "sibling", sourceAnalysis: { summary: "OTHER_RESULT" } },
      {
        findingId: finding["findingId"],
        exploitable: "EXPLOITABLE",
        sourceAnalysis: { inferredEffect: "DATA_LEAKED", summary },
      },
    ];
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record?.proofObservation).toEqual({
      kind: "source_analysis",
      effect: "DATA_LEAKED",
      summary: summary.replace(/\s+/gu, " ").slice(0, 320),
    });
    expect(JSON.stringify(result)).not.toContain("OTHER_RESULT");
  });

  test.each([
    "different source path",
    "same basename at a different path",
    "stale proof",
    "unknown proof time",
    "unknown scoring time",
    "older issue snapshot",
    "other proof reference",
    "absent proof reference",
    "other issue subject",
    "issue ARN from a different environment",
    "other scorer verdict",
    "missing subject",
    "shared issue score",
  ])("keeps the provider score separate with %s", async (scenario) => {
    const fake = withObservation();
    const score =
      fake.artifacts[fake.artifactLists.EVIDENCE.items[0].artifactId];
    const proof =
      fake.artifacts[
        fake.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId
      ];
    const selected = proof.body.validationEvidence.perFindingResults[0];
    const signal = score.body.prevalidationSignals.signals[0];
    fake.issue.severity = "LOW";
    reachability(fake).value = false;
    reachability(fake).reason = "PRIVATE_PRECONDITION";
    fake.issue.severityReasoning = "PRIVATE_FACTORS";
    switch (scenario) {
      case "different source path":
        selected.reasoningChain[0].source = "src/another.py:23";
        break;
      case "same basename at a different path":
        selected.reasoningChain[0].source = "tests/templates.py:23";
        break;
      case "stale proof":
        proof.createdAt = "2026-11-01T00:00:00Z";
        break;
      case "unknown proof time":
        proof.createdAt = "invalid";
        break;
      case "unknown scoring time":
        delete score.createdAt;
        break;
      case "older issue snapshot":
        fake.issue.updatedAt = proof.createdAt;
        break;
      case "other proof reference":
        signal.exploitability.sourceValidationArtifactId = "other-proof";
        break;
      case "absent proof reference":
        delete signal.exploitability.sourceValidationArtifactId;
        break;
      case "other issue subject":
        signal.subjectRef = "other-issue";
        break;
      case "issue ARN from a different environment":
        signal.subjectRef = fake.issue.issueArn.replace(
          fake.environmentId,
          "another-environment",
        );
        break;
      case "other scorer verdict":
        signal.exploitability.verdict = "NOT_EXPLOITABLE";
        break;
      case "missing subject":
        delete signal.subjectRef;
        break;
      case "shared issue score":
        fake.issue.findingIds.push("another-finding");
    }
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record).toMatchObject({
      severityAfter: "high",
      providerSeverity: "low",
    });
    expect(result.record?.proofObservation).toBeUndefined();
    expect(result.report).not.toContain("lower priority");
    if (!scenario.includes("path")) {
      expect(result.record?.reachableFromAttacker).toBeUndefined();
      expect(JSON.stringify(result)).not.toMatch(
        /PRIVATE_PRECONDITION|PRIVATE_FACTORS|likelihood HIGH × impact HIGH/,
      );
    }
  });

  test("a contradictory proof keeps Codex severity even in the same file", async () => {
    const fake = withObservation({
      reasoningChain: [{ ...step, claim: "Resource exhaustion and denial" }],
      exploitArtifact: httpProof,
    });
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record).toMatchObject({
      claimMatch: "different_flaw",
      severityAfter: "high",
      providerSeverity: "critical",
    });
    expect(result.report).toContain(
      "Not validated: Continuum proved a related flaw",
    );
    expect(result.report).not.toContain("findings false-positive");
  });

  test.each([
    "No complete deployment reachability answer was returned.",
    "NOT_EXPOSED cannot be established because the deployment graph is unavailable.",
    "It is not reachable only if a barrier exists; the graph cannot confirm one.",
  ])("UNKNOWN never becomes not exposed from prose: %s", async (reason) => {
    const fake = structuredClone(recorded);
    Object.assign(reachability(fake), {
      value: "UNKNOWN",
      basis: "INFERRED",
      reason,
    });
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.report).toContain("exposure unknown (basis INFERRED)");
    expect(result.report).not.toContain("lower priority");
  });

  test("matches an explicit finding result that differs from the issue verdict", async () => {
    const fake = structuredClone(recorded);
    validation(fake).perFindingResults = [
      {
        findingId: finding["findingId"],
        exploitable: "NOT_EXPLOITABLE",
        reasoningChain: [
          {
            step: 1,
            claim: "The supplied template is sandboxed.",
            source: "src/templates.py:23",
          },
        ],
      },
    ];
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record?.verdict).toBe("NOT_EXPLOITABLE");
    expect(result.record?.resultScope).toBe("finding");
    expect(result.record?.claimMatch).toBe("on_target");
    expect(result.record?.severityAfter).toBe("high");
    expect(result.record?.proofObservation).toBeUndefined();
    expect(finding.severity.level).toBe("high");
  });

  test("a rejected submission and a deadline are isolated from a successful item", async () => {
    let milliseconds = Date.parse("2026-11-06T15:20:00Z");
    const p = new ContinuumValidationProvider({
      environmentId: recorded.environmentId,
      waitMinutes: 1,
      launcher: async (op, args, signal) => {
        if (op === "create-code-finding") {
          const id = JSON.parse(requestBody(args)).ocsfDocument.finding_info
            .uid;
          if (id === "rejected") throw new Error("Fake submission rejected");
          return creation(
            id === finding["occurrenceId"]
              ? (Object.values(recorded.findings)[0] as any).findingId
              : id,
            recorded.environmentId,
          );
        }
        if (op === "get-code-finding" && args.at(-1) === "waiting")
          return {
            status: "SUBMITTED",
            ...creation("waiting", recorded.environmentId),
          };
        return transport()(op, args, signal);
      },
      now: () => new Date(milliseconds),
      delay: async (ms) => {
        await new Promise((resolve) => setTimeout(resolve, 0));
        milliseconds += ms;
      },
    });
    const results = await p.validateBatch(
      [
        finding,
        { ...finding, occurrenceId: "rejected" },
        { ...finding, occurrenceId: "waiting" },
      ],
      context,
    );
    expect(results[0]?.record?.verdict).toBe("EXPLOITABLE");
    expect(results[1]?.record?.unavailable).toContain("rejected");
    expect(results[2]?.record?.unavailable).toMatch(/timed out|deadline/u);
    expect(results.map((r) => r.record?.itemId)).toEqual([
      finding["occurrenceId"],
      "rejected",
      "waiting",
    ]);
  });

  test("waits for BOTH scorer and validation artifacts until the deadline", async () => {
    let milliseconds = 0;
    const p = new ContinuumValidationProvider({
      environmentId: recorded.environmentId,
      waitMinutes: 1,
      launcher: async (op, args, signal) =>
        op === "list-code-issue-artifacts" && args.at(-1) === "EVIDENCE"
          ? { items: [] }
          : transport()(op, args, signal),
      now: () => new Date(milliseconds),
      delay: async (ms) => {
        milliseconds += ms;
      },
    });
    expect((await p.validate(finding, context)).unavailable).toContain(
      "timed out",
    );
  });
});

test.each(["EVIDENCE", "VALIDATION_EVIDENCE"])(
  "rejects %s returned for another requested ID",
  async (kind) => {
    const fake = withObservation();
    fake.artifacts[fake.artifactLists[kind].items[0].artifactId].artifactId =
      "other";
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record?.verdict).toBe("UNAVAILABLE");
    expect(result.record?.proofObservation).toBeUndefined();
  },
);

test("ignores a claim and location echoed in execution output", async () => {
  const fake = withObservation({
    executedProof: {
      code: {
        proofCode: [{ content: "A template injection in src/other.py:23" }],
      },
      output: {
        consoleOutput: "Submitted template injection in src/templates.py:23",
      },
      observedEffect: "BEHAVIOR_CHANGED",
    },
  });
  const result = await provider(transport(fake)).validate(finding, context);
  expect(result.record?.claimMatch).toBe("unknown");
  expect(result.record?.proofObservation).toBeUndefined();
});

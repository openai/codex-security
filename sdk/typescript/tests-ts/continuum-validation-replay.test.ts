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

/** Only the AWS transport is faked. Admission is synthetic, responses have recorded shape. */
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
      return { ...(Object.values(fixture.findings)[0] as object) };
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
function reachability(fixture: typeof recorded) {
  const evidence = Object.values(fixture.artifacts).find(
    (a: any) => a.artifactType === "EVIDENCE",
  ) as any;
  return evidence.body.prevalidationSignals.signals.find(
    (s: any) => s.dimension === "LIKELIHOOD_ASSESSMENT",
  ).preconditions.reachableFromAttacker;
}

// The actual recording contains only a verdict. Give variants their own
// independent observation when testing a successful proof-to-claim match.
function withObservation() {
  const fixture = structuredClone(recorded);
  const proofId = fixture.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId;
  fixture.artifacts[proofId].body.validationEvidence.sourceAnalysis = {
    summary:
      "In src/templates.py:23, evaluating supplied template text permits injection.",
  };
  return fixture;
}

describe("recorded shape, anonymised replay", () => {
  test("reports the issue score and GRAPH exposure without inferring a match from an echoed caption", async () => {
    const result = await provider().validate(finding, context);
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
      const fake = structuredClone(recorded);
      const id = fake.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId;
      fake.artifacts[id].body.validationEvidence = {
        terminalStatus,
        exploitable,
        sourceAnalysis: {
          summary:
            "In src/templates.py:23, evaluating supplied template text permits injection.",
        },
      };
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
          reasoningChain: ["Template injection"],
        },
      ],
    };
    fake.artifactLists.EVIDENCE.items = [];
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.unavailable).toContain("FAILED");
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
    expect(result.record?.severityAfter).toBe("low");
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
        proofObservation: { kind: "source_analysis" },
        severityAfter: "critical",
        claimMatch: "on_target",
      });
    },
  );

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
      const fake = withObservation();
      const id = fake.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId;
      const validation = fake.artifacts[id].body.validationEvidence;
      validation.executedProof = execution;
      const result = await provider(transport(fake)).validate(finding, context);
      expect(result.record?.severityAfter).toBe("critical");
      expect(result.record?.proofObservation).toEqual({
        kind: "source_analysis",
        summary: validation.sourceAnalysis.summary,
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
    expect(result.record?.proofObservation?.kind).toBe("source_analysis");
    expect(result.record?.reachableFromAttacker).toBe(true);
    expect(result.report).toContain("latest issue score");
    expect(JSON.stringify(result)).not.toContain("UNRELATED_FACTORS");
  });

  test("returns the executed effect without copying the proof body", async () => {
    const fake = structuredClone(recorded);
    const id = fake.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId;
    fake.artifacts[id].body.validationEvidence.executedProof = {
      observedEffect: "BEHAVIOR_CHANGED",
      code: {
        proofCode: [
          {
            content: "PRIVATE_PROOF: template injection in src/templates.py:23",
          },
        ],
      },
      output: { consoleOutput: "PRIVATE_OUTPUT" },
    };
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
    const validation = proof.body.validationEvidence;
    const signal = score.body.prevalidationSignals.signals[0];
    fake.issue.severity = "LOW";
    reachability(fake).value = false;
    reachability(fake).reason = "PRIVATE_PRECONDITION";
    fake.issue.severityReasoning = "PRIVATE_FACTORS";
    switch (scenario) {
      case "different source path":
        validation.sourceAnalysis.summary =
          "Template injection in src/another.py";
        break;
      case "same basename at a different path":
        validation.sourceAnalysis.summary =
          "Template injection in tests/templates.py:23";
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
        validation.perFindingResults = [
          {
            findingId: finding["findingId"],
            sourceAnalysis: validation.sourceAnalysis,
            exploitable: validation.exploitable,
          },
        ];
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
    const fake = structuredClone(recorded);
    for (const a of Object.values(fake.artifacts) as any[])
      if (a.artifactType === "VALIDATION_EVIDENCE") {
        a.body.validationEvidence.executedProof = {
          observedEffect: "BEHAVIOR_CHANGED",
          code: {
            proofCode: [
              {
                content:
                  "Resource exhaustion and denial in src/templates.py:23",
              },
            ],
          },
          path: "src/templates.py",
        };
      }
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

  test("reports on-target not exploitable without changing the sealed finding", async () => {
    const fake = withObservation();
    for (const a of Object.values(fake.artifacts) as any[])
      if (a.artifactType === "VALIDATION_EVIDENCE")
        a.body.validationEvidence.exploitable = "NOT_EXPLOITABLE";
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record?.verdict).toBe("NOT_EXPLOITABLE");
    expect(result.record?.claimMatch).toBe("on_target");
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
  const fake = structuredClone(recorded);
  const id = fake.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId;
  fake.artifacts[id].body.validationEvidence.executedProof = {
    code: {
      proofCode: [{ content: "A template injection in src/other.py:23" }],
    },
    output: {
      consoleOutput: "Submitted template injection in src/templates.py:23",
    },
    observedEffect: "BEHAVIOR_CHANGED",
  };
  const result = await provider(transport(fake)).validate(finding, context);
  expect(result.record?.claimMatch).toBe("unknown");
  expect(result.record?.proofObservation).toBeUndefined();
});

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
import { assessPluginFindings } from "../src/plugin-validation.js";
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
    waitMinutes: 1,
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

const proofId = recorded.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId;
const scoreId = recorded.artifactLists.EVIDENCE.items[0].artifactId;
const summary = "Template injection in src/templates.py:23.";

function scoringFixture() {
  const fake = withObservation();
  const proof = fake.artifacts[proofId];
  const score = fake.artifacts[scoreId];
  const signal = score.body.prevalidationSignals.signals[0];
  return {
    fake,
    issue: fake.issue,
    proof,
    score,
    signal,
    exploitability: signal.exploitability,
  };
}

test.each(["member", "failed issue", "sibling"])(
  "tied member and %s validations are independent of list order",
  async (competitor) => {
    const { fake, proof } = scoringFixture();
    const other = structuredClone(proof);
    other.artifactId = "concurrent";
    const evidence = other.body.validationEvidence;
    if (competitor === "failed issue") {
      delete evidence.perFindingResults;
      evidence.terminalStatus = "FAILED";
    } else {
      evidence.perFindingResults[0].exploitable = "NOT_EXPLOITABLE";
      if (competitor === "sibling")
        evidence.perFindingResults[0].findingId = "sibling";
    }
    fake.artifacts[other.artifactId] = other;
    const items = fake.artifactLists.VALIDATION_EVIDENCE.items;
    items.push(other);
    for (let i = 0; i < 2; i++) {
      items.reverse();
      const { record, disposition, unavailable } = await provider(
        transport(fake),
      ).validate(finding, context);
      if (competitor === "sibling") {
        expect(record?.validationArtifactId).toBe(proofId);
        expect(disposition).toBe("reportable");
        continue;
      }
      expect(disposition).toBe("deferred");
      expect(record?.verdict).toBe("UNKNOWN");
      expect(record?.validationArtifactId).toBeUndefined();
      expect(record?.scoringArtifactId).toBeUndefined();
      expect(record?.freshness.evidenceCreatedAt).toBe(proof.createdAt);
      expect(record?.freshness.validatedAt).toBeUndefined();
      expect(unavailable).toContain(proofId);
      expect(unavailable).toContain(other.artifactId);
    }
  },
);

test.each(["SUBMITTED", "VALIDATING"])(
  "waits for current evidence when a %s finding joins an issue with historical proof",
  async (status) => {
    const { fake, proof } = scoringFixture();
    const first = structuredClone(recorded);
    first.artifacts[proofId].createdAt = "2026-11-06T15:19:00Z";
    first.artifactLists.VALIDATION_EVIDENCE.items[0].createdAt =
      first.artifacts[proofId].createdAt;
    let polls = 0;
    const { record } = await provider(async (operation, args) => {
      if (operation === "get-code-finding") polls++;
      const response = await transport(polls < 2 ? first : fake)(
        operation,
        args,
      );
      if (operation === "get-code-finding" && polls === 1)
        response["status"] = status;
      return response;
    }).validate(finding, context);
    expect(polls).toBe(2);
    expect(record?.resultScope).toBe("finding");
    expect(record?.freshness.evidenceCreatedAt).toBe(proof.createdAt);
  },
);

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
      expect(result.record).not.toHaveProperty("proofObservation");
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
    expect(result.report).toContain(fake.artifacts[id].createdAt);
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

  test("keeps issue exposure separate from finding severity", async () => {
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
      severityAfter: "high",
    });
    expect(result.report).toContain(
      "not reachable from attacker (basis GRAPH)",
    );
    expect(result.report).not.toContain("lower priority");
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
        freshness: { scoredAt: score.createdAt },
        severityAfter: "high",
        claimMatch: "unknown",
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
    expect(result.record).not.toHaveProperty("proofObservation");
    expect(result.report).not.toContain("findings false-positive");
  });

  test("reports issue scoring for a conclusive legacy verdict without run status", async () => {
    const fake = withObservation();
    const id = fake.artifactLists.VALIDATION_EVIDENCE.items[0].artifactId;
    delete fake.artifacts[id].body.validationEvidence.terminalStatus;
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.disposition).toBe("reportable");
    expect(result.record).toMatchObject({
      verdict: "EXPLOITABLE",
      claimMatch: "unknown",
      severityAfter: "high",
    });
    expect(result.record?.terminalStatus).toBeUndefined();
    expect(result.record).not.toHaveProperty("proofObservation");
  });

  test.each([
    ["2026-11-06T16:40:18.536989+01:00", "2026-11-06T10:42:53.583051-05:00"],
    ["invalid", "invalid"],
  ])(
    "selects the newest dated proof and score with competing times %s and %s",
    async (proofTime, scoreTime) => {
      const { fake, proof, score } = scoringFixture();
      for (const [artifact, createdAt] of [
        [proof, proofTime],
        [score, scoreTime],
      ]) {
        const artifactId = "older-" + artifact.artifactId;
        fake.artifacts[artifactId] = { ...artifact, artifactId, createdAt };
        fake.artifactLists[artifact.artifactType].items.unshift({
          artifactId,
          createdAt,
        });
      }
      const result = await provider(transport(fake)).validate(finding, context);
      expect(result.record).toMatchObject({
        validationArtifactId: proofId,
        scoringArtifactId: scoreId,
        severityAfter: "high",
        freshness: { evidenceCreatedAt: "2026-11-06T15:40:18.536990+00:00" },
      });
    },
  );

  test.each([true, false])(
    "checks whether a concurrent issue score is also linked (%s)",
    async (linked) => {
      const { fake, score } = scoringFixture();
      const concurrent = {
        ...structuredClone(score),
        artifactId: "concurrent",
      };
      if (!linked)
        concurrent.body.prevalidationSignals.signals[0].exploitability.sourceValidationArtifactId =
          "other";
      fake.artifacts[concurrent.artifactId] = concurrent;
      fake.artifactLists.EVIDENCE.items.push(concurrent);
      const { record } = await provider(transport(fake)).validate(
        finding,
        context,
      );
      expect(record?.verdict).toBe("EXPLOITABLE");
      expect(record?.scoringArtifactId).toBe(linked ? undefined : scoreId);
      expect(record?.scoringPending).toBe(linked ? true : undefined);
      expect(record?.reachableFromAttacker).toBe(linked ? undefined : true);
    },
  );

  test("uses the newest linked evidence while retaining severity if a newer issue score is unrelated", async () => {
    const { fake, score } = scoringFixture();
    for (const [artifactId, createdAt] of [
      ["unrelated", fake.issue.updatedAt],
      ["older", "2026-11-06T15:41:00Z"],
    ]) {
      fake.artifacts[artifactId] = {
        ...structuredClone(score),
        artifactId,
        createdAt,
      };
      fake.artifactLists.EVIDENCE.items.push({ artifactId, createdAt });
    }
    fake.artifacts.unrelated.body.prevalidationSignals.signals[0].exploitability.sourceValidationArtifactId =
      "other-proof";
    for (const signal of score.body.prevalidationSignals.signals)
      delete signal.computed;
    fake.issue.severityReasoning = "UNRELATED_FACTORS";
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record).toMatchObject({
      scoringArtifactId: scoreId,
      severityAfter: "high",
      providerSeverity: "critical",
      reachableFromAttacker: true,
    });
    expect(JSON.stringify(result)).not.toContain("UNRELATED_FACTORS");
  });

  test.each([1, 2])(
    "keeps a bundled proof separate with %i current members",
    async (members) => {
      const fake = structuredClone(recorded);
      if (members === 2) fake.issue.findingIds.push("sibling");
      const validation = fake.artifacts[proofId].body.validationEvidence;
      validation.executedProof = {
        observedEffect: "BEHAVIOR_CHANGED",
        code: { proofCode: [{ content: summary }] },
      };
      validation.perFindingResults = [
        { findingId: "sibling", exploitable: "EXPLOITABLE" },
        {
          findingId: finding["findingId"],
          exploitable: "EXPLOITABLE",
          exploitArtifact: {
            effect: "DATA_LEAKED",
            payload: summary,
            targetUrl: "https://example.test/",
            httpMethod: "POST",
          },
        },
      ];
      const result = await provider(transport(fake)).validate(finding, context);
      expect(result.record).toMatchObject({
        resultScope: "finding",
        verdict: "EXPLOITABLE",
        claimMatch: "unknown",
        severityAfter: "high",
      });
      expect(result.record).not.toHaveProperty("proofObservation");
      expect(result.record?.reachableFromAttacker).toBe(true);
      expect(result.report).toContain("Issue reachable");
    },
  );

  test.each([
    ["proof", "createdAt", "2026-11-01T00:00:00Z"],
    ["proof", "createdAt", "invalid"],
    ["score", "createdAt", undefined],
    ["score", "createdAt", "2026-11-06T16:40:18.536989+01:00"],
    ["issue", "updatedAt", "2026-11-06T10:42:53.583051-05:00"],
    ["issue", "updatedAt", recorded.artifacts[proofId].createdAt],
    ["exploitability", "sourceValidationArtifactId", "other-proof"],
    ["exploitability", "sourceValidationArtifactId", undefined],
    ["exploitability", "verdict", "NOT_EXPLOITABLE"],
    ["signal", "subjectRef", "other-issue"],
    ["signal", "subjectRef", undefined],
    [
      "signal",
      "subjectRef",
      recorded.issue.issueArn.replace(
        recorded.environmentId,
        "other-environment",
      ),
    ],
  ] as const)(
    "rejects scoring when %s.%s is %s",
    async (record, field, value) => {
      const fixture = scoringFixture();
      fixture[record][field] = value;
      reachability(fixture.fake).reason = "PRIVATE_PRECONDITION";
      fixture.issue.severityReasoning = "PRIVATE_FACTORS";
      const result = await provider(transport(fixture.fake)).validate(
        finding,
        context,
      );
      expect(result.record).toMatchObject({
        severityAfter: "high",
        providerSeverity: "critical",
      });
      expect(result.record).not.toHaveProperty("proofObservation");
      expect(result.record?.reachableFromAttacker).toBeUndefined();
      expect(JSON.stringify(result)).not.toMatch(
        /PRIVATE_PRECONDITION|PRIVATE_FACTORS|likelihood HIGH × impact HIGH/,
      );
    },
  );

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

  test("distinguishes a member verdict from the issue verdict referenced by the scorer", async () => {
    const fake = structuredClone(recorded);
    validation(fake).perFindingResults = [
      {
        findingId: finding["findingId"],
        exploitable: "NOT_EXPLOITABLE",
        exploitArtifact: { ...httpProof, effect: "NO_EFFECT" },
        reasoningChain: [
          {
            step: 1,
            claim: "Template injection was blocked by the sandbox.",
            source: "src/templates.py:23",
          },
        ],
      },
    ];
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record?.verdict).toBe("NOT_EXPLOITABLE");
    expect(result.record?.resultScope).toBe("finding");
    expect(result.record?.claimMatch).toBe("unknown");
    expect(result.record?.issueVerdict).toBe("EXPLOITABLE");
    expect(result.record?.scoringArtifactId).toBe(scoreId);
    expect(result.report).toContain("finding verdict: NOT_EXPLOITABLE");
    expect(result.report).toContain("issue verdict: EXPLOITABLE");
    expect(result.record?.severityAfter).toBe("high");
    expect(result.record).not.toHaveProperty("proofObservation");
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

  test.each(["EVIDENCE", scoreId])(
    "keeps the validated verdict and stops polling when reading %s fails",
    async (target) => {
      const launch = transport(withObservation());
      const diagnostic = "AccessDeniedException\nSynthetic score read failure";
      let polls = 0;
      const result = await provider(async (op, args) => {
        if (op === "get-code-finding") polls++;
        if (args.at(-1) === target) throw new Error(diagnostic);
        return launch(op, args);
      }).validate(finding, context);
      expect(result.unavailable).toContain(diagnostic);
      expect(polls).toBe(1);
      expect(result.report).toContain(diagnostic);
      expect(result.record).toMatchObject({
        verdict: "EXPLOITABLE",
        resultScope: "finding",
        terminalStatus: "COMPLETED",
        validationArtifactId: proofId,
        issueId: recorded.issueId,
        scoringPending: true,
        disposition: "deferred",
        unavailable: result.unavailable,
      });
      expect(result.record?.scoringArtifactId).toBeUndefined();
    },
  );

  test.each(["between polls", "first score", "same issue", "changed issue"])(
    "a deadline retains the pending verdict only for its issue (%s)",
    async (stage) => {
      let milliseconds = 0;
      const launch = transport();
      const p = new ContinuumValidationProvider({
        environmentId: recorded.environmentId,
        waitMinutes: 1,
        launcher: async (op, args, signal) => {
          if (
            op === "list-code-issue-artifacts" &&
            args.at(-1) === "EVIDENCE"
          ) {
            if (stage !== "first score") return { items: [] };
            milliseconds = 60_000;
          }
          const response = await launch(op, args, signal);
          if (
            op === "get-code-finding" &&
            milliseconds &&
            stage !== "between polls"
          ) {
            if (stage === "changed issue")
              response["mergedIntoIssueId"] = "new";
            milliseconds = 60_000;
          }
          return response;
        },
        now: () => new Date(milliseconds),
        delay: async (ms) => {
          milliseconds += ms;
        },
      });
      const result = await p.validate(finding, context);
      if (stage === "changed issue") {
        expect(result.record?.verdict).toBe("UNAVAILABLE");
        expect(result.record?.issueId).toBe("new");
        return;
      }
      expect(result.unavailable).toContain("timed out");
      expect(result.record).toMatchObject({
        issueId: recorded.issueId,
        verdict: "EXPLOITABLE",
        terminalStatus: "COMPLETED",
        validationArtifactId: proofId,
        scoringPending: true,
        disposition: "deferred",
      });
      expect(result.record?.scoringArtifactId).toBeUndefined();
      expect(result.report).toContain("Retry");
    },
  );
});

test("a plugin retry drops the old verdict when reading the merge destination fails", async () => {
  const launch = transport();
  let merged = false;
  const p = provider(async (op, args) => {
    if (op === "list-code-issue-artifacts" && args.at(-1) === "EVIDENCE")
      return { items: [] };
    if (op === "get-code-issue" && args.at(-1) === "new")
      throw new Error("Issue read failed");
    const response = await launch(op, args);
    if (op === "get-code-finding" && merged)
      response["mergedIntoIssueId"] = "new";
    return response;
  });
  const pending = await p.validate(finding, context);
  expect(pending.record).toMatchObject({
    issueId: recorded.issueId,
    verdict: "EXPLOITABLE",
    scoringPending: true,
  });
  merged = true;
  const result = await assessPluginFindings(
    {
      provider: "continuum",
      continuum: { environment_id: recorded.environmentId },
    },
    [finding],
    context,
    () => p,
    [pending],
  );
  const record = result.records.items[0]!;
  expect(record).toMatchObject({
    issueId: "new",
    issueArn: recorded.issue.issueArn.replace(recorded.issueId, "new"),
    verdict: "UNAVAILABLE",
    unavailable: "Issue read failed",
  });
  expect(record.validationArtifactId).toBeUndefined();
  expect(record.providerSeverity).toBeUndefined();
  expect(result.summary).not.toContain("EXPLOITABLE");
});

test.each(["EVIDENCE", "VALIDATION_EVIDENCE"])(
  "rejects %s returned for another requested ID",
  async (kind) => {
    const fake = withObservation();
    fake.artifacts[fake.artifactLists[kind].items[0].artifactId].artifactId =
      "other";
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record?.verdict).toBe("UNAVAILABLE");
    expect(result.record).not.toHaveProperty("proofObservation");
  },
);

test("negated same-line evidence cannot authorize a regrade", async () => {
  const fake = withObservation({
    reasoningChain: [
      {
        ...step,
        claim:
          "Template injection is impossible because the template is static.",
      },
      {
        ...step,
        step: 2,
        claim:
          "The actual flaw is credential disclosure in the debug response.",
      },
    ],
    exploitArtifact: { ...httpProof, effect: "DATA_LEAKED" },
  });
  const { record } = await provider(transport(fake)).validate(finding, context);
  expect(record?.claimMatch).not.toStartWith("on_target");
  expect(record?.severityAfter).toBe("high");
  expect(record).not.toHaveProperty("proofObservation");
});

test.each(["FAILED", "PARTIAL", "COMPLETED"])(
  "a newer %s issue run supersedes an earlier finding verdict",
  async (terminalStatus) => {
    const fake = withObservation();
    const newer = {
      ...fake.artifacts[proofId],
      artifactId: "failed-newer",
      createdAt: "2026-11-06T20:00:00Z",
      body: {
        validationEvidence: {
          terminalStatus,
          exploitable: "UNCERTAIN",
        },
      },
    };
    fake.artifacts[newer.artifactId] = newer;
    fake.artifactLists.VALIDATION_EVIDENCE.items.unshift(newer);
    fake.issue.updatedAt = "2026-11-06T20:01:00Z";
    fake.issue.severity = "LOW";
    const { record } = await provider(transport(fake)).validate(
      finding,
      context,
    );
    expect(record?.severityAfter).toBe("high");
    expect(record?.terminalStatus).toBe(terminalStatus);
    expect(record?.disposition).toBe("deferred");
    expect(record?.resultScope).toBe("issue");
    expect(record?.validationArtifactId).toBe(newer.artifactId);
    expect(record?.scoringArtifactId).toBeUndefined();
    expect(record).not.toHaveProperty("proofObservation");
  },
);

test("keep polling when an unrelated score arrives first", async () => {
  const ready = withObservation();
  const waiting = scoringFixture();
  waiting.exploitability.sourceValidationArtifactId = "older-proof";
  waiting.score.artifactId = "older-score";
  waiting.fake.artifacts["older-score"] = waiting.score;
  waiting.fake.artifactLists.EVIDENCE.items[0].artifactId = "older-score";
  let polls = 0;
  const { record } = await provider((operation, args) => {
    if (operation === "get-code-finding") polls++;
    return transport(polls < 2 ? waiting.fake : ready)(operation, args);
  }).validate(finding, context);
  expect(polls).toBeGreaterThan(1);
  expect(record?.scoringArtifactId).toBe(scoreId);
});

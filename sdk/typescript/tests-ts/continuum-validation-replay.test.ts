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

const finding: Record<string, unknown> & { severity: { level: string } } = {
  ...(Object.values(recorded.findings)[0] as Record<string, unknown>),
  severity: { level: "high" },
  occurrenceId: "recorded-shape-item",
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

describe("recorded shape, anonymised replay", () => {
  test("keeps the recorded singleton's verdict, GRAPH exposure and severity on the issue", async () => {
    const result = await provider().validate(finding, context);
    expect(result.report).toContain(
      "issue reachable from attacker (basis GRAPH)",
    );
    expect(result.report).toContain("likelihood HIGH × impact HIGH");
    expect(result.report).toContain(
      "Deployment source identity is not compared",
    );
    expect(result.record).toMatchObject({
      verdict: "EXPLOITABLE",
      severityBefore: "high",
      severityAfter: "high",
      providerSeverity: "critical",
      resultScope: "issue",
      issueFindingCount: 1,
      claimMatch: "unknown",
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
  test("reports the lower issue severity for a NOT_EXPOSED graph answer", async () => {
    const fake = structuredClone(recorded);
    fake.issue.severity = "LOW";
    Object.assign(reachability(fake), {
      value: false,
      basis: "GRAPH",
      reason: "NOT_EXPOSED: the observed deployment has no public ingress.",
    });
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record).toMatchObject({
      resultScope: "issue",
      providerSeverity: "low",
      severityAfter: "high",
    });
    expect(result.report).toContain(
      "not reachable from attacker (basis GRAPH)",
    );
    expect(result.report).toContain("lower priority");
    expect(finding.severity.level).toBe("high");
  });

  test.each([
    "related caption",
    "contradictory proof",
    "conflicting entries",
    "missing verdict",
  ])("an issue's %s leaves the finding match unknown", async (scenario) => {
    const fake = structuredClone(recorded);
    if (scenario === "related caption") {
      fake.issue.name = "Resource exhaustion and denial";
      fake.issue.synopsis = "Resource exhaustion in src/templates.py";
    } else if (scenario === "contradictory proof") {
      validation(fake).executedProof = {
        code: { proofCode: [{ content: "print('synthetic proof')" }] },
        observedEffect: "NO_EFFECT",
      };
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
            source: "src/templates.py:1",
          },
        ],
      },
    ];
    const result = await provider(transport(fake)).validate(finding, context);
    expect(result.record?.verdict).toBe("NOT_EXPLOITABLE");
    expect(result.record?.resultScope).toBe("finding");
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
      "recorded-shape-item",
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

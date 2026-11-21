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

describe("recorded shape, anonymised replay", () => {
  test("projects the real nested GRAPH exposure and critical severity through the adapter", async () => {
    const result = await provider().validate(finding, context);
    expect(result.report).toContain(
      "Codex: high, exposure unknown → Continuum: critical, reachable from attacker (basis GRAPH)",
    );
    expect(result.report).toContain("likelihood HIGH × impact HIGH");
    expect(result.report).toContain(
      "Deployment source identity is not compared",
    );
    expect(result.record).toMatchObject({
      verdict: "EXPLOITABLE",
      terminalStatus: "COMPLETED",
      severityBefore: "high",
      severityAfter: "critical",
      claimMatch: "on_target",
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
      };
      fake.issue.severity = "LOW";
      reachability(fake).value = false;
      const result = await provider(transport(fake)).validate(finding, context);
      expect(result.disposition).toBe("deferred");
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
    const fake = structuredClone(recorded);
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

  test.each(["related caption", "proof contradicts caption"])(
    "a related flaw keeps Codex severity with %s, including in the same file",
    async (scenario) => {
      const fake = structuredClone(recorded);
      if (scenario === "related caption") {
        fake.issue.name = "Resource exhaustion and denial";
        fake.issue.synopsis = "Resource exhaustion in src/templates.py";
      } else {
        for (const a of Object.values(fake.artifacts) as any[])
          if (a.artifactType === "VALIDATION_EVIDENCE") {
            a.body.validationEvidence.executedProof = {
              observedEffect: "Fake resource exhaustion and denial",
              path: "src/templates.py",
            };
          }
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

  test("reports on-target not exploitable without changing the sealed finding", async () => {
    const fake = structuredClone(recorded);
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

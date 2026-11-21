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
const finding: Record<string, unknown> & { severity: { level: string } } = {
  ...(Object.values(recorded.findings)[0] as Record<string, unknown>),
  severity: { level: "high" },
  occurrenceId: "recorded-shape-item",
};

/** Only the AWS transport is faked. Admission is synthetic, responses have recorded shape. */
function transport(fixture = structuredClone(recorded)): ContinuumAwsLauncher {
  return async (operation, args) => {
    if (operation === "create-code-finding")
      return {
        findingId: (Object.values(fixture.findings)[0] as any).findingId,
      };
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
    const result = await provider().validate(finding, {
      repositoryPath: "/not-used",
    });
    expect(result.report).toContain(
      "Continuum: exploitable, Critical, reachable from an attacker.",
    );
    expect(result.record).toMatchObject({
      state: "validated",
      codexSeverity: "high",
      issue: {
        verdict: "EXPLOITABLE",
        severity: "critical",
        validationBeforeSubmission: false,
      },
    });
    expect(result.record?.issue?.url).toContain(recorded.issueId);
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
  test("lowers supplemental severity for a NOT_EXPOSED graph answer", async () => {
    const fake = structuredClone(recorded);
    fake.issue.severity = "LOW";
    Object.assign(reachability(fake), {
      value: false,
      basis: "GRAPH",
      reason: "NOT_EXPOSED: the observed deployment has no public ingress.",
    });
    const result = await provider(transport(fake)).validate(finding, {
      repositoryPath: "/not-used",
    });
    expect(result.record?.issue?.severity).toBe("low");
    expect(result.record?.codexSeverity).toBe("high");
    expect(result.report).toContain("not reachable from an attacker");
    expect(finding.severity.level).toBe("high");
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
    const result = await provider(transport(fake)).validate(finding, {
      repositoryPath: "/not-used",
    });
    expect(result.report).toContain("reachability unknown");
    expect(result.report).not.toContain("lower priority");
  });

  test("reports on-target not exploitable without changing the sealed finding", async () => {
    const fake = structuredClone(recorded);
    for (const a of Object.values(fake.artifacts) as any[])
      if (a.artifactType === "VALIDATION_EVIDENCE")
        a.body.validationEvidence.exploitable = "NOT_EXPLOITABLE";
    const result = await provider(transport(fake)).validate(finding, {
      repositoryPath: "/not-used",
    });
    expect(result.record?.issue?.verdict).toBe("NOT_EXPLOITABLE");
    expect(finding.severity.level).toBe("high");
  });

  test("a rejected submission and a deadline are isolated from a successful item", async () => {
    let milliseconds = Date.parse("2026-11-06T15:20:00Z");
    const p = new ContinuumValidationProvider({
      environmentId: recorded.environmentId,
      waitMinutes: 0.001,
      launcher: async (op, args, signal) => {
        if (op === "create-code-finding") {
          const id = JSON.parse(args[1]!).ocsfDocument.finding_info.uid;
          if (id === "rejected") throw new Error("Fake submission rejected");
          return {
            findingId:
              id === finding["occurrenceId"]
                ? (Object.values(recorded.findings)[0] as any).findingId
                : id,
          };
        }
        if (op === "get-code-finding" && args.at(-1) === "waiting")
          return { status: "SUBMITTED" };
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
      { repositoryPath: "/not-used" },
    );
    expect(results[0]?.record?.issue?.verdict).toBe("EXPLOITABLE");
    expect(results[1]?.record?.unavailable).toContain("rejected");
    expect(results[2]?.record?.unavailable).toMatch(/waiting period/u);
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
      waitMinutes: 0.001,
      launcher: async (op, args, signal) =>
        op === "list-code-issue-artifacts" && args.at(-1) === "EVIDENCE"
          ? { items: [] }
          : transport()(op, args, signal),
      now: () => new Date(milliseconds),
      delay: async (ms) => {
        milliseconds += ms;
      },
    });
    expect(
      (await p.validate(finding, { repositoryPath: "/not-used" })).unavailable,
    ).toContain("waiting period");
  });
});

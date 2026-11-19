import { describe, expect, test } from "bun:test";
import {
  ContinuumValidationProvider,
  assessClaimMatch,
  deterministicClientToken,
  findingToOcsf,
  type ContinuumAwsLauncher,
} from "../src/continuum-validation-provider.js";

const finding = {
  occurrenceId: "occ_demo",
  title: "Authorization weakness permits cross-user access",
  summary: "An ownership check is missing before a record is returned.",
  severity: { level: "high" },
  taxonomy: { category: "authorization", cwe: ["CWE-639"] },
  locations: [
    { path: "src/route.ts", startLine: 10, endLine: 12, role: "entrypoint" },
  ],
  codeEvidence: [
    { path: "src/store.ts", startLine: 40, endLine: 42, role: "sink" },
  ],
};

function fakeAws(link = "createdIssueId") {
  const calls: string[] = [];
  const launcher: ContinuumAwsLauncher = async (operation, args) => {
    calls.push(operation);
    if (operation === "create-code-finding") return { findingId: "finding-1" };
    if (operation === "get-code-finding")
      return { status: "CONFIRMED", [link]: "issue-1" };
    if (operation === "get-code-issue") return { severity: "HIGH" };
    if (operation === "list-code-issue-artifacts")
      return {
        items: [{ artifactId: args.at(-1), createdAt: "2026-11-13T00:00:00Z" }],
      };
    if (operation === "get-code-issue-artifact")
      return args.at(-1) === "EVIDENCE"
        ? {
            artifactType: "EVIDENCE",
            artifactId: "scorer-artifact",
            createdAt: "2026-11-13T00:00:00Z",
            body: {
              prevalidationSignals: {
                signals: [
                  {
                    dimension: "REACHABILITY_ENABLER",
                    conclusion: "The affected route is reachable.",
                    basis: "GRAPH",
                  },
                ],
              },
            },
          }
        : {
            artifactType: "VALIDATION_EVIDENCE",
            artifactId: "validation-artifact",
            createdAt: "2026-11-13T00:00:00Z",
            body: {
              validationEvidence: {
                verdict: "EXPLOITABLE",
                executedProof: {
                  observedEffect: "cross-user authorization changed",
                  path: "src/store.ts",
                  code: "RAW_PROOF_SHOULD_NEVER_APPEAR",
                  output: "RAW_CONSOLE_SHOULD_NEVER_APPEAR",
                  payload: "RAW_PAYLOAD_SHOULD_NEVER_APPEAR",
                },
              },
            },
          };
    throw new Error(`unexpected ${operation}`);
  };
  return { launcher, calls };
}

function provider(launcher: ContinuumAwsLauncher) {
  return new ContinuumValidationProvider({
    environmentId: "environment-1",
    launcher,
    now: () => new Date("2026-11-13T00:00:00Z"),
    delay: async () => {},
  });
}

describe("Continuum validation provider", () => {
  test.each(["createdIssueId", "duplicateOfIssueId", "mergedIntoIssueId"])(
    "follows %s without projecting proof bodies",
    async (link) => {
      const result = await provider(fakeAws(link).launcher).validate(finding, {
        repositoryPath: "/repo",
      });
      expect(result.unavailable).toBeUndefined();
      expect(result.provenance.referenceId).toBe("issue-1");
      expect(result.record?.claimMatch).toBe("on_target");
      expect(result.report).not.toMatch(/RAW_PROOF|RAW_CONSOLE|RAW_PAYLOAD/u);
      expect(JSON.stringify(result.record)).not.toMatch(
        /RAW_PROOF|RAW_CONSOLE|RAW_PAYLOAD/u,
      );
    },
  );

  test("submits every item before polling", async () => {
    const aws = fakeAws();
    const results = await provider(aws.launcher).validateBatch(
      [finding, { ...finding, occurrenceId: "second" }],
      { repositoryPath: "/repo" },
    );
    expect(results).toHaveLength(2);
    expect(aws.calls.slice(0, 2)).toEqual([
      "create-code-finding",
      "create-code-finding",
    ]);
    expect(aws.calls.indexOf("get-code-finding")).toBeGreaterThan(1);
  });

  test("contains a submission rejection to its item", async () => {
    const aws = fakeAws();
    const p = provider(async (op, args, signal) => {
      if (op === "create-code-finding" && args.join(" ").includes("occ_demo"))
        throw new Error("synthetic rejection");
      return aws.launcher(op, args, signal);
    });
    const results = await p.validateBatch(
      [finding, { ...finding, occurrenceId: "second" }],
      { repositoryPath: "/repo" },
    );
    expect(results[0]?.record?.unavailable).toContain("rejection");
    expect(results[1]?.record?.verdict).toBe("EXPLOITABLE");
  });

  test("a downstream discard has unknown match and keeps Codex severity", async () => {
    const result = await provider(async (op) =>
      op === "create-code-finding"
        ? { findingId: "finding-1" }
        : { status: "DISCARDED", statusMessage: "Location not actionable" },
    ).validate(finding, { repositoryPath: "/repo" });
    expect(result.record).toMatchObject({
      verdict: "DISCARDED",
      claimMatch: "unknown",
      severityAfter: "high",
    });
    expect(result.report).not.toContain("proved a related flaw");
  });

  test("reused evidence predating submission is stale", async () => {
    const aws = fakeAws("mergedIntoIssueId");
    const p = new ContinuumValidationProvider({
      environmentId: "environment-1",
      launcher: aws.launcher,
      now: () => new Date("2026-11-14T00:00:00Z"),
      delay: async () => {},
    });
    const result = await p.validate(finding, { repositoryPath: "/repo" });
    expect(result.record?.freshness.stale).toBe(true);
    expect(result.report).toContain("possibly stale");
  });

  test.each(["duplicateOfIssueId", "mergedIntoIssueId"])(
    "scopes bundled validation evidence through %s to the submitted finding",
    async (link) => {
      const aws = fakeAws(link);
      const result = await provider(async (op, args, signal) => {
        const response = await aws.launcher(op, args, signal);
        if (
          op === "get-code-issue-artifact" &&
          args.at(-1) === "VALIDATION_EVIDENCE"
        ) {
          const validation = (response["body"] as any).validationEvidence;
          validation.exploitable = "EXPLOITABLE";
          validation.perFindingResults = [
            {
              findingId: "another-finding",
              exploitable: "EXPLOITABLE",
              executedProof: validation.executedProof,
            },
            {
              findingId: "finding-1",
              exploitable: "NOT_EXPLOITABLE",
              sourceAnalysis: "Insufficient evidence for the submitted claim.",
            },
          ];
        }
        return response;
      }).validate(finding, { repositoryPath: "/repo" });
      expect(result.record?.verdict).toBe("NOT_EXPLOITABLE");
      expect(result.record?.claimMatch).toBe("unknown");
      expect(result.record?.severityAfter).toBe("high");
    },
  );

  test("does not use another finding's proof when a bundle has no matching result", async () => {
    const aws = fakeAws();
    let elapsed = 0;
    const p = new ContinuumValidationProvider({
      environmentId: "environment-1",
      waitMinutes: 0.1,
      now: () => new Date(Date.parse("2026-11-13T00:00:00Z") + elapsed),
      delay: async (ms) => {
        elapsed += ms;
      },
      launcher: async (op, args, signal) => {
        const response = await aws.launcher(op, args, signal);
        if (
          op === "get-code-issue-artifact" &&
          args.at(-1) === "VALIDATION_EVIDENCE"
        ) {
          (response["body"] as any).validationEvidence.perFindingResults = [
            { findingId: "another-finding", exploitable: "EXPLOITABLE" },
          ];
        }
        return response;
      },
    });
    const result = await p.validate(finding, { repositoryPath: "/repo" });
    expect(result.record?.verdict).toBe("UNAVAILABLE");
    expect(result.record?.severityAfter).toBe("high");
  });

  test("polls a ready fifth finding before waiting on four pending findings", async () => {
    const aws = fakeAws();
    const polled: string[] = [];
    let elapsed = 0;
    const p = new ContinuumValidationProvider({
      environmentId: "environment-1",
      waitMinutes: 0.1,
      now: () => new Date(Date.parse("2026-11-13T00:00:00Z") + elapsed),
      delay: async (ms) => {
        expect(polled).toContain("item-5");
        elapsed += ms;
      },
      launcher: async (op, args, signal) => {
        if (op === "create-code-finding")
          return {
            findingId: JSON.parse(args[1]!).ocsfDocument.finding_info.uid,
          };
        if (op === "get-code-finding") {
          const id = args.at(-1)!;
          polled.push(id);
          if (id !== "item-5") return { status: "SUBMITTED" };
        }
        return aws.launcher(op, args, signal);
      },
    });
    const result = await p.validateBatch(
      Array.from({ length: 5 }, (_, i) => ({
        ...finding,
        occurrenceId: `item-${i + 1}`,
      })),
      { repositoryPath: "/repo" },
    );
    expect(
      result.slice(0, 4).every((row) => row.record?.verdict === "UNAVAILABLE"),
    ).toBe(true);
    expect(result[4]?.record?.verdict).toBe("EXPLOITABLE");
    expect(result[4]?.record?.itemId).toBe("item-5");
  });

  test("fresh proof and issue do not make older scorer evidence current", async () => {
    const aws = fakeAws();
    const result = await provider(async (op, args, signal) => {
      const response = await aws.launcher(op, args, signal);
      if (op === "get-code-issue")
        response["updatedAt"] = "2026-11-13T00:00:00Z";
      if (op === "get-code-issue-artifact" && args.at(-1) === "EVIDENCE")
        response["createdAt"] = "2025-11-13T00:00:00Z";
      return response;
    }).validate(finding, { repositoryPath: "/repo" });
    expect(result.record?.freshness.stale).toBe(true);
    expect(result.report).toContain("possibly stale");
    expect(result.report).not.toContain("current at submission");
  });

  test("retries throttling within the same deadline", async () => {
    const aws = fakeAws();
    let first = true,
      elapsed = 0;
    const p = new ContinuumValidationProvider({
      environmentId: "environment-1",
      launcher: async (op, args, signal) => {
        if (op === "create-code-finding" && first) {
          first = false;
          throw new Error("ThrottlingException");
        }
        return aws.launcher(op, args, signal);
      },
      now: () => new Date("2026-11-13T00:00:00Z"),
      delay: async (ms) => {
        elapsed += ms;
      },
    });
    expect(
      (await p.validate(finding, { repositoryPath: "/repo" })).unavailable,
    ).toBeUndefined();
    expect(elapsed).toBe(1000);
  });

  test("maps sink-first code findings and deterministic submission tokens", () => {
    const code = findingToOcsf(finding, new Date(0));
    expect(code["class_uid"]).toBe(2002);
    expect(
      (code["vulnerabilities"] as any[])[0].affected_code[0],
    ).toMatchObject({ file: { path: "src/store.ts" }, start_line: 40 });
    expect(deterministicClientToken("environment-1", finding)).toBe(
      deterministicClientToken("environment-1", finding),
    );
    expect(deterministicClientToken("environment-1", finding)).not.toBe(
      deterministicClientToken("other", finding),
    );
    expect(() => findingToOcsf({ title: "No location" })).toThrow(
      "no code location",
    );
    expect(
      findingToOcsf({ id: "supplied", location: "src/input.ts:7-9" })[
        "class_uid"
      ],
    ).toBe(2002);
  });
});

describe("claim matching", () => {
  test.each([
    [{ effect: "authorization cross-user", path: "src/store.ts" }, "on_target"],
    [
      {
        effect: "authorization cross-user credential exposure",
        path: "src/store.ts",
      },
      "on_target_escalated",
    ],
    [
      { effect: "resource exhaustion and denial", path: "src/store.ts" },
      "different_flaw",
    ],
    [{}, "unknown"],
  ] as const)(
    "compares demonstrated concepts, not just a shared file: %j",
    (proof, expected) => {
      expect(assessClaimMatch(proof, finding)).toBe(expected);
    },
  );
});

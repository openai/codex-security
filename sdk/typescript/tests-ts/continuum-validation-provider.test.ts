import {
  continuumTestRepository,
  registeredSource,
  creation,
  requestBody,
} from "./support/continuum-validation-fixtures.js";
import { describe, expect, test } from "bun:test";
import {
  ContinuumValidationProvider,
  assessClaimMatch,
  findingToOcsf,
  type ContinuumAwsLauncher,
} from "../src/continuum-validation-provider.js";

const context = continuumTestRepository();

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
    const setup = registeredSource(operation);
    if (setup) return setup;
    calls.push(operation);
    if (operation === "create-code-finding") return creation("finding-1");
    if (operation === "get-code-finding")
      return {
        status: "CONFIRMED",
        [link]: "issue-1",
        findingArn:
          "arn:aws:continuum:us-east-1:123456789012:environments/environment1/code-findings/finding-1",
      };
    if (operation === "get-code-issue")
      return {
        severity: "HIGH",
        updatedAt: "2026-11-13T00:00:00Z",
        issueId: "issue-1",
        findingIds: ["finding-1"],
        issueArn:
          "arn:aws:continuum:us-east-1:123456789012:environments/environment1/code-issues/issue-1",
      };
    if (operation === "list-code-issue-artifacts")
      return {
        items: [{ artifactId: args.at(-1), createdAt: "2026-11-13T00:00:00Z" }],
      };
    if (operation === "get-code-issue-artifact")
      return args.at(-1) === "EVIDENCE"
        ? {
            artifactType: "EVIDENCE",
            artifactId: args.at(-1),
            createdAt: "2026-11-13T00:00:00Z",
            body: {
              prevalidationSignals: {
                signals: [
                  {
                    subjectRef: "issue-1",
                    dimension: "REACHABILITY_ENABLER",
                    conclusion: "The affected route is reachable.",
                    basis: "GRAPH",
                  },
                  {
                    dimension: "EXPLOITABILITY",
                    subjectRef: "issue-1",
                    exploitability: {
                      sourceValidationArtifactId: "VALIDATION_EVIDENCE",
                      verdict: "EXPLOITABLE",
                    },
                  },
                ],
              },
            },
          }
        : {
            artifactType: "VALIDATION_EVIDENCE",
            artifactId: args.at(-1),
            createdAt: "2026-11-13T00:00:00Z",
            body: {
              validationEvidence: {
                verdict: "EXPLOITABLE",
                terminalStatus: "COMPLETED",
                executedProof: {
                  observedEffect: "cross-user authorization changed",
                  path: "src/store.ts",
                  code: {
                    proofCode: [
                      {
                        content:
                          "RAW_PROOF_SHOULD_NEVER_APPEAR cross-user authorization at src/store.ts:40",
                      },
                    ],
                  },
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
  let elapsed = 0;
  return new ContinuumValidationProvider({
    environmentId: "environment1",
    launcher,
    now: () => new Date(Date.parse("2026-11-13T00:00:00Z") + elapsed),
    delay: async (ms) => {
      elapsed += ms;
    },
  });
}

describe("Continuum validation provider", () => {
  test("stops before reading the issue when the echoed source is a different occurrence", async () => {
    const aws = fakeAws();
    const result = await provider(async (op, args, signal) => {
      const response = await aws.launcher(op, args, signal);
      if (op === "get-code-finding")
        response["sourceFindingId"] = "another-occurrence";
      return response;
    }).validate(finding, context);
    expect(result.record).toMatchObject({
      itemId: finding.occurrenceId,
      verdict: "UNAVAILABLE",
      severityAfter: "high",
      claimMatch: "unknown",
    });
    expect(aws.calls).not.toContain("get-code-issue");
  });
  test("replays the exact document after a lost response and resumes from its receipt", async () => {
    const requests: string[] = [];
    const aws = fakeAws();
    let failPoll = true;
    const launcher: ContinuumAwsLauncher = async (op, args, signal) => {
      if (op === "create-code-finding") {
        requests.push(requestBody(args));
        if (requests.length === 1) throw new Error("receipt lost");
      }
      if (op === "get-code-finding" && failPoll)
        throw new Error("read interrupted");
      return aws.launcher(op, args, signal);
    };
    const at = (time: string) =>
      new ContinuumValidationProvider({
        environmentId: "environment1",
        launcher,
        now: () => new Date(time),
      });
    const submittedAt = "2026-11-13T00:00:00.000Z";
    expect(
      (await at(submittedAt).validate(finding, context)).unavailable,
    ).toContain("receipt lost");
    const pending = await at("2026-11-14").validate(finding, context);
    expect(pending.record).toMatchObject({
      ...creation("finding-1"),
      submittedAt,
      verdict: "UNAVAILABLE",
    });
    failPoll = false;
    const complete = await at("2026-11-15").validate(finding, context);
    expect(complete.record).toMatchObject({
      ...creation("finding-1"),
      submittedAt,
      issueId: "issue-1",
      issueArn:
        "arn:aws:continuum:us-east-1:123456789012:environments/environment1/code-issues/issue-1",
      verdict: "EXPLOITABLE",
      resultScope: "issue",
      freshness: { stale: false },
    });
    expect(requests).toHaveLength(2);
    expect(requests[1]).toBe(requests[0]);
    await at(submittedAt).validate(
      { ...finding, summary: "Revised claim" },
      context,
    );
    expect(JSON.parse(requests[2]!).clientToken).not.toBe(
      JSON.parse(requests[0]!).clientToken,
    );
  });

  test("concurrent senders share a receipt", async () => {
    const aws = fakeAws();
    const results = await Promise.all(
      [provider(aws.launcher), provider(aws.launcher)].map((p) =>
        p.validate(finding, context),
      ),
    );
    expect(aws.calls.filter((op) => op === "create-code-finding")).toHaveLength(
      1,
    );
    expect(results.map((r) => r.record?.verdict)).toEqual([
      "EXPLOITABLE",
      "EXPLOITABLE",
    ]);
  });

  test("rejects a different source before sending the finding", async () => {
    const aws = fakeAws();
    const p = provider(
      async (op, args, signal) =>
        registeredSource(op, "environment1", "other/repo") ??
        aws.launcher(op, args, signal),
    );
    const result = await p.validate(finding, context);
    expect(result.unavailable).toContain("does not match");
    expect(aws.calls).toEqual([]);
  });
  test.each(["createdIssueId", "duplicateOfIssueId", "mergedIntoIssueId"])(
    "follows %s without projecting proof bodies",
    async (link) => {
      const result = await provider(fakeAws(link).launcher).validate(
        finding,
        context,
      );
      expect(result.unavailable).toBeUndefined();
      expect(result.provenance.referenceId).toBe("issue-1");
      const url =
        "https://us-east-1.console.aws.amazon.com/continuum/environments/environment1/code-vulnerabilities/issues/issue-1?region=us-east-1";
      expect(result.provenance.referenceUrl).toBe(url);
      expect(result.record?.issueUrl).toBe(url);
      expect(result.report).toContain(url);
      expect(result.record?.claimMatch).toBe("unknown");
      expect(result.report).not.toMatch(/RAW_PROOF|RAW_CONSOLE|RAW_PAYLOAD/u);
      expect(JSON.stringify(result.record)).not.toMatch(
        /RAW_PROOF|RAW_CONSOLE|RAW_PAYLOAD/u,
      );
    },
  );

  test("keeps the issue link and full diagnostic when reading evidence fails", async () => {
    const aws = fakeAws();
    const message = `Command failed: aws continuum get-code-issue-artifact --artifact-id ${"a".repeat(180)}\nAccessDeniedException`;
    const p = new ContinuumValidationProvider({
      environmentId: "environment1",
      consoleBaseUrl: "https://console.example/continuum/",
      launcher: async (op, args, signal) => {
        if (op === "get-code-issue-artifact") throw new Error(message);
        return aws.launcher(op, args, signal);
      },
    });
    const result = await p.validate(finding, context);
    expect(result.record?.unavailable).toBe(message);
    expect(result.record?.issueUrl).toBe(
      "https://console.example/continuum/environments/environment1/code-vulnerabilities/issues/issue-1?region=us-east-1",
    );
  });

  test("submits every item before polling", async () => {
    const aws = fakeAws();
    const results = await provider(aws.launcher).validateBatch(
      [finding, { ...finding, occurrenceId: "second" }],
      context,
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
      if (
        op === "create-code-finding" &&
        requestBody(args).includes("occ_demo")
      )
        throw new Error("synthetic rejection");
      return aws.launcher(op, args, signal);
    });
    const results = await p.validateBatch(
      [finding, { ...finding, occurrenceId: "second" }],
      context,
    );
    expect(results[0]?.record?.unavailable).toContain("rejection");
    expect(results[0]?.provenance.validatedAt).toBeUndefined();
    expect(results[1]?.record?.verdict).toBe("EXPLOITABLE");
  });

  test("a downstream discard has unknown match and keeps Codex severity", async () => {
    const result = await provider(async (op) =>
      op === "create-code-finding"
        ? creation("finding-1")
        : (registeredSource(op) ?? {
            ...creation("finding-1"),
            status: "DISCARDED",
            statusMessage: "Location not actionable",
          }),
    ).validate(finding, context);
    expect(result.record).toMatchObject({
      verdict: "DISCARDED",
      statusMessage: "Location not actionable",
      claimMatch: "unknown",
      severityAfter: "high",
    });
    expect(result.disposition).toBe("not_applicable");
    expect(result.record?.providerSeverity).toBeUndefined();
    expect(result.record?.freshness.validatedAt).toBeUndefined();
    expect(result.provenance.validatedAt).toBeUndefined();
    expect(result.report).toContain("Location not actionable");
    expect(result.report).not.toContain("validated at");
    expect(result.report).not.toContain("proved a related flaw");
  });

  test("reused evidence predating submission is stale", async () => {
    const aws = fakeAws("mergedIntoIssueId");
    const p = new ContinuumValidationProvider({
      environmentId: "environment1",
      launcher: aws.launcher,
      now: () => new Date("2026-11-14T00:00:00Z"),
      delay: async () => {},
    });
    const result = await p.validate(finding, context);
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
      }).validate(finding, context);
      expect(result.record?.verdict).toBe("NOT_EXPLOITABLE");
      expect(result.record?.resultScope).toBe("finding");
      expect(result.record?.claimMatch).toBe("unknown");
      expect(result.record?.severityAfter).toBe("high");
    },
  );

  test("labels a bundle without a matching result at issue scope, never as the finding's proof", async () => {
    const aws = fakeAws();
    let elapsed = 0;
    const p = new ContinuumValidationProvider({
      environmentId: "environment1",
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
    const result = await p.validate(finding, context);
    expect(result.record).toMatchObject({
      verdict: "EXPLOITABLE",
      resultScope: "issue",
      claimMatch: "unknown",
      severityAfter: "high",
    });
    expect(result.report).toContain("issue-level result");
    expect(result.report).not.toMatch(/RAW_PROOF|RAW_CONSOLE|RAW_PAYLOAD/u);
  });

  test("polls a ready fifth finding before waiting on four pending findings", async () => {
    const aws = fakeAws();
    const polled: string[] = [];
    let elapsed = 0;
    const p = new ContinuumValidationProvider({
      environmentId: "environment1",
      waitMinutes: 0.1,
      now: () => new Date(Date.parse("2026-11-13T00:00:00Z") + elapsed),
      delay: async (ms) => {
        expect(polled).toContain("item-5");
        elapsed += ms;
      },
      launcher: async (op, args, signal) => {
        if (op === "create-code-finding")
          return creation(
            JSON.parse(requestBody(args)).ocsfDocument.finding_info.uid,
          );
        if (op === "get-code-finding") {
          const id = args.at(-1)!;
          polled.push(id);
          if (id !== "item-5") return { status: "SUBMITTED", ...creation(id) };
        }
        const response = await aws.launcher(op, args, signal);
        if (op === "get-code-finding")
          response["findingArn"] =
            "arn:aws:continuum:us-east-1:123456789012:environments/environment1/code-findings/item-5";
        if (op === "get-code-issue") response["findingIds"] = ["item-5"];
        return response;
      },
    });
    const result = await p.validateBatch(
      Array.from({ length: 5 }, (_, i) => ({
        ...finding,
        occurrenceId: `item-${i + 1}`,
      })),
      context,
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
    }).validate(finding, context);
    expect(result.record?.freshness.stale).toBe(true);
    expect(result.report).toContain("possibly stale");
    expect(result.report).not.toContain("current at submission");
  });

  test.each(["another sole finding", "wrong issue ARN"])(
    "rejects issue-wide proof with %s",
    async (scenario) => {
      const aws = fakeAws("duplicateOfIssueId");
      let elapsed = 0;
      const p = new ContinuumValidationProvider({
        environmentId: "environment1",
        waitMinutes: 0.1,
        now: () => new Date(Date.parse("2026-11-13T00:00:00Z") + elapsed),
        delay: async (ms) => {
          elapsed += ms;
        },
        launcher: async (op, args, signal) => {
          const response = await aws.launcher(op, args, signal);
          if (op === "get-code-issue") {
            if (scenario === "another sole finding")
              response["findingIds"] = ["another-finding"];
            if (scenario === "wrong issue ARN")
              response["issueArn"] =
                "arn:aws:continuum:us-east-1:123456789012:environments/other-environment/code-issues/issue-1";
          }
          return response;
        },
      });
      const result = await p.validate(finding, context);
      expect(result.record?.verdict).toBe("UNAVAILABLE");
      expect(result.record?.severityAfter).toBe("high");
    },
  );

  test("uses the newest available artifact that actually contains the submitted finding", async () => {
    const aws = fakeAws("mergedIntoIssueId");
    const fetched: string[] = [];
    const result = await provider(async (op, args, signal) => {
      if (
        op === "list-code-issue-artifacts" &&
        args.at(-1) === "VALIDATION_EVIDENCE"
      )
        return {
          items: [
            { artifactId: "new-validation", createdAt: "2026-11-14T00:00:00Z" },
            {
              artifactId: "older-validation",
              createdAt: "2026-11-13T00:00:00Z",
            },
          ],
        };
      const response = await aws.launcher(op, args, signal);
      if (op === "get-code-issue-artifact" && args.at(-1) !== "EVIDENCE") {
        fetched.push(args.at(-1)!);
        (response["body"] as any).validationEvidence.perFindingResults = [
          {
            findingId:
              args.at(-1) === "new-validation"
                ? "another-finding"
                : "finding-1",
            exploitable: "NOT_EXPLOITABLE",
          },
        ];
      }
      return response;
    }).validate(finding, context);
    expect(fetched).toEqual(["new-validation", "older-validation"]);
    expect(result.record?.verdict).toBe("NOT_EXPLOITABLE");
  });

  test("shared issue evidence returns promptly without changing the finding severity", async () => {
    const aws = fakeAws();
    const result = await provider(async (op, args, signal) => {
      const response = await aws.launcher(op, args, signal);
      if (op === "get-code-issue") {
        response["findingIds"] = ["finding-1", "other-1", "other-2"];
        response["severity"] = "CRITICAL";
      }
      return response;
    }).validate(finding, context);
    expect(aws.calls.filter((op) => op === "get-code-finding")).toHaveLength(1);
    expect(result.record).toMatchObject({
      resultScope: "issue",
      issueFindingCount: 3,
      joinedValidatedIssue: false,
      verdict: "EXPLOITABLE",
      severityBefore: "high",
      severityAfter: "high",
      providerSeverity: "critical",
      claimMatch: "unknown",
    });
    expect(result.report).toContain("issue-level result");
    expect(result.report).toContain("Continuum issue severity: critical");
    expect(result.report).not.toMatch(/RAW_PROOF|RAW_CONSOLE|RAW_PAYLOAD/u);
  });

  test("labels a finding joining an already validated shared issue and stale scoring", async () => {
    const aws = fakeAws("duplicateOfIssueId");
    const result = await new ContinuumValidationProvider({
      environmentId: "environment1",
      now: () => new Date("2026-11-14T00:00:00Z"),
      delay: async () => {
        throw new Error("must not wait");
      },
      launcher: async (op, args, signal) => {
        const response = await aws.launcher(op, args, signal);
        if (op === "get-code-issue")
          response["findingIds"] = ["finding-1", "other-1"];
        return response;
      },
    }).validate(finding, context);
    expect(result.record).toMatchObject({
      resultScope: "issue",
      joinedValidatedIssue: true,
      freshness: { stale: true },
    });
    expect(result.report).toContain(
      "joined an issue Continuum had already validated",
    );
    expect(result.report).toContain("proof predates this submission");
  });

  test("shared issue without evidence keeps waiting", async () => {
    const aws = fakeAws();
    let rounds = 0;
    const result = await provider(async (op, args, signal) => {
      const response = await aws.launcher(op, args, signal);
      if (op === "get-code-finding") rounds++;
      if (op === "get-code-issue")
        response["findingIds"] = ["finding-1", "other-1"];
      if (op === "list-code-issue-artifacts" && rounds === 1)
        return { items: [] };
      return response;
    }).validate(finding, context);
    expect(rounds).toBe(2);
    expect(result.record?.resultScope).toBe("issue");
  });

  test.each([1, 2])(
    "an older per-finding result beats the newest issue proof with %i members",
    async (members) => {
      const aws = fakeAws();
      const result = await provider(async (op, args, signal) => {
        if (
          op === "list-code-issue-artifacts" &&
          args.at(-1) === "VALIDATION_EVIDENCE"
        )
          return {
            items: [
              { artifactId: "new", createdAt: "2026-11-14T00:00:00Z" },
              { artifactId: "old", createdAt: "2026-11-13T00:00:00Z" },
            ],
          };
        const response = await aws.launcher(op, args, signal);
        if (op === "get-code-issue")
          response["findingIds"] =
            members === 1 ? ["finding-1"] : ["finding-1", "other-1"];
        if (op === "get-code-issue-artifact" && args.at(-1) === "old")
          (response["body"] as any).validationEvidence.perFindingResults = [
            { findingId: "finding-1", exploitable: "NOT_EXPLOITABLE" },
          ];
        return response;
      }).validate(finding, context);
      expect(result.record).toMatchObject({
        resultScope: "finding",
        verdict: "NOT_EXPLOITABLE",
        severityAfter: "high",
        issueFindingCount: members,
      });
    },
  );

  test.each(["FINDING", "FUTURE_SOURCE"])(
    "preserves %s reachability basis",
    async (basis) => {
      const aws = fakeAws();
      const result = await provider(async (op, args, signal) => {
        const response = await aws.launcher(op, args, signal);
        if (op === "get-code-issue-artifact" && args.at(-1) === "EVIDENCE")
          (response["body"] as any).prevalidationSignals.signals = [
            ...(response["body"] as any).prevalidationSignals.signals,
            {
              subjectRef: "issue-1",
              dimension: "LIKELIHOOD_ASSESSMENT",
              conclusion: "reachable",
              preconditions: {
                reachableFromAttacker: {
                  value: true,
                  basis,
                  reason: "The finding describes a public route.",
                },
              },
            },
          ];
        return response;
      }).validate(finding, context);
      expect(result.report).toContain(
        `reachable from attacker (basis ${basis})`,
      );
      expect(result.record?.reasons).toContainEqual({
        basis,
        reason:
          "reachableFromAttacker: true — The finding describes a public route.",
      });
    },
  );

  test("retries throttling within the same deadline", async () => {
    const aws = fakeAws();
    let first = true,
      elapsed = 0;
    const p = new ContinuumValidationProvider({
      environmentId: "environment1",
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
    expect((await p.validate(finding, context)).unavailable).toBeUndefined();
    expect(elapsed).toBe(1000);
  });

  test("maps sink-first code findings", () => {
    const code = findingToOcsf(finding, new Date(0));
    expect(code["class_uid"]).toBe(2002);
    expect(
      (code["vulnerabilities"] as any[])[0].affected_code[0],
    ).toMatchObject({ file: { path: "src/store.ts" }, start_line: 40 });
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
    [
      { effect: "authorization cross-user", path: "src/store.ts:40" },
      "on_target",
    ],
    [
      {
        effect: "authorization cross-user credential exposure",
        path: "src/store.ts:40",
      },
      "on_target_escalated",
    ],
    [
      { effect: "resource exhaustion and denial", path: "src/store.ts:40" },
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

test.each([
  ["src/store.ts:40–42", "on_target"],
  ["./src/store.ts#L42", "on_target"],
  ["src/store.ts:12", "unknown"],
  ["src/store.ts:400", "unknown"],
  ["src/store.ts:40-3", "unknown"],
  ["src/store.ts:1-1000", "unknown"],
  ["src/store.ts", "unknown"],
  ["store.ts:40", "unknown"],
  ["lib/src/store.ts:40", "unknown"],
  ["src/Store.ts:40", "unknown"],
  ["src/route.ts:11", "unknown"],
] as const)(
  "checks the primary submitted location against %s",
  (citation, match) => {
    expect(
      assessClaimMatch("Cross-user authorization in " + citation, finding),
    ).toBe(match);
  },
);

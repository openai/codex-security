import { describe, expect, test } from "bun:test";
import {
  ContinuumValidationProvider,
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
      return {
        status: "CONFIRMED",
        [link]: "issue-1",
        findingArn:
          "arn:aws:continuum:us-east-1:123456789012:environments/environment-1/code-findings/finding-1",
      };
    if (operation === "get-code-issue")
      return {
        severity: "HIGH",
        issueId: "issue-1",
        findingIds: ["finding-1"],
        issueArn:
          "arn:aws:continuum:us-east-1:123456789012:environments/environment-1/code-issues/issue-1",
      };
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
  let elapsed = 0;
  return new ContinuumValidationProvider({
    environmentId: "environment-1",
    launcher,
    now: () => new Date(Date.parse("2026-11-13T00:00:00Z") + elapsed),
    delay: async (ms) => {
      elapsed += ms;
    },
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
      expect(result.record?.state).toBe("validated");
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
    expect(results[1]?.record?.issue?.verdict).toBe("EXPLOITABLE");
  });

  test("a downstream discard has unknown match and keeps Codex severity", async () => {
    const result = await provider(async (op) =>
      op === "create-code-finding"
        ? { findingId: "finding-1" }
        : { status: "DISCARDED", statusMessage: "Location not actionable" },
    ).validate(finding, { repositoryPath: "/repo" });
    expect(result.record).toMatchObject({
      state: "declined",
      codexSeverity: "high",
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
    expect(result.record?.issue?.validationBeforeSubmission).toBe(true);
    expect(result.report).toContain("before this submission");
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
      expect(result.record?.issue?.verdict).toBe("EXPLOITABLE");
      expect(result.record?.findingResult?.verdict).toBe("NOT_EXPLOITABLE");
      expect(result.record?.codexSeverity).toBe("high");
      expect(result.report).toContain("For this finding specifically");
    },
  );

  test("labels a bundle without a matching result at issue scope, never as the finding's proof", async () => {
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
    expect(result.record).toMatchObject({
      state: "validated",
      issue: { verdict: "EXPLOITABLE" },
      codexSeverity: "high",
    });
    expect(result.report).toContain("not individual finding validation");
    expect(result.report).not.toMatch(/RAW_PROOF|RAW_CONSOLE|RAW_PAYLOAD/u);
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
        const response = await aws.launcher(op, args, signal);
        if (op === "get-code-finding")
          response["findingArn"] =
            "arn:aws:continuum:us-east-1:123456789012:environments/environment-1/code-findings/item-5";
        if (op === "get-code-issue") response["findingIds"] = ["item-5"];
        return response;
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
      result.slice(0, 4).every((row) => row.record?.state === "pending"),
    ).toBe(true);
    expect(result[4]?.record?.issue?.verdict).toBe("EXPLOITABLE");
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
    expect(result.record?.issue?.scoringBeforeSubmission).toBe(true);
    expect(result.report).toContain(
      "Scoring was also written before this submission",
    );
  });

  test("reads only the newest artifact, even when older proof names the finding", async () => {
    const aws = fakeAws();
    const fetched: string[] = [];
    const result = await provider(async (op, args, signal) => {
      if (
        op === "list-code-issue-artifacts" &&
        args.at(-1) === "VALIDATION_EVIDENCE"
      )
        return {
          items: [
            { artifactId: "old", createdAt: "2026-11-12T00:00:00Z" },
            { artifactId: "new", createdAt: "2026-11-13T00:00:00Z" },
          ],
        };
      if (op === "get-code-issue-artifact") fetched.push(args.at(-1)!);
      return aws.launcher(op, args, signal);
    }).validate(finding, { repositoryPath: "/repo" });
    expect(fetched).toEqual(["new", "EVIDENCE"]);
    expect(result.record?.issue?.verdict).toBe("EXPLOITABLE");
    expect(result.record?.findingResult).toBeUndefined();
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
    }).validate(finding, { repositoryPath: "/repo" });
    expect(aws.calls.filter((op) => op === "get-code-finding")).toHaveLength(1);
    expect(result.record).toMatchObject({
      state: "validated",
      codexSeverity: "high",
      issue: {
        findingCount: 3,
        verdict: "EXPLOITABLE",
        severity: "critical",
        validationBeforeSubmission: false,
      },
    });
    expect(result.report).toContain("issue holds 3 findings");
    expect(result.report).toContain("not individual finding validation");
    expect(result.report).toContain("Critical");
    expect(result.report).not.toMatch(/RAW_PROOF|RAW_CONSOLE|RAW_PAYLOAD/u);
  });

  test("labels a finding joining an already validated shared issue and stale scoring", async () => {
    const aws = fakeAws("duplicateOfIssueId");
    const result = await new ContinuumValidationProvider({
      environmentId: "environment-1",
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
    }).validate(finding, { repositoryPath: "/repo" });
    expect(result.record?.issue?.validationBeforeSubmission).toBe(true);
    expect(result.report).toContain(
      "Continuum had already validated the issue",
    );
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
    }).validate(finding, { repositoryPath: "/repo" });
    expect(rounds).toBe(2);
    expect(result.record?.state).toBe("validated");
  });

  test.each(["FINDING", "FUTURE_SOURCE"])(
    "preserves %s reachability basis",
    async (basis) => {
      const aws = fakeAws();
      const result = await provider(async (op, args, signal) => {
        const response = await aws.launcher(op, args, signal);
        if (op === "get-code-issue-artifact" && args.at(-1) === "EVIDENCE")
          (response["body"] as any).prevalidationSignals.signals = [
            {
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
      }).validate(finding, { repositoryPath: "/repo" });
      expect(result.report).toContain(`[${basis}]`);
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

  test.each(["SUBMITTED", "VALIDATING"])(
    "keeps %s pending even if an issue link is present",
    async (status) => {
      const aws = fakeAws();
      let elapsed = 0;
      const result = await new ContinuumValidationProvider({
        environmentId: "environment-1",
        waitMinutes: 0.001,
        now: () => new Date(elapsed),
        delay: async (ms) => {
          elapsed += ms;
        },
        launcher: async (op, args, signal) =>
          op === "get-code-finding"
            ? { status, createdIssueId: "issue-1" }
            : aws.launcher(op, args, signal),
      }).validate(finding, { repositoryPath: "/repo" });
      expect(result.record?.state).toBe("pending");
      expect(aws.calls).not.toContain("get-code-issue");
    },
  );

  test.each(["wrong issue ARN", "missing member"])(
    "does not report an unrelated issue: %s",
    async (scenario) => {
      const aws = fakeAws();
      const result = await provider(async (op, args, signal) => {
        const response = await aws.launcher(op, args, signal);
        if (op === "get-code-issue") {
          if (scenario === "wrong issue ARN") response["issueArn"] = "wrong";
          else response["findingIds"] = ["other"];
        }
        return response;
      }).validate(finding, { repositoryPath: "/repo" });
      expect(result.record?.state).toBe("unavailable");
    },
  );

  test("a deadline retains the issue link when scoring is missing", async () => {
    const aws = fakeAws();
    let elapsed = 0;
    const result = await new ContinuumValidationProvider({
      environmentId: "environment-1",
      waitMinutes: 0.001,
      now: () => new Date(Date.parse("2026-11-13T00:00:00Z") + elapsed),
      delay: async (ms) => {
        elapsed += ms;
      },
      launcher: async (op, args, signal) =>
        op === "list-code-issue-artifacts" && args.at(-1) === "EVIDENCE"
          ? { items: [] }
          : aws.launcher(op, args, signal),
    }).validate(finding, { repositoryPath: "/repo" });
    expect(result.record?.state).toBe("pending");
    expect(result.record?.issue?.url).toContain("issue-1");
    expect(result.report).toContain("Continuum has not finished");
  });

  test("a read reaching the shared deadline remains pending with its issue link", async () => {
    const aws = fakeAws();
    let elapsed = 0;
    const result = await new ContinuumValidationProvider({
      environmentId: "environment-1",
      waitMinutes: 0.001,
      now: () => new Date(Date.parse("2026-11-13T00:00:00Z") + elapsed),
      launcher: async (op, args, signal) => {
        if (op === "get-code-issue-artifact") {
          elapsed = 60;
          throw new Error("read reached the deadline");
        }
        return aws.launcher(op, args, signal);
      },
    }).validate(finding, { repositoryPath: "/repo" });
    expect(result.record?.state).toBe("pending");
    expect(result.record?.issue?.url).toContain("issue-1");
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

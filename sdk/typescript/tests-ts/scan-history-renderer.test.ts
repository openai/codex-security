import { join } from "node:path";
import { stripVTControlCharacters } from "node:util";
import { describe, expect, test } from "bun:test";
import { renderScanHistory } from "../src/scan-history-renderer.js";

describe("scan history renderer", () => {
  test("leads comparisons with the outcome and groups root causes", () => {
    const text = stripVTControlCharacters(
      renderScanHistory(
        {
          repository: "/demo/juice-shop",
          beforeScanId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          afterScanId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
          comparable: true,
          coverage: { afterCompleteness: "complete" },
          summary: {
            new: 1,
            persisting: 2,
            resolved: 2,
            reopened: 0,
            unknown: 2,
          },
          findings: [
            {
              findingId: "internal-persisting-id",
              status: "persisting",
              severity: "high",
              title: "Basket ownership check is missing",
              path: "routes/basket.ts",
              beforeOccurrenceIds: ["before-one", "before-two"],
              afterOccurrenceIds: ["after-one"],
              matchReason:
                "Both routes share the same unchecked basket lookup.",
            },
            {
              status: "persisting",
              severity: "high",
              title: "Basket modification omits the ownership check",
              path: "routes/basket.ts",
            },
            {
              status: "new",
              severity: "medium",
              title: "Order input is evaluated",
              path: "routes/b2bOrder.ts",
            },
            {
              status: "resolved",
              severity: "informational",
              title: "Informational cookie observation",
              path: "routes/session.ts",
            },
            {
              status: "resolved",
              severity: "critical",
              title: "Login SQL injection bypasses authentication",
              path: "routes/login.ts",
              beforeOccurrenceId: "before-resolved",
            },
            {
              status: "unknown",
              severity: "high",
              title: "Complaint upload can overwrite trusted files",
              path: "routes/fileUpload.ts",
              reason:
                "The affected path was excluded or outside the later scope.",
            },
            {
              status: "unknown",
              severity: "medium",
              title: "Session handling might match an earlier finding",
              path: "routes/session.ts",
              reason: "The two findings describe different session flows.",
            },
          ],
        },
        "compare",
      ),
    );

    expect(text).toContain("CODEX SECURITY");
    expect(text).toMatch(
      /SCAN COMPARISON[\s\S]*━━ ✓ Resolved \(2 findings\) ━+[\s\S]*━━ \+ New \(1 finding\) ━+[\s\S]*━━ ● Persisting \(2 findings\) ━+[\s\S]*━━ ○ Not rescanned \(1 finding\) ━+[\s\S]*━━ \? Unknown \(1 finding\) ━+/,
    );
    expect(
      text.indexOf("Login SQL injection bypasses authentication"),
    ).toBeLessThan(text.indexOf("Informational cookie observation"));
    for (const expected of [
      "Complaint upload can overwrite trusted files",
      "Outside follow-up scan coverage",
      "Session handling might match an earlier finding",
      "The two findings describe different session flows.",
      "juice-shop",
      "aaaaaaaa → bbbbbbbb",
      "CRITICAL",
      "2 → 1",
      "Both routes share the same unchecked basket lookup.",
    ]) {
      expect(text).toContain(expected);
    }
    for (const hidden of [
      "follow-up scope",
      "internal-persisting-id",
      "before-resolved",
      "NOT_RESCANNED",
      "REOPENED",
    ]) {
      expect(text).not.toContain(hidden);
    }
  });

  test("reserves dim styling for finding and knowledge-base paths", () => {
    const output = renderScanHistory(
      {
        targetPath: "/demo/juice-shop",
        scanId: "scan-1",
        progress: { status: "complete" },
        mode: "standard",
        recipe: { knowledgeBasePaths: ["/demo/threat-model.md"] },
        findings: [
          {
            severity: "HIGH",
            title: "Missing auth",
            path: "routes/login.ts",
          },
        ],
      },
      "show",
    );
    expect(output).toContain("\u001B[1mKNOWLEDGE BASE\u001B[0m");
    expect(
      [...output.matchAll(/\u001B\[90m([^\u001B]*)\u001B\[0m/g)].map(
        ([, value]) => value,
      ),
    ).toEqual(["/demo/threat-model.md", "routes/login.ts"]);
    for (const coverage of ["partial", "unknown", "complete"]) {
      const comparison = renderScanHistory(
        {
          beforeScanId: "before-scan",
          afterScanId: "after-scan",
          coverage: { afterCompleteness: coverage },
          summary: {},
          findings: [],
        },
        "compare",
        { color: false },
      );
      if (coverage === "complete") {
        expect(comparison).not.toContain("Follow-up coverage");
      } else {
        expect(comparison).toContain(
          `⚠ Follow-up coverage is ${coverage}; resolved findings cannot be confirmed.`,
        );
      }
    }
  });

  test("keeps repositories visible at narrow and wide terminal widths", () => {
    const scans = [
      {
        scanId: "11111111-1111-4111-8111-111111111111",
        targetPath: "/demo/juice-shop",
        mode: "standard",
        progress: { status: "complete" },
        findingCount: 8,
        startedAt: "2026-07-24T12:00:00Z",
      },
      {
        scanId: "22222222-2222-4222-8222-222222222222",
        targetPath: "/demo/payment-service",
        mode: "deep",
        progress: { status: "complete" },
        findingCount: 2,
        startedAt: "2026-07-23T12:00:00Z",
      },
    ];

    for (const columns of [72, 100]) {
      const output = stripVTControlCharacters(
        renderScanHistory({ scans }, "list", {
          columns,
          scanRoot: "/demo/results",
        }),
      );
      expect(output).toContain("results");
      expect(output).toContain("juice-shop");
      expect(output).toContain("payment-service");
      expect(output).toContain(scans[0]!.scanId);
      expect(output).toContain(scans[1]!.scanId);
      if (columns >= 96) expect(output).toContain("REPOSITORY");
    }
  });

  test("makes finding identifiers, history, and pagination actionable", () => {
    const page = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "31107fbe-abcd-4567-abcd-1234567890ab",
          findings: [
            {
              occurrenceId: "occ_saved_finding_25",
              severity: { level: "high" },
              title: "Historic login injection",
              locations: [{ path: "routes/login.ts", startLine: 34 }],
              triage: { status: "open" },
            },
          ],
          offset: 20,
          limit: 1,
          nextOffset: 21,
          total: 25,
        },
        "findings",
      ),
    );
    for (const expected of [
      "SAVED FINDINGS",
      "scan 31107fbe",
      "21-21 of 25",
      "routes/login.ts:34",
      "ID occ_saved_finding_25",
      "OPEN",
      "NEXT PAGE  rerun with --offset 21",
      "codex-security findings show OCCURRENCE_ID",
    ]) {
      expect(page).toContain(expected);
    }

    const detail = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "31107fbe-abcd-4567-abcd-1234567890ab",
          scanDir: "/private/codex-security/scan-results",
          targetPath: "/demo/juice-shop",
          occurrenceId: "occ_saved_finding_25",
          severity: {
            level: "high",
            rationale: "Cross-account customer data is exposed.",
          },
          confidence: {
            level: "medium",
            rationale: "The vulnerable query was reproduced locally.",
          },
          title: "Historic login injection",
          locations: [
            { path: "routes/login.ts", startLine: 34, role: "root_control" },
            {
              path: "routes/database.ts",
              startLine: 51,
              endLine: 53,
              role: "sink",
            },
          ],
          summary: "User input reaches a SQL query.",
          rootCause: {
            summary: "Account input bypasses query parameterization.",
          },
          validation: {
            summary: "Traced account input into the database sink.",
          },
          attackPath: {
            summary: "An unauthenticated visitor submits a crafted account ID.",
            impact: {
              level: "high",
              why: "Private customer data is returned.",
            },
            likelihood: {
              level: "medium",
              why: "The affected endpoint accepts public requests.",
            },
          },
          codeEvidence: [
            {
              label: "Untrusted account identifier reaches query execution",
              path: "routes/database.ts",
              startLine: 51,
              explanation: "The driver receives attacker-controlled SQL.",
              code: "database.query(accountId);",
            },
          ],
          sourceExcerpt:
            "50  const accountId = request.body.accountId;\n51  database.query(accountId);",
          remediation: "Use a parameterized query.",
          remediationTests: ["Reject crafted account identifiers."],
          preventiveControls: ["Require the parameterized-query wrapper."],
          artifactPaths: ["findings/login-injection/report.md"],
          knownSince: "2026-06-15T12:00:00Z",
          knownScanIds: ["87654321-abcd-4567-abcd-1234567890ab"],
          matches: [
            {
              scanId: "87654321-abcd-4567-abcd-1234567890ab",
              title: "Previous login injection",
              reason: "The same unsafe query interpolates user input.",
            },
          ],
        },
        "finding",
      ),
    );
    for (const expected of [
      "FINDING DETAILS",
      "juice-shop",
      "ID occ_saved_finding_25",
      "Known since Jun 15, 2026",
      "LINKED FINDINGS",
      "Previous login injection",
      "User input reaches a SQL query.",
      "SEVERITY",
      "Cross-account customer data is exposed.",
      "CONFIDENCE  MEDIUM",
      "The vulnerable query was reproduced locally.",
      "AFFECTED LOCATIONS",
      "routes/database.ts:51-53",
      "ROOT CAUSE",
      "Account input bypasses query parameterization.",
      "VALIDATION",
      "Traced account input into the database sink.",
      "ATTACK PATH",
      "An unauthenticated visitor submits a crafted account ID.",
      "Impact: Private customer data is returned.",
      "Likelihood: The affected endpoint accepts public requests.",
      "CODE EVIDENCE",
      "Untrusted account identifier reaches query execution",
      "The driver receives attacker-controlled SQL.",
      "SOURCE EXCERPT",
      "database.query(accountId);",
      "Use a parameterized query.",
      "REMEDIATION TESTS",
      "Reject crafted account identifiers.",
      "PREVENTIVE CONTROLS",
      "Require the parameterized-query wrapper.",
      "EVIDENCE ARTIFACTS",
      join(
        "/private/codex-security/scan-results",
        "findings/login-injection/report.md",
      ),
      "findings false-positive occ_saved_finding_25 --reason TEXT",
    ]) {
      expect(detail).toContain(expected);
    }
  });

  test("prefers authoritative triage over a conflicting stored finding status", () => {
    const output = renderScanHistory(
      {
        scanId: "scan",
        targetPath: "/demo/repository",
        occurrenceId: "occurrence",
        severity: { level: "high" },
        title: "Missing authorization",
        status: "open",
        triage: {
          status: "closed",
          closeReason: "false_positive",
          note: "Existing authorization prevents access.",
        },
        locations: [{ path: "src/server.ts", startLine: 4 }],
      },
      "finding",
      { color: false },
    );

    expect(output).toContain("CLOSED");
    expect(output).toContain("Reason: false_positive");
    expect(output).toContain("Note: Existing authorization prevents access.");
    expect(output).not.toContain("findings false-positive");
    expect(output).not.toContain("OPEN");
  });

  test("renders structured validation, nested attack paths, and legacy source proof", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "legacy-scan",
          targetPath: "/demo/legacy-service",
          occurrenceId: "legacy-occurrence",
          severity: { level: "high" },
          title: "Unsafe legacy query",
          locations: [{ path: "src/query.py", startLine: 12 }],
          rootCause: {
            summary: "The query accepts untrusted input.",
            language: "python",
            code: "execute(untrusted_query)",
          },
          validation: {
            method: "live replay",
            assertions: ["A cross-account record was returned."],
            evidence: ["A crafted request returned another account's record."],
            counterEvidence: ["Production authentication was not bypassed."],
            limitations: ["Production traffic was not replayed."],
          },
          attackPath: {
            dataflow: {
              summary: "Request input reaches the SQL executor.",
              source: "The account identifier in the request body.",
              sink: "The unparameterized SQL executor.",
              outcome: "A cross-account database row is returned.",
            },
            reachability: {
              summary: "An unauthenticated caller reaches the endpoint.",
              attacker: "An unauthenticated internet user.",
              entrypoint: "POST /api/accounts/search.",
              preconditions: ["The account search route is enabled."],
            },
            preconditions: ["An administrator account is required."],
            limitations: ["The database is reachable only internally."],
          },
          remediation: "Parameterize the database query.",
        },
        "finding",
      ),
    );

    for (const expected of [
      "VALIDATION",
      "Method: live replay",
      "Verified: A cross-account record was returned.",
      "Evidence: A crafted request returned another account's record.",
      "Counterevidence: Production authentication was not bypassed.",
      "Limitation: Production traffic was not replayed.",
      "ATTACK PATH",
      "Dataflow: Request input reaches the SQL executor.",
      "Source: The account identifier in the request body.",
      "Sink: The unparameterized SQL executor.",
      "Outcome: A cross-account database row is returned.",
      "Reachability: An unauthenticated caller reaches the endpoint.",
      "Attacker: An unauthenticated internet user.",
      "Entry point: POST /api/accounts/search.",
      "Precondition: The account search route is enabled.",
      "Precondition: An administrator account is required.",
      "Limitation: The database is reachable only internally.",
      "CODE EVIDENCE",
      "Root-cause source",
      "execute(untrusted_query)",
    ]) {
      expect(output).toContain(expected);
    }
  });

  test("renders legacy snake-case finding evidence", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "legacy-scan",
          targetPath: "/demo/previous-checkout",
          currentTargetPath: "/demo/current-checkout",
          occurrenceId: "legacy-occurrence",
          severity: { level: "high" },
          title: "Unsafe legacy query",
          locations: [{ path: "src/query.py", startLine: 12 }],
          root_cause: { summary: "Legacy authorization bypass." },
          code_evidence: [
            {
              label: "Legacy source proof",
              code: "bypass_authorization()",
            },
          ],
        },
        "finding",
      ),
    );

    expect(output).toContain("current-checkout");
    expect(output).not.toContain("previous-checkout");
    expect(output).toContain("ROOT CAUSE");
    expect(output).toContain("Legacy authorization bypass.");
    expect(output).toContain("CODE EVIDENCE");
    expect(output).toContain("Legacy source proof");
    expect(output).toContain("bypass_authorization()");
  });

  test("preserves every line and the complete width of saved finding evidence", () => {
    const sink = `${"argument_".repeat(18)}dangerous_sink(user_input)`;
    const code = [
      ...Array.from({ length: 14 }, (_, index) => `step_${index}();`),
      sink,
    ].join("\n");
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "complete-evidence-scan",
          targetPath: "/demo/repository",
          occurrenceId: "complete-evidence-occurrence",
          severity: { level: "high" },
          title: "Full evidence",
          locations: [{ path: "src/server.ts" }],
          codeEvidence: [{ label: "Complete validation trace", code }],
          sourceExcerpt: sink,
        },
        "finding",
        { columns: 48 },
      ),
    );

    expect(output).toContain("step_13();");
    expect(output).toContain(sink);
    expect(output.match(/dangerous_sink\(user_input\)/g)).toHaveLength(2);
  });

  test("connects scan history with the next useful commands", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scans: [
            {
              scanId: "5b8e555e-abcd-4567-abcd-1234567890ab",
              targetPath: "/demo/juice-shop",
              mode: "standard",
              progress: { status: "complete" },
              findingCount: 18,
              startedAt: "2026-08-03T12:00:00Z",
            },
            {
              scanId: "31107fbe-abcd-4567-abcd-1234567890ab",
              targetPath: "/demo/juice-shop",
              mode: "standard",
              progress: { status: "complete" },
              findingCount: 25,
              startedAt: "2026-07-31T12:00:00Z",
            },
          ],
        },
        "list",
        { repository: "/demo/juice-shop" },
      ),
    );

    expect(output).toContain("VIEW LATEST  codex-security scans show");
    expect(output).toContain("FINDINGS     codex-security findings list");
    expect(output).toContain(
      "COMPARE      codex-security scans compare 31107fbe 5b8e555e",
    );
  });

  test("identifies every repository in cross-repository findings", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          findings: [
            {
              occurrenceId: "occ-first",
              scanId: "aaaaaaaa-full",
              severity: { level: "high" },
              title: "Missing authorization",
              locationPath: "src/server.ts",
              targetPath: "/demo/checkout-one",
            },
            {
              occurrenceId: "occ-second",
              scanId: "bbbbbbbb-full",
              severity: { level: "high" },
              title: "Missing authorization",
              locationPath: "src/server.ts",
              targetPath: "/demo/checkout-two",
            },
          ],
          offset: 0,
          nextOffset: null,
        },
        "findings",
      ),
    );

    expect(output).toContain("REPOSITORY /demo/checkout-one");
    expect(output).toContain("REPOSITORY /demo/checkout-two");
  });

  test("keeps findings and matching shortcuts in the displayed checkout", () => {
    const scan = {
      scanId: "aaaaaaaa-abcd-4567-abcd-1234567890ab",
      targetPath: "/demo/another-checkout",
      mode: "standard",
      progress: { status: "complete" },
      findingCount: 1,
      startedAt: "2026-08-03T12:00:00Z",
    };
    const list = stripVTControlCharacters(
      renderScanHistory({ scans: [scan] }, "list", {
        currentDirectory: "/demo/current-checkout",
        repository: "/demo/another-checkout",
      }),
    );
    expect(list).toContain(
      "FINDINGS     codex-security findings list --scan aaaaaaaa",
    );

    const ancestor = stripVTControlCharacters(
      renderScanHistory(
        {
          scans: [{ ...scan, targetPath: "/demo/current-checkout" }],
        },
        "list",
        {
          currentDirectory: "/demo/current-checkout/service",
          repository: "/demo/current-checkout/service",
        },
      ),
    );
    expect(ancestor).toContain(
      "FINDINGS     codex-security findings list --scan aaaaaaaa",
    );

    const sibling = stripVTControlCharacters(
      renderScanHistory(
        {
          scans: [
            {
              ...scan,
              scanId: "bbbbbbbb-abcd-4567-abcd-1234567890ab",
              targetPath: "/demo/another-checkout",
              findingCount: 8,
              completedAt: "2026-08-03T12:00:00Z",
            },
            {
              ...scan,
              scanId: "cccccccc-abcd-4567-abcd-1234567890ab",
              targetPath: "/demo/current-checkout",
              findingCount: 2,
              completedAt: "2026-08-02T12:00:00Z",
            },
          ],
        },
        "list",
        {
          currentDirectory: "/demo/current-checkout",
          repository: "/demo/current-checkout",
        },
      ),
    );
    expect(sibling).toContain("latest: 2 findings");
    expect(sibling).toContain(
      "VIEW LATEST  codex-security scans show cccccccc",
    );
    expect(sibling).not.toContain(
      "VIEW LATEST  codex-security scans show bbbbbbbb",
    );

    const details = stripVTControlCharacters(
      renderScanHistory(
        {
          ...scan,
          findings: [
            {
              occurrenceId: "occ-saved",
              severity: { level: "high" },
              title: "Missing authorization",
              locations: [{ path: "src/server.ts" }],
            },
          ],
        },
        "show",
        {
          currentDirectory: "/demo/current-checkout",
          showLinkedFindings: true,
        },
      ),
    );
    expect(details).toContain(
      "from /demo/another-checkout, run codex-security scans match --all",
    );
  });

  test("orders comparison suggestions by scan completion rather than updates", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scans: [
            {
              scanId: "aaaaaaaa-abcd-4567-abcd-1234567890ab",
              targetPath: "/demo/juice-shop",
              mode: "standard",
              progress: { status: "complete" },
              findingCount: 2,
              completedAt: "2026-08-01T12:00:00Z",
              startedAt: "2026-08-01T11:00:00Z",
              updatedAt: "2026-08-04T12:00:00Z",
            },
            {
              scanId: "bbbbbbbb-abcd-4567-abcd-1234567890ab",
              targetPath: "/demo/juice-shop",
              mode: "standard",
              progress: { status: "complete" },
              findingCount: 3,
              completedAt: "2026-08-03T12:00:00Z",
              startedAt: "2026-08-03T11:00:00Z",
              updatedAt: "2026-08-03T12:00:00Z",
            },
          ],
        },
        "list",
        { repository: "/demo/juice-shop" },
      ),
    );

    expect(output).toContain("VIEW LATEST  codex-security scans show bbbbbbbb");
    expect(output).toContain("latest: 3 findings");
    expect(output).not.toContain("latest: 2 findings");
    expect(output).toContain(
      "COMPARE      codex-security scans compare aaaaaaaa bbbbbbbb",
    );
    expect(output).not.toContain("scans compare bbbbbbbb aaaaaaaa");
  });

  test("does not suggest comparing scans from different repositories", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scans: [
            {
              scanId: "aaaaaaaa-abcd-4567-abcd-1234567890ab",
              targetPath: "/demo/juice-shop",
              mode: "standard",
              progress: { status: "complete" },
              findingCount: 8,
              startedAt: "2026-08-03T12:00:00Z",
            },
            {
              scanId: "bbbbbbbb-abcd-4567-abcd-1234567890ab",
              targetPath: "/demo/payment-service",
              mode: "standard",
              progress: { status: "complete" },
              findingCount: 2,
              startedAt: "2026-08-02T12:00:00Z",
            },
          ],
        },
        "list",
        { scanRoot: "/demo/results" },
      ),
    );

    expect(output).toContain("scans show aaaaaaaa");
    expect(output).toContain("findings list --scan aaaaaaaa");
    expect(output).not.toContain("scans compare");
  });

  test("shows bounded findings, saved configuration, and failure reasons", () => {
    const scan = {
      scanId: "12345678-abcd-4567-abcd-1234567890ab",
      parentScanId: "87654321-abcd-4567-abcd-1234567890ab",
      targetPath: "/demo/juice-shop",
      mode: "standard",
      progress: {
        status: "complete",
        coverage: { closedRows: 12, worklistRows: 15, filesTotal: 9 },
      },
      findingCount: 75,
      findingsTruncated: true,
      artifacts: { markdownReport: "/demo/results/report.md" },
      recipe: {
        config: {
          model: "gpt-5.6-sol",
          model_reasoning_effort: "high",
          features: { goals: true, multi_agent_v2: { enabled: true } },
          trusted_paths: ["src", "packages/core"],
        },
      },
      findings: Array.from({ length: 20 }, (_, index) => ({
        severity: { level: "high" },
        title: `Finding ${index + 1}`,
        locations: [{ path: "routes/login.ts", startLine: index + 1 }],
      })),
    };
    const output = stripVTControlCharacters(renderScanHistory(scan, "show"));
    for (const expected of [
      "FINDINGS  20 of 75",
      "PARENT SCAN  87654321",
      "CONFIGURATION",
      "model=gpt-5.6-sol",
      'features={"goals":true,"multi_agent_v2":{"enabled":true}}',
      'trusted_paths=["src","packages/core"]',
      "COVERAGE",
      "12 of 15 reviewed",
      "9 files",
      "ARTIFACTS",
      "/demo/results/report.md",
      "findings list --scan 12345678 --offset 20",
    ]) {
      expect(output).toContain(expected);
    }

    const failed = stripVTControlCharacters(
      renderScanHistory(
        {
          ...scan,
          progress: { status: "failed" },
          failureMessage: "Repository checkout became unavailable.",
          findings: [],
        },
        "show",
      ),
    );
    expect(failed).toContain("ERROR  Repository checkout became unavailable.");
  });

  test("explains when requested cross-scan links have not been generated", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "5b8e555e-abcd-4567-abcd-1234567890ab",
          targetPath: "/demo/juice-shop",
          mode: "standard",
          progress: { status: "complete" },
          findings: [
            {
              occurrenceId: "occ_saved_finding",
              severity: { level: "high" },
              title: "Login injection",
              locations: [{ path: "routes/login.ts", startLine: 34 }],
            },
          ],
        },
        "show",
        { showLinkedFindings: true },
      ),
    );

    expect(output).toContain("No saved links");
    expect(output).toContain("scans match --all (uses Codex)");
  });

  test("does not claim links are missing when scan findings are truncated", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "5b8e555e-abcd-4567-abcd-1234567890ab",
          targetPath: "/demo/juice-shop",
          mode: "standard",
          progress: { status: "complete" },
          findingCount: 25,
          findingsTruncated: true,
          findings: [
            {
              occurrenceId: "occ_saved_finding",
              severity: { level: "high" },
              title: "Login injection",
              locations: [{ path: "routes/login.ts", startLine: 34 }],
            },
          ],
        },
        "show",
        { showLinkedFindings: true },
      ),
    );

    expect(output).toContain("MORE FINDINGS");
    expect(output).not.toContain("No saved links");
    expect(output).not.toContain("scans match --all");
  });

  test("directs nested checkout matching to the scanned target root", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "5b8e555e-abcd-4567-abcd-1234567890ab",
          targetPath: "/demo/plain-directory",
          mode: "standard",
          progress: { status: "complete" },
          findings: [
            {
              occurrenceId: "occ_saved_finding",
              severity: { level: "high" },
              title: "Login injection",
              locations: [{ path: "src/login.ts", startLine: 34 }],
            },
          ],
        },
        "show",
        {
          currentDirectory: "/demo/plain-directory/src/nested",
          showLinkedFindings: true,
        },
      ),
    );

    expect(output).toContain(
      "from /demo/plain-directory, run codex-security scans match --all",
    );
  });

  test("directs historical matching to the relocated checkout", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "5b8e555e-abcd-4567-abcd-1234567890ab",
          targetPath: "/demo/previous-checkout",
          currentTargetPath: "/demo/current-checkout",
          mode: "standard",
          progress: { status: "complete" },
          findings: [
            {
              occurrenceId: "occ_saved_finding",
              severity: { level: "high" },
              title: "Login injection",
              locations: [{ path: "src/login.ts", startLine: 34 }],
            },
          ],
        },
        "show",
        {
          currentDirectory: "/demo/current-checkout/src",
          showLinkedFindings: true,
        },
      ),
    );

    expect(output).toContain(
      "from /demo/current-checkout, run codex-security scans match --all",
    );
    expect(output).not.toContain("from /demo/previous-checkout");
  });

  test("shows saved completion warnings without marking a scan failed", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          scanId: "12345678-abcd-4567-abcd-1234567890ab",
          targetPath: "/demo/juice-shop",
          mode: "standard",
          progress: { status: "complete" },
          findings: [],
          warnings: [
            "Repository HEAD changed while the scan was running; results were saved for the original revision.",
          ],
        },
        "show",
      ),
    );

    expect(output).toContain("COMPLETE");
    expect(output).toContain("WARNING");
    expect(output).toContain(
      "Repository HEAD changed while the scan was running",
    );
    expect(output).not.toContain("ERROR");
  });

  test("renders match-all results from the original workbench data", () => {
    const output = stripVTControlCharacters(
      renderScanHistory(
        {
          repository: "/demo/juice-shop",
          scanCount: 5,
          unavailableScans: 2,
          matchedPairs: 0,
          findingMatches: 0,
        },
        "match-all",
      ),
    );
    for (const expected of [
      "MATCH RESULTS",
      "juice-shop",
      "5 scans",
      "0 comparisons",
      "0 root-cause matches",
      "2 scans unavailable",
    ]) {
      expect(output).toContain(expected);
    }
  });
});

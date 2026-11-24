import assert from "node:assert/strict";
import test from "node:test";
import { createFixture, type SourceCase } from "./fixtures.mts";
import { gradeResult, type Result } from "./grade.mts";

const fixture = createFixture();

function grade(...findings: Result["findings"]) {
  return gradeResult({ findings }, fixture);
}

type FixtureFinding = Required<Result["findings"][number]>;

function findingFor(
  expected: SourceCase,
  role = "root_control",
): FixtureFinding {
  return {
    title: expected.id,
    taxonomy: { cwe: [expected.cwes[0]] },
    locations: [{ path: expected.path, startLine: expected.line, role }],
    codeEvidence: [
      {
        path: expected.path,
        startLine: expected.line,
        code: fixture.files[expected.path].split("\n")[expected.line - 1],
      },
    ],
  };
}

function findingAt(path: string, source: string, cwe: string) {
  const line =
    fixture.files[path].split("\n").findIndex((row) => row.includes(source)) +
    1;
  assert.ok(line > 0, `Missing fixture source: ${source}`);
  return findingFor({ id: source, path, line, cwes: [cwe] }, "sink");
}

function allFindings() {
  return fixture.positives.map((expected) => findingFor(expected));
}

test("authentic source evidence matches every vulnerability family", () => {
  const findings = allFindings();
  findings[1].locations[0].role = "sink";
  const report = grade(...findings);
  assert.equal(report.passed, true);
  assert.equal(report.recall, 1);
  assert.equal(report.expectedCount, fixture.positives.length);
  assert.equal(report.foundCount, fixture.positives.length);
  assert.deepEqual(report.evidenceErrors, []);
});

test("missing SSRF reduces recall even when every other case is found", () => {
  const findings = allFindings().filter(
    (finding) => !finding.taxonomy.cwe.includes("CWE-918"),
  );
  const report = grade(...findings);
  assert.deepEqual(
    report.cases.filter((entry) => !entry.found),
    [{ id: "partner-status-ssrf", found: false }],
  );
  assert.equal(
    report.recall,
    (fixture.positives.length - 1) / fixture.positives.length,
  );
  assert.equal(report.passed, false);
  assert.deepEqual(report.unmatchedFindings, []);
});

test("SSRF earns credit at the user-selected destination and flags the allowlisted destination for review", () => {
  const path = "src/partners.py";
  const positive = grade(
    findingAt(path, 'requests.head(request.args["url"]', "CWE-918"),
  );
  assert.deepEqual(positive.matchedIds, ["partner-status-ssrf"]);
  assert.equal(positive.safeControlFindings, 0);

  const control = grade(findingAt(path, "requests.head(url,", "CWE-918"));
  assert.deepEqual(control.matchedIds, []);
  assert.deepEqual(
    control.safeControlDetails.map((entry) => entry.controlIds),
    [["partner-status-allowlist"]],
  );
  assert.equal(control.needsAdjudication, true);
});

test("path containment and tenant selection are independent controls", () => {
  const path = "src/statements.py";
  const callerSelected = "send_file(statement_path(tenant_id, name)";
  const report = grade(
    findingAt(path, callerSelected, "CWE-639"),
    findingAt(path, "send_file(statement_path(g.tenant_id, name)", "CWE-639"),
    findingAt(path, "if not target.is_relative_to(root):", "CWE-22"),
  );
  assert.deepEqual(report.matchedIds, ["statement-tenant-selection"]);
  assert.deepEqual(
    report.safeControlDetails.map((entry) => entry.controlIds),
    [["statement-session-tenant"], ["statement-contained-path"]],
  );
  const traversal = grade(findingAt(path, callerSelected, "CWE-22"));
  assert.deepEqual(traversal.matchedIds, []);
  assert.equal(traversal.unmatchedFindings.length, 1);
});

test("grant verification distinguishes the selected tenant from the verified tenant", () => {
  const path = "src/grants.py";
  for (const cwe of ["CWE-639", "CWE-862", "CWE-349", "CWE-252"]) {
    const report = grade(
      findingAt(path, 'return invoice_report(batch[0]["tenant_id"])', cwe),
      findingAt(path, 'return invoice_report(grant["tenant_id"])', cwe),
      findingAt(
        path,
        "SELECT id, recipient, total FROM invoices WHERE tenant_id",
        cwe,
      ),
      findingAt(path, 'tenant = signer.loads(grant["proof"],', cwe),
    );
    assert.deepEqual(report.matchedIds, ["report-unverified-grant"]);
    assert.deepEqual(
      report.safeControlDetails.map((entry) => entry.controlIds),
      [["report-verified-grant"]],
    );
    assert.equal(report.unmatchedFindings.length, 2);
    assert.equal(report.needsAdjudication, true);
  }
});

test("the discarded verification result is a grounded root control for the grant finding", () => {
  const path = "src/grants.py";
  const finding = findingAt(path, "    verified_grant(batch)", "CWE-862");
  finding.locations[0].role = "root_control";
  assert.deepEqual(grade(finding).matchedIds, ["report-unverified-grant"]);

  finding.locations[0].role = "supporting";
  assert.deepEqual(grade(finding).matchedIds, []);
  finding.locations[0].role = "root_control";
  finding.codeEvidence = findingAt(
    path,
    "    batch = submitted_grants()",
    "CWE-863",
  ).codeEvidence;
  assert.deepEqual(grade(finding).matchedIds, []);
  assert.equal(grade(finding).evidenceErrors.length, 1);
});

test("an unlabelled affected location can use the role on authentic evidence at the same gold line", () => {
  const finding = findingAt(
    "src/grants.py",
    "    verified_grant(batch)",
    "CWE-863",
  );
  const [location] = finding.locations;
  const [snippet] = finding.codeEvidence;
  delete location.role;
  for (const role of ["root_control", "sink", "entrypoint"]) {
    snippet.role = role;
    assert.deepEqual(grade(finding).matchedIds, ["report-unverified-grant"]);
  }
  for (const role of ["entrypoint", "entrypoint/wrapper"]) {
    location.role = role;
    assert.deepEqual(grade(finding).matchedIds, ["report-unverified-grant"]);
  }
  delete location.role;
  for (const role of [
    undefined,
    "expected_control",
    "supporting",
    "propagation",
  ]) {
    snippet.role = role;
    assert.deepEqual(grade(finding).matchedIds, []);
  }

  // Both lines are gold. A role on one cannot qualify a citation to the other.
  snippet.role = "sink";
  location.startLine++;
  assert.deepEqual(grade(finding).matchedIds, []);
  location.startLine--;
  location.role = "supporting";
  assert.deepEqual(grade(finding).matchedIds, []);
  delete location.role;
  snippet.code = "invented code";
  const fabricated = grade(finding);
  assert.deepEqual(fabricated.matchedIds, []);
  assert.equal(fabricated.evidenceErrors.length, 1);
});

test("a safe sibling cited as a comparison stays clear, while an accusation is flagged", () => {
  const path = "src/statements.py";
  const finding = findingAt(
    path,
    "send_file(statement_path(tenant_id, name)",
    "CWE-639",
  );
  const safe = findingAt(
    path,
    "send_file(statement_path(g.tenant_id, name)",
    "CWE-639",
  );
  delete finding.locations[0].role;
  finding.codeEvidence[0].role = "entrypoint";
  finding.locations.push(...safe.locations);
  finding.codeEvidence.push(...safe.codeEvidence);
  const compare = (evidenceRole?: string, locationRole?: string) => {
    safe.locations[0].role = locationRole;
    safe.codeEvidence[0].role = evidenceRole;
    return grade(finding);
  };
  const comparison = compare("expected_control");
  assert.deepEqual(comparison.matchedIds, ["statement-tenant-selection"]);
  assert.deepEqual(comparison.safeControlDetails, []);
  finding.locations.push({
    path: "src/app.py",
    startLine: 999,
    role: "supporting",
  });
  const unrelatedError = compare("expected_control");
  assert.equal(unrelatedError.evidenceErrors.length, 1);
  assert.deepEqual(unrelatedError.safeControlDetails, []);
  finding.locations.pop();
  for (const report of [
    compare("sink"),
    compare("supporting"),
    compare("consumer"),
    compare(undefined),
    compare("expected_control", "root_control"),
  ]) {
    assert.deepEqual(
      report.safeControlDetails.map(({ controlIds }) => controlIds),
      [["statement-session-tenant"]],
    );
    assert.equal(report.needsAdjudication, true);
  }
  const conflictSnippet = {
    ...safe.codeEvidence[0],
    role: "sink",
    endLine: fixture.files[path].split("\n").length + 1,
  };
  finding.codeEvidence.push(conflictSnippet);
  const conflict = compare("expected_control");
  assert.equal(conflict.passed, false);
  assert.equal(conflict.evidenceErrors.length, 1);
  assert.deepEqual(
    conflict.safeControlDetails.flatMap(({ controlIds }) => controlIds),
    ["statement-session-tenant"],
  );
  conflictSnippet.endLine = conflictSnippet.startLine;
  conflictSnippet.startLine--;
  conflictSnippet.code =
    fixture.files[path].split("\n")[conflictSnippet.startLine - 1];
  const partialQuote = compare("expected_control");
  assert.deepEqual(partialQuote.evidenceErrors, []);
  assert.deepEqual(
    partialQuote.safeControlDetails.flatMap(({ controlIds }) => controlIds),
    ["statement-session-tenant"],
  );
});

test("a snippet cannot assign roles to trailing context outside its declared span", () => {
  const findingWithContext = (expected: SourceCase, role: string) => {
    const finding = findingFor(expected);
    delete finding.locations[0].role;
    const [snippet] = finding.codeEvidence;
    snippet.role = role;
    snippet.startLine--;
    snippet.endLine = snippet.startLine;
    snippet.code = fixture.files[snippet.path]
      .split("\n")
      .slice(snippet.startLine - 1, expected.line)
      .join("\n");
    return finding;
  };
  const [expected] = fixture.positives;
  const finding = findingWithContext(expected, "root_control");
  assert.deepEqual(grade(finding).matchedIds, []);
  finding.locations[0].role = "sink";
  assert.deepEqual(grade(finding).matchedIds, [expected.id]);
  delete finding.locations[0].role;
  const [snippet] = finding.codeEvidence;
  delete snippet.endLine;
  assert.deepEqual(grade(finding).matchedIds, [expected.id]);
  snippet.endLine = expected.line;
  snippet.code = snippet.code.split("\n")[0];
  assert.deepEqual(grade(finding).matchedIds, []);
  const [control] = fixture.controls;
  const comparison = findingWithContext(control, "expected_control");
  assert.deepEqual(
    grade(comparison).safeControlDetails.flatMap(
      ({ controlIds }) => controlIds,
    ),
    [control.id],
  );
});

test("additional fabricated locations invalidate an otherwise grounded finding", () => {
  for (const role of ["root_control", "supporting"]) {
    for (const location of [
      { path: "src/invented.py", startLine: 500 },
      { path: "src/invoices.py", startLine: 500 },
      { path: "src/invoices.py", startLine: 0 },
      { path: "src/invoices.py", startLine: 8, endLine: 7 },
    ]) {
      const findings = allFindings();
      findings[0].locations.push({ ...location, role });
      const report = grade(...findings);
      assert.equal(report.passed, false);
      assert.equal(report.foundCount, fixture.positives.length - 1);
      assert.equal(report.needsAdjudication, true);
      assert.deepEqual(report.evidenceErrors, [
        {
          findingIndex: 0,
          locationIndex: 1,
          reason: "location path or line range does not exist in the source",
        },
      ]);
    }
  }
});

test("duplicate reports cannot increase recall", () => {
  const findings = allFindings();
  findings.push(structuredClone(findings[0]));
  const report = grade(...findings);
  assert.equal(report.recall, 1);
  assert.equal(report.foundCount, fixture.positives.length);
  assert.equal(report.duplicateFindings, 1);
});

test("a different CWE, source line, or non-primary role does not earn a gold match", () => {
  const alterations: Array<(finding: FixtureFinding) => void> = [
    (finding) => {
      finding.taxonomy.cwe = ["CWE-79"];
    },
    (finding) => {
      finding.locations[0].path = "README.md";
    },
    (finding) => {
      finding.locations[0].startLine = 1;
    },
    (finding) => {
      finding.locations[0].role = "supporting";
    },
    (finding) => {
      finding.locations[0].role = "supporting_context";
      finding.locations.unshift({
        path: "README.md",
        startLine: 1,
        role: "root_control",
      });
    },
  ];
  for (const alter of alterations) {
    const findings = allFindings();
    alter(findings[0]);
    const report = grade(...findings);
    assert.equal(report.foundCount, fixture.positives.length - 1);
    assert.equal(report.unmatchedFindings.length, 1);
    assert.equal(report.needsAdjudication, true);
    assert.equal(report.safeControlFindings, 0);
    assert.deepEqual(report.evidenceErrors, []);
  }
});

test("missing, fabricated, misplaced, or unrelated evidence cannot earn recall", () => {
  const alterations: Array<(finding: FixtureFinding) => void> = [
    (finding) => {
      finding.codeEvidence = [];
    },
    (finding) => {
      finding.codeEvidence[0].code = "invented source text";
    },
    (finding) => {
      finding.codeEvidence[0].startLine++;
    },
    (finding) => {
      finding.codeEvidence[0].path = "src/search.py";
    },
    (finding) => {
      finding.codeEvidence = [
        {
          path: "src/invoices.py",
          startLine: 1,
          code: fixture.files["src/invoices.py"].split("\n")[0],
        },
      ];
    },
  ];
  for (const alter of alterations) {
    const findings = allFindings();
    alter(findings[0]);
    const report = grade(...findings);
    assert.equal(report.foundCount, fixture.positives.length - 1);
    assert.equal(report.passed, false);
    assert.ok(report.evidenceErrors.length > 0);
  }
});

test("control accusations and unmatched findings have separate adjudication queues", () => {
  const findings = allFindings();
  findings.push(findingFor(fixture.controls[0]));
  const unmatched = findingFor(fixture.positives[1]);
  unmatched.taxonomy.cwe = ["CWE-400"];
  findings.push(unmatched);
  const report = grade(...findings);
  assert.equal(report.recall, 1);
  assert.equal(report.safeControlFindings, 1);
  assert.deepEqual(report.safeControlDetails[0].controlIds, [
    fixture.controls[0].id,
  ]);
  assert.equal(report.unmatchedFindings.length, 1);
  assert.equal(report.passed, false);
  assert.equal(report.needsAdjudication, true);
});

test("safe-control context does not become a control accusation", () => {
  const findings = allFindings();
  const context = findingFor(fixture.controls[0]);
  context.locations[0].role = "expected_control";
  findings[0].locations.push(...context.locations);
  findings[0].codeEvidence.push(...context.codeEvidence);
  assert.equal(grade(...findings).passed, true);
});

test("descriptive safe-control roles require adjudication rather than a false-positive verdict", () => {
  const findings = allFindings();
  const context = findingFor(fixture.controls[0]);
  context.locations[0].role =
    "safe sibling showing the expected tenant control";
  findings[0].locations.push(...context.locations);
  findings[0].codeEvidence.push(...context.codeEvidence);
  const report = grade(...findings);
  assert.equal(report.recall, 1);
  assert.equal(report.safeControlFindings, 1);
  assert.equal(report.needsAdjudication, true);
  assert.equal(report.passed, false);
  assert.deepEqual(report.safeControlDetails[0].controlIds, [
    fixture.controls[0].id,
  ]);
});

test("source snippets may span the sink", () => {
  const findings = allFindings();
  for (const finding of findings) {
    const evidence = finding.codeEvidence[0];
    const source = fixture.files[evidence.path];
    evidence.startLine--;
    evidence.code = source
      .split("\n")
      .slice(evidence.startLine - 1, evidence.startLine + 1)
      .join("\n");
  }
  assert.equal(grade(...findings).passed, true);
});

test("fixture source is deterministic and contains no gold identifiers", () => {
  assert.deepEqual(createFixture(), fixture);
  const source = Object.values(fixture.files).join("\n");
  for (const expected of [...fixture.positives, ...fixture.controls]) {
    assert.equal(source.includes(expected.id), false);
  }
});

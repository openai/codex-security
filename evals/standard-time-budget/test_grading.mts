import assert from "node:assert/strict";
import test from "node:test";
import { createFixture, type Fixture, type SourceCase } from "./fixtures.mts";
import { gradeResult, type SourceLocation } from "./grade.mts";

function findingFor(
  fixture: Fixture,
  expected: SourceCase,
  role = "root_control",
) {
  return {
    title: expected.id,
    taxonomy: { cwe: [expected.cwes[0]] },
    locations: [
      { path: expected.path, startLine: expected.line, role },
    ] as SourceLocation[],
    codeEvidence: [
      {
        path: expected.path,
        startLine: expected.line,
        code: fixture.files[expected.path].split("\n")[expected.line - 1],
      },
    ],
  };
}

type FixtureFinding = ReturnType<typeof findingFor>;

function completeResult(fixture: Fixture) {
  return {
    findings: fixture.positives.map((expected) =>
      findingFor(fixture, expected),
    ),
  };
}

test("authentic source evidence matches every vulnerability family", () => {
  const fixture = createFixture();
  const result = completeResult(fixture);
  result.findings[1].locations[0].role = "sink";
  const report = gradeResult(result, fixture);
  assert.equal(report.passed, true);
  assert.equal(report.recall, 1);
  assert.equal(report.expectedCount, fixture.positives.length);
  assert.equal(report.foundCount, fixture.positives.length);
  assert.deepEqual(report.evidenceErrors, []);
});

test("missing SSRF reduces recall even when every other case is found", () => {
  const fixture = createFixture();
  const findings = completeResult(fixture).findings.filter(
    (finding) => !finding.taxonomy.cwe.includes("CWE-918"),
  );
  const report = gradeResult({ findings }, fixture);
  assert.deepEqual(
    report.cases.filter((entry) => !entry.found),
    [{ id: "partner-status-ssrf", found: false }],
  );
  assert.equal(report.recall, 4 / 5);
  assert.equal(report.passed, false);
  assert.deepEqual(report.unmatchedFindings, []);
});

test("SSRF earns credit at the user-selected destination and flags the allowlisted destination for review", () => {
  const fixture = createFixture();
  const path = "src/partners.py";
  function findingAt(sink: string) {
    const line =
      fixture.files[path].split("\n").findIndex((row) => row.includes(sink)) +
      1;
    assert.ok(line > 0, `Missing sink: ${sink}`);
    return findingFor(
      fixture,
      { id: "Outbound status request", path, line, cwes: ["CWE-918"] },
      "sink",
    );
  }
  const positive = gradeResult(
    { findings: [findingAt('requests.head(request.args["url"]')] },
    fixture,
  );
  assert.deepEqual(positive.matchedIds, ["partner-status-ssrf"]);
  assert.equal(positive.safeControlFindings, 0);

  const control = gradeResult(
    { findings: [findingAt("requests.head(url,")] },
    fixture,
  );
  assert.deepEqual(control.matchedIds, []);
  assert.deepEqual(
    control.safeControlDetails.map((entry) => entry.controlIds),
    [["partner-status-allowlist"]],
  );
  assert.equal(control.needsAdjudication, true);
});

test("additional fabricated locations invalidate an otherwise grounded finding", () => {
  const fixture = createFixture();
  for (const role of ["root_control", "supporting"]) {
    for (const location of [
      { path: "src/invented.py", startLine: 500 },
      { path: "src/invoices.py", startLine: 500 },
      { path: "src/invoices.py", startLine: 0 },
      { path: "src/invoices.py", startLine: 8, endLine: 7 },
    ]) {
      const result = completeResult(fixture);
      result.findings[0].locations.push({ ...location, role });
      const report = gradeResult(result, fixture);
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
  const fixture = createFixture();
  const result = completeResult(fixture);
  result.findings.push(structuredClone(result.findings[0]));
  const report = gradeResult(result, fixture);
  assert.equal(report.recall, 1);
  assert.equal(report.foundCount, fixture.positives.length);
  assert.equal(report.duplicateFindings, 1);
});

test("a different CWE, source line, or non-primary role does not earn a gold match", () => {
  const fixture = createFixture();
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
    const result = completeResult(fixture);
    alter(result.findings[0]);
    const report = gradeResult(result, fixture);
    assert.equal(report.foundCount, fixture.positives.length - 1);
    assert.equal(report.unmatchedFindings.length, 1);
    assert.equal(report.needsAdjudication, true);
    assert.equal(report.safeControlFindings, 0);
    assert.deepEqual(report.evidenceErrors, []);
  }
});

test("missing, fabricated, misplaced, or unrelated evidence cannot earn recall", () => {
  const fixture = createFixture();
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
    const result = completeResult(fixture);
    alter(result.findings[0]);
    const report = gradeResult(result, fixture);
    assert.equal(report.foundCount, fixture.positives.length - 1);
    assert.equal(report.passed, false);
    assert.ok(report.evidenceErrors.length > 0);
  }
});

test("control accusations and unmatched findings have separate adjudication queues", () => {
  const fixture = createFixture();
  const result = completeResult(fixture);
  result.findings.push(findingFor(fixture, fixture.controls[0]));
  const unmatched = findingFor(fixture, fixture.positives[1]);
  unmatched.taxonomy.cwe = ["CWE-400"];
  result.findings.push(unmatched);
  const report = gradeResult(result, fixture);
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
  const fixture = createFixture();
  const result = completeResult(fixture);
  const context = findingFor(fixture, fixture.controls[0]);
  context.locations[0].role = "expected_control";
  result.findings[0].locations.push(...context.locations);
  result.findings[0].codeEvidence.push(...context.codeEvidence);
  assert.equal(gradeResult(result, fixture).passed, true);
});

test("descriptive safe-control roles require adjudication rather than a false-positive verdict", () => {
  const fixture = createFixture();
  const result = completeResult(fixture);
  const context = findingFor(fixture, fixture.controls[0]);
  context.locations[0].role =
    "safe sibling showing the expected tenant control";
  result.findings[0].locations.push(...context.locations);
  result.findings[0].codeEvidence.push(...context.codeEvidence);
  const report = gradeResult(result, fixture);
  assert.equal(report.recall, 1);
  assert.equal(report.safeControlFindings, 1);
  assert.equal(report.needsAdjudication, true);
  assert.equal(report.passed, false);
  assert.deepEqual(report.safeControlDetails[0].controlIds, [
    fixture.controls[0].id,
  ]);
});

test("source snippets may span the sink", () => {
  const fixture = createFixture();
  const result = completeResult(fixture);
  for (const finding of result.findings) {
    const evidence = finding.codeEvidence[0];
    const source = fixture.files[evidence.path];
    evidence.startLine--;
    evidence.code = source
      .split("\n")
      .slice(evidence.startLine - 1, evidence.startLine + 1)
      .join("\n");
  }
  assert.equal(gradeResult(result, fixture).passed, true);
});

test("fixture source is deterministic and contains no gold identifiers", () => {
  const fixture = createFixture();
  assert.deepEqual(createFixture(), fixture);
  const source = Object.values(fixture.files).join("\n");
  for (const expected of [...fixture.positives, ...fixture.controls]) {
    assert.equal(source.includes(expected.id), false);
  }
});

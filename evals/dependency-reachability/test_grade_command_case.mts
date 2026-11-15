import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test, { type TestContext } from "node:test";
import { cases, type StageFile } from "./cases.mts";
import { checkoutPlacesV2 } from "./checkout-places-v2.mts";
import { gradeCommandCase } from "./grade-command-case.mts";
import {
  gradePlaceV2,
  gradeRunSearchAudit,
  type PlaceScopeExpectation,
} from "./place-rubric-v2.mts";

test("freezes 23 target-place identities and binds their anchors to the snapshot inputs", async () => {
  assert.equal(cases.length, 23);
  assert.equal(Object.keys(checkoutPlacesV2).length, 23);
  assert.deepEqual(
    cases.map(({ id }) => id).sort(),
    Object.keys(checkoutPlacesV2).sort(),
  );
  for (const c of cases) {
    const expected = (
      checkoutPlacesV2 as Record<string, PlaceScopeExpectation>
    )[c.id]!;
    assert.equal(expected.verdict, c.verdict, c.id);
    assert.deepEqual(expected.callSite, c.commandCallSite, c.id);
    assert.ok(expected.identityEvidence?.length, c.id);
    for (const anchor of expected.identityEvidence.flat()) {
      const staged = c.stage.find(
        ({ destination }) => destination === anchor.path,
      );
      if (staged && staged.kind !== "git") {
        const contents =
          staged.kind === "fixture"
            ? await readFile(new URL(staged.source, import.meta.url), "utf8")
            : JSON.stringify(staged.value, null, 2);
        assert.ok(
          anchor.contains && contents.includes(anchor.contains),
          `${c.id}: ${anchor.path} ${anchor.contains}`,
        );
      } else {
        assert.ok(
          c.evidenceGroups
            .flat()
            .some(
              (original) =>
                original.path === anchor.path &&
                original.contains &&
                anchor.contains &&
                original.contains.includes(anchor.contains),
            ),
          `${c.id}: ${anchor.path} ${anchor.contains}`,
        );
      }
    }
  }
});

async function fixture(t: TestContext) {
  const root = await mkdtemp(join(tmpdir(), "command-case-grader-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(join(root, "service.js"), "fixedInput();\nparse(input);\n");
  await writeFile(join(root, "installed.txt"), "libwebp 1.3.1-r1\n");
  const expected = {
    cve: "CVE-2023-4863",
    component: "libwebp",
    version: "1.3.1",
    versionAliases: ["1.3.1-r1"],
    verdict: "ruled_out" as const,
    evidenceGroups: [
      [{ path: "service.js", contains: "fixedInput();" }],
      [{ path: "installed.txt", contains: "libwebp 1.3.1-r1" }],
    ],
  };
  const version = { path: "installed.txt", startLine: 1, endLine: 1 };
  const control = { path: "service.js", startLine: 1, endLine: 1 };
  const use = {
    component: "Pillow (bundled libwebp)",
    location: "service.js",
    version: "1.3.1-r1",
    verdict: "ruled_out",
    reason: "The configured route fixes the input.",
    deployment: "configured",
    evidence: [version, control],
  };
  const answer = { cve: expected.cve, status: "ruled_out", uses: [use] };
  return { root, expected, answer, use, version, control };
}

test("a protected use can coexist with a separate affected library use", async (t) => {
  const { root, expected, answer, use, version } = await fixture(t);
  const library = {
    ...use,
    location: "library API",
    verdict: "potentially_exploitable",
    reason: "The library passes input to the decoder.",
    evidence: [version, { path: "service.js", startLine: 2, endLine: 2 }],
  };
  const mixed = {
    ...answer,
    status: "potentially_exploitable",
    uses: [library, use],
  };
  const grade = await gradeCommandCase(mixed, expected, root);
  assert.equal(grade.pass, true);
  assert.equal(grade.location, use.location);
  const overclaim = {
    ...mixed,
    status: "exploitable",
    uses: [{ ...library, verdict: "exploitable" }, use],
  };
  assert.equal((await gradeCommandCase(overclaim, expected, root)).pass, false);
  assert.equal((await gradeCommandCase(answer, expected, root)).pass, true);
  assert.equal(
    (await gradeCommandCase({ ...mixed, uses: [library] }, expected, root))
      .pass,
    false,
  );
});

test("requires matching advisory, component, version and use verdict in a positive report", async (t) => {
  const { root, expected, answer, use } = await fixture(t);
  const positive = { ...expected, verdict: "potentially_exploitable" as const };
  const subject = {
    ...use,
    verdict: "potentially_exploitable",
    version: expected.version,
  };
  const valid = {
    ...answer,
    status: "potentially_exploitable",
    uses: [subject],
  };
  assert.equal((await gradeCommandCase(valid, positive, root)).pass, true);
  for (const invalid of [
    { ...valid, cve: "CVE-2023-0000" },
    {
      ...valid,
      status: "exploitable",
      uses: [{ ...subject, verdict: "exploitable" }],
    },
    { ...valid, status: "unknown" },
    { ...valid, uses: [] },
    { ...valid, uses: [{ ...subject, component: "Pillow" }] },
    { ...valid, uses: [{ ...subject, version: "1.3.1-r0" }] },
    { ...valid, uses: [{ ...subject, version: null }] },
    { ...valid, uses: [{ ...subject, verdict: "unknown" }] },
    { ...valid, uses: [{ ...subject, reason: "" }] },
  ]) {
    assert.equal((await gradeCommandCase(invalid, positive, root)).pass, false);
  }
});

test("accepts incomplete checkout coverage when all observed uses are ruled out", async (t) => {
  const { root, expected, answer } = await fixture(t);
  const report = {
    ...answer,
    status: "unknown",
    limitations: ["The search did not finish."],
  };
  assert.equal((await gradeCommandCase(report, expected, root)).pass, true);
});

const matchingScope = {
  kind: "job",
  environment: "production",
  artifact: "example-image@sha256:aaa",
  revision: "build-a",
  observationWindow: "2026-01-01T01:00:00Z/2026-01-01T02:00:00Z",
  deploymentDetail: "job run run-1",
} as const;
const matchingSearch = {
  source: "test_inventory",
  tool: "get_run",
  scope: ["environment=production", "run_id=run-1"],
  result: "matches",
  completeness: "complete",
  evidenceReference: "inventory-1",
} as const;
const callSite = { path: "job.js", line: 2 };
const conditions = [
  { label: "Decode condition", status: "met", citations: [callSite] },
] as const;
const resolvedPlace = {
  id: "job-run-1",
  location: "Example job",
  ...matchingScope,
  deploymentBasis: "observed",
  verdict: "exploitable",
  conditions,
  callSite,
  decidingReceiptId: "inventory-1",
  searches: [matchingSearch],
} satisfies PlaceScopeExpectation;
const unresolvedQuestion = "Which image did run-1 load?";
const partialSearch = {
  ...matchingSearch,
  result: "no_match",
  completeness: "partial",
} as const;
const unresolvedPlace = {
  id: "job-run-1",
  location: "Example job",
  kind: "job",
  environment: "production",
  deploymentDetail: "job run run-1",
  deploymentBasis: "unknown",
  verdict: "unknown",
  conditions,
  callSite,
  unresolvedQuestion,
  searches: [partialSearch],
} satisfies PlaceScopeExpectation;
const recorded = (search: unknown) => ({
  searches: [
    {
      ...(search as object),
      startedAt: null,
      finishedAt: "2026-01-01T02:01:00Z",
      evidenceReferences: ["inventory-1"],
      details: [],
    },
  ],
});
const resolvedUse = {
  location: resolvedPlace.location,
  place: {
    ...matchingScope,
    deploymentBasis: "observed",
    unresolvedQuestions: [],
  },
  verdict: "exploitable",
  deployment: "confirmed",
  proof: { conditions, sink: { callSite } },
  evidence: [
    { path: "job.js", startLine: 2, endLine: 2, supports: ["affected_use"] },
  ],
  observations: [{ supports: ["affected_copy", "running", "access"] }],
  decidingEvidence: [{ kind: "receipt", receiptId: "inventory-1" }],
};

test("places v2 checks the exact job, run, environment, artifact, original record and operation", () => {
  const report = recorded(matchingSearch);
  assert.equal(
    gradePlaceV2(resolvedUse, report, resolvedPlace, true).pass,
    true,
  );
  for (const wrong of [
    { deploymentDetail: "job run run-2" },
    { artifact: "example-image@sha256:bbb" },
    { environment: "staging" },
  ]) {
    const grade = gradePlaceV2(
      { ...resolvedUse, place: { ...resolvedUse.place, ...wrong } },
      report,
      resolvedPlace,
    );
    assert.equal(grade.scopeCorrect, false);
    assert.equal(grade.pass, false);
  }
  assert.equal(
    gradePlaceV2(undefined, report, resolvedPlace).discoveryCorrect,
    false,
  );
  assert.equal(
    gradePlaceV2(
      { ...resolvedUse, decidingEvidence: [] },
      report,
      resolvedPlace,
    ).receiptCorrect,
    false,
  );
});

test("places v2 credits a justified unknown and preserves partial and failed coverage", () => {
  const use = {
    ...resolvedUse,
    place: {
      kind: "job",
      environment: "production",
      deploymentDetail: "job run run-1",
      deploymentBasis: "unknown",
      unresolvedQuestions: [unresolvedQuestion],
    },
    deployment: "unknown",
    verdict: "unknown",
    observations: [],
    decidingEvidence: [],
  };
  const report = recorded(partialSearch);
  assert.equal(gradePlaceV2(use, report, unresolvedPlace, true).pass, true);
  assert.equal(
    gradePlaceV2(
      { ...use, place: { ...use.place, unresolvedQuestions: [] } },
      report,
      unresolvedPlace,
    ).gapCorrect,
    false,
  );
  assert.equal(
    gradePlaceV2(use, { searches: [] }, unresolvedPlace).completenessCorrect,
    false,
  );
  assert.equal(
    gradePlaceV2(
      use,
      recorded({
        ...partialSearch,
        scope: ["environment=production", "run_id=run-2"],
      }),
      unresolvedPlace,
    ).completenessCorrect,
    false,
  );
  assert.equal(
    gradePlaceV2(
      use,
      recorded({ ...partialSearch, completeness: "complete" }),
      unresolvedPlace,
    ).completenessCorrect,
    false,
  );
  const error = {
    ...partialSearch,
    result: "unknown",
    completeness: "error",
  } as const;
  assert.equal(
    gradePlaceV2(
      use,
      recorded(error),
      {
        ...unresolvedPlace,
        searches: [error],
      },
      true,
    ).pass,
    true,
  );
  for (const completeness of ["skipped", "unavailable"] as const) {
    const skipped = {
      ...partialSearch,
      result: "not_run",
      completeness,
    } as const;
    assert.equal(
      gradePlaceV2(
        use,
        recorded(skipped),
        {
          ...unresolvedPlace,
          searches: [skipped],
        },
        true,
      ).pass,
      true,
    );
  }
});

test("places v2 requires caller scope for assumptions and keeps verified source exclusions independent", async (t) => {
  const assumption = "Assume this job has no rollout in staging.";
  const assumed = {
    ...resolvedUse,
    verdict: "unknown",
    deployment: "configured",
    place: {
      ...resolvedUse.place,
      environment: "staging",
      deploymentBasis: "assumed_not_deployed",
      deploymentDetail: assumption,
    },
  };
  const expected = {
    id: "job-assumption",
    verdict: "unknown",
    environment: "staging",
    deploymentBasis: "assumed_not_deployed",
  } as const;
  assert.equal(
    gradePlaceV2(assumed, { assumptions: [assumption] }, expected, true).pass,
    true,
  );
  assert.equal(gradePlaceV2(assumed, {}, expected, true).verdictCorrect, false);
  assert.equal(
    gradePlaceV2(
      { ...assumed, verdict: "ruled_out" },
      { assumptions: [assumption] },
      { ...expected, verdict: "ruled_out" },
      true,
    ).verdictCorrect,
    false,
  );
  const fixtureData = await fixture(t);
  const grade = await gradeCommandCase(
    {
      cve: fixtureData.expected.cve,
      schemaVersion: 2,
      uses: [fixtureData.use, assumed],
      searches: [sourceSearch],
    },
    fixtureData.expected,
    fixtureData.root,
  );
  assert.equal(grade.pass, true);
  assert.equal(grade.rubric, "places-v2");
});

const sourceSearch = {
  source: "Checkout trace graph",
  tool: "trace_codex_security_code",
  scope: ["package=libwebp", 'files=["service.js"]'],
  startedAt: "2026-01-01T02:00:59Z",
  finishedAt: "2026-01-01T02:01:00Z",
  result: "matches",
  completeness: "partial",
  details: ["One source batch timed out"],
  evidenceReferences: ["rule-fixture"],
};

test("places v2 discovery needs identified source or a matching original receipt, not a title", async (t) => {
  const { root, expected, use, version } = await fixture(t);
  const row = {
    id: "named-service",
    location: use.location,
    verdict: "ruled_out",
    identityEvidence: [expected.evidenceGroups[0]!],
  } satisfies PlaceScopeExpectation;
  const titleOnly = { ...use, evidence: [version] };
  const report = {
    cve: expected.cve,
    schemaVersion: 2,
    uses: [titleOnly],
    searches: [sourceSearch],
  };
  const grade = await gradeCommandCase(
    report,
    { ...expected, expectedPlacesV2: [row] },
    root,
  );
  assert.equal(grade.rubric, "places-v2");
  assert.equal(grade.discoveryCorrect, false);
  assert.equal(grade.verdictCorrect, false);
  assert.equal(grade.placeGrades[0]?.verdictLabelCorrect, true);
  assert.equal(
    (
      await gradeCommandCase(
        { ...report, uses: [use] },
        { ...expected, expectedPlacesV2: [row] },
        root,
      )
    ).pass,
    true,
  );

  const wrong = recorded({
    ...matchingSearch,
    scope: ["environment=production", "run_id=run-2"],
  });
  assert.equal(
    gradePlaceV2(resolvedUse, wrong, resolvedPlace).receiptCorrect,
    false,
  );
  const partialZero = recorded({
    ...matchingSearch,
    completeness: "partial",
    result: "no_match",
  });
  assert.equal(
    gradePlaceV2(resolvedUse, partialZero, resolvedPlace).discoveryCorrect,
    false,
  );
  const claimedAbsence = {
    ...resolvedUse,
    verdict: "ruled_out",
    deployment: "unknown",
    place: { ...resolvedUse.place, deploymentBasis: "unknown" },
  };
  assert.equal(
    gradePlaceV2(
      claimedAbsence,
      partialZero,
      { ...unresolvedPlace, verdict: "ruled_out", needsDecidingGap: false },
      true,
    ).verdictCorrect,
    false,
  );
});

test("places v2 gives each reported assessment to at most one independently identified place", async (t) => {
  const { root, expected, use, control } = await fixture(t);
  const second = { path: "second.js", startLine: 1, endLine: 1 };
  await writeFile(join(root, second.path), "fixedSecond();\n");
  const sharedUse = { ...use, evidence: [...use.evidence, second] };
  const secondOnly = { ...use, location: "separate copy", evidence: [second] };
  const both = [
    {
      id: "first",
      verdict: "ruled_out",
      identityEvidence: [[{ path: control.path, contains: "fixedInput();" }]],
    },
    {
      id: "second",
      verdict: "ruled_out",
      identityEvidence: [[{ path: second.path, contains: "fixedSecond();" }]],
      evidenceGroups: [[{ path: second.path, contains: "fixedSecond();" }]],
    },
  ] satisfies PlaceScopeExpectation[];
  const report = {
    cve: expected.cve,
    schemaVersion: 2,
    uses: [sharedUse],
    searches: [sourceSearch],
  };
  const withBoth = { ...expected, expectedPlacesV2: both };
  const grade = await gradeCommandCase(report, withBoth, root);
  assert.equal(grade.pass, false);
  assert.equal(grade.rubric, "places-v2");
  assert.equal(
    grade.placeGrades.filter((place) => place.discoveryCorrect).length,
    1,
  );
  assert.equal(
    (
      await gradeCommandCase(
        { ...report, uses: [sharedUse, secondOnly] },
        withBoth,
        root,
      )
    ).pass,
    true,
  );
});

test("places v2 checks run-wide source coverage and exact lookup audit without inventing lookup measurements", () => {
  const packageMatches = (name: unknown) => name === "libwebp";
  const trace = { searches: [sourceSearch] };
  const valid = gradeRunSearchAudit(trace, packageMatches, []);
  assert.equal(valid.sourceAuditCorrect, true);
  assert.equal(valid.sourceTraceResult, "partial");
  assert.equal(valid.lookupCompleteness, "not_measurable");
  assert.equal(
    gradeRunSearchAudit(trace, packageMatches, [], true).lookupCompleteness,
    "not_measurable",
  );
  assert.equal(
    gradeRunSearchAudit({ searches: [] }, packageMatches, [])
      .sourceAuditCorrect,
    false,
  );
  assert.equal(
    gradeRunSearchAudit(
      { searches: [{ ...sourceSearch, scope: ["package=unrelated"] }] },
      packageMatches,
      [],
    ).sourceAuditCorrect,
    false,
  );
  assert.equal(
    gradeRunSearchAudit(
      { searches: [{ ...sourceSearch, startedAt: "later" }] },
      packageMatches,
      [],
    ).sourceAuditCorrect,
    false,
  );
  assert.equal(
    gradeRunSearchAudit(trace, packageMatches, [partialSearch], true)
      .lookupCompleteness,
    "mismatch",
  );
  const searched = {
    searches: [sourceSearch, ...recorded(partialSearch).searches],
  };
  assert.equal(
    gradeRunSearchAudit(searched, packageMatches, [partialSearch], true)
      .lookupCompleteness,
    "verified",
  );
  assert.equal(
    gradeRunSearchAudit(
      searched,
      packageMatches,
      [{ ...partialSearch, evidenceReference: "different-original" }],
      true,
    ).lookupCompleteness,
    "mismatch",
  );
});

test("grades an explicit report status separately from a correct target use", async (t) => {
  const { root, expected, answer, use } = await fixture(t);
  const report = {
    ...answer,
    status: "unknown",
    uses: [
      use,
      {
        ...use,
        location: "Separate library caller",
        verdict: "unknown",
        reason: "This separate caller's selected implementation is unresolved.",
      },
    ],
  };
  const scoped = { ...expected, commandStatus: "ruled_out" as const };
  const grade = await gradeCommandCase(report, scoped, root);
  assert.equal(grade.rubric, "legacy-aggregate-v1");
  assert.equal(grade.verdictCorrect, true);
  assert.equal(grade.evidenceCorrect, true);
  assert.equal(grade.statusCorrect, false);
  assert.equal(grade.overallCorrect, false);
  assert.equal(grade.pass, false);
  assert.match(grade.errors.join("\n"), /Expected report status ruled_out/u);
  assert.equal((await gradeCommandCase(answer, scoped, root)).pass, true);
  assert.equal((await gradeCommandCase(report, expected, root)).pass, true);
  assert.equal(
    (
      await gradeCommandCase(
        report,
        { ...expected, commandStatus: "unknown" },
        root,
      )
    ).pass,
    true,
  );
});

test("checks source ranges in the checkout without borrowing evidence from another use", async (t) => {
  const { root, expected, answer, use, version, control } = await fixture(t);
  for (const uses of [
    [
      { ...use, evidence: [control] },
      { ...use, location: "sibling", evidence: [version] },
    ],
    [
      { ...use, version: "1.3.2" },
      { ...use, evidence: [control] },
    ],
    [
      {
        ...use,
        evidence: [
          version,
          { ...control, startLine: 2, endLine: 2, code: "fixedInput();" },
        ],
      },
    ],
    [{ ...use, evidence: [version, { ...control, endLine: 3 }] }],
    [
      {
        ...use,
        evidence: [version, control, { ...control, path: "../service.js" }],
      },
    ],
  ]) {
    assert.equal(
      (await gradeCommandCase({ ...answer, uses }, expected, root)).pass,
      false,
    );
  }
});

test("an unresolved caller can report the known version but cannot be ruled out overall", async (t) => {
  const { root, expected, answer, use } = await fixture(t);
  const unresolved = { ...expected, verdict: "unknown" as const };
  const uses = [{ ...use, verdict: "unknown", version: expected.version }];
  assert.equal(
    (
      await gradeCommandCase(
        { ...answer, status: "unknown", uses },
        unresolved,
        root,
      )
    ).pass,
    true,
  );
  assert.equal(
    (await gradeCommandCase({ ...answer, uses }, unresolved, root)).pass,
    false,
  );
});

test("separates a correct verdict and version from missing route evidence", async (t) => {
  const { root, expected, answer, use, version } = await fixture(t);
  const grade = await gradeCommandCase(
    { ...answer, uses: [{ ...use, evidence: [version] }] },
    expected,
    root,
  );
  assert.equal(grade.pass, false);
  assert.equal(grade.componentCorrect, true);
  assert.equal(grade.verdictCorrect, true);
  assert.equal(grade.versionCorrect, true);
  assert.equal(grade.evidenceCorrect, false);
  assert.match(grade.errors.join("\n"), /service\.js \(fixedInput\(\);\)/u);
});

test("an unbound runtime declaration leaves the native copy unresolved while its source exclusion is decidable", async (t) => {
  const expected = cases.find(({ id }) => id === "native-charset");
  assert.ok(expected);
  const root = await mkdtemp(join(tmpdir(), "native-version-grader-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "service"));
  await mkdir(join(root, "lib"));
  const sources = new Map<string, string>();
  for (const destination of ["service/deploy.json", "service/runtime.json"]) {
    const staged: StageFile | undefined = expected.stage.find(
      (file) => file.destination === destination,
    );
    assert.ok(staged?.kind === "json");
    sources.set(destination, JSON.stringify(staged.value, null, 2));
  }
  sources.set(
    "service/parse.cjs",
    await readFile(
      new URL("fixtures/mail-service/parse.cjs", import.meta.url),
      "utf8",
    ),
  );
  sources.set(
    "lib/mail-parser.js",
    "function IconvDecoder(Iconv, charset) {\n" +
      "  this.stream = new Iconv(charset, 'UTF-8//TRANSLIT//IGNORE');\n" +
      "}\n",
  );
  for (const [path, source] of sources)
    await writeFile(join(root, path), source);
  const evidence = [...sources].map(([path, source]) => ({
    path,
    startLine: 1,
    endLine: source.trimEnd().split("\n").length,
  }));
  const use = {
    component: "glibc",
    location: "Configured POST /inbox body conversion",
    version: null,
    verdict: "ruled_out",
    deployment: "configured",
    reason:
      "runtime.json declares glibc 2.39 but does not identify the selected native copy. The local output is fixed to UTF-8, excluding conversion to ISO-2022-CN-EXT independently of that unresolved version.",
    evidence,
  };
  const answer = { cve: expected.cve, status: "ruled_out", uses: [use] };
  const grade = await gradeCommandCase(answer, expected, root);
  assert.equal(grade.pass, true);
  assert.equal(grade.versionCorrect, true);
  assert.equal(grade.evidenceCorrect, true);

  const claimedInstalled = await gradeCommandCase(
    {
      ...answer,
      uses: [
        { ...use, version: "2.39", reason: "The selected copy is glibc 2.39." },
      ],
    },
    expected,
    root,
  );
  assert.equal(claimedInstalled.pass, false);
  assert.equal(claimedInstalled.versionCorrect, false);
  assert.equal(claimedInstalled.verdictCorrect, true);
  assert.equal(claimedInstalled.evidenceCorrect, true);

  const missingDeclaration = await gradeCommandCase(
    {
      ...answer,
      uses: [
        {
          ...use,
          evidence: evidence.filter(
            ({ path }) => path !== "service/runtime.json",
          ),
        },
      ],
    },
    expected,
    root,
  );
  assert.equal(missingDeclaration.pass, true);
  assert.equal(missingDeclaration.versionCorrect, true);
  assert.equal(missingDeclaration.evidenceCorrect, true);

  const missingDestination = await gradeCommandCase(
    {
      ...answer,
      uses: [
        {
          ...use,
          evidence: evidence.filter(
            ({ path }) => path !== "lib/mail-parser.js",
          ),
        },
      ],
    },
    expected,
    root,
  );
  assert.equal(missingDestination.pass, false);
  assert.equal(missingDestination.versionCorrect, true);
  assert.equal(missingDestination.verdictCorrect, true);
  assert.equal(missingDestination.evidenceCorrect, false);
  assert.match(
    missingDestination.errors.join("\n"),
    /Missing source evidence: lib\/mail-parser\.js/u,
  );
});

test("a known selected copy still requires its resolved version even when the use is ruled out", async (t) => {
  const { root, expected, answer, use } = await fixture(t);
  assert.equal((await gradeCommandCase(answer, expected, root)).pass, true);
  const unresolved = await gradeCommandCase(
    { ...answer, uses: [{ ...use, version: null }] },
    expected,
    root,
  );
  assert.equal(unresolved.pass, false);
  assert.equal(unresolved.versionCorrect, false);
  assert.equal(unresolved.evidenceCorrect, true);
  assert.equal(unresolved.verdictCorrect, true);
});

test("the bounded task case requires the normal operation and its own build, producer and input proof", async (t) => {
  const expected = cases.find(({ id }) => id === "task-parameter");
  assert.ok(expected);
  assert.ok(expected.commandCallSite);
  const root = await mkdtemp(join(tmpdir(), "task-selection-grader-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const sources = new Map<string, Set<string>>();
  for (const group of expected.evidenceGroups) {
    for (const { path, contains } of group) {
      assert.ok(contains);
      const chunks = sources.get(path) ?? new Set<string>();
      chunks.add(contains);
      sources.set(path, chunks);
    }
  }
  const evidence: { path: string; startLine: number; endLine: number }[] = [];
  for (const [path, chunks] of sources) {
    let source = [...chunks].join("\n") + "\n";
    if (path === expected.commandCallSite.path) {
      const lines = Array.from({ length: 170 }, () => "");
      lines[71] = "return env.renderString(str, JSON.parse(values));";
      lines[156] = "vm.run(mkScript(nunjucksSource));";
      lines[162] = "vm.setGlobal('templateStr', template);";
      lines[163] = "vm.setGlobal('templateValues', JSON.stringify(values));";
      lines[169] = "return vm.run(`render(templateStr, templateValues)`);";
      source = lines.join("\n") + "\n";
    }
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), source);
    evidence.push({
      path,
      startLine: 1,
      endLine: source.trimEnd().split("\n").length,
    });
  }
  await writeFile(
    join(root, "portal/portal.conf"),
    await readFile(new URL("fixtures/backstage/portal.conf", import.meta.url)),
  );
  const use = {
    location: "The scoped task's fixed-template rendering",
    component: "vm2",
    version: "3.9.19",
    verdict: "ruled_out",
    deployment: "configured",
    reason:
      "The selected build keeps the request name as data in the registered fixed template.",
    evidence,
    proof: {
      sink: { function: "VM.run", callSite: expected.commandCallSite },
      conditions: [],
    },
  };
  const answer = { cve: expected.cve, status: "ruled_out", uses: [use] };
  assert.equal((await gradeCommandCase(answer, expected, root)).pass, true);
  assert.equal(
    evidence.some(({ path }) => path === "portal/portal.conf"),
    false,
  );
  assert.equal(
    expected.evidenceGroups
      .flat()
      .some(({ contains }) => contains?.includes(":memory:")),
    false,
  );
  for (const line of [157, 163, 171]) {
    const otherOperation = {
      ...use,
      location: `Separate setup or data call at ${line}`,
      proof: {
        ...use.proof,
        sink: {
          function: line === 163 ? "VM.setGlobal" : "VM.run",
          callSite: { ...expected.commandCallSite, line },
        },
      },
    };
    const grade = await gradeCommandCase(
      { ...answer, uses: [otherOperation] },
      expected,
      root,
    );
    assert.equal(grade.pass, false);
    assert.equal(grade.componentCorrect, true);
    assert.equal(grade.versionCorrect, true);
    assert.equal(grade.verdictCorrect, true);
    assert.equal(grade.evidenceCorrect, true);
    assert.equal(grade.operationCorrect, false);
    assert.match(
      grade.errors.join("\n"),
      /Missing assessment of required operation/u,
    );
  }
  const unbound = await gradeCommandCase(
    { ...answer, uses: [{ ...use, proof: undefined }] },
    expected,
    root,
  );
  assert.equal(unbound.pass, false);
  assert.equal(unbound.operationCorrect, false);

  for (const missing of [
    "packages/backend/package.json",
    "packages/backend/Dockerfile",
    "portal/compose.yaml",
    "portal/template.yaml",
    "plugins/scaffolder-backend/src/service/router.ts",
    "plugins/scaffolder-backend/src/scaffolder/tasks/NunjucksWorkflowRunner.ts",
    "plugins/scaffolder-backend/src/scaffolder/actions/builtin/fetch/template.ts",
    "packages/create-app/templates/default-app/examples/template/content/index.js",
  ]) {
    assert.ok(
      evidence.some(({ path }) => path === missing),
      missing,
    );
    const primary = {
      ...use,
      evidence: evidence.filter(({ path }) => path !== missing),
    };
    const grade = await gradeCommandCase(
      { ...answer, uses: [primary] },
      expected,
      root,
    );
    assert.equal(grade.pass, false, missing);
    assert.equal(grade.evidenceCorrect, false, missing);
    assert.equal(grade.versionCorrect, true, missing);
    assert.match(grade.errors.join("\n"), /Missing source evidence/u);
    const sibling = {
      ...use,
      location: "Separate bootstrap use",
      evidence: evidence.filter(({ path }) => path === missing),
    };
    assert.equal(
      (
        await gradeCommandCase(
          { ...answer, uses: [primary, sibling] },
          expected,
          root,
        )
      ).pass,
      false,
      `cannot borrow ${missing}`,
    );
  }
  const bootstrap = {
    ...use,
    location: "Separate bootstrap",
    proof: {
      ...use.proof,
      sink: {
        function: "VM.run",
        callSite: { ...expected.commandCallSite, line: 157 },
      },
    },
  };
  const missingProducer = {
    ...use,
    evidence: evidence.filter(({ path }) => path !== "portal/template.yaml"),
  };
  const targeted = await gradeCommandCase(
    { ...answer, uses: [bootstrap, missingProducer] },
    expected,
    root,
  );
  assert.equal(targeted.pass, false);
  assert.equal(targeted.location, use.location);
  assert.equal(targeted.operationCorrect, true);
  assert.equal(targeted.evidenceCorrect, false);
  const templater = join(root, expected.commandCallSite.path);
  const original = await readFile(templater, "utf8");
  for (const changed of [
    original.replace("JSON.stringify(values)", "values"),
    original.replace(
      "vm.run(`render(templateStr, templateValues)`)",
      "vm.run(templateValues)",
    ),
  ]) {
    assert.notEqual(changed, original);
    await writeFile(templater, changed);
    const grade = await gradeCommandCase(answer, expected, root);
    assert.equal(grade.pass, false);
    assert.equal(grade.operationCorrect, true);
    assert.equal(grade.evidenceCorrect, false);
    assert.equal(grade.versionCorrect, true);
  }
  await writeFile(templater, original);
  for (const version of [null, "3.9.20"]) {
    const grade = await gradeCommandCase(
      { ...answer, uses: [{ ...use, version }] },
      expected,
      root,
    );
    assert.equal(grade.pass, false);
    assert.equal(grade.versionCorrect, false);
    assert.equal(grade.evidenceCorrect, true);
  }
});

async function mimeCopyFixture(
  t: TestContext,
  caseId = "archive-worker-mime-parts",
) {
  const expected = cases.find(({ id }) => id === caseId);
  assert.ok(expected);
  const root = await mkdtemp(join(tmpdir(), "mime-copy-grader-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const chunks = new Map<string, Set<string>>();
  for (const group of expected.evidenceGroups) {
    for (const { path, contains } of group) {
      assert.ok(contains);
      const values = chunks.get(path) ?? new Set<string>();
      values.add(contains);
      chunks.set(path, values);
    }
  }
  const evidence: { path: string; startLine: number; endLine: number }[] = [];
  for (const [path, values] of chunks) {
    const source = [...values].join("\n") + "\n";
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), source);
    evidence.push({
      path,
      startLine: 1,
      endLine: source.trimEnd().split("\n").length,
    });
  }
  const use = {
    component: "nodemailer",
    version: "7.0.10",
    verdict: expected.verdict,
    deployment: "configured",
    location: "Configured multipart-header worker",
    reason:
      "The selected install and imports bind this configured worker control.",
    evidence,
  };
  return {
    root,
    expected,
    use,
    answer: { cve: expected.cve, status: use.verdict, uses: [use] },
  };
}

test("an unmounted route needs its own pre-parser guard, not a selected image version", async (t) => {
  const expected = cases.find(({ id }) => id === "unmounted-route");
  assert.ok(expected);
  const root = await mkdtemp(join(tmpdir(), "unmounted-route-grader-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const sources = new Map<string, string>();
  for (const destination of ["service/deploy.json", "service/server.cjs"]) {
    const staged: StageFile | undefined = expected.stage.find(
      (file) => file.destination === destination,
    );
    assert.ok(staged && staged.kind !== "git");
    const source =
      staged.kind === "json"
        ? JSON.stringify(staged.value, null, 2)
        : await readFile(new URL(staged.source, import.meta.url), "utf8");
    sources.set(destination, source);
    await mkdir(dirname(join(root, destination)), { recursive: true });
    await writeFile(join(root, destination), source);
  }
  const evidence = [...sources].map(([path, source]) => ({
    path,
    startLine: 1,
    endLine: source.trimEnd().split("\n").length,
  }));
  const use = {
    component: "linkify-it",
    version: null,
    verdict: "ruled_out",
    deployment: "configured",
    location: "Configured POST /inbox returns before body and parser work",
    reason:
      "The configured route map is empty and its guard returns 404 first.",
    evidence,
  };
  const answer = { cve: expected.cve, status: use.verdict, uses: [use] };
  for (const version of [null, "5.0.0"]) {
    const grade = await gradeCommandCase(
      { ...answer, uses: [{ ...use, version }] },
      expected,
      root,
    );
    assert.equal(grade.pass, true);
    assert.equal(grade.versionCorrect, true);
  }
  const incorrect = await gradeCommandCase(
    { ...answer, uses: [{ ...use, version: "5.0.1" }] },
    expected,
    root,
  );
  assert.equal(incorrect.pass, false);
  assert.equal(incorrect.verdictCorrect, true);
  assert.equal(incorrect.evidenceCorrect, true);
  assert.equal(incorrect.versionCorrect, false);
  for (const group of expected.evidenceGroups) {
    assert.equal(group.length, 1);
    const anchor = group[0]!;
    const source = sources.get(anchor.path);
    assert.ok(source && anchor.contains && source.includes(anchor.contains));
    // Remove just the deciding text from real staged source, keeping line bounds.
    await writeFile(
      join(root, anchor.path),
      source.replace(anchor.contains, anchor.contains.replace(/[^\n]/gu, " ")),
    );
    const grade = await gradeCommandCase(answer, expected, root);
    assert.equal(grade.pass, false);
    assert.equal(grade.evidenceCorrect, false);
    assert.equal(grade.versionCorrect, true);
    await writeFile(join(root, anchor.path), source);
  }
  const split = evidence.map((citation) => ({ ...use, evidence: [citation] }));
  assert.equal(
    (await gradeCommandCase({ ...answer, uses: split }, expected, root)).pass,
    false,
  );
});

for (const caseId of [
  "archive-worker-mime-parts",
  "archive-worker-pinned-original",
  "archive-worker-pinned-normalized",
]) {
  test(`${caseId} copy accepts installed metadata or the selected lock, install and source chain`, async (t) => {
    const { root, expected, use, answer } = await mimeCopyFixture(t, caseId);
    assert.equal((await gradeCommandCase(answer, expected, root)).pass, true);
    const selected = {
      ...use,
      evidence: use.evidence.filter(
        ({ path }) => path !== "node_modules/nodemailer/package.json",
      ),
    };
    assert.equal(
      (await gradeCommandCase({ ...answer, uses: [selected] }, expected, root))
        .pass,
      true,
    );
    const legacy = {
      ...use,
      evidence: use.evidence.filter(
        ({ path }) => path !== "index.js" && path !== "lib/simple-parser.js",
      ),
    };
    assert.equal(
      (await gradeCommandCase({ ...answer, uses: [legacy] }, expected, root))
        .pass,
      true,
    );
  });

  test(`${caseId} copy rejects wrong identity, missing links and sibling-only proof`, async (t) => {
    const { root, expected, use, answer } = await mimeCopyFixture(t, caseId);
    const selected = {
      ...use,
      evidence: use.evidence.filter(
        ({ path }) => path !== "node_modules/nodemailer/package.json",
      ),
    };
    for (const invalid of [
      { ...selected, component: "another-parser" },
      { ...selected, version: "7.0.11" },
      { ...selected, version: null },
    ]) {
      assert.equal(
        (await gradeCommandCase({ ...answer, uses: [invalid] }, expected, root))
          .pass,
        false,
      );
    }
    for (const missing of [
      "deploy/compose.yaml",
      "deploy/Dockerfile",
      "package-lock.json",
      "archive/stack.json",
      "archive/ingest.py",
      "archive/importer.py",
      "archive/index-mail.cjs",
      "index.js",
      "lib/simple-parser.js",
      "lib/mail-parser.js",
      ...(expected.verdict === "potentially_exploitable"
        ? ["node_modules/nodemailer/lib/addressparser/index.js"]
        : []),
    ]) {
      const primary = {
        ...selected,
        evidence: selected.evidence.filter(({ path }) => path !== missing),
      };
      const sibling = {
        ...selected,
        location: "Another parser use",
        evidence: selected.evidence.filter(({ path }) => path === missing),
      };
      const grade = await gradeCommandCase(
        { ...answer, uses: [primary, sibling] },
        expected,
        root,
      );
      assert.equal(grade.pass, false, `cannot borrow ${missing}`);
      assert.equal(grade.evidenceCorrect, false, missing);
    }
    const lockPath = join(root, "package-lock.json");
    const lock = await readFile(lockPath, "utf8");
    for (const changed of [
      lock.replace(
        '"node_modules/nodemailer": {',
        '"node_modules/another-parser": {',
      ),
      lock.replace('"version": "7.0.10"', '"version": "7.0.11"'),
      lock.replace('"integrity": "sha512-Us/Se1', '"integrity": "sha512-Other'),
    ]) {
      assert.notEqual(changed, lock);
      await writeFile(lockPath, changed);
      const grade = await gradeCommandCase(
        { ...answer, uses: [selected] },
        expected,
        root,
      );
      assert.equal(grade.pass, false);
      assert.equal(grade.versionCorrect, true);
      assert.equal(grade.evidenceCorrect, false);
    }
    await writeFile(lockPath, lock);
  });
}

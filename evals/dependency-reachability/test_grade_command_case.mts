import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { gradeCommandCase } from "./grade-command-case.mts";

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
    verdict: "exploitable",
    reason: "The library passes input to the decoder.",
    evidence: [version, { path: "service.js", startLine: 2, endLine: 2 }],
  };
  const mixed = { ...answer, status: "exploitable", uses: [library, use] };
  const grade = await gradeCommandCase(mixed, expected, root);
  assert.equal(grade.pass, true);
  assert.equal(grade.location, use.location);
  assert.equal((await gradeCommandCase(answer, expected, root)).pass, true);
  assert.equal(
    (await gradeCommandCase({ ...mixed, uses: [library] }, expected, root))
      .pass,
    false,
  );
});

test("requires matching advisory, component, version and use verdict in a positive report", async (t) => {
  const { root, expected, answer, use } = await fixture(t);
  const positive = { ...expected, verdict: "exploitable" as const };
  const subject = { ...use, verdict: "exploitable", version: expected.version };
  const valid = { ...answer, status: "exploitable", uses: [subject] };
  assert.equal((await gradeCommandCase(valid, positive, root)).pass, true);
  for (const invalid of [
    { ...valid, cve: "CVE-2023-0000" },
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

import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { gradeAnswer, type ReachabilityAnswer } from "./grade.mts";

async function fixture(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), "reachability-grader-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const root = join(directory, "source");
  await mkdir(root);
  await writeFile(
    join(root, "worker.js"),
    "const limit = 50;\r\nif (depth > limit) return [];\r\nparse(input);\r\n",
  );
  await writeFile(join(root, "version.txt"), "1.2.3\n");
  await writeFile(join(root, "deployed.txt"), "library = 1.2.3\n");
  const expected = {
    verdict: "ruled_out" as const,
    version: "1.2.3",
    evidenceGroups: [
      [{ path: "worker.js", contains: "depth > limit" }],
      [{ path: "version.txt" }, { path: "deployed.txt", contains: "1.2.3" }],
    ],
  };
  const answer: ReachabilityAnswer = {
    verdict: "ruled_out",
    dependency_version: "1.2.3",
    reason:
      "The installed code bounds recursion despite its unchanged version.",
    evidence: [
      {
        path: "worker.js",
        startLine: 1,
        endLine: 2,
        code: "const limit = 50;\nif (depth > limit) return [];\n",
      },
      { path: "version.txt", startLine: 1, endLine: 1, code: "1.2.3" },
    ],
  };
  return { directory, root, expected, answer };
}

test("accepts exact multi-line evidence with different line endings and alternative version evidence", async (t) => {
  const { root, expected, answer } = await fixture(t);
  assert.equal((await gradeAnswer(answer, expected, root)).pass, true);
  answer.evidence[1] = {
    path: "./deployed.txt",
    startLine: 1,
    endLine: 1,
    code: "library = 1.2.3",
  };
  assert.equal((await gradeAnswer(answer, expected, root)).pass, true);
});

test("an authentic citation from the right file must identify the deciding operation", async (t) => {
  const { root, expected, answer } = await fixture(t);
  answer.evidence[0] = {
    path: "worker.js",
    startLine: 3,
    endLine: 3,
    code: "parse(input);",
  };
  const grade = await gradeAnswer(answer, expected, root);
  assert.equal(grade.verdictCorrect, true);
  assert.equal(grade.versionCorrect, true);
  assert.equal(grade.evidenceCorrect, false);
  assert.equal(grade.pass, false);
  assert.match(grade.errors.join("\n"), /depth > limit/u);
});

test("rejects a fabricated quote, an invented file, and a correct quote at the wrong lines", async (t) => {
  const { root, expected, answer } = await fixture(t);
  for (const extra of [
    { path: "worker.js", startLine: 3, endLine: 3, code: "parse(sanitized);" },
    { path: "missing.js", startLine: 1, endLine: 1, code: "real();" },
    { path: "worker.js", startLine: 5, endLine: 5, code: "parse(input);" },
    { path: "worker.js", startLine: 1, endLine: 2, code: "const limit = 50;" },
  ]) {
    const result = await gradeAnswer(
      { ...answer, evidence: [...answer.evidence, extra] },
      expected,
      root,
    );
    assert.equal(result.evidenceCorrect, false, JSON.stringify(extra));
    assert.equal(result.pass, false);
  }
});

test("reports wrong version and verdict separately from source evidence", async (t) => {
  const { root, expected, answer } = await fixture(t);
  const result = await gradeAnswer(
    { ...answer, verdict: "unknown", dependency_version: "1.3.0" },
    expected,
    root,
  );
  assert.equal(result.evidenceCorrect, true);
  assert.equal(result.versionCorrect, false);
  assert.equal(result.verdictCorrect, false);
  assert.equal(result.pass, false);
  assert.equal(
    (await gradeAnswer({ ...answer, reason: " " }, expected, root)).pass,
    false,
  );
  assert.equal(
    (
      await gradeAnswer(
        { ...answer, evidence: ["worker.js", "version.txt"] },
        expected,
        root,
      )
    ).pass,
    false,
  );
});

test("the grader never follows a citation outside the staged checkout", async (t) => {
  const { root, directory, expected, answer } = await fixture(t);
  const external = join(directory, "external");
  await mkdir(external);
  await writeFile(join(external, "marker"), "outside\n");
  await symlink(external, join(root, "linked"), "junction");
  for (const path of [
    "../external/marker",
    "linked/marker",
    join(external, "marker"),
    "C:\\outside\\marker",
  ]) {
    const extra = { path, startLine: 1, endLine: 1, code: "outside" };
    const result = await gradeAnswer(
      { ...answer, evidence: [...answer.evidence, extra] },
      expected,
      root,
    );
    assert.equal(result.evidenceCorrect, false, path);
  }
});

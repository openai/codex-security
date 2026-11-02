import assert from "node:assert/strict";
import test from "node:test";
import { cve, gradeCommand, readFixture } from "./command.mts";

const { files } = await readFixture();
const cite = (path: string, startLine: number, endLine = startLine) => ({
  path,
  startLine,
  endLine,
});
const image = cite("Dockerfile", 4, 8);
const notes = {
  location: "notes",
  component: "linkify-it",
  version: "5.0.0",
  verdict: "exploitable",
  deployment: "configured",
  reason: "The HTTP handler passes submitted text to the affected version.",
  evidence: [
    cite("notes/package-lock.json", 13),
    cite("compose.yaml", 5),
    image,
    cite("server.mjs", 12),
  ],
};
const reviews = {
  location: "reviews",
  component: "linkify-it",
  version: "5.0.1",
  verdict: "ruled_out",
  deployment: "configured",
  reason: "The service lockfile resolves the fixed version.",
  evidence: [
    cite("reviews/package-lock.json", 13),
    cite("compose.yaml", 10),
    image,
  ],
};
const result = { cve, status: "exploitable", uses: [reviews, notes] };

test("requires an independent grounded verdict for both configured services", () => {
  assert.equal(gradeCommand(result, files).pass, true);
  for (const uses of [
    [notes],
    [notes, notes],
    [notes, { ...reviews, verdict: "exploitable" }],
    [notes, { ...reviews, deployment: "confirmed" }],
    [{ ...notes, evidence: reviews.evidence }, reviews],
    [
      {
        ...notes,
        evidence: notes.evidence.filter((e) => e.path !== "server.mjs"),
      },
      reviews,
    ],
  ]) {
    assert.equal(gradeCommand({ ...result, uses }, files).pass, false);
  }
});

test("requires the build link between the service lockfile and the running application", () => {
  const withoutImage = reviews.evidence.filter((e) => e.path !== "Dockerfile");
  for (const evidence of [
    withoutImage,
    [...withoutImage, cite("Dockerfile", 4, 5)],
    [...withoutImage, cite("Dockerfile", 8)],
  ]) {
    const grade = gradeCommand(
      { ...result, uses: [notes, { ...reviews, evidence }] },
      files,
    );
    assert.equal(grade.pass, false);
    assert.equal(grade.uses.find((use) => use.service === "notes")?.pass, true);
  }
});

test("every citation must select lines inside the graded checkout", () => {
  for (const citation of [
    cite("../answer.json", 1),
    cite("server.mjs", 0),
    cite("server.mjs", 420),
  ]) {
    const uses = [
      notes,
      { ...reviews, evidence: [...reviews.evidence, citation] },
    ];
    assert.equal(gradeCommand({ ...result, uses }, files).pass, false);
  }
});

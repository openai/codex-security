import { expect, test } from "bun:test";
import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { validateDependencyAssessment } from "../src/dependency-reachability.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

type Verdict = "exploitable" | "unknown" | "ruled_out";
const citation = { path: "service.ts", startLine: 1, endLine: 2 };

function assessment(status: Verdict, verdicts: Verdict[]) {
  return {
    status,
    uses: verdicts.map((verdict, index) => ({
      location: `service-${index}`,
      component: "example",
      version: null,
      verdict,
      deployment: "unknown" as const,
      reason: "Fixture assessment.",
      evidence: [citation],
    })),
    limitations: [],
  };
}

test("reconciles the checkout verdict with cited service verdicts and preserves incomplete coverage", async () => {
  await using repo = await scopedTemporaryDirectory("cve-verdict-");
  await writeFile(join(repo.path, citation.path), "first\nsecond");
  const cases: [Verdict, Verdict[], Verdict][] = [
    ["ruled_out", ["ruled_out", "exploitable", "unknown"], "exploitable"],
    ["ruled_out", ["ruled_out", "unknown"], "unknown"],
    ["ruled_out", ["ruled_out"], "ruled_out"],
    ["unknown", ["ruled_out"], "unknown"],
    ["exploitable", ["ruled_out"], "unknown"],
    ["ruled_out", [], "unknown"],
    ["exploitable", [], "unknown"],
  ];
  for (const [status, verdicts, expected] of cases) {
    const report = assessment(status, verdicts);
    expect(await validateDependencyAssessment(report, repo.path)).toEqual({
      ...report,
      status: expected,
    });
  }
});

test("requires each range to reference existing lines in a regular checkout file", async () => {
  await using temp = await scopedTemporaryDirectory("cve-citation-");
  const repo = join(temp.path, "repo");
  const outside = join(temp.path, "outside");
  await mkdir(repo);
  await mkdir(join(repo, "src"));
  await mkdir(outside);
  await writeFile(join(repo, citation.path), "first\r\nsecond\r\n");
  await writeFile(join(repo, "empty"), "");
  await writeFile(join(outside, citation.path), "outside\ntext");
  await symlink(outside, join(repo, "link"), "junction");
  const valid = assessment("ruled_out", ["ruled_out"]);
  expect(await validateDependencyAssessment(valid, repo)).toEqual(valid);
  for (const invalid of [
    { ...citation, path: "missing.ts" },
    { ...citation, path: "src" },
    { ...citation, path: "empty", endLine: 1 },
    { ...citation, startLine: 2, endLine: 1 },
    { ...citation, endLine: 3 },
    { ...citation, path: join(outside, citation.path) },
    { ...citation, path: "../outside/service.ts" },
    { ...citation, path: "C:\\outside\\service.ts" },
    { ...citation, path: "link/service.ts" },
  ]) {
    const report = assessment("ruled_out", ["ruled_out"]);
    report.uses[0]!.evidence.push(invalid);
    await expect(validateDependencyAssessment(report, repo)).rejects.toThrow();
  }
});

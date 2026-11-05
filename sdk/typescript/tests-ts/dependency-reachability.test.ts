import { expect, test } from "bun:test";
import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";
import {
  dependencyAssessmentSchema,
  validateDependencyAssessment,
} from "../src/dependency-reachability.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

type Assessment = z.output<typeof dependencyAssessmentSchema>;
type Verdict = Assessment["status"];
const citation = { path: "service.ts", startLine: 1, endLine: 2, supports: [] };

function assessment(status: Verdict, verdicts: Verdict[]): Assessment {
  return {
    status,
    uses: verdicts.map((verdict, index) => ({
      location: `service-${index}`,
      component: "example",
      version: null,
      verdict,
      deployment: verdict === "exploitable" ? "confirmed" : "unknown",
      reason: "Fixture assessment.",
      evidence: [
        {
          ...citation,
          supports:
            verdict === "exploitable"
              ? ["affected_copy", "affected_use", "running", "access"]
              : verdict === "potentially_exploitable"
                ? ["affected_copy", "affected_use"]
                : [],
        },
      ],
      observations: [],
    })),
    limitations: [],
  };
}

test("reconciles the checkout verdict with cited service verdicts and preserves incomplete coverage", async () => {
  await using repo = await scopedTemporaryDirectory("cve-verdict-");
  await writeFile(join(repo.path, citation.path), "first\nsecond");
  const cases: [Verdict, Verdict[], Verdict][] = [
    ["ruled_out", ["ruled_out", "exploitable", "unknown"], "exploitable"],
    ["ruled_out", ["potentially_exploitable", "exploitable"], "exploitable"],
    [
      "exploitable",
      ["potentially_exploitable", "unknown"],
      "potentially_exploitable",
    ],
    ["potentially_exploitable", ["ruled_out"], "unknown"],
    ["ruled_out", ["ruled_out", "unknown"], "unknown"],
    ["ruled_out", ["ruled_out"], "ruled_out"],
    ["unknown", ["ruled_out"], "unknown"],
    ["exploitable", ["ruled_out"], "unknown"],
    ["ruled_out", [], "unknown"],
    ["exploitable", [], "unknown"],
  ];
  for (const [status, verdicts, expected] of cases) {
    const report = assessment(status, verdicts);
    const result = await validateDependencyAssessment(report, repo.path);
    expect(result.status).toBe(expected);
    expect(result.uses.map((use) => use.verdict)).toEqual(verdicts);
  }
});

test("requires both code claims on the same use, including for a historical positive", async () => {
  await using repo = await scopedTemporaryDirectory("cve-code-evidence-");
  await writeFile(
    join(repo.path, citation.path),
    "import dependency\ndependency.read(input)",
  );
  const report = assessment("exploitable", [
    "exploitable",
    "potentially_exploitable",
    "exploitable",
  ]);
  report.uses[0]!.evidence[0]!.supports = [
    "affected_copy",
    "running",
    "access",
  ];
  report.uses[1]!.evidence[0]!.supports = ["affected_use"];
  const legacy = report.uses[2]!;
  const historicalUse = {
    ...legacy,
    evidence: [{ path: citation.path, startLine: 1, endLine: 2 }],
  };
  const result = await validateDependencyAssessment(
    { ...report, uses: [...report.uses.slice(0, 2), historicalUse] },
    repo.path,
  );
  expect(result.status).toBe("unknown");
  expect(result.uses.map((use) => use.verdict)).toEqual([
    "unknown",
    "unknown",
    "unknown",
  ]);
  expect(result.uses[0]!.reason).toContain("applicable use");
  expect(result.uses[1]!.reason).toContain("affected dependency copy");
});

test("accepts cited runtime records from selected servers and demotes a positive with incomplete proof", async () => {
  await using repo = await scopedTemporaryDirectory("cve-runtime-evidence-");
  await writeFile(
    join(repo.path, citation.path),
    "locked dependency\naffectedOperation(input)",
  );
  const report = assessment("exploitable", ["exploitable"]);
  const use = report.uses[0]!;
  use.evidence[0]!.supports = ["affected_copy", "affected_use"];
  const running = {
    server: "inventory",
    record: "deployments/prod/service@rev7",
    supports: ["running" as const],
  };
  const access = {
    server: "routes",
    record: "effective-policy/rev7/public-ingress",
    supports: ["access" as const],
  };
  const servers = ["inventory", "routes"];
  for (const [observed, missing] of [
    [running, "access"],
    [access, "revision running"],
  ] as const) {
    use.observations = [observed];
    const result = await validateDependencyAssessment(
      report,
      repo.path,
      undefined,
      servers,
    );
    expect(result.status).toBe("potentially_exploitable");
    expect(result.uses[0]!.verdict).toBe("potentially_exploitable");
    expect(result.uses[0]!.reason).toContain(missing);
    expect(result.uses[0]!.deployment).toBe(
      observed === running ? "confirmed" : "unknown",
    );
    expect(
      await validateDependencyAssessment(result, repo.path, undefined, servers),
    ).toEqual(result);
  }
  use.observations = [running, access];
  expect(
    await validateDependencyAssessment(report, repo.path, undefined, servers),
  ).toEqual(report);
  await expect(
    validateDependencyAssessment(report, repo.path, undefined, ["inventory"]),
  ).rejects.toThrow("routes");
  use.deployment = "configured";
  expect(
    (await validateDependencyAssessment(report, repo.path, undefined, servers))
      .status,
  ).toBe("potentially_exploitable");
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

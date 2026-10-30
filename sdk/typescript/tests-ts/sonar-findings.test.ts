import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  normalizeSonarFindings,
  readSonarFindings,
} from "../src/sonar-findings.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const project = "team:application";
const repository = "https://vcs.example.test/team/application";
const primary = { key: project + ":primary", path: "src/app.ts" };
const secondary = { key: project + ":secondary", path: "src/source.ts" };
const rule = { key: "example:S1", name: "Untrusted input reaches a sink" };

function issue(key = "issue-1") {
  return {
    key,
    project,
    component: primary.key,
    rule: rule.key,
    message: "Check the source of this input.",
    issueStatus: "OPEN",
    type: "VULNERABILITY",
    impacts: [
      { softwareQuality: "RELIABILITY", severity: "BLOCKER" },
      { softwareQuality: "SECURITY", severity: "HIGH" },
    ],
    textRange: { startLine: 7, endLine: 9, startOffset: 4, endOffset: 20 },
    flows: [
      {
        locations: [
          {
            component: secondary.key,
            msg: "Input originates here.",
            textRange: { startLine: 2, endLine: 2 },
          },
        ],
      },
    ],
    updateDate: "2026-10-30T10:05:00+0000",
  };
}

function page(
  issues: Record<string, unknown>[],
  pageIndex = 1,
  pageSize = 10,
  total = issues.length,
) {
  return {
    paging: { pageIndex, pageSize, total },
    issues,
    components: [primary, secondary, { key: "unrelated", path: "other.ts" }],
    rules: [rule],
  };
}

function capture(pages: unknown[]) {
  return {
    format: "sonar-issues/v1",
    server: "https://sonar.example.test/",
    organization: "test-org",
    project,
    branch: "release/v1",
    repositoryUrl: repository,
    projectBase: "",
    pages,
  };
}

test("reads a saved Sonar capture and keeps per-issue primary and cross-file evidence", async () => {
  await using tmp = await scopedTemporaryDirectory("sonar-evidence-");
  const finding = issue("key+1");
  const input = capture([page([finding])]);
  const path = join(tmp.path, "capture.json");
  await writeFile(path, JSON.stringify(input));
  const result = await readSonarFindings(path, "", "local");
  expect(result.excluded).toEqual([]);
  expect(result.findings).toHaveLength(1);
  const imported = result.findings[0]!;
  expect(imported.source_finding_id).toBe(finding.key);
  expect(imported.evidence).toMatchObject({
    title: rule.name,
    description: finding.message,
    severity: "high",
    locations: [{ path: primary.path, line: 7 }],
    branch: "release/v1",
    source_updated_at: Date.parse(finding.updateDate) / 1000,
    details: {
      kind: "sast",
      source_status: "OPEN",
      repository: { url: repository },
      rule: { id: rule.key },
      code: { end_line: 9 },
    },
    source_data: {
      issue: finding,
      components: [primary, secondary],
      rule,
      project,
      organization: "test-org",
    },
  });
  const link = new URL(imported.evidence.url!);
  expect(link.pathname).toBe("/project/issues");
  expect(Object.fromEntries(link.searchParams)).toEqual({
    id: project,
    branch: "release/v1",
    open: finding.key,
    issues: finding.key,
  });
  expect(normalizeSonarFindings(input, repository, "cloud").findings).toEqual(
    result.findings,
  );
});

test("reads complete native pages, keeping stable IDs and distinguishing security from quality", () => {
  const current = issue();
  const classic = {
    ...issue("classic"),
    type: "VULNERABILITY",
    severity: "CRITICAL",
    impacts: undefined,
    issueStatus: undefined,
    status: "CONFIRMED",
  };
  const unrelated = {
    ...issue("other"),
    type: "CODE_SMELL",
    impacts: [{ softwareQuality: "MAINTAINABILITY", severity: "HIGH" }],
  };
  const input = [page([unrelated], 2, 2, 3), page([current, classic], 1, 2, 3)];
  const parsed = normalizeSonarFindings(input, repository);
  expect(parsed.read).toBe(3);
  expect(parsed.excluded).toMatchObject([
    { position: 3, source_finding_id: "other" },
  ]);
  expect(parsed.findings.map((item) => item.source_finding_id)).toEqual([
    "issue-1",
    "classic",
  ]);
  expect(parsed.findings[1]!.evidence).toMatchObject({
    severity: "high",
    url: null,
    details: { source_status: "CONFIRMED" },
  });
  const updated = normalizeSonarFindings(
    page([
      {
        ...current,
        textRange: { startLine: 55, endLine: 55 },
        issueStatus: "FIXED",
      },
    ]),
    repository,
  );
  expect(updated.findings[0]!.source_finding_id).toEqual(
    parsed.findings[0]!.source_finding_id,
  );
  expect(updated.findings[0]!.evidence.details?.source_status).toEqual("FIXED");
  expect(() => normalizeSonarFindings(input, "")).toThrow(
    "source-repository-url",
  );
});

test("rejects missing, overlapping, or changed pages before importing any records", () => {
  const one = page([issue("one")], 1, 1, 2);
  const two = page([issue("two")], 2, 1, 2);
  for (const pages of [
    [one],
    [one, one],
    [one, page([], 2, 1, 2)],
    [one, { ...two, paging: { ...two.paging, total: 3 } }],
  ])
    expect(() => normalizeSonarFindings(capture(pages), repository)).toThrow(
      "every Sonar",
    );
  expect(() =>
    normalizeSonarFindings(
      capture([one, { ...two, issues: one.issues }]),
      repository,
    ),
  ).toThrow("overlap");
  const empty = normalizeSonarFindings(capture([page([])]), "");
  expect(empty).toMatchObject({
    read: 0,
    findings: [],
    report: { project, repositoryUrl: repository },
  });
});

test("validates the repository binding and native project or ref before attributing evidence", () => {
  expect(() =>
    normalizeSonarFindings(capture([page([issue()])]), repository + "-other"),
  ).toThrow("does not match");
  for (const field of [
    { project: "other" },
    { organization: "other" },
    { branch: "other" },
    { pullRequest: "2" },
  ]) {
    expect(() =>
      normalizeSonarFindings(
        capture([page([{ ...issue(), ...field }])]),
        repository,
      ),
    ).toThrow(/conflicting|mixes/);
  }
  const pr = {
    ...capture([page([{ ...issue(), pullRequest: "23" }])]),
    branch: undefined,
    pullRequest: "23",
  };
  const evidence = normalizeSonarFindings(pr, "").findings[0]!.evidence;
  expect(new URL(evidence.url!).searchParams.get("pullRequest")).toBe("23");
  expect(evidence.source_data?.["pullRequest"]).toBe("23");
  expect(evidence.branch).toBeNull();
});

test("maps native component paths relative to a verified monorepo project base", () => {
  const raw = page([issue()]);
  const monorepo = { ...capture([raw]), projectBase: "packages/backend" };
  const finding = normalizeSonarFindings(monorepo, repository).findings[0]!;
  expect(finding.evidence.locations).toEqual([
    { path: "packages/backend/src/app.ts", line: 7 },
  ]);
  expect(finding.evidence.source_data?.["components"]).toEqual([
    primary,
    secondary,
  ]);
  expect(finding.evidence.source_data?.["projectBase"]).toBe(
    "packages/backend",
  );
  for (const input of [raw, { ...monorepo, projectBase: undefined }]) {
    const unknown = normalizeSonarFindings(input, repository).findings[0]!;
    expect(unknown.evidence.locations).toEqual([]);
    expect(unknown.evidence.source_data?.["components"]).toEqual([
      primary,
      secondary,
    ]);
  }
  for (const projectBase of ["../outside", "/absolute", "C:/absolute"]) {
    expect(() =>
      normalizeSonarFindings({ ...monorepo, projectBase }, repository),
    ).toThrow();
  }
});

test("keeps uncertainty about a source path in the evidence", () => {
  const raw = page([issue()]);
  raw.components[0] = { ...primary, path: "../outside/app.ts" };
  const result = normalizeSonarFindings(capture([raw]), repository);
  expect(result.excluded).toEqual([]);
  expect(result.findings[0]!.evidence.locations).toEqual([]);
  expect(result.findings[0]!.evidence.source_data?.["components"]).toEqual([
    raw.components[0],
    secondary,
  ]);
});

test("unknown Sonar ratings remain local and explain the Cloud exclusion", () => {
  const finding = {
    ...issue(),
    impacts: [{ softwareQuality: "SECURITY", severity: "UNRATED" }],
  };
  const input = page([finding]);
  const local = normalizeSonarFindings(input, repository, "local");
  expect(local.findings[0]?.evidence.severity).toBe("unknown");
  expect(local.findings[0]?.evidence.source_data?.["issue"]).toEqual(finding);
  const cloud = normalizeSonarFindings(input, repository, "cloud");
  expect(cloud.findings).toEqual([]);
  expect(cloud.excluded).toMatchObject([
    {
      source_finding_id: finding.key,
      reason: expect.stringContaining("recognized Sonar"),
    },
  ]);
});

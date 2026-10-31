import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import {
  normalizeSnykIssues,
  snykRestFindingRepository,
} from "../src/snyk-rest-findings.js";
import {
  createAndReplayFinding,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";
import {
  snykLocalFixture,
  snykOptions,
  snykRestFixture,
  snykIssue,
  snykProject,
} from "./support/snyk-rest-fixtures.js";

test("replays a v1 Snyk export with its original evidence, then updates the same stored ID from v2", async () => {
  const token = "9007199254740993";
  const projectToken = "9007199254740993e1";
  const project = { ...snykProject().data, counter: projectToken };
  const issue = snykIssue(false);
  const original = {
    ...issue,
    attributes: { ...issue.attributes, description: token, label: token },
  };
  const issueFields = { attributes: { description: token } };
  const v1 = {
    ...snykOptions,
    format: "snyk-rest-issues/v1",
    apiVersion: "2026-03-25",
    complete: true,
    project,
    target: null,
    pages: [{ startingAfter: null, response: { data: [original] } }],
    numericFields: {
      project: { counter: projectToken },
      pages: { 0: { response: { data: { 0: issueFields } } } },
    },
  };
  await using fixture = await snykLocalFixture({
    remote: snykOptions.sourceRepositoryUrl,
  });
  await fixture.writeJson(v1);
  const stored = await createAndReplayFinding(fixture);
  const source = stored.evidence.source_data!;
  expect(stored.evidence.description).toBeNull();
  expect(source).toEqual({
    ...snykOptions,
    format: v1.format,
    apiVersion: v1.apiVersion,
    project,
    target: null,
    issue: original,
    numericFields: { project: { counter: projectToken }, issue: issueFields },
  });
  expect(
    snykRestFindingRepository({
      source_finding_id: stored.sourceFindingId,
      evidence: stored.evidence,
    }).url,
  ).toBe(snykOptions.sourceRepositoryUrl);
  const selected = normalizeSnykIssues(v1);
  expect(selected).not.toHaveProperty("sourceRepositoryPlatform");
  const row = selected.findings[0]!;
  row.evidence.source_data = {
    issue: original,
    project: undefined,
    target: undefined,
    numericFields: { issue: issueFields },
  };
  const projected = await fixture.prepareNormalized(selected);
  expect((await projected.import()).counts.unchanged).toBe(1);
  expect((await fixture.read())[0]).toEqual(stored);

  // A historical native project still identifies a hosted report after a reader removes the issue and ID.
  const assetOnly = { ...source };
  delete assetOnly["format"];
  delete assetOnly["issue"];
  assetOnly["numericFields"] = { project: { counter: projectToken } };
  row.source_finding_id = "reader-id";
  row.evidence.source_data = assetOnly;
  await expect(
    fixture.prepareNormalized({
      read: 1,
      findings: [row],
      excluded: [],
    }),
  ).rejects.toThrow("Snyk original issue");
  expect(() =>
    normalizeSnykIssues({
      ...v1,
      numericFields: { project: { counter: "9007199254740994" } },
    }),
  ).toThrow("Invalid exact scanner number");

  // Earlier v1 files also used native numbers and no sidecar. Both forms replay the same row.
  const native = JSON.stringify({ ...v1, numericFields: undefined })
    .replace(`"counter":"${projectToken}"`, `"counter":${projectToken}`)
    .replace(`"description":"${token}"`, `"description":${token}`);
  await writeFile(fixture.file, gzipSync(native));
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 1,
  });

  const v2 = snykRestFixture("open-source");
  v2.projectJson = JSON.stringify(project).replace(
    `"counter":"${projectToken}"`,
    `"counter":${projectToken}`,
  );
  v2.pages[0]!.responseJson = JSON.stringify(v1.pages[0]!.response).replace(
    `"description":"${token}"`,
    `"description":${token}`,
  );
  await fixture.writeJson(v2);
  const updated = await updateStoredFinding(fixture, stored);
  const retained = updated.evidence.source_data?.["issueJson"];
  expect(retained).toContain(`"description":${token}`);
  expect(retained).toContain(`"label":"${token}"`);
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 1,
  });
});

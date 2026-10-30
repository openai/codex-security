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
  const project = { ...snykProject().data, counter: token };
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
      project: { counter: token },
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
    numericFields: { project: { counter: token }, issue: issueFields },
  });
  expect(
    snykRestFindingRepository({
      source_finding_id: stored.sourceFindingId,
      evidence: stored.evidence,
    }).url,
  ).toBe(snykOptions.sourceRepositoryUrl);
  expect(normalizeSnykIssues(v1)).not.toHaveProperty(
    "sourceRepositoryPlatform",
  );
  expect(() =>
    normalizeSnykIssues({
      ...v1,
      numericFields: { project: { counter: "9007199254740994" } },
    }),
  ).toThrow("Invalid exact scanner number");

  // Earlier v1 files also used native numbers and no sidecar. Both forms replay the same row.
  const native = JSON.stringify({ ...v1, numericFields: undefined })
    .replace(`"counter":"${token}"`, `"counter":${token}`)
    .replace(`"description":"${token}"`, `"description":${token}`);
  await writeFile(fixture.file, gzipSync(native));
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 1,
  });

  const v2 = snykRestFixture("open-source");
  v2.projectJson = JSON.stringify(project).replace(
    `"counter":"${token}"`,
    `"counter":${token}`,
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

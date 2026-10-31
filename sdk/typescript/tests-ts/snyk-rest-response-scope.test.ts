import { expect, test } from "bun:test";
import { readSnykFindings } from "../src/snyk-findings.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { isolatedGitReportFixture } from "./external-findings-local-helpers.js";
import {
  collectSnykIssues,
  normalizeSnykIssues,
} from "../src/snyk-rest-findings.js";
import {
  snykIssue,
  snykLocalFixture,
  snykOptions,
  snykProject,
  snykRestFixture,
} from "./support/snyk-rest-fixtures.js";

function capture(...responses: unknown[]) {
  return collectSnykIssues(
    { ...snykOptions, token: "example-token" },
    {
      environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
      fetch: async () => {
        if (!responses.length) throw new Error("Unexpected Snyk request");
        return Response.json(responses.shift());
      },
    },
  );
}

test("project and target JSON formatting preserves exact native numbers and text", () => {
  const project = snykProject("npm", "").data;
  const target = {
    ...project.relationships.target.data,
    attributes: { url: snykOptions.sourceRepositoryUrl },
  };
  const report = snykRestFixture("open-source");
  const source = (members: string) => {
    const json = (resource: object) =>
      JSON.stringify(resource).replace("{", `{${members},`);
    return normalizeSnykIssues({
      ...report,
      projectJson: json(project),
      targetJson: json(target),
    }).findings[0]!.evidence.source_data!;
  };
  const token = "9007199254740993";
  const original = source(`"amount":${token},"label":"${token}"`);
  expect(
    source(`
 "label": "${token}", "amount": ${token}`),
  ).toEqual(original);
  for (const field of ["projectJson", "targetJson"]) {
    expect(original[field]).toContain(`"amount":${token}`);
    expect(original[field]).toContain(`"label":"${token}"`);
  }
});

test("a saved target accepts unexpanded integration linkage and checks a supplied integration type", async () => {
  const project = snykProject("npm", "");
  const { type, id } = project.data.relationships.target.data;
  const target = (attributes?: Record<string, unknown>) => ({
    data: {
      type,
      id,
      attributes: { url: snykOptions.sourceRepositoryUrl },
      relationships: {
        organization: project.data.relationships.organization,
        integration: {
          data: {
            type: "integration",
            id: "88888888-8888-4888-8888-888888888888",
            attributes,
          },
        },
      },
    },
  });
  const linked = target().data.relationships.integration;
  Object.assign(project.data.relationships.target.data, {
    relationships: { integration: linked },
  });
  const saved = await capture(project, target({ integration_type: "github" }), {
    data: [snykIssue(false)],
  });
  const normalizedTarget = (data: unknown) =>
    normalizeSnykIssues({ ...saved, targetJson: JSON.stringify(data) });
  expect(normalizedTarget(target().data).findings).toHaveLength(1);
  expect(() => normalizedTarget(target({}).data)).toThrow(
    "Snyk integration type",
  );
  expect(() =>
    normalizedTarget(target({ integration_type: "gitlab" }).data),
  ).toThrow("project's github origin");

  const replaced = target({ integration_type: "github" });
  replaced.data.relationships.integration.data.id =
    "99999999-9999-4999-8999-999999999999";
  await using fixture = await snykLocalFixture();
  await fixture.writeJson({
    ...saved,
    targetJson: JSON.stringify(replaced.data),
  });
  await expect(readSnykFindings(fixture.file, "local")).rejects.toThrow(
    "different integration",
  );
  await expect(
    capture(project, replaced, { data: [snykIssue(false)] }),
  ).rejects.toThrow("different integration");
});

test("CLI and API targets can have empty integration linkage", async () => {
  for (const origin of ["cli", "api"]) {
    const project = snykProject();
    project.data.attributes.origin = origin;
    Object.assign(project.data.relationships.target.data, {
      relationships: { integration: { data: null } },
    });
    const saved = await capture(project, { data: [snykIssue(false)] });
    expect(normalizeSnykIssues(saved).findings).toHaveLength(1);
  }
});

test("expanded integrations carry their own resource type and nullable UUID", async () => {
  const project = snykProject();
  const target = project.data.relationships.target.data;
  const original = {
    type: "integration",
    id: "88888888-8888-4888-8888-888888888888",
    attributes: { integration_type: "github" },
  };
  for (const [identity, error] of [
    [{ type: "project" }, "integration resource"],
    [{ type: undefined }, "integration resource"],
    [{ id: "invalid" }, "integration ID"],
    [{ id: undefined }, "integration ID"],
    [{ id: null }, undefined],
  ] as const) {
    Object.assign(target, {
      relationships: { integration: { data: { ...original, ...identity } } },
    });
    const collecting = capture(project, { data: [snykIssue(false)] });
    const saved = {
      ...snykRestFixture("open-source"),
      projectJson: JSON.stringify(project.data),
    };
    if (error) {
      await expect(collecting).rejects.toThrow(error);
      expect(() => normalizeSnykIssues(saved)).toThrow(error);
    } else {
      expect((await collecting).complete).toBe(true);
      expect(normalizeSnykIssues(saved).findings).toHaveLength(1);
    }
  }
});

test("a cross-product issue fails collection but remains an exclusion when reading a saved report", async () => {
  const data = [snykIssue(false), snykIssue(true)];
  await expect(capture(snykProject(), { data })).rejects.toThrow(
    "Only package_vulnerability",
  );
  const saved = snykRestFixture("open-source");
  saved.pages[0]!.responseJson = JSON.stringify({ data });
  const result = normalizeSnykIssues(saved);
  expect(result.findings).toHaveLength(1);
  expect(result.excluded).toMatchObject([
    { reason: expect.stringContaining("Only package_vulnerability") },
  ]);
});

test.each(["expanded", "fetched", "partly expanded"] as const)(
  "the %s target cannot contradict the selected organization or SCM",
  async (representation) => {
    const project = snykProject();
    const { organization, target } = project.data.relationships;
    const integration = {
      data: { type: "integration", id: "88888888-8888-4888-8888-888888888888" },
    };
    await using fixture = await isolatedGitReportFixture(
      "snyk.json",
      { provider: "snyk", sourceKey: snykOptions.projectId },
      { remote: snykOptions.sourceRepositoryUrl },
    );
    for (const [relationships, error] of [
      [{ integration }, undefined],
      [
        {
          organization: {
            data: {
              ...organization.data,
              id: "99999999-9999-4999-8999-999999999999",
            },
          },
        },
        "selected organization",
      ],
      [
        {
          organization,
          integration: {
            data: {
              ...integration.data,
              attributes: { integration_type: "gitlab" },
            },
          },
        },
        "project's github origin",
      ],
    ] as const) {
      const full = { ...target.data, relationships };
      const partial = {
        type: full.type,
        id: full.id,
        ...(representation === "partly expanded" && { relationships }),
      };
      const resource = {
        ...project.data,
        relationships: {
          organization,
          target: { data: representation === "expanded" ? full : partial },
        },
      };
      const lookup =
        representation === "expanded"
          ? null
          : representation === "fetched"
            ? full
            : target.data;
      const saved = {
        ...snykRestFixture("open-source"),
        projectJson: JSON.stringify(resource),
        targetJson: JSON.stringify(lookup),
      };
      await fixture.writeJson(saved);
      const collecting = capture(
        { data: resource },
        ...(lookup ? [{ data: lookup }] : []),
        { data: [snykIssue(false)] },
      );
      if (error) {
        await expect(collecting).rejects.toThrow(error);
        expect(() => normalizeSnykIssues(saved)).toThrow(error);
        await expect(fixture.prepare()).rejects.toThrow(error);
      } else {
        expect((await collecting).complete).toBe(true);
        expect(normalizeSnykIssues(saved).findings).toHaveLength(1);
        expect((await fixture.prepare()).preview.findings).toHaveLength(1);
      }
    }
  },
);

test.each([
  ["cli", {}],
  ["api", { target: { data: null } }],
] as const)(
  "a targetless %s project uses the explicit mapping and verifies its organization",
  async (origin, target) => {
    const { data } = snykProject();
    const { organization } = data.relationships;
    const project = {
      ...data,
      attributes: { ...data.attributes, origin },
      relationships: { organization, ...target },
    };
    const saved = await capture(
      { data: project },
      { data: [snykIssue(false)] },
    );
    expect(saved.targetJson).toBe("null");
    expect(normalizeSnykIssues(saved)).toMatchObject({
      sourceRepositoryUrl: snykOptions.sourceRepositoryUrl,
      findings: [expect.anything()],
    });
    expect(() =>
      normalizeSnykIssues({
        ...saved,
        targetJson: JSON.stringify(data.relationships.target.data),
      }),
    ).toThrow("Unexpected separate Snyk target");
    const unrelated = {
      ...project,
      relationships: {
        ...project.relationships,
        organization: {
          data: {
            ...organization.data,
            id: "99999999-9999-4999-8999-999999999999",
          },
        },
      },
    };
    await expect(capture({ data: unrelated })).rejects.toThrow(
      "selected organization",
    );
    expect(() =>
      normalizeSnykIssues({ ...saved, projectJson: JSON.stringify(unrelated) }),
    ).toThrow("selected organization");
  },
);

test("direct SDK projections can edit display fields but must retain an importable native Snyk issue", async () => {
  const captured = snykRestFixture("open-source");
  const normalized = normalizeSnykIssues(captured);
  const row = normalized.findings[0]!;
  const retained = row.evidence.source_data!;
  const original = String(retained["issueJson"]);
  await using fixture = await isolatedGitReportFixture(
    "snyk.json",
    { provider: "snyk", sourceKey: snykOptions.projectId },
    { remote: snykOptions.sourceRepositoryUrl },
  );
  await fixture.writeJson(captured);
  await (await fixture.prepare()).import();
  const stored = await fixture.read();
  const prepare = () =>
    prepareNormalizedLocalImport(
      normalized,
      {
        provider: "snyk",
        sourceKey: snykOptions.projectId,
        repository: fixture.repository,
      },
      { environment: fixture.environment },
    );
  row.evidence.title = "Reader projection";
  for (const [field, value] of [
    ["status", "absent"],
    ["ignored", null],
    ["updated_at", ""],
    ["effective_severity_level", null],
    ["title", ""],
    ["coordinates", {}],
  ] as const) {
    const issue = JSON.parse(original);
    issue.attributes[field] = value;
    captured.pages[0]!.responseJson = JSON.stringify({ data: [issue] });
    const saved = normalizeSnykIssues(captured);
    expect(saved.findings).toHaveLength(0);
    retained["issueJson"] = JSON.stringify(issue);
    await expect(prepare()).rejects.toThrow(saved.excluded[0]!.reason);
  }
  retained["issueJson"] = original;
  row.evidence.locations = [{ path: "../outside.ts" }];
  await expect(prepare()).rejects.toThrow("repository-relative paths");
  expect(await fixture.read()).toEqual(stored);
  row.evidence.locations = [{ path: "src/reader.ts" }];
  expect((await (await prepare()).import()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 0,
  });
  expect((await fixture.read())[0]).toMatchObject({
    id: stored[0]!.id,
    evidence: {
      title: "Reader projection",
      locations: [{ path: "src/reader.ts" }],
    },
  });
});

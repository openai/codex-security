import { expect, test } from "bun:test";
import { isolatedGitReportFixture } from "./external-findings-local-helpers.js";
import {
  collectSnykIssues,
  normalizeSnykIssues,
} from "../src/snyk-rest-findings.js";
import {
  snykIssue,
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

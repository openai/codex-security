import { expect, test } from "bun:test";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import {
  collectSnykIssues,
  normalizeSnykIssues,
  type CollectSnykIssuesOptions,
} from "../src/snyk-rest-findings.js";
import type { ExternalSourceRepository } from "../src/external-findings.js";
import { readSnykFindings } from "../src/snyk-findings.js";
import { isolatedGitReportFixture } from "./external-findings-local-helpers.js";
import { snykOptions, snykRestFixture } from "./support/snyk-rest-fixtures.js";

const url = "https://scm.example.invalid/Team/Repo";
const clone = "git@scm.example.invalid:Team/Repo.git";

test.each([
  { origin: "cli", platform: "github", empty: false },
  { origin: "api", platform: "gitlab", empty: true },
  { origin: "gitlab", platform: "gitlab", empty: false },
] as const)(
  "requires independent $platform provenance for a private $origin checkout",
  async ({ origin, platform, empty }) => {
    const report = snykRestFixture("open-source", { sourceRepositoryUrl: url });
    const project = JSON.parse(report.projectJson);
    project.attributes.origin = origin;
    // CLI and API projects can report an SSH clone, while GitLab can omit its target.
    if (origin === "gitlab") delete project.relationships;
    else project.relationships.target.data.attributes.url = clone;
    if (empty) report.pages[0]!.responseJson = '{"data":[]}';

    const source = { provider: "snyk", sourceKey: "private/project" } as const;
    await using fixture = await isolatedGitReportFixture("snyk.json", source, {
      remote: clone,
    });
    const settings = { ...source, repository: fixture.repository };
    const dependencies = {
      environment: fixture.environment,
      sourceRepositories: [{ url, platform }],
    };

    const options: CollectSnykIssuesOptions = {
      organizationId: snykOptions.organizationId,
      projectId: snykOptions.projectId,
      sourceRepositoryUrl: url,
    };
    const collect = (
      sourceRepositories?: readonly ExternalSourceRepository[],
    ) =>
      collectSnykIssues(options, {
        environment: {
          CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
          SNYK_TOKEN: "synthetic",
        },
        sourceRepositories,
        fetch: async (request, init) => {
          expect(new Headers(init.headers).get("authorization")).toBe(
            "token synthetic",
          );
          if (request.pathname.endsWith("/issues")) {
            expect(request.searchParams.get("type")).toBe(
              "package_vulnerability",
            );
            return new Response(report.pages[0]!.responseJson);
          }
          return Response.json({ data: project });
        },
      });
    if (origin !== "gitlab") {
      await expect(collect()).rejects.toThrow("target URL");
      await expect(
        collect([{ url: url + "-other", platform }]),
      ).rejects.toThrow("target URL");
    }
    const acquired = await collect(dependencies.sourceRepositories);
    expect(acquired.product).toBe("open-source");
    await fixture.writeJson(acquired);
    await expect(fixture.prepare()).rejects.toThrow();
    if (origin !== "gitlab")
      await expect(readSnykFindings(fixture.file, "local")).rejects.toThrow(
        "target URL",
      );
    const first = await prepareLocalExternalImport(
      fixture.file,
      settings,
      dependencies,
    );
    expect((await first.import()).counts.created).toBe(empty ? 0 : 1);

    const normalized = await readSnykFindings(
      fixture.file,
      "local",
      dependencies.sourceRepositories,
    );
    await expect(
      prepareNormalizedLocalImport(normalized, settings, {
        environment: fixture.environment,
      }),
    ).rejects.toThrow();
    const retry = await prepareNormalizedLocalImport(
      normalized,
      settings,
      dependencies,
    );
    expect((await retry.import()).counts.unchanged).toBe(empty ? 0 : 1);
    await expect(
      prepareLocalExternalImport(fixture.file, settings, {
        ...dependencies,
        sourceRepositories: [{ url: url + "-other", platform }],
      }),
    ).rejects.toThrow();
  },
);

test("saved Snyk exports must still identify the collected product", () => {
  const { product: _product, ...unscoped } = snykRestFixture("open-source");
  expect(() => normalizeSnykIssues(unscoped)).toThrow(
    "Snyk product must be open-source or code",
  );
});

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { listLocalExternalFindings } from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  importedAlert,
  importedAdvisory,
} from "./support/github-import-fixtures.js";

const fixtures: Awaited<ReturnType<typeof localFindingsFixture>>[] = [];
afterEach(async () => {
  for (const fixture of fixtures.splice(0)) await fixture.dispose();
});

type Source = "code-scanning" | "repository-advisory" | "global-advisory";

function githubSource(source: Source) {
  return source === "code-scanning"
    ? importedAlert()
    : importedAdvisory(source === "global-advisory" ? "global" : "repository");
}

test.each(["code-scanning", "repository-advisory", "global-advisory"] as const)(
  "GitHub %s imports into local storage and updates source evidence without assessing it",
  async (kind) => {
    const fixture = await localFindingsFixture({
      remote: "https://github.com/example/project",
    });
    fixtures.push(fixture);
    const source = githubSource(kind);
    const file = join(fixture.root, "github.json");
    await writeFile(file, JSON.stringify([source]));
    const options = {
      repository: fixture.repository,
      provider: "github" as const,
      sourceKey: "github/example/project",
    };
    const dependencies = { environment: fixture.environment };
    const prepare = () =>
      prepareLocalExternalImport(file, options, dependencies);
    const read = () => listLocalExternalFindings(options, dependencies);

    const prepared = await prepare();
    expect(prepared.preview.excluded).toEqual([]);
    expect(await read()).toEqual([]);
    expect((await prepared.import()).counts).toEqual({
      created: 1,
      updated: 0,
      unchanged: 0,
    });
    const stored = await read();
    expect(stored).toHaveLength(1);
    const initial = stored[0]!;
    expect(initial).toMatchObject({
      repository: fixture.repository,
      provider: "github",
      sourceKey: options.sourceKey,
      assessment: { state: "not_assessed" },
      version: 1,
      evidence: { source_data: source },
    });
    if (kind !== "code-scanning") {
      expect(initial.evidence.locations).toEqual([]);
      expect(initial.evidence.packages?.[0]).toMatchObject({
        installed_version: null,
        manifest_path: null,
      });
    }
    if (kind === "global-advisory")
      expect(initial.evidence.details).not.toHaveProperty("repository");
    expect(initial.evidence).not.toHaveProperty("confidence");
    expect(initial.evidence).not.toHaveProperty("assessment");

    expect((await (await prepare()).import()).counts).toEqual({
      created: 0,
      updated: 0,
      unchanged: 1,
    });
    expect(await read()).toEqual(stored);

    if (source.source === "github-code-scanning") {
      source.alert.most_recent_instance.state = "fixed";
      source.alert.most_recent_instance.commit_sha = "b".repeat(40);
      delete source.alert.rule.security_severity_level;
    } else {
      source.advisory.withdrawn_at = "2026-01-03T00:00:00Z";
      source.advisory.severity = null;
    }
    await writeFile(file, JSON.stringify([source]));
    expect((await (await prepare()).import()).counts).toEqual({
      created: 0,
      updated: 1,
      unchanged: 0,
    });
    const updated = await read();
    expect(updated).toHaveLength(1);
    expect(updated[0]).toMatchObject({
      id: initial.id,
      sourceFindingId: initial.sourceFindingId,
      createdAt: initial.createdAt,
      version: 2,
      assessment: { state: "not_assessed" },
      evidence: {
        severity: "unknown",
        source_data: source,
        details: {
          source_status: kind === "code-scanning" ? "fixed" : "withdrawn",
        },
      },
    });
  },
);

test.each(["code-scanning", "repository-advisory"] as const)(
  "GitHub %s refuses to attach another repository's evidence locally",
  async (kind) => {
    const fixture = await localFindingsFixture({
      remote: "https://github.com/example/other",
    });
    fixtures.push(fixture);
    const file = join(fixture.root, "github.json");
    await writeFile(file, JSON.stringify([githubSource(kind)]));
    await expect(
      prepareLocalExternalImport(
        file,
        {
          repository: fixture.repository,
          provider: "github",
          sourceKey: "github/example/project",
        },
        { environment: fixture.environment },
      ),
    ).rejects.toThrow(/repository/iu);
    expect(
      await listLocalExternalFindings(
        { repository: fixture.repository },
        { environment: fixture.environment },
      ),
    ).toEqual([]);
  },
);

test.each(["code-scanning", "repository-advisory"] as const)(
  "GitHub %s matches custom Enterprise repository names without changing source evidence",
  async (kind) => {
    const fixture = await localFindingsFixture({
      remote: "git@git.example.test:example/project.git",
    });
    fixtures.push(fixture);
    const source =
      kind === "code-scanning"
        ? importedAlert("refs/heads/main", "git.example.test")
        : importedAdvisory();
    source.repository = "Example/Project";
    if (source.source === "github-security-advisory") {
      source.githubHost = "git.example.test";
      source.url = source.url.replace("github.com", "git.example.test");
      source.advisory.html_url = source.url;
    }
    const file = join(fixture.root, "github-enterprise.json");
    await writeFile(file, JSON.stringify([source]));
    const options = {
      repository: fixture.repository,
      provider: "github" as const,
      sourceKey: "github/example/project",
    };
    const dependencies = { environment: fixture.environment };
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    expect(prepared.preview.excluded).toEqual([]);
    expect(
      prepared.preview.findings[0]!.evidence.details!.repository,
    ).toMatchObject({
      url: "https://git.example.test/Example/Project",
      name: "Example/Project",
    });
    expect((await prepared.import()).counts).toEqual({
      created: 1,
      updated: 0,
      unchanged: 0,
    });
    const stored = await listLocalExternalFindings(options, dependencies);
    expect(stored[0]!.evidence).toEqual(prepared.preview.findings[0]!.evidence);
    expect(stored[0]!.evidence.source_data).toEqual({ ...source });
  },
);

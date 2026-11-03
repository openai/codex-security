import { expect, test } from "bun:test";
import {
  createAndReplayFinding,
  localReportFixture,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";
import {
  importedAlert,
  importedAdvisory,
} from "./support/github-import-fixtures.js";

type Source = "code-scanning" | "repository-advisory" | "global-advisory";

function githubSource(source: Source) {
  return source === "code-scanning"
    ? importedAlert()
    : importedAdvisory(source === "global-advisory" ? "global" : "repository");
}

test.each(["code-scanning", "repository-advisory", "global-advisory"] as const)(
  "GitHub %s imports into local storage and updates source evidence without assessing it",
  async (kind) => {
    await using fixture = await localReportFixture(
      "github.json",
      { provider: "github", sourceKey: "github/example/project" },
      { remote: "https://github.com/example/project" },
    );
    const source = githubSource(kind);
    await fixture.writeJson([source]);

    const initial = await createAndReplayFinding(fixture);
    expect(initial.provider).toBe("github");
    expect(initial.evidence.source_data).toMatchObject(source);
    if (kind !== "code-scanning") {
      expect(initial.evidence.locations).toEqual([]);
      expect(initial.evidence.packages?.[0]).toMatchObject({
        installed_version: null,
        manifest_path: null,
      });
    }
    if (kind === "global-advisory")
      expect(initial.evidence.details).not.toHaveProperty("repository");
    expect(initial.evidence).not.toHaveProperty("assessment");

    if (source.source === "github-code-scanning") {
      source.alert.most_recent_instance.state = "fixed";
      source.alert.most_recent_instance.commit_sha = "b".repeat(40);
      delete source.alert.rule.security_severity_level;
    } else {
      source.advisory.withdrawn_at = "2026-01-03T00:00:00Z";
      source.advisory.severity = null;
    }
    await fixture.writeJson([source]);
    const updated = await updateStoredFinding(fixture, initial);
    expect(updated).toMatchObject({
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
    await using fixture = await localReportFixture(
      "github.json",
      { provider: "github", sourceKey: "github/example/project" },
      { remote: "https://github.com/example/other" },
    );
    await fixture.writeJson([githubSource(kind)]);
    await expect(fixture.prepare()).rejects.toThrow(/repository/iu);
    expect(await fixture.read()).toEqual([]);
  },
);

test.each(["code-scanning", "repository-advisory"] as const)(
  "GitHub %s matches custom Enterprise repository names without changing source evidence",
  async (kind) => {
    await using fixture = await localReportFixture(
      "github-enterprise.json",
      { provider: "github", sourceKey: "github/example/project" },
      { remote: "git@git.example.test:example/project.git" },
    );
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
    await fixture.writeJson([source]);
    const prepared = await fixture.prepare();
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
    const stored = await fixture.read();
    expect(stored[0]!.evidence).toEqual(prepared.preview.findings[0]!.evidence);
    expect(stored[0]!.evidence.source_data).toEqual({ ...source });
  },
);

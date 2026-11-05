import { expect, test } from "bun:test";
import {
  normalizeGitHubAdvisories,
  normalizeGitHubCodeScanningAlerts,
} from "../src/github-findings.js";
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
  "GitHub %s checks repository scope for raw and previously normalized findings",
  async (kind) => {
    const wrongRepository = "https://github.com/example/other";
    await using fixture = await localReportFixture(
      "github.json",
      { provider: "github", sourceKey: "github/example/project" },
      { remote: wrongRepository },
    );
    const source = githubSource(kind);
    await fixture.writeJson([source]);
    await expect(fixture.prepare()).rejects.toThrow(/repository/iu);
    expect(await fixture.read()).toEqual([]);

    const input =
      source.source === "github-code-scanning"
        ? normalizeGitHubCodeScanningAlerts([source], "local")
        : normalizeGitHubAdvisories([source], "local");
    const row = input.findings[0]!;
    const details = row.evidence.details!;
    details.repository!.url = wrongRepository;
    await expect(fixture.prepareNormalized(input)).rejects.toThrow(
      "does not match the original GitHub finding",
    );
    delete row.evidence.details;
    await expect(fixture.prepareNormalized(input)).rejects.toThrow(
      /configured remote/iu,
    );
    fixture.git(
      "remote",
      "set-url",
      "origin",
      "git@github.com:Example/Project.git",
    );
    expect(
      (await fixture.prepareNormalized(input)).preview.findings,
    ).toHaveLength(1);
    row.evidence.details = details;
    details.repository!.url = "https://github.com:8443/example/project";
    await expect(fixture.prepareNormalized(input)).rejects.toThrow(
      "does not match the original GitHub finding",
    );
    details.repository!.url = "https://github.com:443/example/project";
    row.source_finding_id = "existing-sdk-occurrence";
    const saved = await (await fixture.prepareNormalized(input)).import();
    expect(saved.counts.created).toBe(1);
    expect((await fixture.read())[0]?.sourceFindingId).toBe(
      row.source_finding_id,
    );
  },
);

test("a retained global advisory may be investigated in another repository", async () => {
  const remote = "https://github.com/example/other";
  await using fixture = await localReportFixture(
    "github.json",
    { provider: "github", sourceKey: "github/global-advisories" },
    { remote },
  );
  const input = normalizeGitHubAdvisories(
    [importedAdvisory("global")],
    "local",
  );
  const evidence = input.findings[0]!.evidence;
  expect(
    (await fixture.prepareNormalized(input)).preview.findings,
  ).toHaveLength(1);
  evidence.details = {
    kind: "advisory",
    advisory: { source: "repository" },
    repository: { url: remote },
  };
  await expect(fixture.prepareNormalized(input)).rejects.toThrow(
    "Global advisory evidence cannot claim a source repository",
  );
});

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

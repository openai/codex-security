import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import { normalizeGitHubDependabotAlerts } from "../src/github-dependabot-findings.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import { githubDependabotAlert } from "./support/github-dependabot-fixtures.js";

test("two Dependabot alerts for one advisory retain separate repository histories", async () => {
  const fixture = await localFindingsFixture({
    remote: "git@github.com:example/project.git",
  });
  try {
    const path = join(fixture.root, "dependabot.json.gz");
    const options = {
      repository: fixture.repository,
      provider: "github" as const,
      sourceKey: "github.com/example/project/dependabot",
    };
    const dependencies = { environment: fixture.environment };
    const prepare = async (findings: unknown[]) => {
      await writeFile(path, gzipSync(JSON.stringify(findings)));
      return prepareLocalExternalImport(path, options, dependencies);
    };
    const importCounts = async (alerts: unknown[]) => {
      const prepared = await prepare(alerts);
      return (await prepared.import()).counts;
    };
    const first = { ...githubDependabotAlert(1), source: "extra" };
    const second = githubDependabotAlert(2);
    const saved = await prepare([first, second]);
    expect((await saved.import()).counts.created).toBe(2);
    expect((await importCounts([second, first])).unchanged).toBe(2);
    const fixed = {
      ...first,
      state: "fixed",
      fixed_at: "2026-01-03T00:00:00Z",
    };
    expect((await importCounts([fixed])).updated).toBe(1);
    expect(await importCounts([])).toEqual({
      created: 0,
      updated: 0,
      unchanged: 0,
    });
    const records = await listLocalExternalFindings(options, dependencies);
    expect(records.map((record) => record.version).sort()).toEqual([1, 2]);
    expect(
      records.every(({ assessment }) => assessment.state === "not_assessed"),
    ).toBe(true);
    const other = {
      ...githubDependabotAlert(3, "example/other"),
      source: "extra",
    };
    await expect(prepare([other])).rejects.toThrow(/configured remote/);
    const altered = structuredClone(saved.preview);
    altered.findings[0]!.evidence.details = {
      kind: "sast",
      repository: { url: "https://github.com/example/other" },
    };
    await expect(
      prepareNormalizedLocalImport(altered, options, dependencies),
    ).rejects.toThrow(/original Dependabot alert/i);
    const relabeled = structuredClone(saved.preview);
    relabeled.findings.splice(1);
    relabeled.findings[0]!.source_finding_id =
      saved.preview.findings[1]!.source_finding_id;
    await expect(
      prepareNormalizedLocalImport(relabeled, options, dependencies),
    ).rejects.toThrow(/occurrence|source finding|identity|alert ID/i);
    const foreign = normalizeGitHubDependabotAlerts(other, "local");
    await expect(
      prepareNormalizedLocalImport(foreign, options, dependencies),
    ).rejects.toThrow(/configured remote/);
    expect(await listLocalExternalFindings(options, dependencies)).toEqual(
      records,
    );
  } finally {
    await fixture.dispose();
  }
});

test("normalized local imports bind projected Dependabot occurrences to a single repository", async () => {
  const fixture = await localFindingsFixture();
  try {
    const options = {
      repository: fixture.repository,
      provider: "github" as const,
      sourceKey: "alerts",
    };
    const deps = { environment: fixture.environment };
    const first = normalizeGitHubDependabotAlerts(
      githubDependabotAlert(1),
      "local",
    );
    const second = normalizeGitHubDependabotAlerts(
      githubDependabotAlert(2, "example/other"),
      "local",
    );
    delete first.findings[0]!.evidence.source_data;
    await expect(
      prepareNormalizedLocalImport(
        {
          ...first,
          read: 2,
          findings: [...first.findings, ...second.findings],
        },
        options,
        deps,
      ),
    ).rejects.toThrow(/one GitHub host and repository/);
    first.findings[0]!.source_finding_id =
      second.findings[0]!.source_finding_id;
    await expect(
      prepareNormalizedLocalImport(first, options, deps),
    ).rejects.toThrow(/source finding ID/);
  } finally {
    await fixture.dispose();
  }
});

test("replaying normalized Dependabot evidence keeps the caller's stored ID", async () => {
  const fixture = await localFindingsFixture({
    remote: "https://github.com/example/project",
  });
  try {
    const alert = githubDependabotAlert();
    const selection = normalizeGitHubDependabotAlerts(alert, "local");
    const finding = selection.findings[0]!;
    finding.source_finding_id = "alert-1";
    finding.evidence.url = alert.url;
    const options = {
      repository: fixture.repository,
      provider: "github" as const,
      sourceKey: "alerts",
    };
    const deps = { environment: fixture.environment };
    const importCounts = async () => {
      const prepared = await prepareNormalizedLocalImport(
        selection,
        options,
        deps,
      );
      return (await prepared.import()).counts;
    };
    expect((await importCounts()).created).toBe(1);
    finding.evidence.source_data = {
      security_vulnerability: alert.security_vulnerability,
    };
    expect((await importCounts()).updated).toBe(1);
    expect((await importCounts()).unchanged).toBe(1);
    expect(
      (await listLocalExternalFindings(options, deps)).map(
        (row) => row.sourceFindingId,
      ),
    ).toEqual(["alert-1"]);
  } finally {
    await fixture.dispose();
  }
});

test("binds offline HTTP Enterprise alert URLs without changing the repository scheme", async () => {
  const repository = "git.example.test/example/project";
  const fixture = await localFindingsFixture({
    remote: `http://${repository}`,
  });
  try {
    const alert = githubDependabotAlert(
      1,
      "example/project",
      "git.example.test",
    );
    const http = {
      ...alert,
      html_url: alert.html_url.replace("https:", "http:"),
      url: alert.url.replace("https:", "http:"),
    };
    const normalized = normalizeGitHubDependabotAlerts(http, "local");
    const options = {
      repository: fixture.repository,
      provider: "github" as const,
      sourceKey: "alerts",
    };
    const deps = { environment: fixture.environment };
    expect(
      (await prepareNormalizedLocalImport(normalized, options, deps)).preview
        .findings[0]!.evidence.url,
    ).toBe(http.html_url);
    delete normalized.findings[0]!.evidence.source_data;
    normalized.findings[0]!.evidence.url = alert.html_url;
    await expect(
      prepareNormalizedLocalImport(normalized, options, deps),
    ).rejects.toThrow(/does not match a configured remote/);
    expect(() =>
      normalizeGitHubDependabotAlerts({ ...http, url: alert.url }, "local"),
    ).toThrow(/API url and html_url/);
  } finally {
    await fixture.dispose();
  }
});

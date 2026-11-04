import { expect, test } from "bun:test";
import {
  createAndReplayFinding,
  localReportFixture,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";
import {
  snykJson,
  snykPluginExport,
  snykSarif,
} from "./support/snyk-import-fixtures.js";

test.each(["plugin", "JSON", "SARIF"] as const)(
  "Snyk %s findings persist locally and update without duplicating their identities",
  async (format) => {
    await using fixture = await localReportFixture(
      "snyk.json",
      { provider: "snyk", sourceKey: `snyk-${format.toLowerCase()}` },
      { remote: "https://github.com/example/project" },
    );
    const input =
      format === "plugin"
        ? snykPluginExport()
        : format === "JSON"
          ? snykJson()
          : snykSarif();
    await fixture.writeJson(input);

    const stored = await createAndReplayFinding(fixture);
    expect(stored.provider).toBe("snyk");
    expect(stored.evidence.locations).toEqual([]);
    expect(stored.evidence.packages![0]!.manifest_path).toBeNull();
    if ("findings" in input) {
      expect(stored.evidence.source_data).toMatchObject({
        collection: input.collection,
        finding: input.findings[0],
      });
    } else if ("vulnerabilities" in input) {
      expect(stored.evidence.source_data).toMatchObject({
        vulnerability: input.vulnerabilities[0],
      });
    } else {
      expect(stored.evidence.source_data).toMatchObject({
        result: input.runs[0]!.results[0],
        rule: input.runs[0]!.tool.driver.rules[0],
      });
    }

    if ("findings" in input) {
      input.findings[0]!.severity.value = "low";
      input.findings[0]!.nativeRecord.isIgnored = false;
    } else if ("vulnerabilities" in input) {
      input.vulnerabilities[0]!.severity = "low";
      input.vulnerabilities[0]!.description = "Updated dependency evidence";
    } else {
      input.runs[0]!.tool.driver.rules[0]!.shortDescription.text =
        "Low severity - synthetic vulnerability in @example/package";
      input.runs[0]!.results[0]!.message.text = "Updated dependency evidence";
    }
    await fixture.writeJson(input);
    const updated = await updateStoredFinding(fixture, stored);
    expect(updated.evidence.severity).toBe("low");
    expect(updated.evidence.source_data).not.toEqual(
      stored.evidence.source_data,
    );
  },
);

test.each(["plugin", "JSON", "SARIF"] as const)(
  "Snyk %s repository provenance cannot be imported into a different local checkout",
  async (format) => {
    await using fixture = await localReportFixture(
      "snyk.json",
      { provider: "snyk", sourceKey: "snyk-sca" },
      { remote: "https://github.com/example/other" },
    );
    const sarif = snykSarif();
    const input =
      format === "plugin"
        ? snykPluginExport()
        : format === "JSON"
          ? {
              ...snykJson(),
              path: "https://github.com/example/project#release",
            }
          : {
              ...sarif,
              runs: sarif.runs.map((run) => ({
                ...run,
                versionControlProvenance: [
                  { repositoryUri: "https://github.com/example/project" },
                ],
              })),
            };
    await fixture.writeJson(input);
    await expect(fixture.prepare()).rejects.toThrow(/repository/iu);
    expect(await fixture.read()).toEqual([]);
  },
);

test.each([2222, 2223])(
  "Snyk plugin repository matching preserves the SSH port (checkout port %i)",
  async (port) => {
    await using fixture = await localReportFixture(
      "snyk.json",
      { provider: "snyk", sourceKey: "snyk-sca" },
      { remote: `ssh://git@github.example.test:${port}/example/project.git` },
    );
    const input = snykPluginExport();
    input.collection.target.repository =
      "ssh://git@github.example.test:2222/example/project.git";
    await fixture.writeJson(input);
    if (port !== 2222) {
      await expect(fixture.prepare()).rejects.toThrow(/repository/iu);
      expect(await fixture.read()).toEqual([]);
      return;
    }

    const prepared = await fixture.prepare();
    expect((await prepared.import()).counts.created).toBe(1);
    const records = await fixture.read();
    expect(records).toHaveLength(1);
    expect(records[0]!.evidence.source_data).toMatchObject({
      collection: {
        target: { repository: input.collection.target.repository },
      },
    });
  },
);

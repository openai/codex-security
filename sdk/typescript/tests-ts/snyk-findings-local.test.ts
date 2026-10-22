import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { listLocalExternalFindings } from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  snykJson,
  snykPluginExport,
  snykSarif,
} from "./support/snyk-import-fixtures.js";

test.each(["plugin", "JSON", "SARIF"] as const)(
  "Snyk %s findings persist locally and update without duplicating their identities",
  async (format) => {
    const fixture = await localFindingsFixture({
      remote: "https://github.com/example/project",
    });
    try {
      const input =
        format === "plugin"
          ? snykPluginExport()
          : format === "JSON"
            ? snykJson()
            : snykSarif();
      const path = join(fixture.root, "snyk.json");
      const options = {
        repository: fixture.repository,
        provider: "snyk" as const,
        sourceKey: `snyk-${format.toLowerCase()}`,
      };
      const dependencies = { environment: fixture.environment };
      await writeFile(path, JSON.stringify(input));

      const prepared = await prepareLocalExternalImport(
        path,
        options,
        dependencies,
      );
      expect(prepared.preview.excluded).toEqual([]);
      expect(prepared.preview.findings).toHaveLength(1);
      expect(await listLocalExternalFindings(options, dependencies)).toEqual(
        [],
      );
      expect((await prepared.import()).counts).toEqual({
        created: 1,
        updated: 0,
        unchanged: 0,
      });

      const [stored] = await listLocalExternalFindings(options, dependencies);
      expect(stored).toMatchObject({
        repository: fixture.repository,
        provider: "snyk",
        sourceKey: options.sourceKey,
        sourceFindingId: prepared.preview.findings[0]!.source_finding_id,
        version: 1,
      });
      expect(stored!.evidence).toEqual(prepared.preview.findings[0]!.evidence);
      expect(stored!.assessment).toEqual({ state: "not_assessed" });
      expect(stored!.evidence).not.toHaveProperty("confidence");
      if ("findings" in input) {
        expect(stored!.evidence.locations).toEqual([]);
        expect(stored!.evidence.packages![0]!.manifest_path).toBeNull();
        expect(stored!.evidence.source_data).toMatchObject({
          collection: input.collection,
          finding: input.findings[0],
        });
      } else if ("vulnerabilities" in input) {
        expect(stored!.evidence.locations).toEqual([]);
        expect(stored!.evidence.packages![0]!.manifest_path).toBeNull();
        expect(stored!.evidence.source_data).toMatchObject({
          vulnerability: input.vulnerabilities[0],
        });
      } else {
        expect(stored!.evidence.locations).toEqual([]);
        expect(stored!.evidence.packages![0]!.manifest_path).toBeNull();
        expect(stored!.evidence.source_data).toMatchObject({
          result: input.runs[0]!.results[0],
          rule: input.runs[0]!.tool.driver.rules[0],
        });
      }

      const repeated = await prepareLocalExternalImport(
        path,
        options,
        dependencies,
      );
      expect((await repeated.import()).counts).toEqual({
        created: 0,
        updated: 0,
        unchanged: 1,
      });
      expect(await listLocalExternalFindings(options, dependencies)).toEqual([
        stored!,
      ]);

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
      await writeFile(path, JSON.stringify(input));
      const changed = await prepareLocalExternalImport(
        path,
        options,
        dependencies,
      );
      expect((await changed.import()).counts).toEqual({
        created: 0,
        updated: 1,
        unchanged: 0,
      });
      const updated = await listLocalExternalFindings(options, dependencies);
      expect(updated).toHaveLength(1);
      expect(updated[0]).toMatchObject({
        id: stored!.id,
        sourceFindingId: stored!.sourceFindingId,
        createdAt: stored!.createdAt,
        version: 2,
      });
      expect(updated[0]!.assessment).toEqual({ state: "not_assessed" });
      expect(updated[0]!.evidence).toEqual(
        changed.preview.findings[0]!.evidence,
      );
      expect(updated[0]!.evidence.severity).toBe("low");
      expect(updated[0]!.evidence.source_data).not.toEqual(
        stored!.evidence.source_data,
      );
    } finally {
      await fixture.dispose();
    }
  },
);

test.each(["plugin", "SARIF"] as const)(
  "Snyk %s repository provenance cannot be imported into a different local checkout",
  async (format) => {
    const fixture = await localFindingsFixture({
      remote: "https://github.com/example/other",
    });
    try {
      const sarif = snykSarif();
      const input =
        format === "plugin"
          ? snykPluginExport()
          : {
              ...sarif,
              runs: sarif.runs.map((run) => ({
                ...run,
                versionControlProvenance: [
                  { repositoryUri: "https://github.com/example/project" },
                ],
              })),
            };
      const path = join(fixture.root, "snyk.json");
      await writeFile(path, JSON.stringify(input));
      const options = {
        repository: fixture.repository,
        provider: "snyk" as const,
        sourceKey: "snyk-sca",
      };
      const dependencies = { environment: fixture.environment };
      await expect(
        prepareLocalExternalImport(path, options, dependencies),
      ).rejects.toThrow(/repository/iu);
      expect(await listLocalExternalFindings(options, dependencies)).toEqual(
        [],
      );
    } finally {
      await fixture.dispose();
    }
  },
);

test.each([2222, 2223])(
  "Snyk plugin repository matching preserves the SSH port (checkout port %i)",
  async (port) => {
    const fixture = await localFindingsFixture({
      remote: `ssh://git@github.example.test:${port}/example/project.git`,
    });
    try {
      const input = snykPluginExport();
      input.collection.target.repository =
        "ssh://git@github.example.test:2222/example/project.git";
      const path = join(fixture.root, "snyk.json");
      await writeFile(path, JSON.stringify(input));
      const options = {
        repository: fixture.repository,
        provider: "snyk" as const,
        sourceKey: "snyk-sca",
      };
      const dependencies = { environment: fixture.environment };
      if (port !== 2222) {
        await expect(
          prepareLocalExternalImport(path, options, dependencies),
        ).rejects.toThrow(/repository/iu);
        expect(await listLocalExternalFindings(options, dependencies)).toEqual(
          [],
        );
        return;
      }

      const prepared = await prepareLocalExternalImport(
        path,
        options,
        dependencies,
      );
      expect((await prepared.import()).counts.created).toBe(1);
      const records = await listLocalExternalFindings(options, dependencies);
      expect(records).toHaveLength(1);
      expect(records[0]!.evidence.source_data).toMatchObject({
        collection: {
          target: { repository: input.collection.target.repository },
        },
      });
    } finally {
      await fixture.dispose();
    }
  },
);

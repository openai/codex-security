import { execFileSync, spawnSync } from "node:child_process";
import { gzipSync } from "node:zlib";
import { access, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { listLocalExternalFindings } from "../src/external-findings-local.js";
import { readVendorFindings } from "../src/wiz-findings.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";

test("cancels preparation while the source file read is pending", async () => {
  const fixture = await localFindingsFixture();
  try {
    const file = join(fixture.root, "wiz.json");
    const module = new URL(
      "../src/external-findings-import.ts",
      import.meta.url,
    ).href;
    const mocks = new URL("./support/module-mocks.ts", import.meta.url).href;
    const script = `
      import { strictEqual } from "node:assert/strict";
      import * as fs from "node:fs/promises";
      import { setImmediate } from "node:timers/promises";
      import { mockFs } from ${JSON.stringify(mocks)};
      const file = ${JSON.stringify(file)};
      const originalReadFile = fs.readFile;
      let enteredRead, releaseRead;
      const entered = new Promise((resolve) => { enteredRead = resolve; });
      const read = new Promise((resolve) => { releaseRead = resolve; });
      mockFs(() => ({
        readFile: (path, ...args) => {
          if (path !== file) return originalReadFile(path, ...args);
          enteredRead();
          return read;
        },
      }));
      const { prepareLocalExternalImport } = await import(${JSON.stringify(module)});
      const controller = new AbortController();
      const reason = new Error("Synthetic import cancellation");
      let outcome;
      const preparing = prepareLocalExternalImport(
        file,
        ${JSON.stringify({ repository: fixture.repository, provider: "wiz", sourceKey: "example-project/main" })},
        { signal: controller.signal },
      ).then(
        () => { outcome = "fulfilled"; },
        (error) => { outcome = error; },
      );
      await entered;
      controller.abort(reason);
      await setImmediate();
      try {
        strictEqual(outcome, reason);
      } finally {
        releaseRead(Buffer.from("[]"));
        await preparing;
      }
      console.log("CANCELLED");
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      encoding: "utf8",
      env: fixture.environment,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe("CANCELLED");
    await expect(access(fixture.stateDirectory)).rejects.toThrow();
  } finally {
    await fixture.dispose();
  }
});

test("Wiz JSON imports retain parsed evidence through SQLite readback and updates", async () => {
  const fixture = await localFindingsFixture();
  try {
    const file = join(fixture.root, "wiz.json");
    const record = {
      id: "package-occurrence",
      name: "CVE-2026-0001",
      detailedName: "example-package",
      version: "1.0.0",
      severity: "UNKNOWN",
      vulnerableAsset: { id: "source-branch", type: "REPOSITORY_BRANCH" },
      sourceMetadata: { retained: true },
    };
    await writeFile(file, JSON.stringify([record]));
    const options = {
      repository: fixture.repository,
      provider: "wiz" as const,
      sourceKey: "example-project/main",
    };
    const dependencies = { environment: fixture.environment };
    const parsed = await readVendorFindings(file, "local");
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    expect(prepared.preview.findings).toEqual(parsed.findings);
    await expect(
      access(join(fixture.stateDirectory, "workbench.sqlite3")),
    ).rejects.toThrow();
    const first = await prepared.import();
    expect(first.counts).toEqual({ created: 1, updated: 0, unchanged: 0 });
    const stored = await listLocalExternalFindings(
      { repository: fixture.repository },
      dependencies,
    );
    expect(stored).toEqual(first.findings);
    expect(stored[0]).toMatchObject({
      sourceFindingId: "package-occurrence",
      assessment: { state: "not_assessed" },
      version: 1,
      evidence: {
        severity: "unknown",
        locations: [],
        code_revision: null,
        source_data: record,
      },
    });
    expect(stored[0]!.evidence).toEqual(parsed.findings[0]!.evidence);
    expect(
      (
        await (
          await prepareLocalExternalImport(file, options, dependencies)
        ).import()
      ).counts,
    ).toEqual({ created: 0, updated: 0, unchanged: 1 });
    await writeFile(
      file,
      JSON.stringify([{ ...record, fixedVersion: "1.0.1" }]),
    );
    const changed = await (
      await prepareLocalExternalImport(file, options, dependencies)
    ).import();
    expect(changed.counts).toEqual({ created: 0, updated: 1, unchanged: 0 });
    expect(changed.findings[0]).toMatchObject({
      id: stored[0]!.id,
      version: 2,
    });
    expect(
      await listLocalExternalFindings(
        { repository: fixture.repository },
        dependencies,
      ),
    ).toEqual(changed.findings);
  } finally {
    await fixture.dispose();
  }
});

test.each([
  ["raw JSON", "github#repositoryBranch", "github.com"],
  ["normalized JSONL", "github#repositoryBranch", "github.com"],
  ["raw JSON", "REPOSITORY_BRANCH", "github.com"],
  ["normalized JSONL", "REPOSITORY_BRANCH", "github.com"],
  ["raw JSON", "github#repositoryBranch", "git.example.test"],
  ["normalized JSONL", "github#repositoryBranch", "git.example.test"],
  ["gzip JSON", "github#repositoryBranch", "git.example.test"],
  ["gzip normalized JSONL", "github#repositoryBranch", "git.example.test"],
  ["named GraphQL JSON", "github#repositoryBranch", "git.example.test"],
] as const)(
  "Wiz package %s (%s on %s) binds repository-branch URLs before storing evidence",
  async (format, assetType, host) => {
    const fixture = await localFindingsFixture({
      remote: `git@${host}:example/project.git`,
    });
    try {
      const file = join(fixture.root, "wiz.json");
      const record = {
        id: "package-occurrence",
        name: "CVE-2026-0001",
        detailedName: "example-package",
        severity: "HIGH",
        vulnerableAsset: {
          id: "source-branch",
          ...(assetType === "github#repositoryBranch"
            ? { nativeType: assetType }
            : { type: assetType }),
          cloudProviderURL: `https://${host}/example/other/tree/main`,
        },
      };
      const options = {
        repository: fixture.repository,
        provider: "wiz" as const,
        sourceKey: "example-project/main",
      };
      const dependencies = { environment: fixture.environment };
      async function writeSelection() {
        const contents = JSON.stringify(
          format === "named GraphQL JSON"
            ? { data: { vulnerabilityFindings: { nodes: [record] } } }
            : [record],
        );
        await writeFile(
          file,
          format === "gzip JSON" ? gzipSync(contents) : contents,
        );
        const parsed = await readVendorFindings(file, "local");
        if (format.includes("normalized JSONL")) {
          const normalized = parsed.findings
            .map((finding) => JSON.stringify(finding))
            .join("\n");
          await writeFile(
            file,
            format.startsWith("gzip") ? gzipSync(normalized) : normalized,
          );
        }
        return parsed;
      }
      await writeSelection();
      await expect(
        prepareLocalExternalImport(file, options, dependencies),
      ).rejects.toThrow("does not match");
      await expect(
        access(join(fixture.stateDirectory, "workbench.sqlite3")),
      ).rejects.toThrow();

      record.vulnerableAsset.cloudProviderURL = `https://${host}/Example/Project/tree/feature/imports`;
      const parsed = await writeSelection();
      const prepared = await prepareLocalExternalImport(
        file,
        options,
        dependencies,
      );
      expect(prepared.preview.findings).toEqual(parsed.findings);
      const imported = await prepared.import();
      expect(imported.counts.created).toBe(1);
      const [stored] = await listLocalExternalFindings(options, dependencies);
      expect(stored!.evidence).toEqual(parsed.findings[0]!.evidence);
      expect(stored!.evidence.source_data).toEqual(record);
      expect(stored!.evidence.code_revision).toBeNull();
    } finally {
      await fixture.dispose();
    }
  },
);

test.each(["raw JSON", "normalized JSONL"])(
  "Wiz package %s retains generic repository URLs without guessing their platform",
  async (format) => {
    const fixture = await localFindingsFixture({
      remote: "git@git.example.test:example/group/project.git",
    });
    try {
      const file = join(fixture.root, "wiz.json");
      const record = {
        id: "package-occurrence",
        name: "CVE-2026-0001",
        detailedName: "example-package",
        severity: "HIGH",
        vulnerableAsset: {
          id: "source-branch",
          type: "REPOSITORY_BRANCH",
          cloudProviderURL: "",
        },
      };
      const options = {
        repository: fixture.repository,
        provider: "wiz" as const,
        sourceKey: "example-project/main",
      };
      const dependencies = { environment: fixture.environment };
      async function writeSelection(url: string) {
        record.vulnerableAsset.cloudProviderURL = url;
        await writeFile(file, JSON.stringify([record]));
        const parsed = await readVendorFindings(file, "local");
        if (format === "normalized JSONL")
          await writeFile(
            file,
            parsed.findings
              .map((finding) => JSON.stringify(finding))
              .join("\n"),
          );
        return parsed;
      }
      for (const path of [
        "example/group/other",
        "Example/Group/Project",
        "example/group/project/tree/main",
      ]) {
        await writeSelection(`https://git.example.test/${path}`);
        await expect(
          prepareLocalExternalImport(file, options, dependencies),
        ).rejects.toThrow("does not match");
        await expect(
          access(join(fixture.stateDirectory, "workbench.sqlite3")),
        ).rejects.toThrow();
      }
      const parsed = await writeSelection(
        "https://git.example.test/example/group/project",
      );
      const prepared = await prepareLocalExternalImport(
        file,
        options,
        dependencies,
      );
      expect(prepared.preview.findings).toEqual(parsed.findings);
      expect((await prepared.import()).counts.created).toBe(1);
      const [stored] = await listLocalExternalFindings(options, dependencies);
      expect(stored!.evidence.source_data).toEqual(record);
    } finally {
      await fixture.dispose();
    }
  },
);

for (const kind of [
  "sastFindings",
  "secretInstances",
  "iacFindings",
] as const) {
  test.each(["JSON with supplied URL", "gzip with inventory URL"])(
    `Wiz ${kind} %s retains selected GitHub inventory provenance locally`,
    async (format) => {
      const fixture = await localFindingsFixture({
        remote: "git@git.example.test:example/project.git",
      });
      try {
        const repository = {
          id: "source-repository",
          ...(format.startsWith("JSON")
            ? { url: "https://git.example.test/Example/Project" }
            : {}),
        };
        const record = {
          id: "named-occurrence",
          name: "Example finding",
          severity: "HIGH",
          ...(kind === "secretInstances"
            ? {
                resource: {
                  type: "REPOSITORY_BRANCH",
                  typedProperties: { repository },
                  name: "feature/imports",
                },
              }
            : { repository, filePath: "src/example.ts", startLine: 4 }),
        };
        const inventory = {
          nodes: [
            {
              repository: {
                id: repository.id,
                url: "https://git.example.test/EXAMPLE/PROJECT",
              },
            },
            {
              platform: "GITHUB",
              repository: {
                id: repository.id,
                url: "https://git.example.test/example/project",
              },
            },
            {
              platform: "GITHUB",
              repository: {
                id: "unselected-repository",
                url: "https://other.example.test/example/other",
              },
            },
          ],
        };
        const file = join(fixture.root, "named-wiz.json");
        async function writeReport(nodes: unknown[]) {
          const contents = JSON.stringify({
            data: {
              versionControlResources: inventory,
              [kind]: { nodes },
            },
          });
          await writeFile(
            file,
            format.startsWith("gzip") ? gzipSync(contents) : contents,
          );
        }
        await writeReport([record, { ...record, id: "" }]);
        const options = {
          repository: fixture.repository,
          provider: "wiz" as const,
          sourceKey: "named-project/main",
        };
        const dependencies = { environment: fixture.environment };
        const parsed = await readVendorFindings(file, "local");
        expect(parsed.findings).toHaveLength(1);
        expect(parsed.excluded).toHaveLength(1);
        execFileSync(
          "git",
          [
            "remote",
            "set-url",
            "origin",
            "git@git.example.test:example/other.git",
          ],
          { cwd: fixture.repository },
        );
        await expect(
          prepareLocalExternalImport(file, options, dependencies),
        ).rejects.toThrow("does not match");
        await expect(
          access(join(fixture.stateDirectory, "workbench.sqlite3")),
        ).rejects.toThrow();
        execFileSync(
          "git",
          [
            "remote",
            "set-url",
            "origin",
            "git@git.example.test:example/project.git",
          ],
          { cwd: fixture.repository },
        );
        const prepared = await prepareLocalExternalImport(
          file,
          options,
          dependencies,
        );
        expect(prepared.preview).toMatchObject(parsed);
        await expect(
          access(join(fixture.stateDirectory, "workbench.sqlite3")),
        ).rejects.toThrow();
        const created = await prepared.import();
        expect(created.counts.created).toBe(1);
        expect(created.findings[0]!.evidence).toEqual(
          parsed.findings[0]!.evidence,
        );
        expect(created.findings[0]!.evidence.source_data).toEqual(record);

        // Normalized rows may retain their inventory in a supported named envelope.
        await writeReport(parsed.findings);
        expect(
          (
            await (
              await prepareLocalExternalImport(file, options, dependencies)
            ).import()
          ).counts.unchanged,
        ).toBe(1);
        for (const remote of [
          "git@git.example.test:example/other.git",
          "git@other.example.test:example/project.git",
        ]) {
          execFileSync("git", [
            "-C",
            fixture.repository,
            "remote",
            "set-url",
            "origin",
            remote,
          ]);
          await expect(
            prepareLocalExternalImport(file, options, dependencies),
          ).rejects.toThrow("does not match");
        }
        execFileSync("git", [
          "-C",
          fixture.repository,
          "remote",
          "set-url",
          "origin",
          "git@git.example.test:example/project.git",
        ]);
        expect(await listLocalExternalFindings(options, dependencies)).toEqual(
          created.findings,
        );

        // Findings-only JSONL does not contain the discarded envelope's platform.
        await writeFile(
          file,
          parsed.findings.map((finding) => JSON.stringify(finding)).join("\n"),
        );
        await expect(
          prepareLocalExternalImport(file, options, dependencies),
        ).rejects.toThrow("does not match");
        const withMetadata = await prepareLocalExternalImport(file, options, {
          ...dependencies,
          sourceRepositories: [
            {
              url: parsed.findings[0]!.evidence.details!.repository!.url,
              platform: "github",
            },
          ],
        });
        expect((await withMetadata.import()).counts.unchanged).toBe(1);
        expect(await listLocalExternalFindings(options, dependencies)).toEqual(
          created.findings,
        );
      } finally {
        await fixture.dispose();
      }
    },
  );
}

import { existsSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdir, symlink, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import type { ExternalFindings } from "../src/external-findings.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";

const fixtures: Awaited<ReturnType<typeof localFindingsFixture>>[] = [];
async function fixture(
  options: Parameters<typeof localFindingsFixture>[0] = {},
) {
  const result = await localFindingsFixture(options);
  fixtures.push(result);
  return result;
}
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((item) => item.dispose()));
});

function input(): ExternalFindings {
  return {
    read: 3,
    findings: [
      {
        source_finding_id: "scanner-finding-1",
        evidence: {
          title: "Dependency vulnerability",
          severity: "unknown",
          source_data: {
            id: "scanner-finding-1",
            metadata: { nullable: null, list: [1, "two"] },
          },
        },
      },
      {
        source_finding_id: "scanner-finding-2",
        evidence: {
          title: "Reported source issue",
          severity: "high",
          branch: "release",
          code_revision: "scanner-revision",
          locations: [{ path: "src/main.ts" }],
          source_data: { finding: 2 },
        },
      },
    ],
    excluded: [
      {
        position: 2,
        source_finding_id: null,
        reason: "No supported finding evidence",
      },
    ],
  };
}

const source = { provider: "snyk" as const, sourceKey: "example-project/main" };

describe("local normalized scanner findings", () => {
  test("persists sparse evidence through the native helper and reads it in a separate process", async () => {
    const { repository, stateDirectory, environment } = await fixture();
    const normalized = input();
    const prepared = await prepareNormalizedLocalImport(
      normalized,
      { repository, ...source },
      { environment },
    );
    expect(prepared.preview).toEqual({
      ...normalized,
      repository,
      source: { provider: source.provider, source_key: source.sourceKey },
    });
    expect(existsSync(stateDirectory)).toBe(false);
    normalized.findings[0]!.evidence.title = "Later caller edit";
    prepared.preview.findings[0]!.evidence.title = "Later preview edit";
    const result = await prepared.import();
    expect(result).toMatchObject({
      repository,
      read: 3,
      ready: 2,
      excluded: input().excluded,
      counts: { created: 2, updated: 0, unchanged: 0 },
    });
    expect(existsSync(join(stateDirectory, "workbench.sqlite3"))).toBe(true);
    expect(result.findings.map((row) => row.evidence)).toEqual(
      input().findings.map((row) => row.evidence),
    );
    for (const row of result.findings) {
      expect(row).toMatchObject({
        repository,
        ...source,
        version: 1,
        assessment: { state: "not_assessed" },
      });
      expect(row.createdAt).toBe(row.updatedAt);
    }
    const reloaded = await listLocalExternalFindings(
      { repository },
      { environment },
    );
    expect(new Map(reloaded.map((row) => [row.id, row]))).toEqual(
      new Map(result.findings.map((row) => [row.id, row])),
    );
    expect(
      await listLocalExternalFindings(
        { repository, id: result.findings[0]!.id },
        { environment },
      ),
    ).toEqual([result.findings[0]!]);
  });

  test("upserts reordered and changed exports without deleting omitted records or mixing namespaces", async () => {
    const { root, repository, environment } = await fixture();
    const save = async (
      data: ExternalFindings,
      options = { repository, ...source },
    ) =>
      (
        await prepareNormalizedLocalImport(data, options, { environment })
      ).import();
    const initial = await save(input());
    const reordered = input();
    reordered.findings.reverse();
    reordered.findings[1]!.evidence.source_data = {
      metadata: { list: [1, "two"], nullable: null },
      id: "scanner-finding-1",
    };
    const repeated = await save(reordered);
    expect(repeated.counts).toEqual({ created: 0, updated: 0, unchanged: 2 });
    expect(repeated.findings).toEqual([...initial.findings].reverse());
    const changed = input();
    changed.findings = [changed.findings[0]!];
    changed.findings[0]!.evidence.severity = "critical";
    const updated = await save(changed);
    expect(updated.counts).toEqual({ created: 0, updated: 1, unchanged: 0 });
    expect(updated.findings[0]).toMatchObject({
      id: initial.findings[0]!.id,
      version: 2,
      createdAt: initial.findings[0]!.createdAt,
    });
    expect(
      await listLocalExternalFindings(
        { repository, id: initial.findings[1]!.id },
        { environment },
      ),
    ).toEqual([initial.findings[1]!]);
    const otherSource = await save(changed, {
      repository,
      ...source,
      sourceKey: "other-project/main",
    });
    const otherProvider = await (
      await prepareNormalizedLocalImport(
        changed,
        { repository, ...source, provider: "endor" },
        { environment },
      )
    ).import();
    const otherRepository = join(root, "other-repository");
    await mkdir(otherRepository);
    const otherCheckout = await save(changed, {
      repository: otherRepository,
      ...source,
    });
    expect(
      new Set(
        [updated, otherSource, otherProvider, otherCheckout].map(
          (result) => result.findings[0]!.id,
        ),
      ).size,
    ).toBe(4);
    expect(
      await listLocalExternalFindings(
        { repository: otherRepository },
        { environment },
      ),
    ).toEqual(otherCheckout.findings);
    expect(
      (await listLocalExternalFindings({ repository }, { environment })).length,
    ).toBe(4);
  });

  test("preparation and cancellation leave the database untouched", async () => {
    const { repository, stateDirectory, environment } = await fixture();
    const controller = new AbortController();
    const prepared = await prepareNormalizedLocalImport(
      input(),
      { repository, ...source },
      { environment, signal: controller.signal },
    );
    expect(existsSync(stateDirectory)).toBe(false);
    controller.abort();
    await expect(prepared.import()).rejects.toThrow();
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository, ...source },
        { environment, signal: controller.signal },
      ),
    ).rejects.toThrow();
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("rejects duplicate occurrence identities before creating local state", async () => {
    const { repository, stateDirectory, environment } = await fixture();
    const duplicate = input();
    duplicate.findings.push(duplicate.findings[0]!);
    await expect(
      prepareNormalizedLocalImport(
        duplicate,
        { repository, ...source },
        { environment },
      ),
    ).rejects.toThrow("Duplicate source finding id");
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("rejects non-finite JSON before it can be stored as null", async () => {
    const { repository, stateDirectory, environment } = await fixture();
    const data = input();
    data.findings[0]!.evidence.source_data = JSON.parse('{"score":1e999}');
    await expect(
      prepareNormalizedLocalImport(
        data,
        { repository, ...source },
        { environment },
      ),
    ).rejects.toThrow("non-finite numbers");
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("uses the canonical selected checkout and rejects state inside it", async () => {
    const { root, repository, environment } = await fixture();
    const link = join(root, "repository-link");
    await symlink(
      repository,
      link,
      process.platform === "win32" ? "junction" : "dir",
    );
    const prepared = await prepareNormalizedLocalImport(
      input(),
      { repository: link, ...source },
      { environment },
    );
    expect(prepared.preview.repository).toBe(repository);
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository, ...source },
        {
          environment: {
            ...environment,
            CODEX_SECURITY_STATE_DIR: join(repository, "state"),
          },
        },
      ),
    ).rejects.toThrow();
    const child = join(repository, "src");
    await mkdir(child);
    await expect(
      prepareNormalizedLocalImport(
        input(),
        { repository: child, ...source },
        {
          environment: {
            ...environment,
            CODEX_SECURITY_STATE_DIR: join(repository, "state"),
          },
        },
      ),
    ).rejects.toThrow();
    expect(existsSync(join(repository, "state"))).toBe(false);
  });

  test("matches source repository context against SSH remotes and reader metadata", async () => {
    const { repository, stateDirectory, environment } = await fixture({
      remote: "git@github.com:Example/Project.git",
    });
    const data = input();
    data.findings[0]!.evidence.details = {
      kind: "sast",
      repository: { url: "https://github.com/example/project" },
    };
    await prepareNormalizedLocalImport(
      data,
      { repository, ...source },
      { environment },
    );
    await expect(
      prepareNormalizedLocalImport(
        data,
        { repository, ...source },
        {
          environment,
          sourceRepositories: [{ url: "https://github.com/example/other" }],
        },
      ),
    ).rejects.toThrow("does not match a configured remote");
    data.findings[0]!.evidence.details.repository!.url =
      "https://github.com/example/other";
    await expect(
      prepareNormalizedLocalImport(
        data,
        { repository, ...source },
        { environment },
      ),
    ).rejects.toThrow("does not match a configured remote");
    execFileSync("git", [
      "-C",
      repository,
      "remote",
      "add",
      "upstream",
      "https://github.com/example/other.git",
    ]);
    await prepareNormalizedLocalImport(
      data,
      { repository, ...source },
      { environment },
    );
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("repository matching ignores Git executables in a separate caller checkout", async () => {
    const { root, repository, stateDirectory, environment } = await fixture({
      remote: "https://github.com/example/project",
    });
    const caller = join(root, "caller");
    const callerDirectory = join(caller, "src");
    const callerBin = join(caller, "tools");
    const marker = join(root, "caller-git-executed");
    await Promise.all([
      mkdir(join(caller, ".git"), { recursive: true }),
      mkdir(callerDirectory, { recursive: true }),
      mkdir(callerBin, { recursive: true }),
    ]);
    await writeFile(
      join(callerBin, process.platform === "win32" ? "git.exe" : "git"),
      process.platform === "win32"
        ? "untrusted executable fixture\n"
        : '#!/bin/sh\nprintf executed > "$TEST_LOCAL_IMPORT_GIT_MARKER"\nexit 1\n',
      { mode: 0o700 },
    );
    const inheritedPath = Object.entries(environment).find(
      ([name]) => name.toUpperCase() === "PATH",
    )?.[1];
    const module = new URL("../src/external-findings-local.ts", import.meta.url)
      .href;
    const script = `
      import { rejects } from "node:assert/strict";
      const { prepareNormalizedLocalImport } = await import(${JSON.stringify(module)});
      const input = { read: 0, findings: [], excluded: [] };
      const options = ${JSON.stringify({ repository, ...source })};
      await prepareNormalizedLocalImport(input, options, {
        sourceRepositories: [{ url: "https://github.com/example/project" }],
      });
      await rejects(
        prepareNormalizedLocalImport(input, options, {
          sourceRepositories: [{ url: "https://github.com/example/other" }],
        }),
        /does not match a configured remote/,
      );
    `;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: callerDirectory,
      encoding: "utf8",
      env: {
        ...Object.fromEntries(
          Object.entries(environment).filter(
            ([name]) => name.toUpperCase() !== "PATH",
          ),
        ),
        PATH: [callerBin, inheritedPath ?? ""].join(delimiter),
        TEST_LOCAL_IMPORT_GIT_MARKER: marker,
      },
    });
    expect(result.status, result.stderr).toBe(0);
    expect(existsSync(marker)).toBe(false);
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("matches custom GitHub Enterprise names without changing other VCS identities", async () => {
    const { repository, stateDirectory, environment } = await fixture({
      remote: "git@git.example.test:example/project.git",
    });
    const data = input();
    data.findings[0]!.evidence.details = {
      kind: "sast",
      repository: { url: "https://git.example.test/Example/Project" },
    };
    const options = { repository, ...source, provider: "github" as const };
    const dependencies = {
      environment,
      sourceRepositories: [{ url: "https://git.example.test/EXAMPLE/PROJECT" }],
    };
    const prepared = await prepareNormalizedLocalImport(
      data,
      options,
      dependencies,
    );
    expect(prepared.preview.findings).toEqual(data.findings);
    await expect(
      prepareNormalizedLocalImport(
        data,
        { ...options, provider: "semgrep" },
        dependencies,
      ),
    ).rejects.toThrow("does not match a configured remote");
    for (const url of [
      "https://git.example.test/example/other",
      "https://other.example.test/example/project",
      "http://git.example.test/example/project",
      "https://git.example.test:8443/example/project",
    ]) {
      data.findings[0]!.evidence.details.repository!.url = url;
      await expect(
        prepareNormalizedLocalImport(data, options, dependencies),
      ).rejects.toThrow("does not match a configured remote");
    }
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("retains reader-provided GitHub identity for a matching typed repository URL", async () => {
    const { repository, stateDirectory, environment } = await fixture({
      remote: "git@git.example.test:example/project.git",
    });
    const data = input();
    const url = "https://git.example.test/Example/Project";
    data.findings[0]!.evidence.details = { kind: "sast", repository: { url } };
    const options = { repository, ...source, provider: "wiz" as const };
    await expect(
      prepareNormalizedLocalImport(data, options, { environment }),
    ).rejects.toThrow("does not match a configured remote");
    const dependencies = {
      environment,
      sourceRepositories: [{ url, platform: "github" as const }, { url }],
    };
    const prepared = await prepareNormalizedLocalImport(
      data,
      options,
      dependencies,
    );
    expect(prepared.preview.findings).toEqual(data.findings);
    for (const different of [
      "https://git.example.test/example/other",
      "https://other.example.test/example/project",
      "http://git.example.test/example/project",
      "https://git.example.test:8443/example/project",
    ]) {
      await expect(
        prepareNormalizedLocalImport(data, options, {
          ...dependencies,
          sourceRepositories: [
            ...dependencies.sourceRepositories,
            { url: different, platform: "github" },
          ],
        }),
      ).rejects.toThrow("does not match a configured remote");
    }
    expect(existsSync(stateDirectory)).toBe(false);
  });

  test("does not impose Cloud field-size limits on normalized local evidence", async () => {
    const { repository, environment } = await fixture();
    const data = input();
    data.findings[0]!.evidence.description = "x".repeat(65537);
    data.findings[0]!.evidence.locations = Array.from(
      { length: 101 },
      (_, index) => ({ path: `src/file-${index}.ts` }),
    );
    const result = await (
      await prepareNormalizedLocalImport(
        data,
        { repository, ...source },
        { environment },
      )
    ).import();
    expect(
      (
        await listLocalExternalFindings(
          { repository, id: result.findings[0]!.id },
          { environment },
        )
      )[0]!.evidence,
    ).toEqual(data.findings[0]!.evidence);
  });
});

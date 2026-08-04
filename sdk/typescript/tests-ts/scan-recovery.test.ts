import { spawnSync } from "node:child_process";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { runWorkbench } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

type Finding = Record<string, unknown> & {
  ruleId: string;
  identity: { anchor: string; instance?: string };
  summary: string;
  severity: { level: string; changeConditions?: unknown };
  confidence: { level: string };
  locations: Array<{ path: string }>;
  codeEvidence?: Array<{
    id: string;
    label: string;
    path: string;
    startLine: number;
    code: string;
    explanation: string;
  }>;
  writeup?: unknown;
  remediationTests?: unknown;
  preventiveControls?: unknown;
};

type FindingsDocument = {
  scanId: string;
  findings: Array<Finding | null>;
};

type CoverageSurface = Record<string, unknown> & {
  id: string;
  label: string;
  disposition: string;
  receiptRefs: unknown[];
};

type CoverageDocument = Record<string, unknown> & {
  scanId: string;
  completeness: string;
  inventoryStrategy: string;
  surfaces: CoverageSurface[] | Record<string, unknown>;
  explicitExclusions: unknown;
  deferred: unknown;
};

type ScanSummary = {
  findingCount: number;
  progress: { status: string };
  warnings: string[];
};

type SarifDocument = {
  runs: Array<{
    properties: { codexSecurityCoverageCompleteness?: string };
    results: Array<{ properties: { severity: string } }>;
    invocations?: Array<{
      executionSuccessful: boolean;
      toolExecutionNotifications: Array<{
        level: string;
        message: { text: string };
      }>;
    }>;
  }>;
};

type ScanFixture = {
  python: string;
  repository: string;
  stateDir: string;
  scanDir: string;
  scanId: string;
  registration: Record<string, unknown>;
};

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value)}\n`);
}

async function workbench(
  fixture: ScanFixture,
  args: readonly string[],
  protectedEnvironment: Record<string, string> = {},
) {
  return runWorkbench(
    {
      python: fixture.python,
      pluginRoot: PLUGIN_ROOT,
      environment: {
        PATH: process.env["PATH"],
        CODEX_SECURITY_STATE_DIR: fixture.stateDir,
        ...protectedEnvironment,
      },
    },
    args,
  );
}

async function startDraftScan(
  repositoryKind: "directory" | "clean" | "dirty" | "nested" = "directory",
  requestedPaths?: string[],
  beforeRegistration?: (repository: string) => Promise<void>,
): Promise<ScanFixture> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-scan-recovery-")),
  );
  temporaryDirectories.push(root);
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();

  const target = join(root, "repository");
  const scanDir = join(root, "scan");
  await mkdir(join(target, "src"), { recursive: true });
  await writeFile(join(target, "src", "extract.py"), "# fixture\n");
  await mkdir(scanDir, { mode: 0o700 });

  if (repositoryKind !== "directory") {
    for (const args of [
      ["init", "--quiet", target],
      ["-C", target, "add", "--", "src/extract.py"],
      [
        "-C",
        target,
        "-c",
        "user.name=Codex Security",
        "-c",
        "user.email=codex-security@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "fixture",
      ],
    ]) {
      const result = spawnSync("git", args, { encoding: "utf8" });
      expect(result.status, result.stderr).toBe(0);
    }
    if (repositoryKind === "dirty") {
      await writeFile(join(target, "src", "extract.py"), "# changed fixture\n");
    }
    if (repositoryKind === "nested") {
      const nested = join(target, "nested");
      await mkdir(nested);
      await writeFile(join(nested, "source.py"), "# nested fixture\n");
      const initialized = spawnSync("git", ["init", "--quiet", nested], {
        encoding: "utf8",
      });
      expect(initialized.status, initialized.stderr).toBe(0);
    }
  }

  await beforeRegistration?.(target);

  const fixture: ScanFixture = {
    python: python!,
    repository: target,
    stateDir: join(root, "state"),
    scanDir,
    scanId: "",
    registration: {},
  };
  const registration = await workbench(fixture, [
    "register-cli-scan",
    "--repository",
    target,
    "--scan-dir",
    scanDir,
    "--recipe-json",
    JSON.stringify({
      config: {},
      mode: "standard",
      repository: target,
      target:
        requestedPaths === undefined
          ? { kind: "repository", paths: [] }
          : { kind: "paths", paths: requestedPaths },
    }),
  ]);
  fixture.scanId = String(registration["scanId"]);
  fixture.registration = registration;

  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), scanDir, {
    recursive: true,
  });
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = await readJson<{
    scan: {
      id: string;
      target: { kind: string };
      sealedAt?: string;
      artifacts?: unknown[];
    };
  }>(manifestPath);
  manifest.scan.id = fixture.scanId;
  manifest.scan.target.kind =
    repositoryKind === "directory"
      ? "directory_snapshot"
      : repositoryKind === "clean"
        ? "git_revision"
        : "git_worktree";
  delete manifest.scan.sealedAt;
  delete manifest.scan.artifacts;
  await writeJson(manifestPath, manifest);

  for (const name of ["findings.json", "coverage.json"] as const) {
    const path = join(scanDir, name);
    const document = await readJson<{ scanId: string }>(path);
    document.scanId = fixture.scanId;
    await writeJson(path, document);
  }
  await writeFile(join(scanDir, "report.md"), "# Draft report\n");
  return fixture;
}

async function completeScan(fixture: ScanFixture): Promise<ScanSummary> {
  const result = await workbench(fixture, [
    "complete-scan",
    "--scan-id",
    fixture.scanId,
  ]);
  return result["scan"] as unknown as ScanSummary;
}

describe("malformed scan artifact recovery", () => {
  test("rejects oversized scope exclusion contracts before registration output", async () => {
    const fixture = await startDraftScan();
    const scanDir = join(fixture.stateDir, "oversized-scope-scan");
    await mkdir(scanDir, { mode: 0o700 });
    const recipe = JSON.stringify({
      config: {},
      mode: "standard",
      repository: fixture.repository,
      target: { kind: "repository", paths: [] },
    });
    const result = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        [
          "import sys",
          "sys.path.insert(0, sys.argv[1])",
          "import workbench_db",
          "workbench_db.standard_scope_exclusions = lambda *_: [",
          "    {'pattern': f'{index:04d}', 'reason': 'x' * 1024}",
          "    for index in range(1100)",
          "]",
          "sys.argv = ['workbench_db.py', *sys.argv[2:]]",
          "workbench_db.main()",
        ].join("\n"),
        join(PLUGIN_ROOT, "scripts"),
        "register-cli-scan",
        "--repository",
        fixture.repository,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        recipe,
      ],
      {
        encoding: "utf8",
        env: {
          PATH: process.env["PATH"],
          CODEX_SECURITY_STATE_DIR: fixture.stateDir,
        },
      },
    );

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("scope exclusions exceed the 1 MiB");
    expect(result.stdout).toBe("");
  });

  test("verifies app-backed standard coverage before publishing scan completion", async () => {
    const fixture = await startDraftScan();
    const discovery = join(fixture.scanDir, "artifacts", "02_discovery");
    await mkdir(discovery, { recursive: true });
    await writeFile(join(discovery, "scope_inventory.jsonl"), "");
    const before = await readFile(
      join(fixture.scanDir, "scan-manifest.json"),
      "utf8",
    );

    await expect(completeScan(fixture)).rejects.toThrow("Scope-review ledger");
    const context = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((context["scan"] as ScanSummary).progress.status).toBe("running");
    expect(
      await readFile(join(fixture.scanDir, "scan-manifest.json"), "utf8"),
    ).toBe(before);
  });

  test("rejects a missing durable inventory when a protected snapshot exists", async () => {
    const fixture = await startDraftScan();
    const protectedInventory = join(
      fixture.stateDir,
      "protected-inventory.jsonl",
    );
    await writeFile(protectedInventory, "");
    const before = await readFile(
      join(fixture.scanDir, "scan-manifest.json"),
      "utf8",
    );

    await expect(
      workbench(fixture, ["complete-scan", "--scan-id", fixture.scanId], {
        CODEX_SECURITY_SCOPE_INVENTORY_FILE: protectedInventory,
      }),
    ).rejects.toThrow("Durable standard scope inventory is missing");
    const context = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((context["scan"] as ScanSummary).progress.status).toBe("running");
    expect(
      await readFile(join(fixture.scanDir, "scan-manifest.json"), "utf8"),
    ).toBe(before);
  });

  test("rejects scan recipe paths that differ from their protected snapshot", async () => {
    const fixture = await startDraftScan("directory", ["src"]);
    const protectedPaths = join(fixture.stateDir, "protected-scope-paths.json");
    await writeFile(protectedPaths, `${JSON.stringify(["src"])}\n`);
    const tamper = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        [
          "import json, sqlite3, sys",
          "with sqlite3.connect(sys.argv[1]) as connection:",
          "    recipe = json.loads(connection.execute('SELECT recipe_json FROM scans WHERE id = ?', (sys.argv[2],)).fetchone()[0])",
          "    recipe['target']['paths'] = ['.']",
          "    connection.execute('UPDATE scans SET recipe_json = ? WHERE id = ?', (json.dumps(recipe), sys.argv[2]))",
        ].join("\n"),
        join(fixture.stateDir, "workbench.sqlite3"),
        fixture.scanId,
      ],
      { encoding: "utf8" },
    );
    expect(tamper.status, tamper.stderr).toBe(0);

    await expect(
      workbench(fixture, ["complete-scan", "--scan-id", fixture.scanId], {
        CODEX_SECURITY_SCOPE_PATHS_FILE: protectedPaths,
      }),
    ).rejects.toThrow("scope paths do not match their protected snapshot");
    const context = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((context["scan"] as ScanSummary).progress.status).toBe("running");
  });

  test("reverifies recovered standard findings before writing sealed artifacts", async () => {
    const fixture = await startDraftScan();
    const discovery = join(fixture.scanDir, "artifacts", "02_discovery");
    await mkdir(discovery, { recursive: true });
    await writeFile(join(discovery, "scope_inventory.jsonl"), "");
    const findingsPath = join(fixture.scanDir, "findings.json");
    const findings = await readJson<FindingsDocument>(findingsPath);
    delete findings.findings[0]!["title"];
    await writeJson(findingsPath, findings);
    const before = await readFile(
      join(fixture.scanDir, "scan-manifest.json"),
      "utf8",
    );
    const result = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        [
          "import sys",
          "sys.path.insert(0, sys.argv[1])",
          "import workbench_db",
          "def verify(args):",
          "    if hasattr(args, 'findings') and not args.findings['findings']:",
          "        raise SystemExit('Finalizer recovery discarded an authoritative scan finding.')",
          "workbench_db.verify_scope_coverage = verify",
          "sys.argv = ['workbench_db.py', *sys.argv[2:]]",
          "workbench_db.main()",
        ].join("\n"),
        join(PLUGIN_ROOT, "scripts"),
        "complete-scan",
        "--scan-id",
        fixture.scanId,
      ],
      {
        encoding: "utf8",
        env: {
          PATH: process.env["PATH"],
          CODEX_SECURITY_STATE_DIR: fixture.stateDir,
        },
      },
    );

    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(
      "Finalizer recovery discarded an authoritative scan finding",
    );
    const context = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((context["scan"] as ScanSummary).progress.status).toBe("running");
    expect(
      await readFile(join(fixture.scanDir, "scan-manifest.json"), "utf8"),
    ).toBe(before);
  });

  test("rejects model-edited persisted scope exclusions against the protected snapshot", async () => {
    const fixture = await startDraftScan();
    const scope = (
      fixture.registration["contract"] as {
        scope: {
          requiredExplicitExclusions: Array<{
            pattern: string;
            reason: string;
          }>;
        };
      }
    ).scope.requiredExplicitExclusions;
    const attestation = join(
      fixture.stateDir,
      "expected-scope-exclusions.json",
    );
    await writeFile(attestation, JSON.stringify(scope));
    for (const tampered of [
      "[]",
      null,
      JSON.stringify(
        scope.map((exclusion, index) =>
          index === 0
            ? { ...exclusion, reason: "fabricated reason" }
            : exclusion,
        ),
      ),
    ]) {
      const tamper = spawnSync(
        fixture.python,
        [
          "-I",
          "-B",
          "-c",
          [
            "import sqlite3, sys",
            "with sqlite3.connect(sys.argv[1]) as connection:",
            "    value = None if sys.argv[3] == 'NULL' else sys.argv[3]",
            "    connection.execute('UPDATE scans SET scope_exclusions_json = ? WHERE id = ?', (value, sys.argv[2]))",
          ].join("\n"),
          join(fixture.stateDir, "workbench.sqlite3"),
          fixture.scanId,
          tampered ?? "NULL",
        ],
        { encoding: "utf8" },
      );
      expect(tamper.status, tamper.stderr).toBe(0);

      await expect(
        runWorkbench(
          {
            python: fixture.python,
            pluginRoot: PLUGIN_ROOT,
            environment: {
              PATH: process.env["PATH"],
              CODEX_SECURITY_STATE_DIR: fixture.stateDir,
              CODEX_SECURITY_SCOPE_EXCLUSIONS_FILE: attestation,
            },
          },
          ["get-scan", "--scan-id", fixture.scanId],
        ),
      ).rejects.toThrow(/protected snapshot/iu);
    }
  });

  test("returns the authoritative directory snapshot contract at registration", async () => {
    const fixture = await startDraftScan();
    const registration = fixture.registration;
    const contract = registration["contract"] as {
      target: {
        allowedKinds: string[];
        displayName: string;
        targetId: string;
        requiredSnapshotDigest?: string;
      };
    };

    expect(registration["targetRevision"]).toBe("unversioned");
    expect(contract.target).toMatchObject({
      allowedKinds: ["directory_snapshot"],
      displayName: "repository",
      targetId: registration["targetId"],
      requiredSnapshotDigest: expect.stringMatching(
        /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/,
      ),
    });
  });

  test("binds standard inventory exclusions into the sealed scan contract", async () => {
    const fixture = await startDraftScan();
    const expectedPaths = [
      "**/.git",
      "**/.git/**",
      "**/node_modules",
      "**/node_modules/**",
      ".git",
      "node_modules",
    ];
    const contract = fixture.registration["contract"] as {
      scope: {
        requiredExcludePaths: string[];
        requiredExplicitExclusions: Array<{ pattern: string; reason: string }>;
      };
    };

    expect(contract.scope.requiredExcludePaths).toEqual(expectedPaths);
    expect(
      contract.scope.requiredExplicitExclusions.map((item) => item.pattern),
    ).toEqual(expectedPaths);
    expect(
      contract.scope.requiredExplicitExclusions.every(
        (item) => item.reason.trim().length > 0,
      ),
    ).toBe(true);

    expect((await completeScan(fixture)).progress.status).toBe("complete");

    const manifest = await readJson<{
      scan: { scope: { excludePaths: string[] } };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    const coverage = await readJson<{
      excludePaths: string[];
      explicitExclusions: Array<{ pattern: string; reason: string }>;
    }>(join(fixture.scanDir, "coverage.json"));

    expect(manifest.scan.scope.excludePaths).toEqual(expectedPaths);
    expect(coverage.excludePaths).toEqual(expectedPaths);
    expect(coverage.explicitExclusions).toEqual(
      contract.scope.requiredExplicitExclusions,
    );
  });

  test("preserves registered exclusions when a requested scope disappears", async () => {
    const fixture = await startDraftScan("directory", ["src"]);
    const contract = fixture.registration["contract"] as {
      scope: {
        requiredExcludePaths: string[];
        requiredExplicitExclusions: Array<{ pattern: string; reason: string }>;
      };
    };
    const expectedExclusions = [
      "src/**/.git",
      "src/**/.git/**",
      "src/**/node_modules",
      "src/**/node_modules/**",
      "src/.git",
      "src/node_modules",
    ];

    expect(contract.scope.requiredExcludePaths).toEqual(expectedExclusions);
    await rm(join(fixture.repository, "src"), {
      recursive: true,
      force: true,
    });

    const prepared = await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);

    expect((prepared["scan"] as ScanSummary).progress.status).toBe("running");
    expect((await completeScan(fixture)).progress.status).toBe("complete");

    const manifest = await readJson<{
      scan: { scope: { includePaths: string[]; excludePaths: string[] } };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    const coverage = await readJson<{
      includePaths: string[];
      excludePaths: string[];
      explicitExclusions: Array<{ pattern: string; reason: string }>;
    }>(join(fixture.scanDir, "coverage.json"));

    expect(manifest.scan.scope.includePaths).toEqual(["src"]);
    expect(manifest.scan.scope.excludePaths).toEqual(expectedExclusions);
    expect(coverage.includePaths).toEqual(["src"]);
    expect(coverage.excludePaths).toEqual(expectedExclusions);
    expect(coverage.explicitExclusions).toEqual(
      contract.scope.requiredExplicitExclusions,
    );
  });

  test("preserves a registered symlink exclusion after the link disappears", async () => {
    if (process.platform === "win32") return;

    const fixture = await startDraftScan(
      "directory",
      undefined,
      async (repository) => {
        await symlink("src/extract.py", join(repository, "source-link.py"));
      },
    );
    const contract = fixture.registration["contract"] as {
      scope: {
        requiredExcludePaths: string[];
        requiredExplicitExclusions: Array<{ pattern: string; reason: string }>;
      };
    };

    expect(contract.scope.requiredExcludePaths).toContain("source-link.py");
    expect(contract.scope.requiredExplicitExclusions).toContainEqual({
      pattern: "source-link.py",
      reason:
        "Symbolic links are not followed during standard scope inventory.",
    });
    await rm(join(fixture.repository, "source-link.py"));

    const prepared = await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);

    expect((prepared["scan"] as ScanSummary).progress.status).toBe("running");
    expect((await completeScan(fixture)).progress.status).toBe("complete");

    const coverage = await readJson<{
      excludePaths: string[];
      explicitExclusions: Array<{ pattern: string; reason: string }>;
    }>(join(fixture.scanDir, "coverage.json"));

    expect(coverage.excludePaths).toEqual(contract.scope.requiredExcludePaths);
    expect(coverage.explicitExclusions).toEqual(
      contract.scope.requiredExplicitExclusions,
    );
  });

  test("migrates existing scan state without changing its saved recipe", async () => {
    const fixture = await startDraftScan();
    const recipeArguments = ["get-scan-recipe", "--scan-id", fixture.scanId];
    const originalRecipe = await workbench(fixture, recipeArguments);
    const database = join(fixture.stateDir, "workbench.sqlite3");
    const downgrade = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        [
          "import sqlite3, sys",
          "with sqlite3.connect(sys.argv[1]) as connection:",
          "    connection.execute('ALTER TABLE scans DROP COLUMN scope_exclusions_json')",
          "    connection.execute('DELETE FROM schema_migrations WHERE version = 27')",
        ].join("\n"),
        database,
      ],
      { encoding: "utf8" },
    );
    expect(downgrade.status, downgrade.stderr).toBe(0);

    expect(await workbench(fixture, recipeArguments)).toEqual(originalRecipe);

    const migration = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        [
          "import json, sqlite3, sys",
          "with sqlite3.connect(sys.argv[1]) as connection:",
          "    version = connection.execute('SELECT version FROM schema_migrations WHERE version = 27').fetchone()",
          "    exclusions = connection.execute('SELECT scope_exclusions_json FROM scans WHERE id = ?', (sys.argv[2],)).fetchone()",
          "    print(json.dumps({'version': None if version is None else version[0], 'exclusions': None if exclusions is None else exclusions[0]}))",
        ].join("\n"),
        database,
        fixture.scanId,
      ],
      { encoding: "utf8" },
    );
    expect(migration.status, migration.stderr).toBe(0);
    expect(JSON.parse(migration.stdout)).toEqual({
      version: 27,
      exclusions: null,
    });
    expect((await completeScan(fixture)).progress.status).toBe("complete");
  });

  test("preserves empty exclusions on completed legacy standard scans", async () => {
    const fixture = await startDraftScan();
    const database = join(fixture.stateDir, "workbench.sqlite3");
    const removeExclusions = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        [
          "import sqlite3, sys",
          "with sqlite3.connect(sys.argv[1]) as connection:",
          "    connection.execute('UPDATE scans SET scope_exclusions_json = ? WHERE id = ?', ('[]', sys.argv[2]))",
        ].join("\n"),
        database,
        fixture.scanId,
      ],
      { encoding: "utf8" },
    );
    expect(removeExclusions.status, removeExclusions.stderr).toBe(0);
    expect((await completeScan(fixture)).progress.status).toBe("complete");

    const downgrade = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        [
          "import sqlite3, sys",
          "with sqlite3.connect(sys.argv[1]) as connection:",
          "    connection.execute('ALTER TABLE scans DROP COLUMN scope_exclusions_json')",
          "    connection.execute('DELETE FROM schema_migrations WHERE version = 27')",
        ].join("\n"),
        database,
      ],
      { encoding: "utf8" },
    );
    expect(downgrade.status, downgrade.stderr).toBe(0);

    expect((await completeScan(fixture)).progress.status).toBe("complete");
    expect(
      (
        await readJson<{
          scan: { scope: { excludePaths: string[] } };
        }>(join(fixture.scanDir, "scan-manifest.json"))
      ).scan.scope.excludePaths,
    ).toEqual([]);
  });

  test("rejects tampered registered scope exclusions without sealing a scan", async () => {
    for (const tamperedExclusions of [
      "{}",
      JSON.stringify([
        { pattern: "src", reason: "duplicate" },
        { pattern: "src", reason: "duplicate" },
      ]),
    ]) {
      const fixture = await startDraftScan();
      const database = join(fixture.stateDir, "workbench.sqlite3");
      const tamper = spawnSync(
        fixture.python,
        [
          "-I",
          "-B",
          "-c",
          [
            "import sqlite3, sys",
            "with sqlite3.connect(sys.argv[1]) as connection:",
            "    connection.execute('UPDATE scans SET scope_exclusions_json = ? WHERE id = ?', (sys.argv[2], sys.argv[3]))",
          ].join("\n"),
          database,
          tamperedExclusions,
          fixture.scanId,
        ],
        { encoding: "utf8" },
      );
      expect(tamper.status, tamper.stderr).toBe(0);

      await expect(
        workbench(fixture, [
          "prepare-scan-completion",
          "--scan-id",
          fixture.scanId,
        ]),
      ).rejects.toThrow("Stored standard scope exclusions are invalid.");

      const persisted = spawnSync(
        fixture.python,
        [
          "-I",
          "-B",
          "-c",
          [
            "import sqlite3, sys",
            "with sqlite3.connect(sys.argv[1]) as connection:",
            "    print(connection.execute('SELECT status FROM scans WHERE id = ?', (sys.argv[2],)).fetchone()[0])",
          ].join("\n"),
          database,
          fixture.scanId,
        ],
        { encoding: "utf8" },
      );
      expect(persisted.status, persisted.stderr).toBe(0);
      expect(persisted.stdout.trim()).toBe("running");
    }
  });

  test("returns authoritative clean, dirty, and nested Git target contracts", async () => {
    for (const kind of ["clean", "dirty", "nested"] as const) {
      const fixture = await startDraftScan(kind);
      const registration = fixture.registration;
      const contract = registration["contract"] as {
        target: {
          allowedKinds: string[];
          targetId: string;
          requiredSnapshotDigest?: string;
        };
      };
      const revision = spawnSync(
        "git",
        ["-C", fixture.repository, "rev-parse", "HEAD"],
        { encoding: "utf8" },
      );

      expect(revision.status, revision.stderr).toBe(0);
      expect(registration["targetRevision"]).toBe(revision.stdout.trim());
      expect(registration["targetId"]).toBe(contract.target.targetId);
      expect(contract.target.allowedKinds).toEqual([
        kind === "clean" ? "git_revision" : "git_worktree",
      ]);
      if (kind === "clean") {
        expect(contract.target).not.toHaveProperty("requiredSnapshotDigest");
      } else {
        expect(contract.target.requiredSnapshotDigest).toMatch(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/,
        );
      }
      if (kind === "nested") {
        const copied = spawnSync(
          fixture.python,
          [
            "-I",
            "-B",
            "-c",
            [
              "import sys",
              "from pathlib import Path",
              "sys.path.insert(0, sys.argv[1])",
              "import workbench_target as target",
              "source = Path(sys.argv[2])",
              "checkout = target.copy_git_worktree_files(source, Path(sys.argv[3]), ())",
              "git_dir = Path(target.git_output(source, 'rev-parse', '--absolute-git-dir'))",
              "assert target.worktree_content_digest_for_context(checkout, '.', git_dir=git_dir, work_tree=checkout) == target.worktree_content_digest(source)",
            ].join("\n"),
            join(PLUGIN_ROOT, "scripts"),
            fixture.repository,
            join(fixture.stateDir, "checkout"),
          ],
          { encoding: "utf8" },
        );
        expect(copied.status, copied.stderr).toBe(0);
      }
    }
  });

  test("seals a prepared scan without publishing it before acceptance", async () => {
    const fixture = await startDraftScan();

    const prepared = await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);

    expect((prepared["scan"] as ScanSummary).progress.status).toBe("running");
    const manifest = await readJson<{
      scan: { sealedAt: string; completedAt: string };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(manifest.scan.sealedAt).toBe(manifest.scan.completedAt);
    const running = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((running["scan"] as ScanSummary).progress.status).toBe("running");
    expect((await completeScan(fixture)).progress.status).toBe("complete");
  });

  test("marks rejected prepared scans as failed without publishing completion", async () => {
    const fixture = await startDraftScan();
    await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);
    await writeFile(join(fixture.scanDir, "findings.json"), "corrupted\n");

    const failed = await workbench(fixture, [
      "fail-scan",
      "--scan-id",
      fixture.scanId,
      "--message",
      "Sealed scan could not be accepted.",
    ]);

    expect((failed["scan"] as ScanSummary).progress.status).toBe("failed");
    const stored = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((stored["scan"] as ScanSummary).progress.status).toBe("failed");
  });

  test("normalizes finding identities and persists recovery warnings", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const finding = document.findings[0]!;
    finding.ruleId = "Path Traversal: Archive Extraction";
    finding.identity.anchor = "Archive Entry Write Without Containment";
    finding.identity.instance = "User Input #1";
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toEqual([
      "Recovered finding 1: normalized rule identifier, semantic anchor, instance.",
    ]);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;
    expect(recovered.ruleId).toBe("path-traversal-archive-extraction");
    expect(recovered.identity).toEqual({
      anchor: "archive-entry-write-without-containment",
      instance: "user-input-1",
    });
    const saved = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((saved["scan"] as unknown as ScanSummary).warnings).toEqual(
      completed.warnings,
    );
  });

  test("preserves recovery warnings across prepared scan completion", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    document.findings[0]!.identity.anchor = "Archive Entry Without Containment";
    await writeJson(path, document);

    const prepared = await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);
    const warning = "Recovered finding 1: normalized semantic anchor.";

    expect((prepared["scan"] as ScanSummary).progress.status).toBe("running");
    expect((prepared["scan"] as ScanSummary).warnings).toEqual([warning]);
    const completed = await completeScan(fixture);
    expect(completed.progress.status).toBe("complete");
    expect(completed.warnings).toEqual([warning]);
    const saved = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((saved["scan"] as ScanSummary).warnings).toEqual([warning]);
  });

  test("normalizes severity change-condition lists without losing findings", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    document.findings[0]!.severity.changeConditions = [
      "Raise if the vulnerable path becomes internet-reachable.",
      "Lower if the input is constrained before parsing.",
    ];
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toEqual([
      "Recovered finding 1: normalized severity change conditions.",
    ]);
    const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;
    expect(recovered.severity.changeConditions).toBe(
      "Raise if the vulnerable path becomes internet-reachable. " +
        "Lower if the input is constrained before parsing.",
    );
    const coverage = await readJson<CoverageDocument>(
      join(fixture.scanDir, "coverage.json"),
    );
    expect(coverage.completeness).toBe("complete");
  });

  test("rejects severity change-condition lists with malformed entries", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const valid = document.findings[0]!;

    for (const [anchor, conditions] of [
      ["empty-severity-conditions", []],
      ["blank-severity-condition", ["  "]],
      ["mixed-severity-conditions", ["Valid condition.", 1]],
      ["surrogate-severity-condition", ["\uD800"]],
    ] as const) {
      const finding = structuredClone(valid);
      finding.identity.anchor = anchor;
      finding.severity.changeConditions = conditions;
      document.findings.push(finding);
    }
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toHaveLength(4);
    expect(
      completed.warnings.every((warning) =>
        warning.includes("severity.changeConditions"),
      ),
    ).toBe(true);
  });

  test("keeps valid findings and skips malformed or duplicate findings", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const valid = document.findings[0]!;
    const missingSummary = structuredClone(valid);
    missingSummary.identity.anchor = "missing-summary";
    missingSummary.summary = "";
    const unsafeLocation = structuredClone(valid);
    unsafeLocation.identity.anchor = "unsafe-location";
    unsafeLocation.locations[0]!.path = "../outside.py";
    const missingIdentity = structuredClone(valid);
    delete (missingIdentity as Partial<Finding>).identity;
    document.findings.push(
      missingSummary,
      unsafeLocation,
      missingIdentity,
      structuredClone(valid),
      null,
    );
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(1);
    expect(completed.warnings).toHaveLength(5);
    expect(
      completed.warnings.every((warning) =>
        warning.startsWith("Skipped malformed finding"),
      ),
    ).toBe(true);
    for (const reason of [
      "summary",
      "safe repository-relative",
      "identity",
      "duplicate logical finding",
      "expected an object",
    ]) {
      expect(
        completed.warnings.some((warning) => warning.includes(reason)),
      ).toBe(true);
    }
    expect((await readJson<FindingsDocument>(path)).findings).toHaveLength(1);
    const coverage = await readJson<CoverageDocument>(
      join(fixture.scanDir, "coverage.json"),
    );
    expect(coverage.completeness).toBe("partial");
    expect((coverage.surfaces as CoverageSurface[])[0]?.disposition).toBe(
      "needs_follow_up",
    );
    expect(coverage.deferred).toHaveLength(4);
  });

  test("retains the strongest duplicate finding regardless of input order", async () => {
    const cases = [
      {
        name: "severity ascending",
        candidates: [
          ["informational", "high", 1],
          ["critical", "high", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "severity descending",
        candidates: [
          ["critical", "high", 1],
          ["informational", "high", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "confidence ascending",
        candidates: [
          ["critical", "low", 1],
          ["critical", "high", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "confidence descending",
        candidates: [
          ["critical", "high", 1],
          ["critical", "low", 1],
        ],
        expected: ["critical", "high", 1],
      },
      {
        name: "evidence ascending",
        candidates: [
          ["critical", "high", 1],
          ["critical", "high", 2],
        ],
        expected: ["critical", "high", 2],
      },
      {
        name: "evidence descending",
        candidates: [
          ["critical", "high", 2],
          ["critical", "high", 1],
        ],
        expected: ["critical", "high", 2],
      },
    ] as const;

    for (const { name, candidates, expected } of cases) {
      const fixture = await startDraftScan();
      const path = join(fixture.scanDir, "findings.json");
      const document = await readJson<FindingsDocument>(path);
      const baseline = document.findings[0]!;
      document.findings = candidates.map(([severity, confidence, count]) => {
        const finding = structuredClone(baseline);
        finding.severity.level = severity;
        finding.confidence.level = confidence;
        finding.codeEvidence = Array.from({ length: count }, (_, index) => ({
          id: `evidence-${index + 1}`,
          label: "Archive extraction",
          path: "src/extract.py",
          startLine: 1,
          code: "# fixture",
          explanation: "The archive entry reaches a filesystem write.",
        }));
        return finding;
      });
      await writeJson(path, document);

      const completed = await completeScan(fixture);

      expect(completed.progress.status, name).toBe("complete");
      expect(completed.findingCount, name).toBe(1);
      expect(completed.warnings, name).toHaveLength(1);
      expect(completed.warnings[0], name).toContain(
        "duplicate logical finding",
      );
      const recovered = (await readJson<FindingsDocument>(path)).findings[0]!;
      expect(
        [
          recovered.severity.level,
          recovered.confidence.level,
          recovered.codeEvidence?.length,
        ],
        name,
      ).toEqual([...expected]);
      const coverage = await readJson<CoverageDocument>(
        join(fixture.scanDir, "coverage.json"),
      );
      expect(coverage.completeness, name).toBe("complete");
      expect(
        await readFile(join(fixture.scanDir, "report.md"), "utf8"),
        name,
      ).not.toContain("### No findings");
      const sarif = await readJson<SarifDocument>(
        join(fixture.scanDir, "exports", "results.sarif"),
      );
      expect(sarif.runs[0]?.results[0]?.properties.severity, name).toBe(
        "critical",
      );
    }
  });

  test("completes scans when every draft finding is malformed", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    document.findings[0]!.summary = "";
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(0);
    expect(completed.warnings).toHaveLength(1);
    expect(completed.warnings[0]).toContain("summary");
    expect((await readJson<FindingsDocument>(path)).findings).toEqual([]);
    const coverage = await readJson<CoverageDocument>(
      join(fixture.scanDir, "coverage.json"),
    );
    expect(coverage.completeness).toBe("partial");
    expect((coverage.surfaces as CoverageSurface[])[0]?.disposition).toBe(
      "needs_follow_up",
    );
    expect(coverage.deferred).toEqual([
      { id: "discarded-finding-1", reason: completed.warnings[0] },
    ]);
    const report = await readFile(join(fixture.scanDir, "report.md"), "utf8");
    expect(report).toContain("| Coverage | partial |");
    expect(report).toContain("Skipped malformed finding 1");
    const sarif = await readJson<SarifDocument>(
      join(fixture.scanDir, "exports", "results.sarif"),
    );
    expect(sarif.runs[0]?.properties.codexSecurityCoverageCompleteness).toBe(
      "partial",
    );
    expect(sarif.runs[0]?.invocations).toEqual([
      {
        executionSuccessful: true,
        toolExecutionNotifications: [
          { level: "warning", message: { text: completed.warnings[0]! } },
        ],
      },
    ]);
  });

  test("keeps findings while removing invalid or duplicate writeups", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const valid = document.findings[0]!;
    const reportPath = "findings/linked-writeup/linked-writeup.md";
    await mkdir(join(fixture.scanDir, "findings", "linked-writeup"), {
      recursive: true,
    });
    await writeFile(join(fixture.scanDir, reportPath), "# Verified finding\n");

    for (const [anchor, writeup] of [
      ["linked-writeup", { reportPath }],
      ["duplicate-writeup", { reportPath }],
      ["missing-writeup", { reportPath: "findings/missing/missing.md" }],
      ["unsafe-writeup", { reportPath: "../outside.md" }],
      ["invalid-writeup", "not an object"],
    ] as const) {
      const finding = structuredClone(valid);
      finding.identity.anchor = anchor;
      finding.writeup = writeup;
      document.findings.push(finding);
    }
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(6);
    expect(completed.warnings).toHaveLength(4);
    expect(
      completed.warnings.every((warning) =>
        warning.startsWith("Skipped malformed writeup for finding"),
      ),
    ).toBe(true);
    expect(completed.warnings.join("\n")).not.toContain("../outside.md");
    const recovered = (await readJson<FindingsDocument>(path)).findings;
    expect(
      recovered.find((finding) => finding?.identity.anchor === "linked-writeup")
        ?.writeup,
    ).toEqual({ reportPath });
    for (const anchor of [
      "duplicate-writeup",
      "missing-writeup",
      "unsafe-writeup",
      "invalid-writeup",
    ]) {
      expect(
        recovered.find((finding) => finding?.identity.anchor === anchor),
      ).not.toHaveProperty("writeup");
    }
  });

  test("keeps findings while removing malformed remediation guidance", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    const valid = document.findings[0]!;

    const cases: Array<
      [string, "remediationTests" | "preventiveControls", unknown]
    > = [
      [
        "valid-remediation-tests",
        "remediationTests",
        ["Add a regression test."],
      ],
      ["prose-remediation-tests", "remediationTests", "Add a regression test."],
      [
        "object-remediation-tests",
        "remediationTests",
        [{ description: "Add a regression test." }],
      ],
      [
        "prose-preventive-controls",
        "preventiveControls",
        "Centralize validation.",
      ],
    ];
    for (const [anchor, field, value] of cases) {
      const finding = structuredClone(valid);
      finding.identity.anchor = anchor;
      finding[field] = value;
      document.findings.push(finding);
    }
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.findingCount).toBe(5);
    expect(completed.warnings).toHaveLength(3);
    expect(
      completed.warnings.filter((warning) =>
        warning.startsWith("Skipped malformed remediationTests for finding"),
      ),
    ).toHaveLength(2);
    expect(
      completed.warnings.filter((warning) =>
        warning.startsWith("Skipped malformed preventiveControls for finding"),
      ),
    ).toHaveLength(1);
    const recovered = (await readJson<FindingsDocument>(path)).findings;
    expect(
      recovered.find(
        (finding) => finding?.identity.anchor === "valid-remediation-tests",
      )?.remediationTests,
    ).toEqual(["Add a regression test."]);
    for (const [anchor, field] of [
      ["prose-remediation-tests", "remediationTests"],
      ["object-remediation-tests", "remediationTests"],
      ["prose-preventive-controls", "preventiveControls"],
    ] as const) {
      const finding = recovered.find(
        (candidate) => candidate?.identity.anchor === anchor,
      );
      expect(finding).toBeDefined();
      expect(finding).not.toHaveProperty(field);
    }
  });

  test("keeps verified coverage receipts and downgrades invalid coverage", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "coverage.json");
    const document = await readJson<CoverageDocument>(path);
    const receipt = "artifacts/02_discovery/work_ledger.jsonl";
    await mkdir(join(fixture.scanDir, "artifacts", "02_discovery"), {
      recursive: true,
    });
    await writeFile(join(fixture.scanDir, receipt), '{"status":"reviewed"}\n');
    const surface = (document.surfaces as CoverageSurface[])[0]!;
    surface.receiptRefs = [
      receipt,
      "report.md",
      "../outside.json",
      "artifacts/02_discovery/missing.jsonl",
      null,
    ];
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.warnings).toHaveLength(4);
    expect(
      completed.warnings.every((warning) =>
        warning.startsWith("Skipped malformed coverage receipt"),
      ),
    ).toBe(true);
    expect(completed.warnings.join("\n")).not.toContain("../outside.json");
    const recovered = await readJson<CoverageDocument>(path);
    expect(recovered.completeness).toBe("partial");
    expect((recovered.surfaces as CoverageSurface[])[0]).toMatchObject({
      disposition: "needs_follow_up",
      receiptRefs: [receipt],
    });
    const manifest = await readJson<{
      scan: { artifacts: Array<{ path: string }> };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(manifest.scan.artifacts.map((artifact) => artifact.path)).toContain(
      receipt,
    );
  });

  test("downgrades malformed coverage collections without claiming completeness", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "coverage.json");
    const document = await readJson<CoverageDocument>(path);
    document.completeness = "finished";
    document.surfaces = { id: "not-an-array" };
    document.explicitExclusions = null;
    document.deferred = "later";
    await writeJson(path, document);

    const completed = await completeScan(fixture);

    expect(completed.progress.status).toBe("complete");
    expect(completed.warnings).toHaveLength(3);
    const expectedExclusions = (
      fixture.registration["contract"] as {
        scope: {
          requiredExplicitExclusions: Array<{
            pattern: string;
            reason: string;
          }>;
        };
      }
    ).scope.requiredExplicitExclusions;
    const recovered = await readJson<CoverageDocument>(path);
    expect(recovered).toMatchObject({
      completeness: "partial",
      surfaces: [],
      explicitExclusions: expectedExclusions,
      deferred: [],
    });
  });

  test("discards unsafe hardening portfolios without discarding findings", async () => {
    for (const hardening of [
      "not an object",
      { portfolioPath: "../outside.md" },
      { portfolioPath: "hardening/hardening.md" },
    ]) {
      const fixture = await startDraftScan();
      const path = join(fixture.scanDir, "scan-manifest.json");
      const manifest = await readJson<{
        scan: { hardening?: unknown };
      }>(path);
      manifest.scan.hardening = hardening;
      await writeJson(path, manifest);

      const completed = await completeScan(fixture);

      expect(completed.progress.status).toBe("complete");
      expect(completed.findingCount).toBe(1);
      expect(completed.warnings).toHaveLength(1);
      expect(completed.warnings[0]).toContain(
        "Skipped malformed hardening portfolio:",
      );
      expect(completed.warnings[0]).not.toContain("../outside.md");
      expect(
        (await readJson<{ scan: { hardening?: unknown } }>(path)).scan,
      ).not.toHaveProperty("hardening");
    }
  });

  test("keeps direct finalization strict unless recovery is explicitly enabled", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(path);
    document.findings[0]!.identity.anchor = "Invalid Anchor";
    await writeJson(path, document);

    const strict = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        join(PLUGIN_ROOT, "scripts", "finalize_scan_contract.py"),
        "--scan-dir",
        fixture.scanDir,
      ],
      { encoding: "utf8" },
    );

    expect(strict.status).not.toBe(0);
    expect(strict.stderr).toContain("stable lowercase semantic slug");
    expect((await completeScan(fixture)).findingCount).toBe(1);
  });

  test("refuses to repair scan-wide coverage contract violations", async () => {
    const fixture = await startDraftScan();
    const path = join(fixture.scanDir, "coverage.json");
    const document = await readJson<CoverageDocument>(path);
    document.inventoryStrategy = "";
    await writeJson(path, document);
    const original = await readFile(path, "utf8");

    await expect(completeScan(fixture)).rejects.toThrow("inventoryStrategy");
    expect(await readFile(path, "utf8")).toBe(original);
  });
});

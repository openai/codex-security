import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
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

async function workbench(fixture: ScanFixture, args: readonly string[]) {
  return runWorkbench(
    {
      python: fixture.python,
      pluginRoot: PLUGIN_ROOT,
      environment: {
        PATH: process.env["PATH"],
        CODEX_SECURITY_STATE_DIR: fixture.stateDir,
      },
    },
    args,
  );
}

function fixtureGit(repository: string, ...args: string[]): string {
  const result = spawnSync("git", ["-C", repository, ...args], {
    encoding: "utf8",
  });
  expect(result.status, result.stderr).toBe(0);
  return result.stdout.trim();
}

async function startDraftScan(
  repositoryKind:
    | "directory"
    | "clean"
    | "dirty"
    | "nested"
    | "committed" = "directory",
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
  let committedDiff: { base: string; head: string } | undefined;

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
    if (repositoryKind === "committed") {
      const base = fixtureGit(target, "rev-parse", "HEAD");
      await writeFile(join(target, "src", "extract.py"), "# changed fixture\n");
      fixtureGit(target, "add", "--", "src/extract.py");
      fixtureGit(
        target,
        "-c",
        "user.name=Codex Security",
        "-c",
        "user.email=codex-security@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "committed changes",
      );
      committedDiff = {
        base,
        head: fixtureGit(target, "rev-parse", "HEAD"),
      };
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
        committedDiff === undefined
          ? { kind: "repository", paths: [] }
          : { kind: "refs", paths: [], ...committedDiff },
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
      target: { kind: string } & Record<string, unknown>;
      sealedAt?: string;
      artifacts?: unknown[];
    };
  }>(manifestPath);
  manifest.scan.id = fixture.scanId;
  if (committedDiff === undefined) {
    manifest.scan.target.kind =
      repositoryKind === "directory"
        ? "directory_snapshot"
        : repositoryKind === "clean"
          ? "git_revision"
          : "git_worktree";
  } else {
    manifest.scan.target = {
      kind: "git_diff",
      targetId: manifest.scan.target["targetId"],
      displayName: manifest.scan.target["displayName"],
      baseRevision: committedDiff.base,
      headRevision: committedDiff.head,
    };
  }
  delete manifest.scan.sealedAt;
  delete manifest.scan.artifacts;
  await writeJson(manifestPath, manifest);

  for (const name of ["findings.json", "coverage.json"] as const) {
    const path = join(scanDir, name);
    const document = await readJson<{ scanId: string; mode?: string }>(path);
    document.scanId = fixture.scanId;
    if (committedDiff !== undefined && name === "coverage.json") {
      document.mode = "branch_diff";
    }
    await writeJson(path, document);
  }
  await writeFile(join(scanDir, "report.md"), "# Draft report\n");
  return fixture;
}

function committedDiffTarget(fixture: ScanFixture): {
  baseRevision: string;
  headRevision: string;
  contentDigest: string;
} {
  const contract = fixture.registration["contract"] as {
    diffTarget: {
      baseRevision: string;
      headRevision: string;
      contentDigest: string;
    };
  };
  expect(contract.diffTarget.contentDigest).toMatch(
    /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
  );
  return contract.diffTarget;
}

async function replaceCommittedDiffHead(fixture: ScanFixture): Promise<void> {
  const { headRevision } = committedDiffTarget(fixture);
  await writeFile(
    join(fixture.repository, "src", "extract.py"),
    "# substituted after selection\n",
  );
  fixtureGit(fixture.repository, "add", "--", "src/extract.py");
  fixtureGit(
    fixture.repository,
    "-c",
    "user.name=Codex Security",
    "-c",
    "user.email=codex-security@example.invalid",
    "commit",
    "--quiet",
    "-m",
    "replacement",
  );
  const replacement = fixtureGit(fixture.repository, "rev-parse", "HEAD");
  fixtureGit(fixture.repository, "reset", "--hard", headRevision);
  fixtureGit(fixture.repository, "replace", "-f", headRevision, replacement);
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
  test("rejoins a headless scan after its running context changes", async () => {
    const fixture = await startDraftScan();
    const threadId = "context-rejoin-regression";
    const startArguments = [
      "start-headless-standard-scan",
      "--thread-id",
      threadId,
      "--target-path",
      fixture.repository,
      "--scope",
      ".",
      "--user-context",
      "original security focus",
    ];
    const created = await workbench(fixture, startArguments);
    const scan = created["scan"] as {
      scanId: string;
      handoffClaimToken: string;
      userContext: string;
    };

    const updated = await workbench(fixture, [
      "update-scan-context",
      "--scan-id",
      scan.scanId,
      "--user-context",
      "updated security focus",
      "--thread-id",
      threadId,
      "--claim-token",
      scan.handoffClaimToken,
    ]);
    expect(updated["scan"]).toMatchObject({
      scanId: scan.scanId,
      userContext: "updated security focus",
    });
    expect(updated["workspace"]).toMatchObject({
      userContext: "updated security focus",
    });

    const retried = await workbench(fixture, startArguments);
    expect(retried["startDisposition"]).toBe("joined");
    expect(retried["scan"]).toMatchObject({
      scanId: scan.scanId,
      userContext: "updated security focus",
    });
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

  test("builds each ordinary scan context once without losing selected findings", async () => {
    const fixture = await startDraftScan();
    const findingsPath = join(fixture.scanDir, "findings.json");
    const document = await readJson<FindingsDocument>(findingsPath);
    const original = document.findings[0]!;
    document.findings = Array.from({ length: 21 }, (_, index) => {
      const finding = structuredClone(original);
      finding.identity.anchor = `scan-context-finding-${index}`;
      return finding;
    });
    await writeJson(findingsPath, document);
    await completeScan(fixture);

    const page = await workbench(fixture, [
      "list-findings",
      "--scan-id",
      fixture.scanId,
      "--offset",
      "20",
      "--limit",
      "1",
    ]);
    const occurrenceId = (
      page["findingsPage"] as {
        findings: Array<{ occurrenceId: string }>;
      }
    ).findings[0]!.occurrenceId;
    const probe = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        [
          "import json, sys",
          "sys.path.insert(0, sys.argv[1])",
          "import workbench_db as workbench",
          "calls = []",
          "original = workbench.scan_result",
          "def count_result(connection, scan, **kwargs):",
          "    calls.append(kwargs.get('occurrence_id'))",
          "    return original(connection, scan, **kwargs)",
          "workbench.scan_result = count_result",
          "with workbench.connect() as connection:",
          "    ordinary = workbench.scan_context(connection, sys.argv[2])",
          "    ordinary_calls = len(calls)",
          "    calls.clear()",
          "    selected = workbench.scan_context(connection, sys.argv[2], sys.argv[3])",
          "print(json.dumps({'ordinaryCalls': ordinary_calls, 'selectedCalls': len(calls), 'ordinaryCount': len(ordinary['scan']['findings']), 'selectedCount': len(selected['scan']['findings']), 'workspaceCount': len(selected['workspace']['results']['findings']), 'selectedIncluded': any(finding['occurrenceId'] == sys.argv[3] for finding in selected['scan']['findings'])}))",
        ].join("\n"),
        join(PLUGIN_ROOT, "scripts"),
        fixture.scanId,
        occurrenceId,
      ],
      {
        encoding: "utf8",
        env: {
          PATH: process.env["PATH"],
          CODEX_SECURITY_STATE_DIR: fixture.stateDir,
        },
      },
    );

    expect(probe.status, probe.stderr).toBe(0);
    expect(JSON.parse(probe.stdout)).toEqual({
      ordinaryCalls: 1,
      selectedCalls: 2,
      ordinaryCount: 20,
      selectedCount: 21,
      workspaceCount: 20,
      selectedIncluded: true,
    });
  }, 30_000);

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

  test("seals a committed diff with its registered content digest", async () => {
    const fixture = await startDraftScan("committed");
    const selected = committedDiffTarget(fixture);

    expect((await completeScan(fixture)).progress.status).toBe("complete");

    const sealed = await readJson<{
      scan: {
        target: {
          kind: string;
          baseRevision: string;
          headRevision: string;
          snapshotDigest: string;
        };
      };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(sealed.scan.target).toMatchObject({
      kind: "git_diff",
      baseRevision: selected.baseRevision,
      headRevision: selected.headRevision,
      snapshotDigest: selected.contentDigest,
    });
  });

  test("rejects committed diff replacements before the selected scan starts", async () => {
    const fixture = await startDraftScan("committed");
    const selected = committedDiffTarget(fixture);
    await replaceCommittedDiffHead(fixture);

    await expect(
      workbench(fixture, [
        "inspect-setup",
        "--target-path",
        fixture.repository,
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "range",
        "--diff-base-revision",
        selected.baseRevision,
        "--diff-head-revision",
        selected.headRevision,
        "--diff-content-digest",
        selected.contentDigest,
      ]),
    ).rejects.toThrow("no longer produce the same diff");
  });

  test("rejects replaced Git blob contents in a committed diff", async () => {
    const fixture = await startDraftScan("committed");
    const selected = committedDiffTarget(fixture);
    const original = fixtureGit(
      fixture.repository,
      "rev-parse",
      `${selected.headRevision}:src/extract.py`,
    );
    const replacement = spawnSync(
      "git",
      ["-C", fixture.repository, "hash-object", "-w", "--stdin"],
      { encoding: "utf8", input: "# replaced blob contents\n" },
    );
    expect(replacement.status, replacement.stderr).toBe(0);
    fixtureGit(
      fixture.repository,
      "replace",
      "-f",
      original,
      replacement.stdout.trim(),
    );

    await expect(
      workbench(fixture, [
        "inspect-setup",
        "--target-path",
        fixture.repository,
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "range",
        "--diff-base-revision",
        selected.baseRevision,
        "--diff-head-revision",
        selected.headRevision,
        "--diff-content-digest",
        selected.contentDigest,
      ]),
    ).rejects.toThrow("no longer produce the same diff");
  });

  test.each(["workspace", "cli"] as const)(
    "rejects committed diff replacements during %s scan registration",
    async (scenario) => {
      const fixture = await startDraftScan("committed");
      const selected = committedDiffTarget(fixture);
      await replaceCommittedDiffHead(fixture);
      const replacement = fixtureGit(
        fixture.repository,
        "rev-parse",
        `refs/replace/${selected.headRevision}`,
      );
      fixtureGit(fixture.repository, "replace", "-d", selected.headRevision);

      const workspaceId = randomUUID();
      const scanDirectory = join(fixture.stateDir, "registration-race-scan");
      await mkdir(scanDirectory, { mode: 0o700 });
      if (scenario === "workspace") {
        await workbench(fixture, [
          "create-workspace",
          "--workspace-id",
          workspaceId,
        ]);
        await workbench(fixture, [
          "save-workspace",
          "--workspace-id",
          workspaceId,
          "--target-path",
          fixture.repository,
          "--scope",
          ".",
          "--mode",
          "diff",
          "--diff-target-kind",
          "range",
          "--diff-base-revision",
          selected.baseRevision,
          "--diff-head-revision",
          selected.headRevision,
          "--diff-content-digest",
          selected.contentDigest,
        ]);
      }

      const probe = spawnSync(
        fixture.python,
        [
          "-I",
          "-B",
          "-c",
          [
            "import argparse, json, subprocess, sys",
            "from pathlib import Path",
            "sys.path.insert(0, sys.argv[1])",
            "import workbench_db as workbench",
            "repository = Path(sys.argv[2])",
            "head, replacement, workspace_id = sys.argv[3:6]",
            "scan_directory, scenario, base = sys.argv[6:9]",
            "original_count = workbench.directory_snapshot_regular_file_count",
            "def replace_during_count(path):",
            "    count = original_count(path)",
            "    subprocess.run(['git', '-C', str(repository), 'replace', '-f', head, replacement], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)",
            "    return count",
            "workbench.directory_snapshot_regular_file_count = replace_during_count",
            "if scenario == 'workspace':",
            "    arguments = argparse.Namespace(workspace_id=workspace_id, scan_root=None, model=None, reasoning_effort=None)",
            "    start = workbench.start_scan",
            "else:",
            "    recipe = {'config': {}, 'mode': 'standard', 'repository': str(repository), 'target': {'kind': 'refs', 'paths': [], 'base': base, 'head': head}}",
            "    arguments = argparse.Namespace(repository=str(repository), scan_dir=scan_directory, recipe_json=json.dumps(recipe), archive_existing=False, archived_scan_dir=None, parent_scan_id=None)",
            "    start = workbench.register_cli_scan",
            "with workbench.connect() as connection:",
            "    previous = connection.execute('SELECT COUNT(*) FROM scans').fetchone()[0]",
            "    try:",
            "        start(connection, arguments)",
            "    except SystemExit as exception:",
            "        error = str(exception)",
            "    else:",
            "        error = None",
            "    created = connection.execute('SELECT COUNT(*) FROM scans').fetchone()[0] - previous",
            "print(json.dumps({'error': error, 'createdScans': created}))",
          ].join("\n"),
          join(PLUGIN_ROOT, "scripts"),
          fixture.repository,
          selected.headRevision,
          replacement,
          workspaceId,
          scanDirectory,
          scenario,
          selected.baseRevision,
        ],
        {
          encoding: "utf8",
          env: {
            PATH: process.env["PATH"],
            CODEX_SECURITY_STATE_DIR: fixture.stateDir,
          },
        },
      );

      expect(probe.status, probe.stderr).toBe(0);
      expect(JSON.parse(probe.stdout)).toMatchObject({
        error: expect.stringContaining("no longer produce the same diff"),
        createdScans: 0,
      });
    },
  );

  test("warns when committed diff contents change before scan completion", async () => {
    const fixture = await startDraftScan("committed");
    const selected = committedDiffTarget(fixture);
    await replaceCommittedDiffHead(fixture);

    const warning =
      "Committed changes changed while the scan was running; results were saved for the original snapshot.";
    const completed = await workbench(fixture, [
      "complete-scan",
      "--scan-id",
      fixture.scanId,
    ]);

    expect(completed["targetWarnings"]).toEqual([warning]);
    expect((completed["scan"] as ScanSummary).warnings).toContain(warning);
    const sealed = await readJson<{
      scan: { target: { snapshotDigest: string } };
    }>(join(fixture.scanDir, "scan-manifest.json"));
    expect(sealed.scan.target.snapshotDigest).toBe(selected.contentDigest);
  });

  test("keeps committed snapshots stable when Git diff rendering settings change", async () => {
    const fixture = await startDraftScan("committed");
    const selected = committedDiffTarget(fixture);

    for (const [setting, value] of [
      ["diff.noprefix", "true"],
      ["diff.mnemonicprefix", "true"],
      ["diff.relative", "true"],
      ["diff.renames", "true"],
      ["diff.algorithm", "histogram"],
      ["diff.indentheuristic", "true"],
      ["diff.context", "9"],
      ["diff.interhunkcontext", "5"],
      ["diff.suppressblankempty", "true"],
      ["diff.submodule", "log"],
      ["core.quotepath", "false"],
      ["color.ui", "always"],
    ] as const) {
      fixtureGit(fixture.repository, "config", setting, value);
    }

    const inspected = await workbench(fixture, [
      "inspect-setup",
      "--target-path",
      fixture.repository,
      "--scope",
      ".",
      "--mode",
      "diff",
      "--diff-target-kind",
      "range",
      "--diff-base-revision",
      selected.baseRevision,
      "--diff-head-revision",
      selected.headRevision,
      "--diff-content-digest",
      selected.contentDigest,
    ]);

    expect(inspected["diffTarget"]).toMatchObject({
      contentDigest: selected.contentDigest,
    });
    expect((await completeScan(fixture)).warnings).toEqual([]);
  });

  test("keeps committed snapshots stable when Git attribute sources change", async () => {
    const fixture = await startDraftScan("committed");
    const selected = committedDiffTarget(fixture);
    await writeFile(
      join(fixture.repository, ".gitattributes"),
      "src/extract.py binary\n",
    );
    const globalAttributes = join(fixture.stateDir, "global.attributes");
    await writeFile(globalAttributes, "src/extract.py binary\n");
    fixtureGit(
      fixture.repository,
      "config",
      "core.attributesFile",
      globalAttributes,
    );
    await writeFile(
      join(fixture.repository, ".git", "info", "attributes"),
      "src/extract.py binary\n",
    );

    const inspected = await workbench(fixture, [
      "inspect-setup",
      "--target-path",
      fixture.repository,
      "--scope",
      ".",
      "--mode",
      "diff",
      "--diff-target-kind",
      "range",
      "--diff-base-revision",
      selected.baseRevision,
      "--diff-head-revision",
      selected.headRevision,
      "--diff-content-digest",
      selected.contentDigest,
    ]);

    expect(inspected["diffTarget"]).toMatchObject({
      contentDigest: selected.contentDigest,
    });
    expect((await completeScan(fixture)).warnings).toEqual([]);
  });

  test("hashes committed diffs without newer Git attribute-source options", async () => {
    const fixture = await startDraftScan("committed");
    const selected = committedDiffTarget(fixture);
    const probe = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        [
          "import json, sys",
          "from pathlib import Path",
          "sys.path.insert(0, sys.argv[1])",
          "import workbench_target as target",
          "repository, base, head = Path(sys.argv[2]), sys.argv[3], sys.argv[4]",
          "commands = []",
          "original = target.git_command",
          "def supported_git(where, *args, **options):",
          "    if any(argument.startswith('--attr-source') for argument in args):",
          "        raise AssertionError('Git 2.39 does not support --attr-source')",
          "    commands.append(args)",
          "    return original(where, *args, **options)",
          "target.git_command = supported_git",
          "digest = target.committed_diff_content_digest(repository, base, head)",
          "print(json.dumps({'digest': digest, 'commands': commands}))",
        ].join("\n"),
        join(PLUGIN_ROOT, "scripts"),
        fixture.repository,
        selected.baseRevision,
        selected.headRevision,
      ],
      {
        encoding: "utf8",
        env: {
          PATH: process.env["PATH"],
          CODEX_SECURITY_STATE_DIR: fixture.stateDir,
        },
      },
    );

    expect(probe.status, probe.stderr).toBe(0);
    const result = JSON.parse(probe.stdout) as {
      digest: string;
      commands: string[][];
    };
    expect(result.digest).toBe(selected.contentDigest);
    expect(result.commands.some((command) => command.includes("diff"))).toBe(
      true,
    );
  });

  test("keeps committed snapshots stable when named Git diff drivers change", async () => {
    const fixture = await startDraftScan("committed");
    const selected = committedDiffTarget(fixture);
    await writeFile(
      join(fixture.repository, ".gitattributes"),
      "src/extract.py diff=special\n",
    );
    fixtureGit(fixture.repository, "add", "--", ".gitattributes");
    fixtureGit(
      fixture.repository,
      "-c",
      "user.name=Codex Security",
      "-c",
      "user.email=codex-security@example.invalid",
      "commit",
      "--quiet",
      "-m",
      "versioned diff driver",
    );
    const headRevision = fixtureGit(fixture.repository, "rev-parse", "HEAD");
    const arguments_ = [
      "inspect-setup",
      "--target-path",
      fixture.repository,
      "--scope",
      ".",
      "--mode",
      "diff",
      "--diff-target-kind",
      "range",
      "--diff-base-revision",
      selected.baseRevision,
      "--diff-head-revision",
      headRevision,
    ];
    const original = await workbench(fixture, arguments_);
    const contentDigest = (original["diffTarget"] as { contentDigest: string })
      .contentDigest;

    fixtureGit(fixture.repository, "config", "diff.special.binary", "true");
    const inspected = await workbench(fixture, [
      ...arguments_,
      "--diff-content-digest",
      contentDigest,
    ]);

    expect(inspected["diffTarget"]).toMatchObject({ contentDigest });
  });

  test("hashes committed diff output without buffering the Git patch", async () => {
    const fixture = await startDraftScan("committed");
    const selected = committedDiffTarget(fixture);
    const probe = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        [
          "import hashlib, io, json, sys",
          "from pathlib import Path",
          "sys.path.insert(0, sys.argv[1])",
          "import workbench_target as target",
          "repository, base, head = Path(sys.argv[2]), sys.argv[3], sys.argv[4]",
          "calls = []",
          "original = target.git_bytes",
          "def record(where, *args, **options):",
          "    calls.append(args)",
          "    return original(where, *args, **options)",
          "target.git_bytes = record",
          "streamed = target.committed_diff_content_digest(repository, base, head)",
          "target.git_bytes = original",
          "root, pathspec = target.git_worktree_context(repository)",
          "metadata = original(root, *target.committed_diff_arguments(base, head, pathspec))",
          "requests = io.BytesIO()",
          "target.write_committed_diff_object_requests(io.BytesIO(metadata), requests)",
          "objects = target.git_command(root, 'cat-file', '--batch', text=False, input_data=requests.getvalue()).stdout",
          "digest = hashlib.sha256()",
          "target.update_digest_field(digest, b'format', b'codex-security-snapshot/v1')",
          "target.update_digest_field(digest, b'tracked-diff', metadata)",
          "target.update_digest_field(digest, b'tracked-objects', objects)",
          "print(json.dumps({'streamed': streamed, 'buffered': 'codex-security-snapshot/v1:sha256:' + digest.hexdigest(), 'bufferedDiffCalls': [args for args in calls if 'diff' in args]}))",
        ].join("\n"),
        join(PLUGIN_ROOT, "scripts"),
        fixture.repository,
        selected.baseRevision,
        selected.headRevision,
      ],
      {
        encoding: "utf8",
        env: {
          PATH: process.env["PATH"],
          CODEX_SECURITY_STATE_DIR: fixture.stateDir,
        },
      },
    );

    expect(probe.status, probe.stderr).toBe(0);
    expect(JSON.parse(probe.stdout)).toEqual({
      streamed: selected.contentDigest,
      buffered: selected.contentDigest,
      bufferedDiffCalls: [],
    });
  });

  test("keeps committed diff spooling in the approved workbench state directory", async () => {
    const fixture = await startDraftScan("committed");
    const selected = committedDiffTarget(fixture);
    const probe = spawnSync(
      fixture.python,
      [
        "-I",
        "-B",
        "-c",
        [
          "import json, sys",
          "from pathlib import Path",
          "sys.path.insert(0, sys.argv[1])",
          "import workbench_target as target",
          "repository, base, head = Path(sys.argv[2]), sys.argv[3], sys.argv[4]",
          "approved = Path(sys.argv[5]).resolve()",
          "directories = []",
          "original = target.tempfile.TemporaryFile",
          "def restricted_temporary(*args, **options):",
          "    directory = options.get('dir')",
          "    if directory is None or Path(directory).resolve() != approved:",
          "        raise PermissionError('temporary files outside the workbench state directory are denied')",
          "    directories.append(str(Path(directory).resolve()))",
          "    return original(*args, **options)",
          "target.tempfile.TemporaryFile = restricted_temporary",
          "digest = target.committed_diff_content_digest(repository, base, head)",
          "print(json.dumps({'digest': digest, 'spoolDirectories': directories}))",
        ].join("\n"),
        join(PLUGIN_ROOT, "scripts"),
        fixture.repository,
        selected.baseRevision,
        selected.headRevision,
        fixture.stateDir,
      ],
      {
        encoding: "utf8",
        env: {
          PATH: process.env["PATH"],
          CODEX_SECURITY_STATE_DIR: fixture.stateDir,
        },
      },
    );

    expect(probe.status, probe.stderr).toBe(0);
    expect(JSON.parse(probe.stdout)).toEqual({
      digest: selected.contentDigest,
      spoolDirectories: [fixture.stateDir, fixture.stateDir, fixture.stateDir],
    });
  });

  test("selects root commits in SHA-1 and supported SHA-256 repositories", async () => {
    const fixture = await startDraftScan("committed");
    const emptyTrees = {
      sha1: "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
      sha256:
        "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321",
    };

    for (const objectFormat of ["sha1", "sha256"] as const) {
      const repository = join(fixture.stateDir, `root-${objectFormat}`);
      await mkdir(repository, { recursive: true });
      const initialized = spawnSync(
        "git",
        ["init", "--quiet", `--object-format=${objectFormat}`, repository],
        { encoding: "utf8" },
      );
      if (objectFormat === "sha256" && initialized.status !== 0) continue;
      expect(initialized.status, initialized.stderr).toBe(0);
      await writeFile(join(repository, "source.txt"), "root fixture\n");
      fixtureGit(repository, "add", "--", "source.txt");
      fixtureGit(
        repository,
        "-c",
        "user.name=Codex Security",
        "-c",
        "user.email=codex-security@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "root",
      );
      const headRevision = fixtureGit(repository, "rev-parse", "HEAD");
      const inspected = await workbench(fixture, [
        "inspect-setup",
        "--target-path",
        repository,
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        headRevision,
      ]);

      expect(inspected["diffTarget"]).toMatchObject({
        kind: "commit",
        baseRevision: emptyTrees[objectFormat],
        headRevision,
        contentDigest: expect.stringMatching(
          /^codex-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
        ),
      });
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

  test.each([
    ["unavailable", undefined],
    [
      "worker-inclusive",
      {
        coverage: "complete",
        source: "codex_rollout",
        threadCount: 3,
        inputTokens: 5_000,
        cachedInputTokens: 400,
        cacheWriteInputTokens: 0,
        outputTokens: 120,
        reasoningOutputTokens: 20,
        totalTokens: 5_120,
      },
    ],
  ] as const)(
    "reconciles authoritative scan cost without replacing %s usage or sealed artifacts",
    async (_scenario, measuredUsage) => {
      const fixture = await startDraftScan();
      const firstCompletion = await workbench(fixture, [
        "complete-scan",
        "--scan-id",
        fixture.scanId,
        ...(measuredUsage === undefined
          ? []
          : ["--cost-json", JSON.stringify({ usage: measuredUsage })]),
      ]);
      const initiallyCompleted = firstCompletion["scan"] as ScanSummary & {
        usage: Record<string, unknown>;
        cost?: unknown;
      };
      expect(initiallyCompleted.progress.status).toBe("complete");
      expect(initiallyCompleted.usage).toBeDefined();
      if (measuredUsage !== undefined) {
        expect(initiallyCompleted.usage).toEqual(measuredUsage);
      }
      expect(initiallyCompleted.cost).toBeUndefined();

      const artifactNames = [
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
        "report.md",
      ];
      const sealedArtifacts = await Promise.all(
        artifactNames.map((name) => readFile(join(fixture.scanDir, name))),
      );
      const cost = {
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 200,
        cacheWriteInputTokens: 0,
        outputTokens: 30,
        estimatedUsd: 0.00625,
      };

      const reconciled = await workbench(fixture, [
        "complete-scan",
        "--scan-id",
        fixture.scanId,
        "--cost-json",
        JSON.stringify(cost),
      ]);
      expect(reconciled["scan"]).toMatchObject({
        progress: { status: "complete" },
        usage: initiallyCompleted.usage,
        cost,
      });

      const persisted = await workbench(fixture, [
        "get-scan",
        "--scan-id",
        fixture.scanId,
      ]);
      expect(persisted["scan"]).toMatchObject({
        progress: { status: "complete" },
        usage: initiallyCompleted.usage,
        cost,
      });
      expect(
        await Promise.all(
          artifactNames.map((name) => readFile(join(fixture.scanDir, name))),
        ),
      ).toEqual(sealedArtifacts);
    },
  );

  test("preserves target-drift classification from prepared completion", async () => {
    const fixture = await startDraftScan();
    const source = join(fixture.repository, "src", "extract.py");
    const original = await readFile(source, "utf8");
    await writeFile(source, "# target changed during scan\n");

    const prepared = await workbench(fixture, [
      "prepare-scan-completion",
      "--scan-id",
      fixture.scanId,
    ]);
    const warning =
      "Directory contents changed while the scan was running; results were saved for the original snapshot.";
    expect(prepared["targetWarnings"]).toEqual([warning]);

    await writeFile(source, original);
    const completed = await workbench(fixture, [
      "complete-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    expect((completed["scan"] as ScanSummary).warnings).toContain(warning);
    expect(completed["targetWarnings"]).toEqual([]);
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

  test("keeps explicit scan cancellation distinct from failure", async () => {
    const fixture = await startDraftScan();

    await workbench(fixture, ["cancel-scan", "--scan-id", fixture.scanId]);
    const stored = await workbench(fixture, [
      "get-scan",
      "--scan-id",
      fixture.scanId,
    ]);

    expect(stored["scan"]).toMatchObject({
      canceledAt: expect.any(String),
      failureMessage: null,
      progress: { status: "canceled" },
    });
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
    const completion = await workbench(fixture, [
      "complete-scan",
      "--scan-id",
      fixture.scanId,
    ]);
    const completed = completion["scan"] as ScanSummary;
    expect(completed.progress.status).toBe("complete");
    expect(completed.warnings).toEqual([warning]);
    expect(completion["targetWarnings"]).toEqual([]);
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

  test.each([
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
  ] as const)(
    "retains the strongest duplicate finding with $name input order",
    async ({ name, candidates, expected }) => {
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
    },
  );

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
    expect(completed.warnings).toHaveLength(4);
    const recovered = await readJson<CoverageDocument>(path);
    expect(recovered).toMatchObject({
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
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

  test.each(["complete-scan", "prepare-scan-completion"] as const)(
    "keeps a repairable %s contract failure resumable",
    async (command) => {
      const fixture = await startDraftScan();
      const path = join(fixture.scanDir, "coverage.json");
      const document = await readJson<CoverageDocument>(path);
      const validInventoryStrategy = document.inventoryStrategy;
      document.inventoryStrategy = "";
      await writeJson(path, document);

      await expect(
        workbench(fixture, [command, "--scan-id", fixture.scanId]),
      ).rejects.toThrow("inventoryStrategy");
      const pending = await workbench(fixture, [
        "get-scan",
        "--scan-id",
        fixture.scanId,
      ]);
      expect((pending["scan"] as ScanSummary).progress.status).toBe("running");

      document.inventoryStrategy = validInventoryStrategy;
      await writeJson(path, document);
      expect((await completeScan(fixture)).findingCount).toBe(1);
    },
  );
});

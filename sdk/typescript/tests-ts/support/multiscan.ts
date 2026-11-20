import { execFileSync } from "node:child_process";
import { gitText } from "./shell.js";
import { readJson, readJsonLines, writeJson } from "./json.js";
import { reseal as resealArtifacts } from "./sealed-scan.js";
import { setFindingIdentity, sha256 } from "./finding-identity.js";
import { Database } from "bun:sqlite";
import { randomUUID } from "node:crypto";
import {
  chmod,
  cp,
  mkdir,
  readFile,
  realpath,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, posix, relative, sep } from "node:path";
import { zipSync } from "fflate";
import Papa from "papaparse";
import type { CoverageDocument } from "../../src/models.js";
import { ScanResult } from "../../src/result.js";
import type { runMultiscan } from "../../src/multiscan.js";
import {
  normalizeExcludedPaths,
  normalizeTarget,
  type NormalizedTarget,
} from "../../src/targets.js";
import { scanRequestDigest } from "../../src/finding-workflow.js";
import { resolvePluginPython, runWorkbench } from "../../src/runtime.js";
import { PYTHON } from "./security-policy.js";
import { loadContract } from "../../src/contract.js";
import { workbenchCommand } from "./workbench-command.js";
import { fakeResult } from "../cli-fixtures.js";
import { createApiTestFixtures } from "./temporary-directories.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "../plugin-root.js";

export type MultiscanOptions = Parameters<typeof runMultiscan>[0];

export type SecurityClient = ReturnType<MultiscanOptions["createSecurity"]>;

export function git(repository: string, ...args: string[]): string {
  return gitText(["-C", repository, ...args], {
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

export async function repository(
  root: string,
  name: string,
  objectFormat = "sha1",
) {
  const path = join(root, name);
  await mkdir(join(path, "src"), { recursive: true });
  await writeFile(
    join(path, "src", "app.ts"),
    `export const name = "${name}";\n`,
  );
  git(path, "init", "-q", `--object-format=${objectFormat}`);
  git(path, "add", ".");
  git(
    path,
    "-c",
    "user.name=Multiscan Test",
    "-c",
    "user.email=multiscan@example.test",
    "commit",
    "-qm",
    "initial",
  );
  return { path, revision: git(path, "rev-parse", "HEAD") };
}

export async function customPlugin(
  root: string,
  format: "directory" | "zip",
): Promise<string> {
  const files: Record<string, Uint8Array> = {};
  for (const name of [
    ".codex-plugin/plugin.json",
    "schemas/scan-manifest.schema.json",
    "schemas/findings.schema.json",
    "schemas/coverage.schema.json",
  ]) {
    files[name] = await readFile(join(PLUGIN_ROOT, name));
  }
  const coverage = JSON.parse(
    Buffer.from(files["schemas/coverage.schema.json"]!).toString("utf8"),
  );
  coverage.properties.schemaVersion = { enum: ["1.0", "custom-test"] };
  files["schemas/coverage.schema.json"] = Buffer.from(JSON.stringify(coverage));
  const path = join(root, format === "zip" ? "plugin.zip" : "plugin");
  if (format === "zip") {
    await writeFile(path, zipSync(files));
  } else {
    await mkdir(join(path, ".codex-plugin"), { recursive: true });
    await mkdir(join(path, "schemas"));
    for (const [name, bytes] of Object.entries(files)) {
      await writeFile(join(path, name), bytes);
    }
  }
  return path;
}

export function client<Run extends SecurityClient["run"]>(
  run: Run,
  close: SecurityClient["close"] = async () => {},
): SecurityClient & { run: Run } {
  return { run, close };
}

export const results = readJsonLines<Record<string, unknown>>;

/** Run the real registration and completion commands with synthetic scanner output. */
export async function registeredCampaignResult(
  environment: NodeJS.ProcessEnv,
  config: MultiscanOptions["config"],
  repository: string,
  scan: NonNullable<Parameters<SecurityClient["run"]>[1]>,
  outcome: "findings" | "empty" | "interrupted",
): Promise<ScanResult> {
  const checkout = await realpath(repository);
  const scanDir = scan.outputDir!;
  const target = await normalizeTarget(checkout, scan.target ?? "repository");
  const excludePaths = normalizeExcludedPaths(scan.excludePaths);
  const includePaths = target.kind === "paths" ? [...target.paths] : ["."];
  await mkdir(scanDir, { recursive: true, mode: 0o700 });
  const python = await resolvePluginPython({ environment });
  const workbench = workbenchCommand(python, () => environment);
  const registered = await workbench(
    [
      "register-cli-scan",
      "--repository",
      checkout,
      "--scan-dir",
      scanDir,
      "--registration-json-stdin",
    ],
    JSON.stringify({
      recipe: {
        ...(excludePaths.length ? { excludePaths } : {}),
        repository: checkout,
        mode: scan.mode,
        target,
        config: config.codexOverrides ?? {},
        maxCostUsd: scan.maxCostUsd,
        ownerSuggestions: scan.ownerSuggestions,
        scanRequestDigest: scanRequestDigest(config, scan, checkout),
      },
      userContext: scan.scanPrompt,
    }),
  );
  if (outcome === "interrupted")
    throw new Error("Synthetic interruption after private registration.");

  await cp(join(PLUGIN_ROOT, "examples/completed-scan"), scanDir, {
    recursive: true,
  });
  const manifestPath = join(scanDir, "scan-manifest.json");
  const findingsPath = join(scanDir, "findings.json");
  const manifest = await readJson<ScanResult["manifest"]>(manifestPath);
  const findings = await readJson<ScanResult["findings"]>(findingsPath);
  const scanId = String(registered["scanId"]);
  manifest.scan.id = scanId;
  findings.scanId = scanId;
  manifest.scan.target = {
    kind: "git_revision",
    targetId: String(registered["targetId"]),
    displayName: basename(checkout),
    revision: git(checkout, "rev-parse", "HEAD"),
  };
  manifest.scan.scope = { ...manifest.scan.scope, includePaths, excludePaths };
  manifest.scan.mode =
    target.kind === "paths"
      ? "scoped_path"
      : scan.mode === "deep"
        ? "deep_repository"
        : "repository";
  if (outcome === "empty") findings.findings = [];
  for (const finding of findings.findings) {
    setFindingIdentity(manifest.scan, finding);
    for (const location of finding.locations)
      location.path = `${includePaths[0]}/index.ts`;
  }
  await writeJson(findingsPath, findings);
  await writeJson(manifestPath, {
    ...manifest,
    scan: { ...manifest.scan, sealedAt: undefined, artifacts: undefined },
  });
  if (scan.mode === "deep") {
    await workbench([
      "begin-deep-scan",
      "--scan-id",
      scanId,
      "--thread-id",
      randomUUID(),
      "--available-parallelism",
      "4",
      "--workflow-version",
      "deep-scan-mcp/v1",
    ]);
    // The fake scanner supplied a finished Deep result. Persist that
    // coordinator fixture before asking the real workbench to seal it.
    execFileSync(
      python,
      [
        "-I",
        "-c",
        "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE deep_scan_runs SET status='succeeded', phase='terminal', terminal_reason='saturated', manifest_path=?, completed_at=updated_at WHERE scan_id=?\", (sys.argv[2],sys.argv[3])); c.commit()",
        join(environment["CODEX_SECURITY_STATE_DIR"]!, "workbench.sqlite3"),
        manifestPath,
        scanId,
      ],
      { env: environment },
    );
  }
  await workbench(["complete-scan", "--scan-id", scanId]);
  return new ScanResult({
    ...(await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT })),
    scanDir,
    threadId: "synthetic-thread",
    turnResult: {},
  });
}

export function createMultiscanFixtures() {
  const { temporaryDirectory, cleanup: cleanupDirectories } =
    createApiTestFixtures("codex-security-multiscan-");
  const fixtureRoots = new Set<string>();
  const fixtureInputs = new Map<string, string>();
  const fixtureRequests = new Map<
    string,
    {
      id: string;
      repository: string;
      revision: string;
      digest: string;
      target: NormalizedTarget;
    }
  >();
  let fixtureState: string | undefined;
  async function cleanup() {
    await cleanupDirectories();
    fixtureRoots.clear();
    fixtureInputs.clear();
    fixtureRequests.clear();
    fixtureState = undefined;
  }
  async function fixture() {
    const root = await temporaryDirectory();
    fixtureRoots.add(root);
    if (fixtureState === undefined) {
      fixtureState = join(root, "state");
      await runWorkbench(
        {
          python: PYTHON,
          pluginRoot: PLUGIN_ROOT,
          environment: {
            ...process.env,
            CODEX_SECURITY_STATE_DIR: fixtureState,
          },
        },
        ["database-info"],
      );
    }
    return {
      root,
      input: join(root, "repositories.csv"),
      output: join(root, "results"),
    };
  }

  async function repositoryFixture(name: string, id = name) {
    const paths = await fixture();
    const source = await repository(paths.root, name);
    await writeFile(
      paths.input,
      `id,repository,revision\n${id},${source.path},${source.revision}\n`,
    );
    return { paths, source };
  }

  async function fixtureTask(outputDir: string) {
    const root = [...fixtureRoots].find((root) =>
      outputDir.startsWith(root + sep),
    );
    if (root === undefined) return undefined;
    const inventory = await readFile(
      fixtureInputs.get(outputDir) ?? join(root, "repositories.csv"),
      "utf8",
    ).catch(() => undefined);
    if (inventory === undefined) return undefined;
    const id = basename(dirname(outputDir)).toLowerCase();
    return Papa.parse<Record<string, string>>(inventory, {
      header: true,
      transformHeader: (header) => header.trim(),
      skipEmptyLines: true,
    }).data.find((entry) => entry["id"]?.trim().toLowerCase() === id);
  }

  async function completedScan(
    outputDir: string,
    completeness: "complete" | "partial" | "unknown" = "complete",
    targetRoot?: string,
  ) {
    const request = fixtureRequests.get(outputDir);
    targetRoot ??= request?.repository;
    await mkdir(outputDir, { recursive: true, mode: 0o700 });
    await chmod(outputDir, 0o700);
    await copyCompletedScanFixture(outputDir);
    await writeFile(join(outputDir, "report.md"), "# Scan report\n");
    const manifestPath = join(outputDir, "scan-manifest.json");
    const findingsPath = join(outputDir, "findings.json");
    const coveragePath = join(outputDir, "coverage.json");
    const manifest = await readJson<ScanResult["manifest"]>(manifestPath);
    const findings = await readJson<ScanResult["findings"]>(findingsPath);
    const coverage = await readJson<CoverageDocument>(coveragePath);
    if (request) {
      manifest.scan.id = request.id;
      findings.scanId = request.id;
      coverage.scanId = request.id;
      if (targetRoot !== undefined) request.repository = targetRoot;
    }
    const id = basename(dirname(outputDir));
    const campaignRoot = dirname(dirname(dirname(outputDir)));
    const task = await fixtureTask(outputDir);
    if (task !== undefined) {
      const checkout = targetRoot ?? join(campaignRoot, "checkouts", id);
      manifest.scan.target.kind = "git_revision";
      const digest = sha256(`local-workspace\0${checkout}`);
      manifest.scan.target.targetId = `target_sha256_${digest}`;
      manifest.scan.target.displayName = basename(checkout);
      manifest.scan.target.revision = task["revision"]!;
      delete manifest.scan.target.snapshotDigest;
      const scope = task["scope"]?.trim();
      let normalizedScope = scope ? posix.normalize(scope) : ".";
      if (scope) {
        const canonicalScope = await realpath(join(checkout, scope)).catch(
          () => undefined,
        );
        if (canonicalScope !== undefined) {
          normalizedScope =
            relative(await realpath(checkout), canonicalScope)
              .split(sep)
              .join("/") || ".";
        }
      }
      const includePaths = [normalizedScope];
      manifest.scan.scope.includePaths = includePaths;
      coverage.includePaths = includePaths;
      coverage.mode = scope
        ? "scoped_path"
        : task["mode"]?.trim() === "deep"
          ? "deep_repository"
          : "repository";
      coverage.inventoryStrategy = scope ? "scoped_path" : "repository";
    }
    for (const finding of findings.findings)
      setFindingIdentity(manifest.scan, finding);
    coverage["completeness"] = completeness;
    await writeJson(manifestPath, manifest);
    await writeJson(findingsPath, findings);
    await writeJson(coveragePath, coverage);
    await reseal(outputDir);
    return {
      manifest,
      findings,
      coverage,
      mode: coverage.mode,
      review: fakeResult([], completeness).review,
    } as ScanResult & { coverage: CoverageDocument };
  }

  async function reseal(outputDir: string) {
    await resealArtifacts(outputDir);
    await recordFixtureAuthority(outputDir);
  }

  async function recordFixtureRequest(
    repository: string,
    settings: NonNullable<Parameters<SecurityClient["run"]>[1]>,
    config: MultiscanOptions["config"] = {},
    revision?: string,
  ): Promise<void> {
    // The coordinator verified this immutable task SHA before calling the producer.
    revision ??= (await fixtureTask(settings.outputDir!))?.["revision"]
      ?.trim()
      .toLowerCase();
    if (revision === undefined)
      throw new Error("Fixture scan has no pinned task revision.");
    fixtureRequests.set(settings.outputDir!, {
      id: fixtureRequests.get(settings.outputDir!)?.id ?? randomUUID(),
      repository,
      revision,
      digest: scanRequestDigest(config, settings, repository),
      target: Array.isArray(settings.target)
        ? await normalizeTarget(repository, settings.target)
        : { kind: "repository", paths: [] },
    });
  }

  async function recordFixtureAuthority(outputDir: string): Promise<void> {
    const request = fixtureRequests.get(outputDir);
    if (!request || !fixtureState) return;
    const bytes = await readFile(join(outputDir, "scan-manifest.json")).catch(
      () => undefined,
    );
    let manifest: ScanResult["manifest"] | undefined;
    try {
      if (bytes) manifest = JSON.parse(bytes.toString("utf8"));
    } catch {
      return;
    }
    if (manifest && manifest.scan.id !== request.id) return;
    const database = new Database(join(fixtureState, "workbench.sqlite3"));
    try {
      const { id } = request;
      const prior = database
        .query("SELECT id FROM scans WHERE scan_dir = ?")
        .get(outputDir) as { id: string } | null;
      if (prior && prior.id !== id) return;
      const timestamp = new Date().toISOString();
      database.run(
        "INSERT OR IGNORE INTO workspaces (id, target_path, created_at, updated_at) VALUES (?, ?, ?, ?)",
        [id, request.repository, timestamp, timestamp],
      );
      database.run(
        `INSERT INTO scans (id, workspace_id, target_path, target_revision, target_id, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at, recipe_json, seal_manifest_digest)
      VALUES (?, ?, ?, ?, ?, '.', 'standard', ?, ?, 'reporting', ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET target_path=excluded.target_path, status=excluded.status, recipe_json=excluded.recipe_json, seal_manifest_digest=excluded.seal_manifest_digest`,
        [
          id,
          id,
          request.repository,
          request.revision,
          manifest?.scan.target.targetId ?? "fixture-running-target",
          outputDir,
          bytes ? "complete" : "running",
          timestamp,
          timestamp,
          timestamp,
          JSON.stringify({
            scanRequestDigest: request.digest,
            target: request.target,
          }),
          bytes ? `sha256:${sha256(bytes)}` : null,
        ],
      );
    } finally {
      database.close();
    }
  }

  const completeRun: SecurityClient["run"] = (_repository, scanOptions = {}) =>
    completedScan(scanOptions.outputDir!);

  function options(
    paths: { input: string; output: string },
    security: SecurityClient,
    overrides: Partial<MultiscanOptions> = {},
  ): MultiscanOptions {
    const selected: MultiscanOptions = {
      environment: { ...process.env, CODEX_SECURITY_STATE_DIR: fixtureState },
      inputPath: paths.input,
      outputDir: paths.output,
      workers: 1,
      mode: "standard",
      maxAttempts: 2,
      config: {},
      createSecurity: () => security,
      ...overrides,
    };
    const create = selected.createSecurity;
    selected.createSecurity = (config) => {
      const instance = create(config);
      return {
        close: () => instance.close(),
        run: async (repository, settings = {}) => {
          fixtureInputs.set(settings.outputDir!, selected.inputPath);
          await recordFixtureRequest(repository, settings, config);
          try {
            return await instance.run(repository, settings);
          } finally {
            await recordFixtureAuthority(settings.outputDir!);
          }
        },
      };
    };
    return selected;
  }

  return {
    temporaryDirectory,
    cleanup,
    fixture,
    repositoryFixture,
    completedScan,
    completeRun,
    reseal,
    options,
    recordFixtureRequest,
    recordFixtureAuthority,
    fixtureRequests,
  };
}

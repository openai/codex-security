import { afterEach, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  cp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadContract, hasSealedReport } from "../src/contract.js";
import { normalizeTarget } from "../src/targets.js";
import { scanRequestDigest, workflowDigest } from "../src/finding-workflow.js";
import { runMultiscan } from "../src/multiscan.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import type { ScanResult } from "../src/result.js";
import type { ScanOptions } from "../src/api.js";
import type { CodexSecurityConfig } from "../src/config.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { rejecting } from "./support/errors.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "multiscan-authority-",
);
afterEach(cleanup);

async function fixture(registerOnly = false) {
  const root = await temporaryDirectory();
  const source = join(root, "source");
  await mkdir(source);
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", source, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  git("init", "--quiet");
  await mkdir(join(source, "src"));
  await writeFile(join(source, "src/app.ts"), "export const value = 1;\n");
  await writeFile(
    join(source, ".gitattributes"),
    "src/*.ts text eol=lf filter=codexCampaignFixture\n",
  );
  git("add", ".");
  git(
    "-c",
    "user.name=Synthetic",
    "-c",
    "user.email=synthetic@example.test",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "-qm",
    "Synthetic baseline",
  );
  const revision = git("rev-parse", "HEAD");
  const state = join(root, "state");
  const environment = { ...process.env, CODEX_SECURITY_STATE_DIR: state };
  const python = await resolvePluginPython({ environment });
  const workbench = (args: string[], input?: unknown) =>
    runWorkbench(
      { python, pluginRoot, environment },
      args,
      input === undefined ? undefined : JSON.stringify(input),
    );
  const inputPath = join(root, "repositories.csv");
  await writeFile(
    inputPath,
    `id,repository,revision\nrepo,${source},${revision}\n`,
  );
  let runs = 0;
  const options: Parameters<typeof runMultiscan>[0] = {
    inputPath,
    outputDir: join(root, "campaign"),
    workers: 1,
    mode: "standard",
    maxAttempts: 1,
    environment,
    scanPrompt: "Original requested instructions.",
    onProgress: (event) => {
      if (event.error) console.error(event.error);
    },
    config: { pluginPath: pluginRoot },
    createSecurity: (config) => ({
      close: async () => {},
      run: async (checkout, scan = {}) => {
        runs++;
        return await registeredResult(config, checkout, scan);
      },
    }),
  };
  async function registeredResult(
    config: CodexSecurityConfig,
    checkout: string,
    scan: ScanOptions,
  ): Promise<ScanResult> {
    const scanDir = scan.outputDir!;
    const target = await normalizeTarget(checkout, scan.target ?? "repository");
    const includePaths = target.kind === "repository" ? ["."] : target.paths;
    await mkdir(scanDir, { recursive: true, mode: 0o700 });
    const registered = await workbench(
      [
        "register-cli-scan",
        "--repository",
        checkout,
        "--scan-dir",
        scanDir,
        "--registration-json-stdin",
      ],
      {
        recipe: {
          repository: checkout,
          mode: scan.mode ?? "standard",
          target,
          config: {},
          scanRequestDigest: scanRequestDigest(config, scan, checkout),
        },
        userContext: scan.scanPrompt,
      },
    );
    if (registerOnly)
      throw new Error("Synthetic interruption after private registration.");
    await cp(join(pluginRoot, "examples/completed-scan"), scanDir, {
      recursive: true,
    });
    const manifest = JSON.parse(
      await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
    );
    manifest.scan.id = registered["scanId"];
    manifest.scan.target = {
      kind: "git_revision",
      targetId: registered["targetId"],
      displayName: basename(checkout),
      revision,
    };
    manifest.scan.scope = { includePaths, excludePaths: [] };
    delete manifest.scan.sealedAt;
    delete manifest.scan.artifacts;
    const findings = {
      documentType: "codex-security.findings",
      schemaVersion: "1.0",
      scanId: registered["scanId"],
      findings: [],
    };
    const coverage = JSON.parse(
      await readFile(join(scanDir, "coverage.json"), "utf8"),
    );
    Object.assign(coverage, {
      scanId: registered["scanId"],
      mode: target.kind === "repository" ? "repository" : "scoped_path",
      includePaths,
      excludePaths: [],
      deferred: [],
      surfaces: [],
      completeness: "complete",
    });
    for (const [name, value] of [
      ["scan-manifest", manifest],
      ["findings", findings],
      ["coverage", coverage],
    ])
      await writeFile(join(scanDir, `${name}.json`), JSON.stringify(value));
    execFileSync(
      python,
      [
        "-I",
        "-B",
        join(pluginRoot, "scripts/finalize_scan_contract.py"),
        "--scan-dir",
        scanDir,
      ],
      { env: environment, stdio: ["ignore", "pipe", "pipe"] },
    );
    const sealed = JSON.parse(
      await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
    );
    sealed.scan.artifacts.push({
      path: "report.md",
      mediaType: "text/markdown",
      sha256: createHash("sha256")
        .update(await readFile(join(scanDir, "report.md")))
        .digest("hex"),
    });
    await writeFile(
      join(scanDir, "scan-manifest.json"),
      execFileSync(
        python,
        [
          "-I",
          "-c",
          "import json,sys; sys.stdout.buffer.write((json.dumps(json.load(sys.stdin), indent=2, sort_keys=True) + '\\n').encode('utf-8'))",
        ],
        { input: JSON.stringify(sealed), env: environment },
      ),
    );
    await workbench([
      "complete-scan",
      "--scan-id",
      String(registered["scanId"]),
    ]);
    const result = await loadContract(scanDir, { pluginRoot });
    expect(await hasSealedReport(scanDir, result.manifest)).toBe(true);
    return {
      ...result,
      scanDir,
      cost: null,
      threatModelPath: null,
    } as ScanResult;
  }
  return { root, source, state, options, runs: () => runs, registeredResult };
}

test("registered sealed campaign reuse does not need report Python", async () => {
  const value = await fixture();
  value.options.config.pythonPath = join(value.root, "unavailable-python");
  expect(await runMultiscan(value.options)).toMatchObject({
    completed: 1,
    skipped: 0,
  });
  expect(await runMultiscan(value.options)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
  expect(value.runs()).toBe(1);
});

for (const recovery of [false, true]) {
  test(`concurrent campaigns retain independent invocation authority with recovery=${recovery}`, async () => {
    const ambientState = process.env["CODEX_SECURITY_STATE_DIR"];
    const values = await Promise.all([fixture(), fixture()]);
    const run = () =>
      Promise.all(values.map((value) => runMultiscan(value.options)));
    for (const result of await run())
      expect(result).toMatchObject({ completed: 1, skipped: 0 });
    let recovered = 0;
    if (recovery) {
      for (const value of values) {
        await writeFile(join(value.options.outputDir, "results.jsonl"), "");
        value.options.recoverScan = async (scanDir) => {
          recovered++;
          return {
            ...(await loadContract(scanDir, { pluginRoot })),
            cost: null,
          };
        };
      }
    }
    for (const result of await run())
      expect(result).toMatchObject({ completed: 1, skipped: recovery ? 0 : 1 });
    expect(recovered).toBe(recovery ? 2 : 0);
    expect(values.map((value) => value.runs())).toEqual([1, 1]);
    expect(process.env["CODEX_SECURITY_STATE_DIR"]).toBe(ambientState);
  });
}

for (const registerOnly of [false, true]) {
  for (const retargeted of [false, true]) {
    test(`registered task recovery binds its revision with running=${registerOnly} retargeted=${retargeted}`, async () => {
      const value = await fixture(registerOnly);
      expect(await runMultiscan(value.options)).toMatchObject({
        completed: registerOnly ? 0 : 1,
        failed: registerOnly ? 1 : 0,
      });
      const scanDir = join(value.options.outputDir, "artifacts/repo/attempt-1");
      const database = new Database(join(value.state, "workbench.sqlite3"), {
        readonly: process.platform !== "darwin",
        readwrite: process.platform === "darwin",
        create: false,
      });
      database.exec("PRAGMA query_only = ON");
      const registered = database
        .query("SELECT id,target_revision FROM scans WHERE scan_dir=?")
        .get(scanDir) as { id: string; target_revision: string };
      database.close();
      let revision = registered.target_revision;
      if (retargeted) {
        await writeFile(
          join(value.source, "src/app.ts"),
          "export const value = 2;\n",
        );
        execFileSync("git", ["-C", value.source, "add", "."]);
        execFileSync("git", [
          "-C",
          value.source,
          "-c",
          "user.name=Synthetic",
          "-c",
          "user.email=synthetic@example.test",
          "-c",
          "commit.gpgsign=false",
          "commit",
          "-qm",
          "Second requested revision",
        ]);
        revision = execFileSync(
          "git",
          ["-C", value.source, "rev-parse", "HEAD"],
          { encoding: "utf8" },
        ).trim();
        expect(revision).not.toBe(registered.target_revision);
        await writeFile(
          value.options.inputPath,
          `id,repository,revision\nrepo,${value.source},${revision}\n`,
        );
        const path = join(value.options.outputDir, "manifest.json");
        const campaign = JSON.parse(await readFile(path, "utf8"));
        campaign.tasks[0].revision = revision;
        await writeFile(path, JSON.stringify(campaign));
      }
      const ledger = join(value.options.outputDir, "results.jsonl");
      const receipt = JSON.parse(
        (await readFile(ledger, "utf8")).trim().split("\n").at(-1)!,
      );
      receipt.revision = revision;
      receipt.status = "failed";
      receipt.error =
        "Synthetic interruption after registration or completion.";
      await writeFile(ledger, JSON.stringify(receipt) + "\n");
      let recovered = 0,
        fresh = 0;
      value.options.recoverScan = async (path) => {
        recovered++;
        if (registerOnly) return undefined;
        return {
          ...(await loadContract(path, {
            pluginRoot,
            expectedScanId: registered.id,
          })),
          cost: null,
        };
      };
      value.options.createSecurity = () => ({
        close: async () => {},
        run: async (checkout) => {
          fresh++;
          expect(
            execFileSync("git", ["-C", checkout, "rev-parse", "HEAD"], {
              encoding: "utf8",
            }).trim(),
          ).toBe(revision);
          throw new Error(
            "Synthetic stop after preparing the requested fresh revision.",
          );
        },
      });
      const outcome = await runMultiscan(value.options);
      expect(recovered).toBe(retargeted ? 0 : 1);
      expect(fresh).toBe(retargeted || registerOnly ? 1 : 0);
      expect(outcome).toMatchObject({
        completed: retargeted || registerOnly ? 0 : 1,
        failed: retargeted || registerOnly ? 1 : 0,
      });
    });
  }
}

test("registered campaign reuses equivalent staged knowledge sources", async () => {
  const value = await fixture();
  const knowledge = join(value.root, "knowledge");
  await mkdir(knowledge);
  const document = join(knowledge, "context.md");
  await writeFile(document, "Original staged context.");
  value.options.knowledgeBasePaths = [knowledge];
  expect(await runMultiscan(value.options)).toMatchObject({
    completed: 1,
    skipped: 0,
  });
  value.options.knowledgeBasePaths = [document, document];
  expect(await runMultiscan(value.options)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
  expect(value.runs()).toBe(1);
  await writeFile(document, "Changed staged context.");
  await expect(runMultiscan(value.options)).rejects.toThrow(
    "manifest does not match",
  );
  expect(value.runs()).toBe(1);
});

for (const kind of ["prompt", "configuration", "legacy", "seal"] as const) {
  for (const recovery of [false, true]) {
    test(`registered campaign rejects editable ${kind} reuse authority with recovery=${recovery}`, async () => {
      const value = await fixture();
      expect(await runMultiscan(value.options)).toMatchObject({
        completed: 1,
        skipped: 0,
      });
      if (recovery)
        value.options.recoverScan = async () => {
          throw new Error("Unverified settings must not reach recovery.");
        };
      const manifestPath = join(value.options.outputDir, "manifest.json");
      const campaign = JSON.parse(await readFile(manifestPath, "utf8"));
      if (kind === "prompt") {
        value.options.scanPrompt = "Different requested instructions.";
        campaign.scanPrompt = value.options.scanPrompt;
      } else if (kind === "configuration") {
        value.options.config.codexOverrides = { analytics: { enabled: false } };
        const { workflowDigest } = await import("../src/finding-workflow.js");
        campaign.configurationDigest = workflowDigest({
          scanOptions: value.options.scanOptionsByMode,
          codex: value.options.config.codexOverrides,
          pluginPath: value.options.config.pluginPath,
          pythonPath: value.options.config.pythonPath,
        });
      } else if (kind === "legacy") {
        const database = new Database(join(value.state, "workbench.sqlite3"));
        try {
          database.run(
            "UPDATE scans SET recipe_json = json_remove(recipe_json, '$.scanRequestDigest')",
          );
        } finally {
          database.close();
        }
      } else {
        const path = join(
          value.options.outputDir,
          "artifacts/repo/attempt-1/scan-manifest.json",
        );
        const scan = JSON.parse(await readFile(path, "utf8"));
        scan.scan.extensions = { syntheticChanged: true };
        await writeFile(path, JSON.stringify(scan, null, 2) + "\n");
        // The bundle is still internally sealed, but no longer the registered manifest bytes.
        await loadContract(
          join(value.options.outputDir, "artifacts/repo/attempt-1"),
          { pluginRoot },
        );
      }
      await writeFile(manifestPath, JSON.stringify(campaign, null, 2) + "\n");
      expect(await runMultiscan(value.options)).toMatchObject({
        completed: 1,
        skipped: 0,
      });
      expect(value.runs()).toBe(2);
    });
  }
}

test("SDK registration records the same complete request identity used by campaign reuse", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository"),
    home = join(root, "home"),
    outputDir = join(root, "scan");
  for (const path of [repository, home, outputDir])
    await mkdir(path, { mode: 0o700 });
  const config: CodexSecurityConfig = {
    pluginPath: pluginRoot,
    codexOverrides: {
      analytics: { enabled: false },
      shell_environment_policy: { inherit: "none" },
    },
  };
  const options: ScanOptions = {
    outputDir,
    mode: "standard",
    scanPrompt: "Supplied discovery instructions.",
    validationPrompt: "Supplied verification instructions.",
    postScanPrompt: "Supplied reporting instructions.",
  };
  let recipe: Record<string, unknown> | undefined;
  const client = new TestClient(config, {
    environment: {
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    },
    resolvePluginPython: async () => "/managed/python",
    prepareRuntime: async () => ({
      codexHome: home,
      environment: {},
      credentialsAvailable: true,
      plugin: {
        pluginRoot,
        marketplaceRoot: pluginRoot,
        installedRoot: pluginRoot,
        marketplaceName: "codex-security-sdk",
        name: "codex-security",
        version: "0.1.0",
      },
    }),
    prepareOutputDir: async () => outputDir,
    repositoryRevision: async () => "deadbeef",
    runWorkbench: async (_runtime, args, input) => {
      if (args[0] === "register-cli-scan") recipe = JSON.parse(input!).recipe;
      return mockWorkbench(args, input);
    },
    createCodex: async () => ({
      startThread: () => ({
        id: null,
        runStreamed: rejecting("synthetic stop after registration"),
      }),
    }),
  });
  try {
    await expect(client.run(repository, options)).rejects.toThrow(
      "synthetic stop after registration",
    );
    expect(recipe?.["scanRequestDigest"]).toBe(
      workflowDigest({ config, options: { ...options, target: "repository" } }),
    );
    expect(recipe?.["scanRequestDigest"]).not.toBe(
      scanRequestDigest(config, {
        ...options,
        validationPrompt: "Different verification instructions.",
      }),
    );
  } finally {
    await client.close();
  }
});

test.each([
  "duplicate-resolved",
  "active-id",
  "active-candidate",
  "nested-legacy",
  "reachability-legacy",
  "duplicate-legacy-catalog",
  "partial",
  "failed",
  "canceled",
  "interrupted",
] as const)("canonical sealed readers agree for %s", async (kind) => {
  const root = await temporaryDirectory();
  const scanDir = join(root, "scan");
  await cp(join(pluginRoot, "examples/completed-scan"), scanDir, {
    recursive: true,
  });
  await chmod(scanDir, 0o700);
  const read = async (name: string) =>
    JSON.parse(await readFile(join(scanDir, name + ".json"), "utf8"));
  const manifest = await read("scan-manifest"),
    coverage = await read("coverage"),
    findings = await read("findings");
  coverage.completeness = "partial";
  if (kind === "duplicate-resolved")
    coverage.resolvedDeferred = [
      { id: "task", reason: "Closed once." },
      { id: "task", reason: "Closed twice." },
    ];
  else if (kind === "active-id" || kind === "active-candidate") {
    coverage.resolvedDeferred = [{ id: "task", reason: "Closed." }];
    coverage.deferred = [
      {
        id: kind === "active-id" ? "task" : "other-task",
        ...(kind === "active-candidate" ? { candidateId: "task" } : {}),
        reason: "Still open.",
      },
    ];
  } else if (kind === "nested-legacy")
    findings.findings[0].attackPath = {
      dataFlow: { summary: "Saved path", evidenceRefs: ["missing-evidence"] },
    };
  else if (kind === "reachability-legacy")
    findings.findings[0].attackPath = {
      reachability: {
        summary: "Saved reachability",
        evidence_refs: ["missing-evidence"],
      },
    };
  else if (kind === "duplicate-legacy-catalog") {
    findings.findings[0].code_evidence = [
      { id: "same", code: "a()" },
      { id: "same", code: "b()" },
    ];
    findings.findings[0].root_cause = {
      summary: "Saved cause",
      evidence_refs: ["same", "missing"],
    };
  }
  if (["partial", "failed", "canceled", "interrupted"].includes(kind)) {
    manifest.scan.status = kind === "partial" ? "completed" : kind;
    coverage.deferred = [
      { id: "still-open", reason: "Retained work after stop." },
    ];
    coverage.surfaces[0].disposition = "needs_follow_up";
  }
  await writeFile(join(scanDir, "coverage.json"), JSON.stringify(coverage));
  await writeFile(join(scanDir, "findings.json"), JSON.stringify(findings));
  for (const artifact of manifest.scan.artifacts)
    artifact.sha256 = createHash("sha256")
      .update(await readFile(join(scanDir, artifact.path)))
      .digest("hex");
  await writeFile(
    join(scanDir, "scan-manifest.json"),
    JSON.stringify(manifest),
  );
  const before = await readFile(join(scanDir, "findings.json"));
  const python = await resolvePluginPython({ environment: process.env });
  const canonical = () =>
    execFileSync(
      python,
      [
        "-I",
        "-B",
        join(pluginRoot, "scripts/finalize_scan_contract.py"),
        "--scan-dir",
        scanDir,
        "--export-format",
        "json",
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
  if (
    kind.includes("legacy") ||
    ["partial", "failed", "canceled", "interrupted"].includes(kind)
  ) {
    await loadContract(scanDir, { pluginRoot });
    expect(canonical().length).toBeGreaterThan(0);
  } else {
    expect(canonical).toThrow();
    await expect(loadContract(scanDir, { pluginRoot })).rejects.toThrow(
      /resolved deferred|still active/,
    );
  }
  expect(await readFile(join(scanDir, "findings.json"))).toEqual(before);
});

test.each(["local", "include", "worktree", "host"] as const)(
  "retained restoration isolates %s configuration while preserving trusted host filters",
  async (kind) => {
    const value = await fixture();
    value.options.scanOptionsByMode = { standard: { target: ["src/app.ts"] } };
    expect(await runMultiscan(value.options)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    const checkout = join(value.options.outputDir, "checkouts/repo");
    execFileSync("git", ["clone", "--quiet", value.source, checkout]);
    const marker = join(value.root, "filter-called");
    const script = join(value.root, "filter.cjs");
    await writeFile(
      script,
      `const fs = require("node:fs"); fs.writeFileSync(${JSON.stringify(marker)}, "called"); process.stdout.write(fs.readFileSync(0));`,
    );
    const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
    const filter = `${quote(process.execPath)} ${quote(script)}`;
    const configured =
      kind === "host" || kind === "include"
        ? join(value.root, "synthetic.gitconfig")
        : join(
            checkout,
            ".git",
            kind === "worktree" ? "config.worktree" : "config",
          );
    execFileSync("git", [
      "config",
      "--file",
      configured,
      "filter.codexCampaignFixture.smudge",
      filter,
    ]);
    if (kind === "include")
      execFileSync("git", [
        "-C",
        checkout,
        "config",
        "include.path",
        configured,
      ]);
    if (kind === "worktree")
      execFileSync("git", [
        "-C",
        checkout,
        "config",
        "extensions.worktreeConfig",
        "true",
      ]);
    const originalConfig = await readFile(join(checkout, ".git/config"));
    await rm(join(checkout, "src/app.ts"));
    const hostConfig = process.env["GIT_CONFIG_GLOBAL"];
    if (kind === "host") process.env["GIT_CONFIG_GLOBAL"] = configured;
    try {
      expect(await runMultiscan(value.options)).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(value.runs()).toBe(1);
      expect(await readFile(join(checkout, "src/app.ts"), "utf8")).toBe(
        "export const value = 1;\n",
      );
      if (kind === "host")
        expect(await readFile(marker, "utf8")).toBe("called");
      else await expect(readFile(marker)).rejects.toThrow();
      const archived = (await readdir(join(checkout, ".git"))).filter((name) =>
        name.startsWith("config.retained-"),
      );
      expect(archived).toHaveLength(1);
      expect(await readFile(join(checkout, ".git", archived[0]!))).toEqual(
        originalConfig,
      );
    } finally {
      if (hostConfig === undefined) delete process.env["GIT_CONFIG_GLOBAL"];
      else process.env["GIT_CONFIG_GLOBAL"] = hostConfig;
    }
  },
);

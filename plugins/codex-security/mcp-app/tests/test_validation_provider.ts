import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { hash } from "node:crypto";
import {
  chmod,
  mkdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, join } from "node:path";
import { test } from "node:test";
import { importSource as bundle } from "./import-module.ts";
import { finding as draftFinding } from "./scan-draft-fixture.ts";
import { readJson } from "./support/json.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import type * as Host from "../src/validation-provider.js";

const plugin = join(import.meta.dirname, "../..");
const runtime = join(import.meta.dirname, "../../../../sdk/typescript");
function importSource(path: string) {
  return bundle(path, {
    define: {
      __dirname: JSON.stringify(join(plugin, "mcp")),
      "import.meta.url": JSON.stringify(
        join(runtime, "_bundled_plugin/mcp/helpers.mjs"),
      ),
    },
    alias: {
      "#validation-runtime": join(runtime, "src/plugin-validation.ts"),
    },
  });
}

const {
  bindValidationProviderConfiguration,
  readCompletedValidation,
  validateCompletedScan,
  validationCompletionText,
} = (await importSource(
  join(import.meta.dirname, "../src/validation-provider.ts"),
)) as typeof Host;

const { deriveFindingIdentity } = await importSource(
  join(import.meta.dirname, "../src/contract-values.ts"),
);
const configuration = {
  provider: "continuum",
  continuum: { environment_id: "example" },
};

async function sealedScan(
  scanDir: string,
  targetPath: string,
  scanId: string,
  count = 1,
) {
  const example = join(plugin, "examples/completed-scan");
  const document = await readJson(example, "findings.json");
  const manifest = await readJson(example, "scan-manifest.json");
  const first = document.findings[0];
  const members = Array.from({ length: count }, (_, index) => ({
    ...first,
    ...deriveFindingIdentity(
      scanId,
      manifest.scan.target.targetId,
      first.ruleId,
      { anchor: `item-${index + 1}` },
    ),
  }));
  const ids: string[] = members.map((member) => member.occurrenceId);
  const findings = JSON.stringify({ ...document, scanId, findings: members });
  manifest.scan.id = scanId;
  manifest.scan.artifacts[0].sha256 = hash("sha256", findings);
  const seal = JSON.stringify(manifest);
  await writeFile(join(scanDir, "scan-manifest.json"), seal);
  await writeFile(join(scanDir, "findings.json"), findings);
  return {
    scan: {
      scanId,
      targetPath,
      scanDir,
      progress: { status: "complete" },
      sealManifestDigest: "sha256:" + hash("sha256", seal),
    },
    findings,
    ids,
  };
}

await test("packaged and source-only runtimes read the same assessment version and home", async () => {
  const standalone = await import("../src/standalone-validation.ts");
  const oldState = process.env.CODEX_SECURITY_STATE_DIR;
  const oldHome = process.env.CODEX_HOME;
  const home = await temporaryDirectory("plugin-provider-home-");
  try {
    delete process.env.CODEX_SECURITY_STATE_DIR;
    process.env.CODEX_HOME = home;
    await bindValidationProviderConfiguration("selected", configuration, true);
    const { scan } = await sealedScan(home, home, "selected", 0);
    await validateCompletedScan(scan, () => ({
      name: "fixture",
      version: "1",
    }));
    const state = join(home, "state", "plugins", "codex-security");
    assert.equal(standalone.codexSecurityStateDirectory(), state);
    assert.deepEqual(
      await readJson(state, "validation-providers", "selected.json"),
      configuration,
    );
    const saved = await readJson(
      state,
      "validation-providers",
      "selected.json.result",
    );
    assert.equal(standalone.continuumAssessmentVersion, saved.schemaVersion);
  } finally {
    if (oldState !== undefined) process.env.CODEX_SECURITY_STATE_DIR = oldState;
    if (oldHome === undefined) delete process.env.CODEX_HOME;
    else process.env.CODEX_HOME = oldHome;
    await rm(home, { recursive: true, force: true });
  }
});

await test("unconfigured plugin scans never invoke a validation provider", async () => {
  let calls = 0;
  const result = await validateCompletedScan(
    { scanId: "unconfigured-fixture" },
    () => {
      calls++;
      throw new Error("unexpected provider");
    },
  );
  assert.equal(result, undefined);
  assert.equal(validationCompletionText(result), "");
  assert.equal(calls, 0);
});

for (const schemaVersion of [undefined, 2, 4, 5, 6]) {
  const mixed = schemaVersion === 2;
  await test(`legacy version ${schemaVersion} assessments refresh only on explicit completion`, async () => {
    const root = await temporaryDirectory("plugin-validation-upgrade-");
    const oldState = process.env.CODEX_SECURITY_STATE_DIR;
    process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
    try {
      const directory = join(root, "state", "validation-providers");
      const repositoryPath = join(root, "repository");
      await mkdir(directory, { recursive: true });
      await mkdir(repositoryPath);
      const { scan, ids } = await sealedScan(
        root,
        repositoryPath,
        "upgrade",
        mixed ? 2 : 1,
      );
      const path = join(directory, "upgrade.json");
      await bindValidationProviderConfiguration(
        scan.scanId,
        configuration,
        true,
      );
      const record = {
        itemId: ids[0],
        verdict: "EXPLOITABLE",
        claimMatch: (schemaVersion ?? 0) >= 4 ? "unknown" : "on_target",
        resultScope: "finding",
        severityBefore: "high",
        severityAfter: (schemaVersion ?? 0) >= 4 ? "high" : "critical",
      };
      const old = JSON.stringify({
        schemaVersion,
        configuration,
        repositoryPath,
        records: { schemaVersion: 1, items: [record] },
        result: {
          provider: "continuum",
          findings: ids.length,
          status: mixed ? "incomplete" : "complete",
          report: "Legacy regrade",
          summary: "Legacy regrade",
        },
        retry: mixed
          ? [{ record, report: "Legacy regrade" }, { unavailable: "timeout" }]
          : null,
      });
      await writeFile(path + ".result", old);
      const read = await readCompletedValidation(scan);
      assert.equal(read?.status, "outdated");
      assert.equal(read?.items, undefined);
      assert.equal(read?.retryable, true);
      assert.doesNotMatch(validationCompletionText(read), /Legacy regrade/);
      assert.equal(await readFile(path + ".result", "utf8"), old);
      const calls: string[] = [];
      const resolveProvider = () => ({
        name: "continuum",
        version: "1",
        async validate(finding: { occurrenceId: string }) {
          calls.push(finding.occurrenceId);
          return {
            disposition: "reportable",
            report: "Current assessment",
            provenance: { provider: "continuum", providerVersion: "1" },
          };
        },
      });
      const refreshed = await validateCompletedScan(scan, resolveProvider);
      assert.deepEqual(calls, ids);
      assert.equal(refreshed?.status, "complete");
      assert.doesNotMatch(String(refreshed?.report), /Legacy regrade/);
      assert.equal((await readCompletedValidation(scan))?.status, "complete");
      await validateCompletedScan(scan, resolveProvider);
      assert.deepEqual(calls, ids);
    } finally {
      if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
      else process.env.CODEX_SECURITY_STATE_DIR = oldState;
      await rm(root, { recursive: true, force: true });
    }
  });
}

await test("explicit completion retries pending assessments and preserves terminal results and sealed artifacts", async () => {
  const root = await temporaryDirectory("plugin-validation-");
  const oldState = process.env.CODEX_SECURITY_STATE_DIR;
  process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
  try {
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(scanDir);
    const { scan, findings, ids } = await sealedScan(
      scanDir,
      repository,
      "synthetic-scan",
      2,
    );
    await bindValidationProviderConfiguration(scan.scanId, configuration, true);
    const calls: string[] = [];
    const resolveProvider = () => ({
      name: "continuum",
      version: "1",
      async validate(finding: unknown, context: { repositoryPath: string }) {
        const id = (finding as { occurrenceId: string }).occurrenceId;
        const failed = id === ids[1];
        const retry = calls.includes(id);
        calls.push(id);
        assert.equal(context.repositoryPath, repository);
        if (failed && !retry) throw new Error("transport unavailable");
        return {
          disposition: failed ? "deferred" : "reportable",
          report: failed
            ? "Validation failed"
            : "High → Critical, internet-exposed (GRAPH)",
          unavailable: failed ? "Validation failed" : undefined,
          provenance: {
            provider: "continuum",
            providerVersion: "1",
            validatedAt: "2026-01-01",
          },
          record: {
            itemId: id,
            provider: "continuum",
            verdict: failed ? "UNCERTAIN" : "EXPLOITABLE",
            terminalStatus: failed ? "FAILED" : "COMPLETED",
            severityBefore: "high",
            severityAfter: failed ? "high" : "critical",
            reasons: [
              {
                basis: "GRAPH" as const,
                reason: "Detailed synthetic context.",
              },
            ],
            claimMatch: failed ? "unknown" : "on_target",
            freshness: { stale: false, reasons: [] },
          },
        };
      },
    });
    // Concurrent completion calls share even a retryable outcome.
    const [result, waiter] = await Promise.all([
      validateCompletedScan(scan, resolveProvider),
      validateCompletedScan(scan, resolveProvider),
    ]);
    assert.deepEqual(waiter, result);
    assert.equal(result?.status, "incomplete");
    assert.equal(result?.retryable, true);
    assert.match(
      validationCompletionText(result),
      /complete_codex_security_scan/,
    );
    assert.match(String(result?.report), /High → Critical/);
    assert.match(validationCompletionText(result), /high → critical/i);
    assert.match(validationCompletionText(result), /GRAPH/);
    assert.match(validationCompletionText(result), /transport unavailable/);
    assert.match(validationCompletionText(result), /validation\.md/);
    assert.match(String(result?.report), /transport unavailable/);
    assert.equal(
      await readFile(join(scanDir, "findings.json"), "utf8"),
      findings,
    );
    const saved = JSON.parse(
      await readFile(String(result?.recordsPath), "utf8"),
    );
    assert.equal(saved.items.length, 1);
    assert.equal(
      saved.items[0].reasons[0].reason,
      "Detailed synthetic context.",
    );
    // Rejoining cannot replace the selected provider.
    await bindValidationProviderConfiguration(
      scan.scanId,
      { provider: "different" },
      false,
    );
    await writeFile(
      join(scanDir, "validation.md"),
      "Fabricated negative result",
    );
    await writeFile(
      join(scanDir, "validation.json"),
      JSON.stringify({
        findings: 0,
        items: [],
        summary: "Fabricated negative result",
      }),
    );
    const read = await readCompletedValidation(scan);
    assert.equal(read?.retryable, true);
    assert.deepEqual(read?.items, saved.items);
    assert.deepEqual(calls, ids);
    assert.match(
      await readFile(join(scanDir, "validation.md"), "utf8"),
      /Fabricated/,
    );
    // Every new attempt uses exactly the bytes sealed at completion.
    await writeFile(join(scanDir, "findings.json"), findings + "\n");
    assert.equal(
      (await validateCompletedScan(scan, resolveProvider))?.status,
      "failed",
    );
    assert.deepEqual(calls, ids);
    assert.deepEqual((await readCompletedValidation(scan))?.items, saved.items);
    await writeFile(join(scanDir, "findings.json"), findings);
    const [cached, joined] = await Promise.all([
      validateCompletedScan(scan, resolveProvider),
      validateCompletedScan(scan, resolveProvider),
    ]);
    assert.deepEqual(cached, joined);
    assert.deepEqual(calls, [...ids, ids[1]]);
    assert.equal(cached?.status, "incomplete");
    assert.equal(cached?.retryable, undefined);
    assert.match(validationCompletionText(cached), /FAILED/);
    const { items } = JSON.parse(
      await readFile(String(cached?.recordsPath), "utf8"),
    );
    assert.deepEqual(
      items.map((item: { verdict: string }) => item.verdict),
      ["EXPLOITABLE", "UNCERTAIN"],
    );
    assert.deepEqual((await readCompletedValidation(scan))?.items, items);
    assert.equal(cached?.findings, 2);
    assert.doesNotMatch(validationCompletionText(cached), /Fabricated/);
    assert.match(
      await readFile(join(scanDir, "validation.md"), "utf8"),
      /High → Critical/,
    );
  } finally {
    if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
    else process.env.CODEX_SECURITY_STATE_DIR = oldState;
    await rm(root, { recursive: true, force: true });
  }
});

await test("a conflicting rejoin blocks automatic upload by the original caller", async (t) => {
  const root = await temporaryDirectory("plugin-consent-");
  const oldState = process.env.CODEX_SECURITY_STATE_DIR;
  process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
  t.after(async () => {
    if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
    else process.env.CODEX_SECURITY_STATE_DIR = oldState;
    await rm(root, { recursive: true, force: true });
  });
  const enabled = {
    ...configuration,
    continuum: { ...configuration.continuum, include_local_validation: true },
  };
  const resolveProvider = t.mock.fn(() => {
    throw new Error("unexpected upload");
  });
  for (const mode of ["standard", "deep"] as const) {
    const { scan } = await sealedScan(root, root, mode);
    const file = join(root, "project.json");
    const selection = { file, target: root, mode };
    await bindValidationProviderConfiguration(scan.scanId, enabled, true);
    await writeFile(
      file,
      JSON.stringify({ scan: { mode, validation: enabled } }),
    );
    assert.equal(
      await bindValidationProviderConfiguration(
        scan.scanId,
        enabled,
        false,
        selection,
      ),
      undefined,
    );
    // A scan-ID-only recovery keeps the original grant without reading the file.
    await rm(file);
    assert.equal(
      await bindValidationProviderConfiguration(scan.scanId, enabled, false),
      undefined,
    );
    await writeFile(
      file,
      JSON.stringify({ scan: { mode, validation: configuration } }),
    );
    const notice = await bindValidationProviderConfiguration(
      scan.scanId,
      enabled,
      false,
      selection,
    );
    assert.match(String(notice), /Automatic Continuum validation is disabled/);
    // Neither a detached original caller nor later recovery can reuse the old grant.
    await bindValidationProviderConfiguration(scan.scanId, enabled, true);
    const result = await validateCompletedScan(scan, resolveProvider);
    assert.equal(result?.status, "failed");
    assert.equal(result?.message, notice);
    assert.deepEqual(await readCompletedValidation(scan), result);
  }
  assert.equal(resolveProvider.mock.callCount(), 0);
});

await test("only the selected completed scan can start a validation batch", async (t) => {
  const root = await temporaryDirectory("plugin-seal-");
  const oldState = process.env.CODEX_SECURITY_STATE_DIR;
  process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
  t.after(async () => {
    if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
    else process.env.CODEX_SECURITY_STATE_DIR = oldState;
    await rm(root, { recursive: true, force: true });
  });
  const { scan } = await sealedScan(root, root, "sealed");
  await bindValidationProviderConfiguration(scan.scanId, configuration, true);
  await bindValidationProviderConfiguration("other", configuration, true);
  const resolveProvider = t.mock.fn(() => {
    throw new Error("unexpected batch");
  });
  for (const change of [
    { sealManifestDigest: undefined },
    { sealManifestDigest: "sha256:" + "0".repeat(64) },
    { scanId: "other" },
    { progress: { status: "running" } },
  ]) {
    const result = await validateCompletedScan(
      { ...scan, ...change },
      resolveProvider,
    );
    assert.equal(result?.status, "failed");
  }
  await validateCompletedScan(scan, resolveProvider, AbortSignal.abort());
  assert.equal(resolveProvider.mock.callCount(), 0);
  assert.equal(await readCompletedValidation(scan), undefined);
});

for (const reachable of [true, false, undefined])
  await test(`compact completion distinguishes shared issue results with reachability ${reachable}`, async () => {
    const root = await temporaryDirectory("plugin-validation-issue-");
    const oldState = process.env.CODEX_SECURITY_STATE_DIR;
    process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
    try {
      const scanDir = join(root, "scan");
      await mkdir(scanDir);
      const { scan, ids } = await sealedScan(scanDir, root, "issue-scan");
      await bindValidationProviderConfiguration(
        scan.scanId,
        configuration,
        true,
      );
      const result = await validateCompletedScan(scan, () => ({
        name: "fake",
        version: "1",
        async validate() {
          return {
            disposition: "reportable" as const,
            report: "Synthetic issue-level result",
            provenance: {
              provider: "fake",
              providerVersion: "1",
              validatedAt: "2026-01-01",
            },
            record: {
              itemId: ids[0],
              provider: "fake",
              verdict: "EXPLOITABLE",
              severityBefore: "high",
              severityAfter: "high",
              providerSeverity: "critical",
              resultScope: "issue" as const,
              issueFindingCount: 2,
              joinedValidatedIssue: true,
              reachableFromAttacker: reachable,
              claimMatch: "unknown" as const,
              reasons: [
                {
                  basis: "FINDING" as const,
                  reason:
                    "Basis: FINDING — reachableFromAttacker: true (Reported public route).",
                },
              ],
              freshness: {
                stale: true,
                reasons: ["Evidence predates submission."],
              },
            },
          };
        },
      }));
      const completion = validationCompletionText(result);
      assert.match(completion, /Codex severity high retained/);
      assert.match(completion, /Findings in issue: 2\./);
      assert.match(
        completion,
        /Issue-level verdict: EXPLOITABLE; issue severity: critical/,
      );
      assert.match(completion, /Not individually validated/);
      assert.ok(
        completion.includes(
          `Issue reachability: ${reachable === true ? "reachable from attacker" : reachable === false ? "not reachable from attacker" : "unknown"}.`,
        ),
      );
      assert.match(completion, /Context: Basis: FINDING/);
      assert.match(
        completion,
        /joined an issue Continuum had already validated/,
      );
      assert.doesNotMatch(completion, /high → critical/);
      const saved = JSON.parse(
        await readFile(join(scanDir, "validation.json"), "utf8"),
      );
      assert.equal(saved.items[0].resultScope, "issue");
      assert.equal(saved.items[0].issueFindingCount, 2);
    } finally {
      if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
      else process.env.CODEX_SECURITY_STATE_DIR = oldState;
      await rm(root, { recursive: true, force: true });
    }
  });

await test("model-authored supplemental files cannot impersonate provider results or disclose symlink targets", async () => {
  const root = await temporaryDirectory("plugin-validation-symlink-");
  const oldState = process.env.CODEX_SECURITY_STATE_DIR;
  process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
  try {
    const scanDir = join(root, "scan");
    await mkdir(scanDir);
    const privatePath = join(root, "private.txt");
    const marker = "HOST_ONLY_SYNTHETIC_CONTENT";
    await writeFile(
      privatePath,
      JSON.stringify({ items: [], summary: marker }),
    );
    const privateBefore = await readFile(privatePath, "utf8");
    for (const [index, name] of [
      "regular",
      "validation.md",
      "validation.json",
    ].entries()) {
      const scanId = `untrusted-output-${index}`;
      const { scan, findings } = await sealedScan(scanDir, root, scanId);
      await bindValidationProviderConfiguration(scanId, configuration, true);
      const reportPath = join(scanDir, "validation.md");
      const recordsPath = join(scanDir, "validation.json");
      await writeFile(reportPath, marker);
      await writeFile(
        recordsPath,
        JSON.stringify({ findings: 0, items: [], summary: marker }),
      );
      if (name !== "regular") {
        await rm(join(scanDir, name));
        await symlink(privatePath, join(scanDir, name));
      }
      let calls = 0;
      const result = await validateCompletedScan(scan, () => ({
        name: "fake",
        version: "1",
        async validate() {
          calls++;
          return {
            disposition: "reportable" as const,
            report: "Synthetic provider assessment",
            provenance: {
              provider: "fake",
              providerVersion: "1",
              validatedAt: "2026-01-01",
            },
          };
        },
      }));
      assert.equal(result?.status, "complete");
      assert.equal(result?.findings, 1);
      assert.equal(calls, 1);
      assert.doesNotMatch(JSON.stringify(result), new RegExp(marker));
      assert.doesNotMatch(validationCompletionText(result), new RegExp(marker));
      assert.match(
        await readFile(reportPath, "utf8"),
        /Synthetic provider assessment/,
      );
      assert.equal(JSON.parse(await readFile(recordsPath, "utf8")).findings, 1);
      assert.equal(await readFile(privatePath, "utf8"), privateBefore);
      assert.equal(
        await readFile(join(scanDir, "findings.json"), "utf8"),
        findings,
      );
      await rm(reportPath);
      await rm(recordsPath);
    }
  } finally {
    if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
    else process.env.CODEX_SECURITY_STATE_DIR = oldState;
    await rm(root, { recursive: true, force: true });
  }
});

await test("app-backed Deep Scan binds the saved setup provider without a project path", async () => {
  const { WorkbenchDeepScanStore } = await importSource(
    join(import.meta.dirname, "../src/deep-scan/store.ts"),
  );
  const root = await temporaryDirectory("plugin-validation-snapshot-");
  const oldState = process.env.CODEX_SECURITY_STATE_DIR;
  process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
  try {
    const configuration = {
      provider: "continuum",
      continuum: { environment_id: "snapshot-environment" },
    };
    const store = new WorkbenchDeepScanStore(async () => ({
      startDisposition: "created",
      validationProviderConfiguration: configuration,
      deepScan: {
        scanId: "snapshot-scan",
        status: "running",
        targetPath: root,
        scope: ".",
        scanDir: root,
        dispatchedCount: 0,
        noNewStreak: 0,
        config: {
          workers: 1,
          subagents: 0,
          stopAfterNoNew: 1,
          maxDiscoveryRuns: 1,
        },
      },
    }));
    await store.begin({
      scanId: "snapshot-scan",
      threadId: "snapshot-owner",
      scanRoot: root,
    });
    const { scan } = await sealedScan(root, root, "snapshot-scan", 0);
    let resolved = false;
    const result = await validateCompletedScan(scan, (saved) => {
      assert.deepEqual(saved, configuration);
      resolved = true;
      return {
        name: "fake",
        version: "1",
        async validate() {
          throw new Error("No findings");
        },
      };
    });
    assert.equal(resolved, true);
    assert.equal(result?.status, "complete");
  } finally {
    if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
    else process.env.CODEX_SECURITY_STATE_DIR = oldState;
    await rm(root, { recursive: true, force: true });
  }
});

await test("rejoining Deep Scan recovers an interrupted binding from saved setup", async () => {
  const { WorkbenchDeepScanStore } = await importSource(
    join(import.meta.dirname, "../src/deep-scan/store.ts"),
  );
  const { runWorkbench } = await importSource(
    join(import.meta.dirname, "../src/workbench-client.ts"),
  );
  const root = await temporaryDirectory("plugin-validation-rejoin-");
  const oldState = process.env.CODEX_SECURITY_STATE_DIR;
  const state = join(root, "state");
  process.env.CODEX_SECURITY_STATE_DIR = state;
  try {
    const input = {
      targetPath: join(root, "repository"),
      threadId: "snapshot-owner",
      scanRoot: join(root, "scans"),
      projectConfigPath: join(root, "selected.json"),
    };
    await mkdir(input.targetPath);
    await writeFile(join(input.targetPath, "fixture.py"), "print('fixture')\n");
    await writeFile(
      input.projectConfigPath,
      JSON.stringify({ scan: { validation: configuration } }),
    );
    const store = new WorkbenchDeepScanStore(runWorkbench);
    const { scanId } = await store.begin(input);
    const binding = join(state, "validation-providers", scanId + ".json");
    // Simulate a host exit after registration but before writing the binding.
    await rm(binding);
    await rm(input.projectConfigPath);
    const joined = await new WorkbenchDeepScanStore(runWorkbench).begin(input);
    assert.equal(joined.scanId, scanId);
    assert.deepEqual(
      JSON.parse(await readFile(binding, "utf8")),
      configuration,
    );
  } finally {
    if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
    else process.env.CODEX_SECURITY_STATE_DIR = oldState;
    await rm(root, { recursive: true, force: true });
  }
});

await test("batch transport failure is supplemental, not a scan completion failure", async () => {
  const root = await temporaryDirectory("plugin-validation-batch-");
  const oldState = process.env.CODEX_SECURITY_STATE_DIR;
  process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
  try {
    const { scan } = await sealedScan(root, root, "batch-scan", 2);
    await bindValidationProviderConfiguration(scan.scanId, configuration, true);
    const result = await validateCompletedScan(scan, () => ({
      name: "fake",
      version: "1",
      async validate() {
        throw new Error("batch expected");
      },
      async validateBatch() {
        throw new Error("offline");
      },
    }));
    assert.equal(result?.status, "complete");
    assert.equal(result?.findings, 2);
    assert.match(String(result?.report), /offline/);
  } finally {
    if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
    else process.env.CODEX_SECURITY_STATE_DIR = oldState;
    await rm(root, { recursive: true, force: true });
  }
});

await test(
  "plugin adapter resumes a receipt-backed scan with a fake AWS process",
  { skip: process.platform === "win32" },
  async () => {
    const root = await temporaryDirectory("plugin-aws-process-");
    const oldState = process.env.CODEX_SECURITY_STATE_DIR;
    const oldPath = process.env.PATH;
    process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
    try {
      const repository = join(root, "repository");
      const bin = join(root, "bin");
      execFileSync("git", ["init", "-q", repository]);
      execFileSync(
        "git",
        ["remote", "add", "origin", "https://github.com/example/project"],
        { cwd: repository },
      );
      await mkdir(bin);
      const aws = join(bin, "aws");
      await writeFile(
        aws,
        `#!/bin/sh
case "$2" in
get-environment) printf '{"environmentArn":"arn:aws:continuum:us-east-1:123456789012:environments/example","configuration":{"codeConfiguration":{"sourceConfiguration":{"repositorySources":[{"integrationId":"demo","repository":"example/project"}]}}}}' ;;
get-integration) printf '{"integrationType":"GITHUB"}' ;;
create-code-finding)
  [ ! -f "$0.created" ] || exit 1
  touch "$0.created"
  printf '{"findingId":"fixture","findingArn":"arn:aws:continuum:us-east-1:123456789012:environments/example/code-findings/fixture"}' ;;
get-code-finding)
  [ -f "$0.ready" ] || exit 1
  printf '{"findingId":"fixture","findingArn":"arn:aws:continuum:us-east-1:123456789012:environments/example/code-findings/fixture","status":"DISCARDED","discardReason":"fixture rejection"}' ;;
*) exit 1 ;;
esac
`,
      );
      await chmod(aws, 0o755);
      process.env.PATH = bin + delimiter + oldPath;
      const { runWorkbench } = await importSource(
        join(import.meta.dirname, "../src/workbench-client.ts"),
      );
      const { createScanArtifactContext } = await importSource(
        join(import.meta.dirname, "../src/artifact-context.ts"),
      );
      const { recordCodexSecurityScanDraftViaWorkbench } = await importSource(
        join(import.meta.dirname, "../src/artifact-scan-draft.ts"),
      );
      const source = join(repository, "app.py");
      await writeFile(source, "# synthetic source\n");
      execFileSync("git", ["add", "app.py"], { cwd: repository });
      execFileSync(
        "git",
        [
          "-c",
          "user.name=Example",
          "-c",
          "user.email=example@example.invalid",
          "commit",
          "-qm",
          "fixture",
        ],
        { cwd: repository },
      );
      const scanDir = join(root, "scan");
      await mkdir(scanDir, { mode: 0o700 });
      const { scanId } = await runWorkbench([
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        JSON.stringify({
          config: {},
          mode: "standard",
          repository,
          target: { kind: "repository", paths: [] },
        }),
      ]);
      const context = await createScanArtifactContext(scanId, runWorkbench, {
        requireRunning: true,
      });
      await recordCodexSecurityScanDraftViaWorkbench(
        context,
        {
          scanId,
          complete: true,
          findings: [draftFinding("example", "app.py")],
          reviewState: {
            completeness: "complete",
            surfaces: [],
            explicitExclusions: [],
            deferred: [],
          },
        },
        runWorkbench,
      );
      const { scan } = await runWorkbench([
        "complete-scan",
        "--scan-id",
        scanId,
      ]);
      await bindValidationProviderConfiguration(scanId, configuration, true);
      await writeFile(source, "# edited source\n");
      const changed = await validateCompletedScan(scan);
      assert.equal(changed?.status, "incomplete", JSON.stringify(changed));
      await assert.rejects(readFile(aws + ".created"), { code: "ENOENT" });
      await writeFile(source, "# synthetic source\n");
      const pending = await validateCompletedScan(scan);
      assert.equal(pending?.retryable, true);
      // Reproduce the previous aggregate cache format on plugin upgrade.
      const cachePath = join(
        root,
        "state",
        "validation-providers",
        scanId + ".json.result",
      );
      const cache = JSON.parse(await readFile(cachePath, "utf8"));
      delete cache.schemaVersion;
      delete cache.retry;
      delete cache.result.retryable;
      cache.result.status = "complete";
      await writeFile(cachePath, JSON.stringify(cache));
      await writeFile(aws + ".ready", "");
      await writeFile(source, "# edited source\n");
      assert.equal((await readCompletedValidation(scan))?.status, "outdated");
      const result = await validateCompletedScan(scan);
      assert.equal(result?.status, "complete");
      assert.equal(result?.retryable, undefined);
      assert.match(String(result?.report), /DISCARDED/);
      assert.match(String(result?.report), /fixture rejection/);
      assert.match(validationCompletionText(result), /fixture rejection/);
    } finally {
      if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
      else process.env.CODEX_SECURITY_STATE_DIR = oldState;
      if (oldPath === undefined) delete process.env.PATH;
      else process.env.PATH = oldPath;
      await rm(root, { recursive: true, force: true });
    }
  },
);

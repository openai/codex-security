import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmod,
  mkdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { delimiter } from "node:path";
import { join } from "node:path";
import { test } from "node:test";
import { importSource as bundle } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import type * as Host from "../src/validation-provider.js";

function importSource(path: string) {
  return bundle(path, {
    alias: {
      "#validation-runtime": join(
        import.meta.dirname,
        "../../../../sdk/typescript/src/plugin-validation.ts",
      ),
    },
  });
}

const {
  bindValidationProvider,
  readCompletedValidation,
  validateCompletedScan,
  validationCompletionText,
} = (await importSource(
  join(import.meta.dirname, "../src/validation-provider.ts"),
)) as typeof Host;

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

for (const mixed of [false, true]) {
  await test(`legacy ${mixed ? "mixed retry" : "completed"} assessments refresh only on explicit completion`, async () => {
    const root = await temporaryDirectory("plugin-validation-upgrade-");
    const oldState = process.env.CODEX_SECURITY_STATE_DIR;
    process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
    try {
      const directory = join(root, "state", "validation-providers");
      const repositoryPath = join(root, "repository");
      await mkdir(directory, { recursive: true });
      await mkdir(repositoryPath);
      const scan = {
        scanId: "upgrade",
        targetPath: repositoryPath,
        scanDir: root,
      };
      const configuration = {
        provider: "continuum",
        continuum: { environment_id: "example" },
      };
      const path = join(directory, "upgrade.json");
      await writeFile(path, JSON.stringify(configuration));
      const ids = mixed ? ["accepted", "pending"] : ["accepted"];
      await writeFile(
        join(root, "findings.json"),
        JSON.stringify({
          findings: ids.map((occurrenceId) => ({ occurrenceId })),
        }),
      );
      const record = {
        itemId: "accepted",
        verdict: "EXPLOITABLE",
        claimMatch: "on_target",
        resultScope: "finding",
        severityBefore: "high",
        severityAfter: "critical",
      };
      const old = JSON.stringify({
        schemaVersion: mixed ? 2 : undefined,
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
    await writeFile(
      join(repository, "security.json"),
      JSON.stringify({
        scan: {
          validation: {
            provider: "continuum",
            continuum: { environment_id: "synthetic-environment" },
          },
        },
      }),
    );
    const findings = JSON.stringify({
      findings: [
        { occurrenceId: "item-1", severity: "high" },
        { occurrenceId: "item-2", severity: "high" },
      ],
    });
    await writeFile(join(scanDir, "findings.json"), findings);
    await bindValidationProvider(
      "synthetic-scan",
      repository,
      "security.json",
      true,
    );
    const calls: string[] = [];
    const scan = { scanId: "synthetic-scan", targetPath: repository, scanDir };
    const resolveProvider = () => ({
      name: "continuum",
      version: "1",
      async validate(finding: unknown, context: { repositoryPath: string }) {
        const id = (finding as { occurrenceId: string }).occurrenceId;
        const failed = id === "item-2";
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
    const result = await validateCompletedScan(scan, resolveProvider);
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
    await bindValidationProvider(
      "synthetic-scan",
      repository,
      "missing.yaml",
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
    assert.deepEqual(calls, ["item-1", "item-2"]);
    assert.match(
      await readFile(join(scanDir, "validation.md"), "utf8"),
      /Fabricated/,
    );
    const [cached, joined] = await Promise.all([
      validateCompletedScan(scan, resolveProvider),
      validateCompletedScan(scan, resolveProvider),
    ]);
    assert.deepEqual(cached, joined);
    assert.deepEqual(calls, ["item-1", "item-2", "item-2"]);
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

for (const reachable of [true, false, undefined])
  await test(`compact completion distinguishes shared issue results with reachability ${reachable}`, async () => {
    const root = await temporaryDirectory("plugin-validation-issue-");
    const oldState = process.env.CODEX_SECURITY_STATE_DIR;
    process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
    try {
      const scanDir = join(root, "scan");
      await mkdir(scanDir);
      await writeFile(
        join(root, "security.json"),
        JSON.stringify({
          scan: {
            validation: {
              provider: "continuum",
              continuum: { environment_id: "synthetic-environment" },
            },
          },
        }),
      );
      await writeFile(
        join(scanDir, "findings.json"),
        JSON.stringify({ findings: [{ id: "item-1" }] }),
      );
      await bindValidationProvider("issue-scan", root, "security.json", true);
      const result = await validateCompletedScan(
        { scanId: "issue-scan", targetPath: root, scanDir },
        () => ({
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
                itemId: "item-1",
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
        }),
      );
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
    await writeFile(
      join(root, "security.json"),
      JSON.stringify({
        scan: {
          validation: {
            provider: "continuum",
            continuum: { environment_id: "synthetic-environment" },
          },
        },
      }),
    );
    const findings = JSON.stringify({
      findings: [{ id: "item-1", severity: "high" }],
    });
    await writeFile(join(scanDir, "findings.json"), findings);
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
      await bindValidationProvider(scanId, root, "security.json", true);
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
      const result = await validateCompletedScan(
        { scanId, targetPath: root, scanDir },
        () => ({
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
        }),
      );
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
    await writeFile(
      join(root, "findings.json"),
      JSON.stringify({ findings: [] }),
    );
    let resolved = false;
    const result = await validateCompletedScan(
      { scanId: "snapshot-scan", targetPath: root, scanDir: root },
      (saved) => {
        assert.deepEqual(saved, configuration);
        resolved = true;
        return {
          name: "fake",
          version: "1",
          async validate() {
            throw new Error("No findings");
          },
        };
      },
    );
    assert.equal(resolved, true);
    assert.equal(result?.status, "complete");
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
    await writeFile(
      join(root, "security.json"),
      JSON.stringify({
        scan: {
          validation: {
            provider: "continuum",
            continuum: { environment_id: "synthetic-environment" },
          },
        },
      }),
    );
    await writeFile(
      join(root, "findings.json"),
      JSON.stringify({ findings: [{ id: "a" }, { id: "b" }] }),
    );
    await bindValidationProvider("batch-scan", root, "security.json", true);
    const result = await validateCompletedScan(
      { scanId: "batch-scan", targetPath: root, scanDir: root },
      () => ({
        name: "fake",
        version: "1",
        async validate() {
          throw new Error("batch expected");
        },
        async validateBatch() {
          throw new Error("offline");
        },
      }),
    );
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
      await writeFile(
        join(repository, "security.json"),
        JSON.stringify({
          scan: {
            validation: {
              provider: "continuum",
              continuum: { environment_id: "example" },
            },
          },
        }),
      );
      await writeFile(
        join(root, "findings.json"),
        JSON.stringify({
          findings: [
            {
              occurrenceId: "fake-process-item",
              title: "Synthetic weakness",
              summary: "Synthetic code flaw",
              severity: { level: "high" },
              locations: [{ path: "app.py", startLine: 1, endLine: 1 }],
            },
          ],
        }),
      );
      await bindValidationProvider(
        "process-scan",
        repository,
        "security.json",
        true,
      );
      const scan = {
        scanId: "process-scan",
        targetPath: repository,
        scanDir: root,
      };
      const pending = await validateCompletedScan(scan);
      assert.equal(pending?.retryable, true);
      // Reproduce the previous aggregate cache format on plugin upgrade.
      const cachePath = join(
        root,
        "state",
        "validation-providers",
        "process-scan.json.result",
      );
      const cache = JSON.parse(await readFile(cachePath, "utf8"));
      delete cache.schemaVersion;
      delete cache.retry;
      delete cache.result.retryable;
      cache.result.status = "complete";
      await writeFile(cachePath, JSON.stringify(cache));
      await writeFile(aws + ".ready", "");
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

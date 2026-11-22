import assert from "node:assert/strict";
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
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import type * as Host from "../src/validation-provider.js";

const {
  bindValidationProvider,
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

await test("provider configuration and cache follow CODEX_HOME without a state override", async () => {
  const root = await temporaryDirectory("plugin-provider-home-");
  const oldState = process.env.CODEX_SECURITY_STATE_DIR;
  const oldHome = process.env.CODEX_HOME;
  delete process.env.CODEX_SECURITY_STATE_DIR;
  process.env.CODEX_HOME = join(root, "codex-home");
  try {
    const configuration = {
      provider: "continuum",
      continuum: { environment_id: "synthetic-environment" },
    };
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(scanDir);
    await writeFile(
      join(repository, "security.json"),
      JSON.stringify({ scan: { validation: configuration } }),
    );
    await writeFile(
      join(scanDir, "findings.json"),
      JSON.stringify({ findings: [{}] }),
    );
    await bindValidationProvider(
      "custom-home-scan",
      repository,
      "security.json",
      true,
    );
    const savedPath = join(
      process.env.CODEX_HOME,
      "state",
      "plugins",
      "codex-security",
      "validation-providers",
      "custom-home-scan.json",
    );
    assert.deepEqual(
      JSON.parse(await readFile(savedPath, "utf8")),
      configuration,
    );
    let calls = 0;
    const scan = {
      scanId: "custom-home-scan",
      targetPath: repository,
      scanDir,
    };
    const provider = () => ({
      name: "synthetic",
      version: "1",
      async validate() {
        calls++;
        return {
          disposition: "deferred" as const,
          report: "Synthetic result",
          provenance: {
            provider: "synthetic",
            providerVersion: "1",
            validatedAt: "2026-01-01",
          },
        };
      },
    });
    assert.equal(
      (await validateCompletedScan(scan, provider))?.status,
      "complete",
    );
    assert.equal(
      JSON.parse(await readFile(`${savedPath}.result`, "utf8")).result.status,
      "complete",
    );
    assert.equal(
      (await validateCompletedScan(scan, provider))?.status,
      "complete",
    );
    assert.equal(calls, 1);
  } finally {
    if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
    else process.env.CODEX_SECURITY_STATE_DIR = oldState;
    if (oldHome === undefined) delete process.env.CODEX_HOME;
    else process.env.CODEX_HOME = oldHome;
    await rm(root, { recursive: true, force: true });
  }
});

await test("configured plugin completion returns supplemental results and preserves sealed artifacts", async () => {
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
    let submitted = 0;
    const scan = { scanId: "synthetic-scan", targetPath: repository, scanDir };
    const resolveProvider = () => ({
      name: "fake",
      version: "1",
      async validate(finding: unknown, context: { repositoryPath: string }) {
        submitted++;
        assert.equal(context.repositoryPath, repository);
        if ((finding as { occurrenceId: string }).occurrenceId === "item-2")
          throw new Error("transport unavailable");
        return {
          disposition: "reportable" as const,
          report: "Synthetic provider assessment",
          provenance: {
            provider: "fake",
            providerVersion: "1",
            validatedAt: "2026-01-01",
          },
          record: {
            itemId: "item-1",
            provider: "fake",
            state: "validated" as const,
            codexSeverity: "high",
            issue: {
              id: "issue-1",
              url: "https://example.com/issue-1",
              verdict: "EXPLOITABLE",
              severity: "critical",
              reachableFromAttacker: true,
              reachabilityBasis: "GRAPH" as const,
            },
            reasons: [
              {
                basis: "GRAPH" as const,
                reason: "Detailed synthetic context.",
              },
            ],
          },
        };
      },
    });
    const result = await validateCompletedScan(scan, resolveProvider);
    assert.equal(result?.status, "complete");
    assert.equal(submitted, 2);
    assert.match(String(result?.report), /Continuum: exploitable, Critical/);
    assert.match(validationCompletionText(result), /Codex rated it High/i);
    assert.match(String(result?.report), /GRAPH/);
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
    // Rejoining cannot replace the selected provider; cached completion cannot resubmit.
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
    const cached = await validateCompletedScan(scan, resolveProvider);
    assert.equal(cached?.status, "complete");
    assert.match(validationCompletionText(cached), /transport unavailable/);
    assert.equal(submitted, 2);
    assert.equal(cached?.findings, 2);
    assert.doesNotMatch(validationCompletionText(cached), /Fabricated/);
    assert.match(
      await readFile(join(scanDir, "validation.md"), "utf8"),
      /Continuum: exploitable, Critical/,
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
                state: "validated" as const,
                codexSeverity: "high",
                issue: {
                  id: "issue-1",
                  url: "https://example.com/issue-1",
                  verdict: "EXPLOITABLE",
                  severity: "critical",
                  findingCount: 2,
                  validationBeforeSubmission: true,
                  reachableFromAttacker: reachable,
                  reachabilityBasis: "FINDING" as const,
                  reachabilityReason: "Reported public route",
                  validatedAt: "2026-01-01T00:00:00Z",
                },
                reasons: [
                  {
                    basis: "FINDING" as const,
                    reason: "Reported public route",
                  },
                ],
              },
            };
          },
        }),
      );
      const completion = validationCompletionText(result);
      assert.match(completion, /Codex rated it High/);
      assert.match(completion, /Continuum: exploitable, Critical/);
      assert.ok(
        completion.includes(
          reachable === true
            ? "reachable from an attacker"
            : reachable === false
              ? "not reachable from an attacker"
              : "reachability unknown",
        ),
      );
      assert.match(String(result?.report), /not individual finding validation/);
      assert.match(String(result?.report), /issue holds 2 findings/);
      assert.match(
        String(result?.report),
        /stated in the finding, not independently checked/,
      );
      assert.match(String(result?.report), /before this submission/);
      const saved = JSON.parse(
        await readFile(join(scanDir, "validation.json"), "utf8"),
      );
      assert.equal(saved.schemaVersion, 2);
      assert.equal(saved.items[0].issue.findingCount, 2);
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
  "plugin adapter uses host path protection with a fake AWS process",
  { skip: process.platform === "win32" },
  async () => {
    const root = await temporaryDirectory("plugin-aws-process-");
    const oldState = process.env.CODEX_SECURITY_STATE_DIR;
    const oldPath = process.env.PATH;
    process.env.CODEX_SECURITY_STATE_DIR = join(root, "state");
    try {
      const repository = join(root, "repository");
      const bin = join(root, "bin");
      await mkdir(repository);
      await mkdir(bin);
      const aws = join(bin, "aws");
      await writeFile(
        aws,
        `#!/bin/sh
case "$2" in
create-code-finding) printf '{"findingId":"fixture-finding"}' ;;
get-code-finding) printf '{"status":"DISCARDED","discardReason":"fixture rejection"}' ;;
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
              continuum: { environment_id: "synthetic-environment" },
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
      const result = await validateCompletedScan({
        scanId: "process-scan",
        targetPath: repository,
        scanDir: root,
      });
      assert.equal(result?.status, "complete");
      assert.match(String(result?.report), /declined/);
      assert.match(String(result?.report), /fixture rejection/);
    } finally {
      if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
      else process.env.CODEX_SECURITY_STATE_DIR = oldState;
      if (oldPath === undefined) delete process.env.PATH;
      else process.env.PATH = oldPath;
      await rm(root, { recursive: true, force: true });
    }
  },
);

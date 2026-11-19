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
          report: "High → Critical, internet-exposed (GRAPH)",
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
            severityAfter: "critical",
            reasons: [
              {
                basis: "GRAPH" as const,
                reason: "Detailed synthetic context.",
              },
            ],
            claimMatch: "on_target" as const,
            freshness: { stale: false, reasons: [] },
          },
        };
      },
    });
    const result = await validateCompletedScan(scan, resolveProvider);
    assert.equal(result?.status, "complete");
    assert.equal(submitted, 2);
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
    // Rejoining cannot replace the selected provider; cached completion cannot resubmit.
    await bindValidationProvider(
      "synthetic-scan",
      repository,
      "missing.yaml",
      false,
    );
    const cached = await validateCompletedScan(scan, resolveProvider);
    assert.equal(cached?.status, "complete");
    assert.match(validationCompletionText(cached), /transport unavailable/);
    assert.equal(submitted, 2);
  } finally {
    if (oldState === undefined) delete process.env.CODEX_SECURITY_STATE_DIR;
    else process.env.CODEX_SECURITY_STATE_DIR = oldState;
    await rm(root, { recursive: true, force: true });
  }
});

await test("cached supplemental artifacts cannot disclose a symlink target", async () => {
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
    await bindValidationProvider("symlink-scan", root, "security.json", true);
    const privatePath = join(root, "private.txt");
    const marker = "HOST_ONLY_SYNTHETIC_CONTENT";
    await writeFile(
      privatePath,
      JSON.stringify({ items: [], summary: marker }),
    );
    for (const name of ["validation.md", "validation.json"]) {
      const reportPath = join(scanDir, "validation.md");
      const recordsPath = join(scanDir, "validation.json");
      await writeFile(reportPath, "Synthetic public report");
      await writeFile(recordsPath, JSON.stringify({ items: [] }));
      await rm(join(scanDir, name));
      await symlink(privatePath, join(scanDir, name));
      const result = await validateCompletedScan(
        { scanId: "symlink-scan", targetPath: root, scanDir },
        () => {
          throw new Error(
            "No provider should run for unsafe cached artifacts.",
          );
        },
      );
      assert.equal(result?.status, "failed");
      assert.doesNotMatch(JSON.stringify(result), new RegExp(marker));
      assert.doesNotMatch(validationCompletionText(result), new RegExp(marker));
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
      assert.match(String(result?.report), /DISCARDED/);
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

import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ScanResult } from "../src/index.js";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
} from "../src/index.js";

const manifest = {
  documentType: "codex-security.scan-manifest",
  schemaVersion: "1.0",
  scan: {
    id: "scan",
    producer: { name: "codex-security-plugin", version: "0.1.14" },
    status: "completed",
    startedAt: "2026-01-01T00:00:00Z",
    completedAt: "2026-01-01T00:00:01Z",
    sealedAt: "2026-01-01T00:00:01Z",
    target: { kind: "git_revision", targetId: "id", displayName: "repo" },
    scope: { includePaths: ["."], excludePaths: [] },
    coverageRef: "coverage.json",
    findingsRef: "findings.json",
    artifacts: [],
  },
} satisfies ScanManifest;

const findings = {
  documentType: "codex-security.findings",
  schemaVersion: "1.0",
  scanId: "scan",
  findings: [],
} satisfies FindingsDocument;

const coverage = {
  documentType: "codex-security.coverage",
  schemaVersion: "1.0",
  scanId: "scan",
  mode: "repository",
  completeness: "complete",
  inventoryStrategy: "repository",
  includePaths: ["."],
  excludePaths: [],
  surfaces: [],
  explicitExclusions: [],
  deferred: [],
} satisfies CoverageDocument;

describe("ScanResult", () => {
  test("exposes canonical paths and machine serialization", () => {
    const result = new ScanResult({
      manifest,
      findings,
      coverage,
      scanDir: "/scan",
      threadId: "thread",
      turnResult: { id: "turn", status: "completed" },
    });
    expect(result.pluginVersion).toBe("0.1.14");
    expect(result.manifestPath).toBe(join("/scan", "scan-manifest.json"));
    expect(result.artifactsDir).toBe(join("/scan", "artifacts"));
    expect(result.toJSON()).toMatchObject({
      scanDir: "/scan",
      threadId: "thread",
      rolloutSessionIndexPath: null,
      cost: null,
    });
  });

  test("exposes the rollout session index in machine-readable results", () => {
    const result = new ScanResult({
      manifest,
      findings,
      coverage,
      scanDir: "/scan",
      threadId: "thread",
      turnResult: { status: "completed" },
      rolloutSessionIndexPath: "/scan/artifacts/rollout-sessions/index.json",
    });

    expect(result.rolloutSessionIndexPath).toBe(
      "/scan/artifacts/rollout-sessions/index.json",
    );
    expect(result.toJSON()["rolloutSessionIndexPath"]).toBe(
      result.rolloutSessionIndexPath,
    );
  });

  test.skipIf(process.platform === "win32")(
    "does not discover a symlinked rollout session index",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-result-"));
      try {
        const scanDir = join(root, "scan");
        const indexDirectory = join(scanDir, "artifacts", "rollout-sessions");
        const outside = join(root, "outside-index.json");
        await mkdir(indexDirectory, { recursive: true });
        await writeFile(outside, "{}\n");
        await symlink(outside, join(indexDirectory, "index.json"));

        const result = new ScanResult({
          manifest,
          findings,
          coverage,
          scanDir,
          threadId: "thread",
          turnResult: { status: "completed" },
        });
        expect(result.rolloutSessionIndexPath).toBeNull();
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test("includes the model and estimated cost in machine-readable results", () => {
    const result = new ScanResult({
      manifest,
      findings,
      coverage,
      scanDir: "/scan",
      threadId: "thread",
      turnResult: {
        model: "gpt-5.6-sol",
        usage: {
          input_tokens: 1_250,
          cached_input_tokens: 200,
          output_tokens: 30,
        },
      },
    });

    expect(result.cost?.estimatedUsd).toBe(0.00625);
    expect(result.toJSON()["cost"]).toEqual(result.cost);
  });

  test("discovers SARIF at its canonical scan path", async () => {
    const scanDir = await mkdtemp(join(tmpdir(), "codex-security-result-"));
    try {
      const sarifPath = join(scanDir, "exports", "results.sarif");
      await mkdir(join(scanDir, "exports"));
      await writeFile(sarifPath, "{}\n");
      const result = new ScanResult({
        manifest,
        findings,
        coverage,
        scanDir,
        threadId: "thread",
        turnResult: { id: "turn", status: "completed" },
      });
      expect(result.sarifPath).toBe(sarifPath);
      expect(result.toJSON()["sarifPath"]).toBe(sarifPath);
    } finally {
      await rm(scanDir, { recursive: true, force: true });
    }
  });

  test("does not discover a directory named results.sarif", async () => {
    const scanDir = await mkdtemp(join(tmpdir(), "codex-security-result-"));
    try {
      await mkdir(join(scanDir, "exports", "results.sarif"), {
        recursive: true,
      });
      const result = new ScanResult({
        manifest,
        findings,
        coverage,
        scanDir,
        threadId: "thread",
        turnResult: { id: "turn", status: "completed" },
      });
      expect(result.sarifPath).toBeNull();
      expect(result.toJSON()["sarifPath"]).toBeNull();
    } finally {
      await rm(scanDir, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "does not fail implicit SARIF discovery on a symlink loop",
    async () => {
      const scanDir = await mkdtemp(join(tmpdir(), "codex-security-result-"));
      try {
        const exportsDir = join(scanDir, "exports");
        await mkdir(exportsDir);
        await symlink("loop", join(exportsDir, "loop"));
        const result = new ScanResult({
          manifest,
          findings,
          coverage,
          scanDir: join(exportsDir, "loop"),
          threadId: "thread",
          turnResult: { id: "turn", status: "completed" },
        });
        expect(result.sarifPath).toBeNull();
        expect(result.toJSON()["sarifPath"]).toBeNull();
      } finally {
        await rm(scanDir, { recursive: true, force: true });
      }
    },
  );
});

import { lstatSync, statSync } from "node:fs";
import { join } from "node:path";
import type {
  CoverageDocument,
  FindingsDocument,
  ScanManifest,
} from "./models.js";
import { estimateScanCost, type ScanCost } from "./cost.js";

export interface TurnResultMetadata {
  id?: string;
  status?: string;
  model?: string;
  durationMs?: number;
  finalResponse?: string;
  usage?: unknown;
  [key: string]: unknown;
}

export interface ScanResultOptions {
  manifest: ScanManifest;
  findings: FindingsDocument;
  coverage: CoverageDocument;
  scanDir: string;
  threadId: string;
  turnResult: TurnResultMetadata;
  sarifPath?: string | null;
  rolloutSessionIndexPath?: string | null;
}

export class ScanResult {
  public readonly manifest: ScanManifest;
  public readonly findings: FindingsDocument;
  public readonly coverage: CoverageDocument;
  public readonly scanDir: string;
  public readonly threadId: string;
  public readonly turnResult: Readonly<TurnResultMetadata>;
  public readonly cost: Readonly<ScanCost> | null;
  public readonly sarifPath: string | null;
  public readonly rolloutSessionIndexPath: string | null;

  public constructor(options: ScanResultOptions) {
    this.manifest = options.manifest;
    this.findings = options.findings;
    this.coverage = options.coverage;
    this.scanDir = options.scanDir;
    this.threadId = options.threadId;
    this.turnResult = options.turnResult;
    this.cost = estimateScanCost(
      options.turnResult.model,
      options.turnResult.usage,
    );
    if (options.sarifPath !== undefined) {
      this.sarifPath = options.sarifPath;
    } else {
      const defaultSarifPath = join(
        options.scanDir,
        "exports",
        "results.sarif",
      );
      try {
        this.sarifPath = statSync(defaultSarifPath, {
          throwIfNoEntry: false,
        })?.isFile()
          ? defaultSarifPath
          : null;
      } catch {
        this.sarifPath = null;
      }
    }
    if (options.rolloutSessionIndexPath !== undefined) {
      this.rolloutSessionIndexPath = options.rolloutSessionIndexPath;
    } else {
      const defaultIndexPath = join(
        options.scanDir,
        "artifacts",
        "rollout-sessions",
        "index.json",
      );
      try {
        this.rolloutSessionIndexPath = lstatSync(defaultIndexPath, {
          throwIfNoEntry: false,
        })?.isFile()
          ? defaultIndexPath
          : null;
      } catch {
        this.rolloutSessionIndexPath = null;
      }
    }
  }

  public get reportPath(): string {
    return join(this.scanDir, "report.md");
  }

  public get pluginVersion(): string {
    return this.manifest.scan.producer.version;
  }

  public get manifestPath(): string {
    return join(this.scanDir, "scan-manifest.json");
  }

  public get findingsPath(): string {
    return join(this.scanDir, "findings.json");
  }

  public get coveragePath(): string {
    return join(this.scanDir, "coverage.json");
  }

  public get artifactsDir(): string {
    return join(this.scanDir, "artifacts");
  }

  public toJSON(): Record<string, unknown> {
    return {
      manifest: this.manifest,
      findings: this.findings,
      coverage: this.coverage,
      scanDir: this.scanDir,
      threadId: this.threadId,
      reportPath: this.reportPath,
      artifactsDir: this.artifactsDir,
      sarifPath: this.sarifPath,
      rolloutSessionIndexPath: this.rolloutSessionIndexPath,
      cost: this.cost,
      turn: this.turnResult,
    };
  }
}

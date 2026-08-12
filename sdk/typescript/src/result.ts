import { statSync } from "node:fs";
import { join } from "node:path";
import type {
  CoverageDocument,
  Finding,
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

export interface RepositoryFinding
  extends Pick<
    Finding,
    "findingId" | "occurrenceId" | "title" | "summary" | "severity"
  > {
  scanId: string;
  targetId: string;
  status: "open" | "closed";
  confirmedInLatestScan: boolean;
  knownSince?: string;
  knownScanIds?: string[];
  matchedFindingIds?: string[];
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
  warnings?: readonly string[];
  repositoryFindings?: readonly RepositoryFinding[];
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
  public readonly warnings: readonly string[];
  public repositoryFindings: readonly RepositoryFinding[] | undefined;

  public constructor(options: ScanResultOptions) {
    this.manifest = options.manifest;
    this.findings = options.findings;
    this.coverage = options.coverage;
    this.scanDir = options.scanDir;
    this.threadId = options.threadId;
    this.turnResult = options.turnResult;
    this.warnings = options.warnings ?? [];
    this.repositoryFindings = options.repositoryFindings;
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

  /**
   * Returns this result with `warnings` appended. A run keeps reporting warnings
   * after its result is collected, so they are attached once the run is over.
   */
  public withWarnings(warnings: readonly string[]): ScanResult {
    if (warnings.length === 0) return this;
    return new ScanResult({
      manifest: this.manifest,
      findings: this.findings,
      coverage: this.coverage,
      scanDir: this.scanDir,
      threadId: this.threadId,
      turnResult: this.turnResult,
      sarifPath: this.sarifPath,
      warnings: [...this.warnings, ...warnings],
      repositoryFindings: this.repositoryFindings,
    });
  }

  public toJSON(): Record<string, unknown> {
    return {
      manifest: this.manifest,
      repositoryFindings: this.repositoryFindings,
      findings: this.findings,
      coverage: this.coverage,
      scanDir: this.scanDir,
      threadId: this.threadId,
      reportPath: this.reportPath,
      artifactsDir: this.artifactsDir,
      sarifPath: this.sarifPath,
      cost: this.cost,
      // Always present, empty when the run reported nothing, so a machine consumer
      // can test it without distinguishing "no warnings" from "an older result".
      warnings: this.warnings,
      turn: this.turnResult,
    };
  }
}

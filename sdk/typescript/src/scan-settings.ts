import { z } from "zod";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "./deep-scan-defaults.js";
import type { Finding, SeverityLevel } from "./models.js";
import type { ScanTarget } from "./targets.js";

export const SCAN_AUTH_MODES = ["auto", "chatgpt", "api-key"] as const;
export type ScanAuthMode = (typeof SCAN_AUTH_MODES)[number];
export const SCAN_MODES = ["standard", "deep"] as const;
export type ScanMode = (typeof SCAN_MODES)[number];
export const DEFAULT_SCAN_AUTH = "auto";
export const DEFAULT_SCAN_MODE = "standard";
export const REPORTABLE_SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
] as const;
export const SCAN_SEVERITIES = [
  ...REPORTABLE_SEVERITIES,
  "informational",
] as const;
export const FailureSeveritySchema = z.enum(REPORTABLE_SEVERITIES);
export type FailureSeverity = z.infer<typeof FailureSeveritySchema>;

export const DEEP_SCAN_SETTINGS = [
  ["workers", "workers", 1],
  ["subagents", "subagents", 0],
  ["stopAfterNoNew", "stop_after_no_new", 1],
  ["stopAfterConsecutiveErrors", "stop_after_consecutive_errors", 1],
  ["maxDiscoveryRuns", "max_discovery_runs", 1],
  ["maxTimeHours", "max_time_hours", 0],
] as const;

export const DeepScanSettingsSchema = z.strictObject({
  workers: z.number().int().positive().optional().meta({
    default: DEFAULT_DEEP_SCAN_SETTINGS.workers,
    description: "Maximum concurrent deep-scan discovery workers.",
  }),
  subagents: z.number().int().nonnegative().optional().meta({
    default: DEFAULT_DEEP_SCAN_SETTINGS.subagents,
    description: "Subagents available to each deep-scan worker. Zero is valid.",
  }),
  stopAfterNoNew: z.number().int().positive().optional().meta({
    default: DEFAULT_DEEP_SCAN_SETTINGS.stopAfterNoNew,
    description: "Stop after this many runs find no new issues.",
  }),
  stopAfterConsecutiveErrors: z.number().int().positive().optional().meta({
    default: DEFAULT_DEEP_SCAN_SETTINGS.stopAfterConsecutiveErrors,
    description: "Stop after this many consecutive discovery errors.",
  }),
  maxDiscoveryRuns: z.number().int().positive().optional().meta({
    default: DEFAULT_DEEP_SCAN_SETTINGS.maxDiscoveryRuns,
    description: "Maximum deep-scan discovery runs.",
  }),
  maxTimeHours: z.number().positive().max(96).optional().meta({
    default: DEFAULT_DEEP_SCAN_SETTINGS.maxTimeHours,
    description:
      "Maximum deep-scan discovery hours (default: 96; maximum: 96).",
  }),
});

export type DeepScanOptions = z.infer<typeof DeepScanSettingsSchema>;

const inputPath = z.string().min(1);

export const ScanSettingsSchema = DeepScanSettingsSchema.extend({
  auth: z.enum(SCAN_AUTH_MODES).optional().meta({ default: DEFAULT_SCAN_AUTH }),
  mode: z.enum(SCAN_MODES).optional().meta({ default: DEFAULT_SCAN_MODE }),
  knowledgeBasePaths: z.array(inputPath).optional(),
  scanPrompt: z.string().optional(),
  scanPromptFile: inputPath.optional(),
  validationPrompt: z.string().optional(),
  validationPromptFile: inputPath.optional(),
  postScanPrompt: z.string().optional(),
  postScanPromptFile: inputPath.optional(),
  outputDir: inputPath.optional(),
  failureSeverity: z.enum(SCAN_SEVERITIES).optional(),
  maxCostUsd: z.number().positive().optional(),
});

/** Scan settings shared by SDK calls, CLI flags, and project files. */
export interface ScanSettings extends z.infer<typeof ScanSettingsSchema> {
  target?: ScanTarget;
}

export interface ResolvedScanSettings extends ScanSettings {
  auth: ScanAuthMode;
  mode: ScanMode;
  target: ScanTarget;
  knowledgeBasePaths: string[];
}

export type ScanPromptSettings = Pick<
  ScanSettings,
  | "scanPrompt"
  | "scanPromptFile"
  | "validationPrompt"
  | "validationPromptFile"
  | "postScanPrompt"
  | "postScanPromptFile"
>;

export function scanSettings(settings: ScanSettings): ScanSettings {
  const keys = [
    "target",
    ...Object.keys(ScanSettingsSchema.shape),
  ] as (keyof ScanSettings)[];
  return Object.fromEntries(
    keys
      .filter((key) => settings[key] !== undefined)
      .map((key) => [key, settings[key]]),
  ) as ScanSettings;
}

export function meetsSeverity(
  finding: Pick<Finding, "severity">,
  threshold: SeverityLevel,
): boolean {
  const severity = SCAN_SEVERITIES.indexOf(finding.severity.level);
  return severity >= 0 && severity <= SCAN_SEVERITIES.indexOf(threshold);
}

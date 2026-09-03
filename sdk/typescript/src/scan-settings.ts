import { z } from "zod";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "./deep-scan-defaults.js";
import { ConfigurationError } from "./errors.js";
import type { Finding, SeverityLevel } from "./models.js";
import type { AbsolutePath } from "./config-path.js";
import { SCAN_MODES, type ScanMode } from "./scan-modes.js";
import type { ScanTarget } from "./targets.js";

export const SCAN_AUTH_MODES = ["auto", "chatgpt", "api-key"] as const;
export type ScanAuthMode = (typeof SCAN_AUTH_MODES)[number];
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

// SDK name, legacy TOML key, project key, and CLI flag (when exposed).
export const DEEP_SCAN_SETTINGS = [
  ["workers", "workers", "workers", "--workers"],
  ["subagents", "subagents", "subagents_per_worker", "--subagents"],
  [
    "stopAfterNoNew",
    "stop_after_no_new",
    "stop_after_no_new",
    "--stop-after-no-new",
  ],
  [
    "stopAfterConsecutiveErrors",
    "stop_after_consecutive_errors",
    "stop_after_consecutive_errors",
    null,
  ],
  [
    "maxDiscoveryRuns",
    "max_discovery_runs",
    "max_discovery_runs",
    "--max-discovery-runs",
  ],
  ["maxTimeHours", "max_time_hours", "max_time_hours", "--max-time-hours"],
] as const;

const positiveIntegerError = "must be a positive integer";
const positiveInteger = z
  .number({ error: positiveIntegerError })
  .int({ error: positiveIntegerError })
  .positive({ error: positiveIntegerError });
const nonnegativeIntegerError = "must be a non-negative integer";
const nonnegativeInteger = z
  .number({ error: nonnegativeIntegerError })
  .int({ error: nonnegativeIntegerError })
  .nonnegative({ error: nonnegativeIntegerError });
const maximumHours = 96;
const hoursError = `must be a positive number no greater than ${maximumHours}`;

export const DeepScanSettingsSchema = z.strictObject({
  workers: positiveInteger.optional().meta({
    default: DEFAULT_DEEP_SCAN_SETTINGS.workers,
    description: "Maximum concurrent deep-scan discovery workers.",
  }),
  subagents: nonnegativeInteger.optional().meta({
    default: DEFAULT_DEEP_SCAN_SETTINGS.subagents,
    description: "Subagents available to each deep-scan worker. Zero is valid.",
  }),
  stopAfterNoNew: positiveInteger.optional().meta({
    default: DEFAULT_DEEP_SCAN_SETTINGS.stopAfterNoNew,
    description: "Stop after this many runs find no new issues.",
  }),
  stopAfterConsecutiveErrors: positiveInteger.optional().meta({
    default: DEFAULT_DEEP_SCAN_SETTINGS.stopAfterConsecutiveErrors,
    description: "Stop after this many consecutive discovery errors.",
  }),
  maxDiscoveryRuns: positiveInteger.optional().meta({
    default: DEFAULT_DEEP_SCAN_SETTINGS.maxDiscoveryRuns,
    description: "Maximum deep-scan discovery runs.",
  }),
  maxTimeHours: z
    .number({ error: hoursError })
    .positive({ error: hoursError })
    .max(maximumHours, { error: hoursError })
    .optional()
    .meta({
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
  knowledgeBasePaths: AbsolutePath[];
  scanPromptFile?: AbsolutePath;
  validationPromptFile?: AbsolutePath;
  postScanPromptFile?: AbsolutePath;
  outputDir?: AbsolutePath;
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

/** Pick defined scan settings without copying callbacks or workflow controls. */
export function pickScanSettings(settings: ScanSettings): ScanSettings {
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
  const thresholdRank = severityThresholdRank(threshold);
  const severity = SCAN_SEVERITIES.indexOf(finding.severity.level);
  return severity >= 0 && severity <= thresholdRank;
}

export function severityThresholdRank(threshold: SeverityLevel): number {
  const rank = SCAN_SEVERITIES.indexOf(threshold);
  if (rank < 0) {
    throw new ConfigurationError(
      `Unknown severity threshold: ${String(threshold)}.`,
    );
  }
  return rank;
}

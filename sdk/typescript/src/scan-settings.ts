import { z } from "zod";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "./deep-scan-defaults.js";

export const SCAN_AUTH_MODES = ["auto", "chatgpt", "api-key"] as const;
export type ScanAuthMode = (typeof SCAN_AUTH_MODES)[number];
export const REPORTABLE_SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
] as const;

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

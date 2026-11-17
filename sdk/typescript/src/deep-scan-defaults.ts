// Generated from the plugin Deep Scan defaults and settings. Run pnpm build.
export const DEFAULT_DEEP_SCAN_SETTINGS = {
  workers: 4,
  subagents: 3,
  stopAfterNoNew: 4,
  stopAfterConsecutiveErrors: 3,
  maxDiscoveryRuns: 40,
  maxTimeHours: 96,
} as const;

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

export function hoursConflict(hours: number, prior = hours) {
  return Math.abs(prior - hours) > Number.EPSILON * Math.max(prior, hours);
}

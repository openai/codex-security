import type { ScanAuthentication, ScanAuthMode } from "./api.js";
import type { ScanAccountRateLimit, ScanUsageObservation } from "./cost.js";

export const ACCOUNT_LIMITS_UNAVAILABLE =
  "ChatGPT allowance not reported by Codex";
export const USAGE_TIME_UNAVAILABLE =
  "Usage report time unavailable · in-flight usage may be missing";

export function isChatGptAuthentication(
  authentication: ScanAuthentication | null,
  requested?: ScanAuthMode,
): boolean {
  return (
    authentication?.method === "stored_credentials" &&
    (authentication.credentialType ?? requested) === "chatgpt"
  );
}

function receiptTime(timestamp: string): string {
  return `${timestamp.slice(0, 10)} ${timestamp.slice(11, 19)} UTC`;
}

export function formatUsageFreshness(
  observation: Readonly<ScanUsageObservation>,
): string | null {
  return observation.tokensUpdatedAt === null
    ? null
    : `Last usage report ${receiptTime(observation.tokensUpdatedAt)} · in-flight usage may be missing`;
}

function formatWindow(
  window: ScanAccountRateLimit["primary"],
  name: string,
): string | null {
  if (window === null) return null;
  const minutes = window.windowMinutes;
  let duration = name;
  if (minutes !== null) {
    if (minutes % 1440 === 0) duration = `${minutes / 1440}d`;
    else if (minutes % 60 === 0) duration = `${minutes / 60}h`;
    else duration = `${minutes}m`;
  }
  return `${duration} ${window.usedPercent}% used`;
}

export function formatAccountLimits(
  observation: Readonly<ScanUsageObservation>,
): string | null {
  const readings = observation.accountRateLimits.flatMap((limit) => {
    const windows = [
      formatWindow(limit.primary, "primary"),
      formatWindow(limit.secondary, "secondary"),
    ].filter((window) => window !== null);
    return windows.length === 0
      ? []
      : [
          `${limit.limitId} ${windows.join(", ")} (as of ${receiptTime(limit.observedAt)})`,
        ];
  });
  return readings.length === 0
    ? null
    : `Account allowance: ${readings.join(" | ")}`;
}

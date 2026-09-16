import { createHash } from "node:crypto";

const MAX_PERSISTED_ERROR_LENGTH = 2_400;

const RATE_LIMIT_PATTERN = /\b(?:429|rate[ _-]*limit(?:ed|ing)?|too many requests)\b/iu;

const ARTIFACT_MCP_STARTUP_TIMEOUT_PATTERN =
  /\b(?:cs_artifacts|codex_security_artifacts)\b[^\r\n]*(?:timed out handshaking with MCP server|timed out after \d+(?:\.\d+)?\s*(?:seconds?|s)\b|request timed out\b)/iu;

const REMOTE_PLUGIN_AUTH_WARNING_PATTERN =
  /\bchatgpt authentication required (?:for remote plugin catalog|to sync remote plugins)(?:; api key auth is not supported)?/giu;

const STALE_COORDINATOR_GENERATION_MESSAGE =
  "Deep Scan coordinator lease belongs to a newer generation.";

const CYBERSECURITY_POLICY_REFUSAL_PATTERNS = [
  /\bflagged for possible cybersecurity risk\b/iu,
  /\bflagged for potentially high-risk cyber activity\b/iu,
  /\bcyber[_\s-]?policy\b/iu,
  /\b(?:cybersecurity|cyber)[ _-]*policy[ _-]*(?:violation|refusal|refused)\b/iu,
  /\b(?:content|safety)[ _-]*policy[ _-]*(?:violation|refusal|refused)\b/iu,
  /\b(?:refusal|refused)\b[^\n]*\b(?:cybersecurity|cyber|safety policy)\b/iu,
  /\b(?:cybersecurity|cyber|safety policy)\b[^\n]*\b(?:refusal|refused)\b/iu
] as const;

export class DeepScanNonRetryableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DeepScanNonRetryableError";
  }
}

/** Keep SQLite's bounded diagnostic useful while the manifest retains the full error. */
export function boundedDeepScanErrorMessage(error: unknown): string {
  return boundedDeepScanErrorText(deepScanErrorMessage(error), MAX_PERSISTED_ERROR_LENGTH);
}

export function boundedDeepScanErrorPair(
  primary: unknown,
  separator: string,
  secondary: unknown,
): string {
  const primaryMessage = deepScanErrorMessage(primary);
  const secondaryMessage = deepScanErrorMessage(secondary);
  const available = MAX_PERSISTED_ERROR_LENGTH - separator.length;
  const balancedBudget = Math.floor(available / 2);
  let primaryBudget = Math.min(primaryMessage.length, balancedBudget);
  const secondaryBudget = Math.min(
    secondaryMessage.length,
    available - primaryBudget,
  );
  primaryBudget = Math.min(primaryMessage.length, available - secondaryBudget);
  return [
    boundedDeepScanErrorText(primaryMessage, primaryBudget),
    separator,
    boundedDeepScanErrorText(secondaryMessage, secondaryBudget),
  ].join("");
}

function deepScanErrorMessage(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).trim()
    || "Codex Security Deep Scan failed.";
}

function boundedDeepScanErrorText(message: string, maxLength: number): string {
  if (message.length <= maxLength) return message;
  const digest = createHash("sha256").update(message).digest("hex");
  const suffix = `\n...[truncated; sha256:${digest}]`;
  if (suffix.length >= maxLength) return message.slice(0, maxLength);
  return `${message.slice(0, maxLength - suffix.length)}${suffix}`;
}

export function isStaleCoordinatorGenerationError(error: unknown): boolean {
  for (let current = error; current instanceof Error; current = current.cause) {
    if (current.message.includes(STALE_COORDINATOR_GENERATION_MESSAGE)) return true;
  }
  return false;
}

/** A safety refusal retires the refused thread; it is not a broken scan. */
export function isCodexCybersecurityPolicyRefusal(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  if (RATE_LIMIT_PATTERN.test(message)) return false;
  return CYBERSECURITY_POLICY_REFUSAL_PATTERNS.some((pattern) => pattern.test(message));
}

export function classifyCodexWorkerError(error: unknown): Error {
  const normalized = error instanceof Error ? error : new Error(String(error));
  if (normalized instanceof DeepScanNonRetryableError) return normalized;
  const code = "code" in normalized && typeof normalized.code === "string"
    ? normalized.code
    : undefined;
  if (code === "ENOENT" || code === "EACCES" || code === "ENOEXEC" || code === "EPERM") {
    return new DeepScanNonRetryableError(normalized.message, { cause: normalized });
  }
  // API-key workers cannot catalog or sync remote plugins, but those warnings
  // are unrelated when their local artifact MCP server merely starts too slowly.
  const configurationMessage = ARTIFACT_MCP_STARTUP_TIMEOUT_PATTERN.test(normalized.message)
    ? normalized.message.replace(REMOTE_PLUGIN_AUTH_WARNING_PATTERN, "")
    : normalized.message;
  if (
    isCodexConfigurationFailure(configurationMessage)
    || isCodexCybersecurityPolicyRefusal(normalized)
  ) {
    return new DeepScanNonRetryableError(normalized.message, { cause: normalized });
  }
  return normalized;
}

function isCodexConfigurationFailure(message: string): boolean {
  return [
    /Codex Exec exited with code 2:/i,
    /Codex Exec exited with code 1:[\s\S]*\(os error 2\)/i,
    /agents\.max_threads cannot be set when features\.multi_agent_v2 is enabled/i,
    /failed to (?:load|parse|read) (?:the )?(?:Codex )?config(?:uration)?/i,
    /(?:config(?:uration)?|config\.toml).*(?:invalid|parse|syntax|unknown)/i,
    /(?:invalid|unknown).*(?:--config|config(?:uration)? key)/i,
    /not logged in|authentication required|missing (?:an? )?(?:api key|credentials)/i
  ].some((pattern) => pattern.test(message));
}

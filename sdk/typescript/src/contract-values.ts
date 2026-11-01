/* Generated from plugin contract-values.ts. Run `pnpm generate:models`. */
import { hash } from "node:crypto";
import { isAbsolute, posix } from "node:path";
import type { Finding } from "./models.js";
import { isWindowsUnsafePathComponent } from "./windows-path.js";

export class SealedContractError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class SealedContractSchemaError extends SealedContractError {}

export const SEALED_DEFERRED_PATH_RULE = "invalidSealedDeferredPath";
export const DEFERRED_PATH_LOCATION = /^\/deferred\/(\d+)\/paths\/(\d+)$/u;

/** Match the producer's Python str.strip without changing saved text. */
export function hasRequiredFindingText(value: string): boolean {
  return !/^[\p{White_Space}\u001c-\u001f]*$/u.test(value);
}

export function safeRelativePath(
  value: string,
  context: string,
  allowDot = false,
): string {
  const parts = value.split("/");
  if (
    value.length === 0 ||
    Buffer.from(value, "utf8").toString("utf8") !== value ||
    (!allowDot && value === ".") ||
    value.startsWith("/") ||
    /^[A-Za-z]:/.test(value) ||
    parts.includes("..") ||
    value.includes("\\") ||
    /[\u0000-\u001f]/u.test(value)
  ) {
    throw new SealedContractError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  const normalized = posix.normalize(value).replace(/\/+$/, "");
  if (
    (!allowDot && normalized === ".") ||
    normalized.startsWith("../") ||
    isAbsolute(normalized)
  ) {
    throw new SealedContractError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  return normalized;
}

export function portableRelativePath(value: string, context: string): string {
  const normalized = safeRelativePath(value, context);
  if (
    value.trim().length === 0 ||
    value.split("/").some(isWindowsUnsafePathComponent)
  ) {
    throw new SealedContractError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  return normalized;
}

export function safeScopePath(value: string): string {
  return value === "."
    ? value
    : safeRelativePath(value, "manifest scope include path");
}

/** @internal */
export function sha256Text(value: string): string {
  return hash("sha256", value);
}

export function deriveFindingIdentity(
  scanId: string,
  targetId: string,
  ruleId: string,
  identity: Finding["identity"],
) {
  const fingerprint = `codex-security/v1:sha256:${sha256Text(
    [
      "codex-security/v1",
      targetId,
      ruleId,
      identity.anchor,
      identity.instance ?? "",
    ].join("\0"),
  )}`;
  return {
    findingId: `csf_${sha256Text(fingerprint).slice(0, 24)}`,
    occurrenceId: `occ_${sha256Text([scanId, fingerprint].join("\0")).slice(0, 24)}`,
    ruleId,
    identity,
    fingerprints: {
      algorithm: "codex-security/v1" as const,
      primary: fingerprint,
    },
  };
}

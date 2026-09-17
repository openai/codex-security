import { isAbsolute, posix } from "node:path";
import { ContractValidationError } from "./errors.js";

export function safeRelativePath(value: string, context: string): string {
  const parts = value.split("/");
  if (
    value.trim().length === 0 ||
    !isWellFormedUnicode(value) ||
    value === "." ||
    value.startsWith("/") ||
    /^[A-Za-z]:/.test(value) ||
    parts.includes("..") ||
    value.includes("\\") ||
    /[\u0000-\u001f]/u.test(value)
  ) {
    throw new ContractValidationError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  const normalized = posix.normalize(value).replace(/\/+$/, "");
  if (
    normalized === "." ||
    normalized.startsWith("../") ||
    isAbsolute(normalized)
  ) {
    throw new ContractValidationError(
      `${context}: expected a safe scan-relative POSIX path.`,
    );
  }
  return normalized;
}

export function isWellFormedUnicode(value: string): boolean {
  return Buffer.from(value, "utf8").toString("utf8") === value;
}

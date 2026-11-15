import { createHash } from "node:crypto";

export function shortArchivePrefix(originalName: string): string {
  return `.previous-${createHash("sha256").update(originalName).digest("hex")}-`;
}

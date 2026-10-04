/** @internal */
export function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

/** @internal */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** @internal */
export function parseJson(read: () => string): unknown {
  try {
    return JSON.parse(read());
  } catch {
    return null;
  }
}

/** @internal */
export const findingEntry = <T extends { findingId: string }>(
  finding: T,
): [string, T] => [finding.findingId, finding];

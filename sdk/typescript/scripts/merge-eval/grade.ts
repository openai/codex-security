import type { ExpectedGroup } from "./fixtures.js";

const object = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
const key = (refs: readonly string[]) => JSON.stringify([...refs].sort());

/** Closed-world oracle, independent of the host's source-retention validator.
 * Only canonical user-visible fields can satisfy repair requirements.
 */
export function gradeMerge(
  raw: unknown,
  expected: readonly ExpectedGroup[],
): string[] {
  const findings = object(raw)["findings"];
  if (!Array.isArray(findings)) return ["Missing findings array."];
  const errors: string[] = [];
  const remaining = new Map(expected.map((group) => [key(group.refs), group]));
  for (const value of findings) {
    const finding = object(value);
    const refs = object(finding["provenance"])["sourceFindingIds"];
    if (!Array.isArray(refs) || !refs.every((ref) => typeof ref === "string")) {
      errors.push("Invalid source references.");
      continue;
    }
    const expectedGroup = remaining.get(key(refs));
    if (!expectedGroup) {
      errors.push(`Wrong merge partition: ${key(refs)}.`);
      continue;
    }
    remaining.delete(key(refs));
    if (object(finding["severity"])["level"] !== expectedGroup.severity)
      errors.push(`Wrong severity: ${key(refs)}.`);
    for (const [field, facts] of Object.entries(expectedGroup.facts)) {
      const identifiers = new Set(
        JSON.stringify(finding[field] ?? "")
          .toLowerCase()
          .match(/[a-z0-9_-]+/g),
      );
      for (const fact of facts)
        if (!identifiers.has(fact.toLowerCase()))
          errors.push(`Missing canonical ${field} fact ${fact}: ${key(refs)}.`);
    }
  }
  for (const refs of remaining.keys())
    errors.push(`Missing expected group: ${refs}.`);
  return errors;
}

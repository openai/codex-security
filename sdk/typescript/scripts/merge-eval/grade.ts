import type { ExpectedGroup } from "./fixtures.js";

const object = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
const key = (refs: readonly string[]) => JSON.stringify([...refs].sort());

/** Independent oracle for partitions and evidence-supported canonical selection. */
export function gradeMerge(
  raw: unknown,
  expected: readonly ExpectedGroup[],
): string[] {
  const findings = object(raw)["groups"];
  if (!Array.isArray(findings)) return ["Missing groups array."];
  const errors: string[] = [];
  const remaining = new Map(expected.map((group) => [key(group.refs), group]));
  for (const value of findings) {
    const finding = object(value);
    const refs = finding["sourceFindingIds"];
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
    if (
      !expectedGroup.canonicalSourceFindingIds.includes(
        String(finding["canonicalSourceFindingId"]),
      )
    )
      errors.push(`Wrong canonical source: ${key(refs)}.`);
  }
  for (const refs of remaining.keys())
    errors.push(`Missing expected group: ${refs}.`);
  return errors;
}

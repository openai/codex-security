export function confirmedGroup(
  beforeOccurrenceIds: string[],
  afterOccurrenceIds: string[],
  reason: string,
) {
  return {
    beforeOccurrenceIds,
    afterOccurrenceIds,
    confidence: "high" as const,
    reason,
  };
}

export function findingPair(
  beforeOccurrenceId: string,
  afterOccurrenceId: string,
  reason: string,
) {
  return { beforeOccurrenceId, afterOccurrenceId, reason };
}

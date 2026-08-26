export interface DeduplicationResult {
  uniqueFindingIds: string[];
  duplicateGroups: string[][];
  deduplicationStatus: "not_implemented";
}

export class DeduplicationService {
  async run(findingIds: readonly string[]): Promise<DeduplicationResult> {
    console.log(
      `Deduplication not implemented (${findingIds.length} findings).`,
    );
    return {
      uniqueFindingIds: [...new Set(findingIds)],
      duplicateGroups: [],
      deduplicationStatus: "not_implemented",
    };
  }
}

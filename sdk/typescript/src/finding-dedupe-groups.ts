/** A reviewed set of duplicate findings. A finding may belong to multiple groups. */
export interface FindingDedupeGroup {
  groupId: string;
  findingIds: string[];
  createdAt: string;
}

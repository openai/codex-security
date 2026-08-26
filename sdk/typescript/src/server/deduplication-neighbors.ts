import type { Finding } from "../models.js";
import { FindingsError } from "./errors.js";
import type { EmbeddedFinding } from "./storage.js";

export const MAX_DEDUPLICATION_NEIGHBORS = 50;
export const MIN_DEDUPLICATION_SIMILARITY = 0.55;

export function findingNeighborhoods(
  entries: readonly EmbeddedFinding[],
  findingIds: readonly string[],
): Finding[][] {
  const normalized = entries.map(({ embedding }) => {
    const norm = Math.hypot(...embedding.vector);
    if (norm === 0 || !Number.isFinite(norm)) {
      throw new FindingsError(
        "deduplication_failed",
        "A stored embedding cannot be compared. Reimport the finding.",
      );
    }
    return embedding.vector.map((value) => value / norm);
  });
  const positions = new Map(
    entries.map(({ finding }, index) => [finding.findingId, index]),
  );
  return findingIds.map((id) => {
    const position = positions.get(id);
    if (position === undefined) {
      throw new FindingsError(
        "finding_conflict",
        "A finding changed before deduplication. Retry the import.",
      );
    }
    const anchor = entries[position]!;
    const vector = normalized[position]!;
    const neighbors: { index: number; similarity: number }[] = [];
    for (const [index, entry] of entries.entries()) {
      if (
        index === position ||
        entry.embedding.model !== anchor.embedding.model ||
        entry.embedding.vector.length !== vector.length
      )
        continue;
      const other = normalized[index]!;
      let similarity = 0;
      for (let dimension = 0; dimension < vector.length; dimension++) {
        similarity += vector[dimension]! * other[dimension]!;
      }
      if (similarity >= MIN_DEDUPLICATION_SIMILARITY) {
        neighbors.push({ index, similarity });
      }
    }
    neighbors.sort(
      (left, right) =>
        right.similarity - left.similarity || left.index - right.index,
    );
    return [
      anchor.finding,
      ...neighbors
        .slice(0, MAX_DEDUPLICATION_NEIGHBORS)
        .map(({ index }) => entries[index]!.finding),
    ];
  });
}

import type { FindingNeighborhood } from "../deduplication/deduplication.js";
import { FindingsError } from "./errors.js";
import type { EmbeddedFinding } from "./storage.js";

export const MAX_DEDUPLICATION_NEIGHBORS = 50;
export const MIN_DEDUPLICATION_SIMILARITY = 0.55;

export function potentialDuplicates(
  entries: readonly EmbeddedFinding[],
  findingId: string,
): FindingNeighborhood {
  const position = entries.findIndex(
    ({ finding }) => finding.findingId === findingId,
  );
  if (position === -1) {
    throw new FindingsError(
      "finding_not_indexed",
      "The finding has no current embedding. Import it through POST /v1/bulk/findings before requesting potential duplicates.",
    );
  }
  const normalized = entries.map(({ embedding }) => {
    const norm = Math.hypot(...embedding.vector);
    if (norm === 0 || !Number.isFinite(norm)) {
      throw new FindingsError(
        "embedding_failed",
        "A stored embedding cannot be compared. Reimport the finding.",
      );
    }
    return embedding.vector.map((value) => value / norm);
  });
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
  return {
    finding: anchor.finding,
    potentialDuplicates: neighbors
      .slice(0, MAX_DEDUPLICATION_NEIGHBORS)
      .map(({ index }) => entries[index]!.finding),
  };
}

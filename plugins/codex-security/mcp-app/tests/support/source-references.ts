export const sourceReferences =
  (worker: { id: string }) =>
  <T extends { provenance: object }>(finding: T, index: number) => ({
    ...finding,
    provenance: {
      ...finding.provenance,
      sourceFindingIds: [`${worker.id}:${index}`],
    },
  });

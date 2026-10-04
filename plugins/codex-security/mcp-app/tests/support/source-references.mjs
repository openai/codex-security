export const sourceReferences = (worker) => (finding, index) => ({
  ...finding,
  provenance: {
    ...finding.provenance,
    sourceFindingIds: [`${worker.id}:${index}`],
  },
});

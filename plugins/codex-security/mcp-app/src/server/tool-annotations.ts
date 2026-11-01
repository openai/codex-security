export const readingAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

export const writingAnnotations = {
  ...readingAnnotations,
  readOnlyHint: false,
};

export const propertyOptions = {
  seed: Number(process.env["CODEX_SECURITY_PROPERTY_SEED"] ?? "20260817"),
  numRuns: Number(process.env["CODEX_SECURITY_PROPERTY_RUNS"] ?? "100"),
  ...(process.env["CODEX_SECURITY_PROPERTY_PATH"] === undefined
    ? {}
    : { path: process.env["CODEX_SECURITY_PROPERTY_PATH"] }),
};

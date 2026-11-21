// Source-only builds resolve this module. Full builds bundle the SDK
// implementation through build_mcp_app.mjs.
export type ValidationProviderConfiguration = {
  provider: string;
  [key: string]: unknown;
};

function unavailable(): never {
  throw new Error(
    "For host-side validation, install the packaged plugin or build it from a checkout including sdk/typescript. For a completed scan use codex-security validate --scan with the project file.",
  );
}

export const validationProviderFromConfiguration: (
  configuration: ValidationProviderConfiguration,
) => unknown = unavailable;
export const assessPluginFindings: (...args: unknown[]) => never = unavailable;
// Source-only builds can read the protected cache written by the packaged SDK.
export const continuumAssessmentVersion = 2;

export async function savedContinuumAssessments(
  _environment: Record<string, string | undefined>,
  _scanId: string,
  _repositoryPath: string,
  _occurrenceIds: readonly string[],
): Promise<Map<string, unknown>> {
  return new Map();
}

// Only the SDK can run the provider or update the saved assessment.
export function withPublicationLock<T>(
  _state: string,
  _key: string,
  _signal: AbortSignal | undefined,
  operation: () => Promise<T>,
) {
  return operation();
}

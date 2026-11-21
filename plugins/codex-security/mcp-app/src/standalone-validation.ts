// Source-only builds resolve this module. Full builds bundle the SDK
// implementation using the first path in tsconfig.json.
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

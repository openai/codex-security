import { continuumProviderFromConfig } from "./continuum-validation-provider.js";
import type {
  ValidationProvider,
  ValidationProviderConfiguration,
} from "./validation-provider.js";

/** Resolve built-ins without leaking provider-specific options into callers. */
export function validationProviderFromConfiguration(
  configuration: ValidationProviderConfiguration,
): ValidationProvider {
  const name = configuration.provider.trim().toLowerCase();
  if (name === "continuum") {
    const selected = configuration["continuum"];
    return continuumProviderFromConfig(
      selected !== null &&
        typeof selected === "object" &&
        !Array.isArray(selected)
        ? (selected as Record<string, unknown>)
        : {},
    );
  }
  throw new Error(`Unknown validation provider: ${configuration.provider}`);
}

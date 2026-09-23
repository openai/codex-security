import { InvalidTargetError } from "./errors.js";
import { valid } from "semver";

/** An installed public npm package and the exact version to review. */
export interface DependencyIdentity {
  ecosystem: "npm";
  registry: "https://registry.npmjs.org";
  package: string;
  oldVersion: null;
  newVersion: string;
}

export const MAX_SELECTED_DEPENDENCIES = 20;
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const EXACT_VERSION =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function parseDependencyIdentities(
  value: unknown,
): DependencyIdentity[] {
  if (!Array.isArray(value)) {
    throw new InvalidTargetError("Dependency identities must be an array.");
  }
  const seen = new Set<string>();
  return value.map((entry: unknown) => {
    if (
      entry === null ||
      typeof entry !== "object" ||
      !("ecosystem" in entry) ||
      entry.ecosystem !== "npm" ||
      !("registry" in entry) ||
      entry.registry !== "https://registry.npmjs.org" ||
      !("package" in entry) ||
      typeof entry.package !== "string" ||
      !PACKAGE_NAME.test(entry.package) ||
      !("oldVersion" in entry) ||
      entry.oldVersion !== null ||
      !("newVersion" in entry) ||
      typeof entry.newVersion !== "string" ||
      !EXACT_VERSION.test(entry.newVersion) ||
      valid(entry.newVersion) === null
    ) {
      throw new InvalidTargetError(
        "Select exact installed public npm identities with registry https://registry.npmjs.org and oldVersion null.",
      );
    }
    const key = `${entry.package}@${entry.newVersion}`;
    if (seen.has(key)) {
      throw new InvalidTargetError(
        "Dependency identities must not contain duplicates.",
      );
    }
    seen.add(key);
    return {
      ecosystem: entry.ecosystem,
      registry: entry.registry,
      package: entry.package,
      oldVersion: entry.oldVersion,
      newVersion: entry.newVersion,
    };
  });
}

export function parseSelectedDependencies(
  value: unknown,
): DependencyIdentity[] {
  const identities = parseDependencyIdentities(value);
  if (
    identities.length === 0 ||
    identities.length > MAX_SELECTED_DEPENDENCIES
  ) {
    throw new InvalidTargetError(
      `Select between 1 and ${MAX_SELECTED_DEPENDENCIES} dependencies.`,
    );
  }
  return identities;
}

export function selectDependencies(
  requested: readonly string[],
  inventory: DependencyIdentity[] | undefined,
): DependencyIdentity[] {
  if (inventory === undefined) {
    throw new InvalidTargetError(
      "The saved calculation has no selectable dependency inventory. Calculate dependencies again without --dependency-graph.",
    );
  }
  return parseSelectedDependencies(
    requested.map((selector) => {
      const split = selector.lastIndexOf("@");
      if (
        split <= 0 ||
        !EXACT_VERSION.test(selector.slice(split + 1)) ||
        valid(selector.slice(split + 1)) === null
      ) {
        throw new InvalidTargetError(
          "Use --dependency with an exact name@version, including the scope for scoped npm packages.",
        );
      }
      const matches = inventory.filter(
        (identity) =>
          identity.package === selector.slice(0, split) &&
          identity.newVersion === selector.slice(split + 1),
      );
      if (matches.length !== 1) {
        throw new InvalidTargetError(
          `Dependency selection ${JSON.stringify(selector)} must match exactly one installed public npm package in this scope.`,
        );
      }
      return matches[0];
    }),
  );
}

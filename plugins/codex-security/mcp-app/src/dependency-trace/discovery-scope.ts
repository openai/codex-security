import { lstat, realpath } from "node:fs/promises";
import { join, posix, relative } from "node:path";
import { safeRelativePath } from "../contract-values.js";
import { resolveSecurityMd } from "../helpers/resolve-security-md.js";

export interface DiscoveryOmission {
  path: string;
  excludedBy: string;
  basis?: "production_default";
}

const within = (prefix: string, path: string) =>
  path === prefix || path.startsWith(prefix + "/");

const nonProductionDirectory =
  /^(?:docs?|documentation|examples?|tests?|__tests__)$/iu;
const nonProductionFile =
  /\.(?:md|markdown|mdx|rst|adoc)$|^(?:test_.*\.py|conftest\.py)$|_test\.(?:py|go)$|\.(?:test|spec)\.[^.]+$/iu;

function productionDiscoveryExclusion(file: string): string | undefined {
  const parts = file.split("/");
  const name = parts.pop()!;
  const directory = parts.findIndex((part) =>
    nonProductionDirectory.test(part),
  );
  if (directory >= 0) return parts.slice(0, directory + 1).join("/");
  if (nonProductionFile.test(name)) return file;
}

/** The operator's literal discovery boundary. Repository policy can only
 * retain a location that this declaration would otherwise omit. */
export async function createDiscoveryScope(
  root: string,
  excludedPaths: readonly string[],
  productionDiscovery = false,
) {
  const paths = [
    ...new Set(
      excludedPaths.map((path) =>
        safeRelativePath(path, "Exploitability scope exclusion"),
      ),
    ),
  ];
  const exclusions = await Promise.all(
    paths.map(async (path) => {
      const target = join(root, path);
      try {
        const info = await lstat(target);
        if (relative(target, await realpath(target)) !== "") return;
        if (!info.isFile() && !info.isDirectory()) return;
        const policy = resolveSecurityMd(root, path, undefined, {
          requireResolvedLinks: true,
        });
        return { path, directory: info.isDirectory(), policy };
      } catch {
        // An unavailable or unsafe path or policy cannot narrow discovery.
        return undefined;
      }
    }),
  );
  const reopened = new Set<string>();
  const operatorExclusion = (file: string) =>
    exclusions.find(
      (region) =>
        region &&
        (region.directory ? within(region.path, file) : file === region.path),
    );

  return {
    includeExactFile(path: string) {
      reopened.add(path);
    },
    omit(files: readonly string[], structural: boolean): DiscoveryOmission[] {
      const policies = new Map<string, string | undefined>();
      function policy(directory: string) {
        if (!policies.has(directory)) {
          let value: string | undefined;
          try {
            value = resolveSecurityMd(root, directory, undefined, {
              requireResolvedLinks: true,
            });
          } catch {
            // An unresolved policy cannot narrow discovery.
          }
          policies.set(directory, value);
        }
        return policies.get(directory);
      }
      return files.flatMap((file) => {
        if (reopened.has(file)) return [];
        const applicablePolicy = () => policy(posix.dirname(file));
        const operator = structural ? operatorExclusion(file) : undefined;
        if (operator) {
          return applicablePolicy() === operator.policy
            ? [{ path: file, excludedBy: operator.path }]
            : [];
        }
        const excludedBy = productionDiscovery
          ? productionDiscoveryExclusion(file)
          : undefined;
        if (!excludedBy) return [];
        const localPolicy = applicablePolicy();
        return localPolicy !== undefined &&
          localPolicy === policy(posix.dirname(excludedBy))
          ? [{ path: file, excludedBy, basis: "production_default" }]
          : [];
      });
    },
  };
}

export type DiscoveryScope = Awaited<ReturnType<typeof createDiscoveryScope>>;

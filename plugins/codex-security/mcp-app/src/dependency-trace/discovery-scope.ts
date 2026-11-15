import { lstat, realpath } from "node:fs/promises";
import { join, posix, relative } from "node:path";
import { safeRelativePath } from "../contract-values.js";
import { resolveSecurityMd } from "../helpers/resolve-security-md.js";

export interface DiscoveryOmission {
  path: string;
  excludedBy: string;
}

const within = (prefix: string, path: string) =>
  path === prefix || path.startsWith(prefix + "/");

/** The operator's literal discovery boundary. Repository policy can only
 * retain a location that this declaration would otherwise omit. */
export async function createDiscoveryScope(
  root: string,
  excludedPaths: readonly string[],
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
  const exclusionFor = (file: string) =>
    exclusions.find(
      (region) =>
        region &&
        (region.directory ? within(region.path, file) : file === region.path),
    );

  return {
    includeExactFile(path: string) {
      if (exclusionFor(path)) reopened.add(path);
    },
    omit(files: readonly string[]): DiscoveryOmission[] {
      const policies = new Map<string, string | undefined>();
      return files.flatMap((file) => {
        if (reopened.has(file)) return [];
        const exclusion = exclusionFor(file);
        if (!exclusion) return [];
        const directory = posix.dirname(file);
        if (!policies.has(directory)) {
          let policy: string | undefined;
          try {
            policy = resolveSecurityMd(root, directory, undefined, {
              requireResolvedLinks: true,
            });
          } catch {
            // Keep the file if the applicable policy could not be resolved.
          }
          policies.set(directory, policy);
        }
        return policies.get(directory) === exclusion.policy
          ? [{ path: file, excludedBy: exclusion.path }]
          : [];
      });
    },
  };
}

export type DiscoveryScope = Awaited<ReturnType<typeof createDiscoveryScope>>;

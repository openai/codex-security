import type { LoadedContract } from "./contract.js";
import { CodexSecurityError } from "./errors.js";

/** Identity captured in sealed provenance; never consult the current checkout. */
export function cloudRepositoryIdentity(remote: string): string {
  const url = new URL(remote);
  const path = url.pathname
    .replace(/^\//u, "")
    .replace(/\/+$/u, "")
    .replace(/\.git$/u, "");
  if (
    !["https:", "ssh:"].includes(url.protocol) ||
    url.search ||
    url.hash ||
    url.username ||
    url.password ||
    url.port ||
    path.split("/").length !== 2 ||
    path.split("/").some((part) => !part || part === "." || part === "..")
  ) {
    throw new CodexSecurityError(
      "Cloud publication requires a credential-free HTTPS or SSH SCM repository identity without an explicit port.",
    );
  }
  return `${url.hostname.toLowerCase()}/${path.toLowerCase()}`;
}

export function requireCloudScanEligibility({
  manifest,
  coverage,
}: LoadedContract): string {
  if (manifest.scan.status !== "completed")
    throw new CodexSecurityError(
      `Cloud publication requires a completed scan; this scan is ${manifest.scan.status}.`,
    );
  const { target, scope } = manifest.scan;
  if (
    !["git_revision", "git_worktree"].includes(target.kind) ||
    !["repository", "deep_repository"].includes(coverage.mode) ||
    scope.includePaths.length !== 1 ||
    scope.includePaths[0] !== "." ||
    scope.excludePaths.length !== 0 ||
    target.repositoryPath !== "." ||
    coverage.includePaths.length !== 1 ||
    coverage.includePaths[0] !== "." ||
    coverage.excludePaths.length !== 0
  ) {
    throw new CodexSecurityError(
      "Cloud publication accepts full-repository SCM scans only; diff, scoped, and non-SCM imports are unsupported.",
    );
  }
  if (
    !target.remote ||
    !target.revision ||
    (target.kind === "git_worktree" && !target.snapshotDigest)
  ) {
    throw new CodexSecurityError(
      "This scan has no complete saved SCM provenance. Run a new full-repository scan to capture its remote, base commit, and snapshot identity.",
    );
  }
  return cloudRepositoryIdentity(target.remote);
}

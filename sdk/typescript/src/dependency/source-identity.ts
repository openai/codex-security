import { createHash, hash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { basename } from "node:path";
import { z } from "zod";
import { portableRelativePath } from "../contract-values.js";
import { CodexSecurityError } from "../errors.js";
import { parseGitRemote } from "../git-remote.js";
import { gitOutput } from "../targets.js";

export const dependencyGitCommitSchema = z
  .string()
  .regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u, "Expected a full Git commit ID.");

export const dependencyTargetSchema = z.strictObject({
  repository: z.string().min(1),
  sha: dependencyGitCommitSchema,
});
export type DependencyTarget = z.infer<typeof dependencyTargetSchema>;

const localObjects = {
  GIT_NO_LAZY_FETCH: "1",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_ALLOW_PROTOCOL: "",
  GIT_LITERAL_PATHSPECS: "1",
};

function repositoryLabel(directory: string, origin?: string) {
  const checkout = basename(directory);
  if (!origin || /^[A-Za-z]:[\\/]/u.test(origin)) return checkout;
  try {
    const remote = parseGitRemote(origin);
    if (!remote?.url.hostname || remote.url.protocol === "file:")
      return checkout;
    // Record only the repository path, excluding URL credentials and query.
    return (
      remote.path.replace(/^\/+|\/+$/gu, "").replace(/\.git$/u, "") || checkout
    );
  } catch {
    return checkout;
  }
}

/** Capture once, before discovery, so all advisories analyze the same commit. */
export async function readDependencyTarget(
  directory: string,
  signal?: AbortSignal,
): Promise<DependencyTarget | undefined> {
  const read = (args: string[]) =>
    gitOutput(directory, args, signal, localObjects).catch(() => {
      signal?.throwIfAborted();
      return undefined;
    });
  const [sha, origin] = await Promise.all([
    read(["rev-parse", "--verify", "HEAD^{commit}"]),
    read(["remote", "get-url", "--", "origin"]),
  ]);
  const repository = repositoryLabel(directory, origin);
  return sha && repository ? { repository, sha } : undefined;
}

/** Resolve the exact regular blob in the requested commit, including when the worktree is dirty. */
export async function readDependencyGitSource(
  repository: string,
  revision: string,
  relativePath: string,
  signal?: AbortSignal,
) {
  const commit = dependencyGitCommitSchema.parse(revision);
  const path = portableRelativePath(relativePath, "Git source path");
  const repositoryRoot = await realpath(
    await gitOutput(
      repository,
      ["rev-parse", "--show-toplevel"],
      signal,
      localObjects,
    ),
  );
  const git = (args: string[]) =>
    gitOutput(repositoryRoot, args, signal, localObjects);
  if ((await git(["rev-parse", "--verify", commit + "^{commit}"])) !== commit)
    throw new CodexSecurityError(
      "Expected the complete ID of a Git commit object.",
    );
  const entry = await git(["ls-tree", "-z", "--full-tree", commit, "--", path]);
  const match = /^100(?:644|755) blob ([0-9a-f]+)\t([^\0]+)\0$/u.exec(entry);
  if (!match || match[2] !== path)
    throw new CodexSecurityError(`No regular Git file at ${commit}:${path}.`);
  const blob = match[1]!;
  const bytes = await gitOutput(
    repositoryRoot,
    ["cat-file", "blob", blob],
    signal,
    localObjects,
    repositoryRoot,
    "buffer",
  );
  const actual = createHash(blob.length === 40 ? "sha1" : "sha256")
    .update(`blob ${bytes.length}\0`)
    .update(bytes)
    .digest("hex");
  if (actual !== blob)
    throw new CodexSecurityError(
      "Git file bytes do not match their object ID.",
    );
  return {
    bytes,
    identity: {
      kind: "git" as const,
      status: "verified" as const,
      repositoryRoot,
      repositoryPath: path,
      commit,
      blob,
      contentSha256: hash("sha256", bytes),
    },
  };
}

export async function readDependencySourceCitation(
  repository: string,
  commit: string,
  range: { path: string; startLine: number; endLine: number },
  signal?: AbortSignal,
) {
  if (
    !Number.isSafeInteger(range.startLine) ||
    !Number.isSafeInteger(range.endLine) ||
    range.startLine < 1 ||
    range.endLine < range.startLine
  )
    throw new CodexSecurityError(
      "Expected a one-based source range in ascending order.",
    );
  const { bytes, identity } = await readDependencyGitSource(
    repository,
    commit,
    range.path,
    signal,
  );
  // Git line boundaries are LF bytes. Other lines can use another source encoding.
  let start = 0;
  let end = 0;
  let endLine = 0;
  while (end < bytes.length && endLine < range.endLine) {
    endLine++;
    if (endLine === range.startLine) start = end;
    const newline = bytes.indexOf(0x0a, end);
    end = newline < 0 ? bytes.length : newline + 1;
  }
  if (range.startLine > endLine)
    throw new CodexSecurityError(
      "Source range starts past the end of the Git file.",
    );
  const excerpt = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: true,
  }).decode(bytes.subarray(start, end));
  return {
    path: identity.repositoryPath,
    commit: identity.commit,
    blob: identity.blob,
    contentSha256: identity.contentSha256,
    startLine: range.startLine,
    endLine,
    excerpt,
  };
}

import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { relative, sep } from "node:path";
import { gitOutput, relativePathIsOutside } from "./targets.js";

/** Host-captured identity of the complete file underlying a source excerpt. */
export interface DependencySourceIdentity {
  kind: "git";
  status: "verified" | "modified" | "not_in_commit" | "unavailable";
  repositoryRoot: string | null;
  repositoryPath: string | null;
  commit: string | null;
  blob: string | null;
  contentSha256: string;
  reason?: string;
}

export type DependencySourceIdentityReader = (
  file: string,
  bytes: Buffer,
  signal?: AbortSignal,
) => Promise<DependencySourceIdentity>;

interface GitContext {
  repositoryRoot: string;
  commit: string;
}

interface ExpectedFile {
  blob: string | null;
  contentSha256?: string;
  status?: "not_in_commit" | "unavailable";
  reason?: string;
}

const gitEnvironment = {
  GIT_NO_LAZY_FETCH: "1",
  GIT_ALLOW_PROTOCOL: "",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_LITERAL_PATHSPECS: "1",
};

/** Freeze one investigation's commit and reuse its per-file object lookups. */
export function createDependencySourceIdentityReader(
  repository: string,
): DependencySourceIdentityReader {
  let context: Promise<GitContext> | undefined;
  const expectedFiles = new Map<string, Promise<ExpectedFile>>();

  async function git(
    args: readonly string[],
    signal?: AbortSignal,
    workingDirectory = repository,
  ) {
    return await gitOutput(
      repository,
      args,
      signal,
      gitEnvironment,
      workingDirectory,
      "buffer",
    );
  }

  async function resolveContext(signal?: AbortSignal): Promise<GitContext> {
    const repositoryRoot = await realpath(
      (await git(["rev-parse", "--show-toplevel"], signal))
        .toString("utf8")
        .replace(process.platform === "win32" ? /\r?\n$/u : /\n$/u, ""),
    );
    const commit = (
      await git(["rev-parse", "--verify", "HEAD^{commit}"], signal)
    )
      .toString("utf8")
      .trim();
    return { repositoryRoot, commit };
  }

  async function expectedFile(
    context: GitContext,
    path: string,
    signal?: AbortSignal,
  ): Promise<ExpectedFile> {
    const tree = await git(
      ["ls-tree", "-z", "--full-tree", context.commit, "--", path],
      signal,
      context.repositoryRoot,
    );
    const entry = tree
      .toString("utf8")
      .split("\0")
      .find((entry) => entry.slice(entry.indexOf("\t") + 1) === path);
    const match = entry?.match(/^\d+ blob ([0-9a-f]+)\t/u);
    if (!match) {
      return {
        blob: null,
        status: "not_in_commit",
        reason: "The cited file is not a blob in the captured commit.",
      };
    }
    const blob = match[1]!;
    let bytes: Buffer;
    try {
      bytes = await git(
        ["cat-file", "blob", blob],
        signal,
        context.repositoryRoot,
      );
    } catch (error) {
      signal?.throwIfAborted();
      return {
        blob,
        status: "unavailable",
        reason: error instanceof Error ? error.message : String(error),
      };
    }
    const objectId = createHash(blob.length === 64 ? "sha256" : "sha1")
      .update(`blob ${bytes.length}\0`)
      .update(bytes)
      .digest("hex");
    if (objectId !== blob) {
      return {
        blob,
        status: "unavailable",
        reason: "The local Git object bytes do not match the tree's blob ID.",
      };
    }
    return {
      blob,
      contentSha256: createHash("sha256").update(bytes).digest("hex"),
    };
  }

  return async (file, bytes, signal) => {
    signal?.throwIfAborted();
    const identity: DependencySourceIdentity = {
      kind: "git",
      status: "unavailable",
      repositoryRoot: null,
      repositoryPath: null,
      commit: null,
      blob: null,
      contentSha256: createHash("sha256").update(bytes).digest("hex"),
    };
    try {
      const selected = await (context ??= resolveContext(signal));
      identity.repositoryRoot = selected.repositoryRoot;
      identity.commit = selected.commit;
      const path = relative(selected.repositoryRoot, file);
      if (relativePathIsOutside(path)) {
        identity.reason = "The cited file is outside the Git worktree.";
        return identity;
      }
      identity.repositoryPath = path.split(sep).join("/");
      let expected = expectedFiles.get(identity.repositoryPath);
      if (!expected) {
        expected = expectedFile(selected, identity.repositoryPath, signal);
        expectedFiles.set(identity.repositoryPath, expected);
      }
      const captured = await expected;
      identity.blob = captured.blob;
      if (captured.status) {
        identity.status = captured.status;
        identity.reason = captured.reason;
      } else {
        identity.status =
          captured.contentSha256 === identity.contentSha256
            ? "verified"
            : "modified";
        if (identity.status === "modified") {
          identity.reason =
            "The captured file bytes differ from the captured commit's blob.";
        }
      }
    } catch (error) {
      signal?.throwIfAborted();
      identity.reason = error instanceof Error ? error.message : String(error);
    }
    return identity;
  };
}

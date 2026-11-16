import { execFile as execFileCallback } from "node:child_process";
import { lstat, readdir, realpath } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { promisify } from "node:util";
import { CodexSecurityError, InvalidTargetError } from "../checkout/errors.js";
import type {
  OwnerFinding,
  OwnerContext,
  OwnerEvidence,
  CodeownerIdentity,
} from "./types.js";
import {
  nullIfMissingFile,
  enclosingGitWorktreeRoot,
  gitMetadataDirectories,
  normalizeRepository,
  relativePathIsOutside,
  repositoryRevision,
  validatedGitEnvironment,
} from "../checkout/git.js";
import { resolveTrustedExecutable } from "../checkout/trusted-executable.js";
import { codeownersForPath, parseCodeowners } from "./codeowners.js";

const execFile = promisify(execFileCallback);

export async function findingsAtScanRevision(
  repository: string,
  revision: string,
  findings: readonly OwnerFinding[],
  signal?: AbortSignal,
): Promise<OwnerFinding[]> {
  if ((await repositoryRevision(repository, signal)) !== revision)
    throw new Error(
      "Owner checkout does not match the completed scan revision.",
    );
  const scanRoot = await normalizeRepository(repository, signal);
  const gitRoot =
    (await enclosingGitWorktreeRoot(scanRoot, signal, {
      requireIfPresent: true,
    })) ?? scanRoot;
  const prefix = relative(gitRoot, scanRoot).split(sep).join("/");
  return findings.map((finding) => ({
    ...finding,
    sourceRevision: revision,
    locations: finding.locations.map((location) => ({
      ...location,
      path: prefix ? `${prefix}/${location.path}` : location.path,
    })),
  }));
}

// Drafts may spell a tracked path with a dot component. Keep its original
// spelling in citations, but use Git's spelling for tree and history lookups.
function gitTreePath(path: string): string {
  return path
    .split("/")
    .filter((part) => part !== ".")
    .join("/");
}

/** Read committed objects, so dirty files and source symlinks are never followed. */
export async function ownerRepository(
  repository: string,
  environment: NodeJS.ProcessEnv,
  signal?: AbortSignal,
) {
  repository = await normalizeRepository(repository, signal);
  validatedGitEnvironment(environment);
  repository =
    (await enclosingGitWorktreeRoot(repository, signal, {
      requireIfPresent: true,
    })) ?? repository;
  const executable = await resolveTrustedExecutable(
    "git",
    environment,
    repository,
  );
  if (executable === null)
    throw new CodexSecurityError("Git is required to suggest owners.");
  const run = async (cwd: string, args: string[], encoding: BufferEncoding) => {
    signal?.throwIfAborted();
    const { stdout } = await execFile(executable.executable, args, {
      cwd,
      env: { ...executable.environment, GIT_NO_LAZY_FETCH: "1" },
      signal,
      maxBuffer: Infinity,
      encoding: "buffer",
    });
    return stdout.toString(encoding);
  };
  const [gitDirectory, commonDirectory, ...objectDirectories] =
    await gitMetadataDirectories(repository, signal, {
      includeLocalObjects: true,
    });
  const metadataDirectories = [...new Set([gitDirectory, commonDirectory])];
  if (
    objectDirectories.some((path) =>
      metadataDirectories.every((root) =>
        relativePathIsOutside(relative(root, path)),
      ),
    )
  ) {
    throw new InvalidTargetError(
      "Git objects are not bound to the selected checkout. Use a checkout that does not borrow external object stores.",
    );
  }
  await requireBoundMetadata(metadataDirectories, objectDirectories, signal);
  // Blame otherwise reads an uncommitted .mailmap from the working directory.
  const gitOutput = (encoding: BufferEncoding, ...args: string[]) =>
    run(
      gitDirectory,
      [
        `--git-dir=${gitDirectory}`,
        "--literal-pathspecs",
        "-c",
        "core.bare=true",
        "-c",
        "i18n.logOutputEncoding=UTF-8",
        ...args,
      ],
      encoding,
    );
  const git = (...args: string[]) => gitOutput("utf8", ...args);
  const revision = (await git("rev-parse", "--verify", "HEAD^{commit}")).trim();
  const files = new Set(
    (await gitOutput("latin1", "ls-tree", "-r", "-z", "--full-tree", revision))
      .split("\0")
      .filter((record) => /^100(?:644|755) blob /u.test(record))
      .map((record) => record.slice(record.indexOf("\t") + 1)),
  );
  const shallow =
    (await git("rev-parse", "--is-shallow-repository")).trim() === "true";
  // Latin-1 keys preserve Git's filename bytes, including unrelated non-UTF-8 names.
  const hasFile = (path: string) =>
    path.isWellFormed() && files.has(Buffer.from(path).toString("latin1"));
  const loadCodeowners = async () => {
    const path = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"].find(
      hasFile,
    );
    if (path === undefined) return null;
    const source = await git("cat-file", "blob", `${revision}:${path}`);
    // GitHub requires CODEOWNERS to be under 3 MB.
    return {
      path,
      rules:
        Buffer.byteLength(source) >= 3_000_000 ? null : parseCodeowners(source),
    };
  };
  let codeowners: ReturnType<typeof loadCodeowners> | undefined;
  // Cache the bounded history window when several findings mention the same file.
  const fileHistories = new Map<string, string[]>();
  async function recentFileHistory(path: string) {
    let history = fileHistories.get(path);
    if (!history) {
      history = (
        await git(
          "log",
          "-100",
          "--no-merges",
          "--no-use-mailmap",
          "--no-show-signature",
          "--no-notes",
          "-z",
          "--format=%H%x00%an%x00%ae%x00%ct",
          revision,
          "--",
          path,
        )
      ).split("\0");
      fileHistories.set(path, history);
    }
    return history;
  }
  return {
    git,
    revision,
    hasFile,
    recentFileHistory,
    shallow,
    // Keep the load lazy so failures remain inside per-finding error handling.
    codeowners: () => (codeowners ??= loadCodeowners()),
  };
}

/** Neither references nor objects may link into another checkout. */
async function requireBoundMetadata(
  metadataDirectories: string[],
  objectDirectories: string[],
  signal?: AbortSignal,
): Promise<void> {
  const pending = [
    ...objectDirectories,
    ...metadataDirectories.flatMap((directory) =>
      ["HEAD", "refs", "packed-refs", "reftable"].map((name) =>
        join(directory, name),
      ),
    ),
  ];
  const visited = new Set<string>();
  while (pending.length > 0) {
    signal?.throwIfAborted();
    const path = pending.pop()!;
    if (visited.has(path)) continue;
    visited.add(path);
    const entry = await lstat(path).catch(nullIfMissingFile);
    if (entry?.isSymbolicLink()) {
      const destination = await realpath(path);
      if (
        metadataDirectories.every((root) =>
          relativePathIsOutside(relative(root, destination)),
        )
      ) {
        throw new InvalidTargetError(
          "Git metadata is not bound to the selected checkout. Select the intended checkout or repair its Git metadata.",
        );
      }
      pending.push(destination);
    } else if (entry?.isDirectory()) {
      for (const name of await readdir(path)) pending.push(join(path, name));
    }
  }
}

export async function collectOwnerEvidence(
  finding: OwnerFinding,
  repository: Awaited<ReturnType<typeof ownerRepository>>,
  policy: "scan" | "standalone",
): Promise<OwnerContext> {
  const { revision, hasFile, shallow } = repository;
  const context: OwnerContext = {
    identities: [],
    evidence: [],
    declaredOwners: [],
    limitations: [
      "Git authors are not verified tracker accounts or proof of current employment.",
    ],
  };
  if (shallow)
    context.limitations.push(
      "This checkout has shallow history; earlier contributors may be missing.",
    );
  const stale =
    finding.sourceRevision !== undefined && finding.sourceRevision !== revision;
  if (stale)
    context.limitations.push(
      "The finding revision differs from HEAD; its line ranges were not used.",
    );
  if (finding.locations.length === 0)
    context.limitations.push("No source locations were supplied.");
  const codeowners = await repository.codeowners();
  if (codeowners !== null) {
    if (codeowners.rules === null) {
      context.limitations.push(
        "CODEOWNERS meets or exceeds GitHub's 3 MB file-size limit and was ignored.",
      );
    } else {
      for (const path of new Set(finding.locations.map(({ path }) => path))) {
        const trackedPath = gitTreePath(path);
        if (!hasFile(trackedPath)) continue;
        const rule = codeownersForPath(codeowners.rules, trackedPath);
        if (rule === undefined) continue;
        if (rule.owners.length === 0) continue;
        const citation = addOwnerEvidence(context, {
          kind: "codeowners",
          path: codeowners.path,
          commit: revision,
          startLine: rule.line,
          endLine: rule.line,
          rule: rule.rule,
          matchedPath: path,
          content: rule.rule,
          identityIndex: null,
        });
        for (const owner of rule.owners)
          context.declaredOwners.push({ owner, evidenceIds: [citation.id] });
      }
    }
  }
  if (context.declaredOwners.length > 0)
    context.limitations.push(
      "CODEOWNERS identities are declarations; their existence and repository access are not verified.",
    );
  if (policy === "standalone" && !context.declaredOwners.length)
    await collectGitOwnerEvidence(finding, repository, context, stale, policy);
  return context;
}

function addOwnerEvidence(
  context: OwnerContext,
  item: Omit<OwnerEvidence, "id">,
): OwnerEvidence {
  const evidence = { id: `e${context.evidence.length + 1}`, ...item };
  context.evidence.push(evidence);
  return evidence;
}

export async function collectGitOwnerEvidence(
  finding: OwnerFinding,
  repository: Awaited<ReturnType<typeof ownerRepository>>,
  context: OwnerContext,
  stale: boolean,
  policy: "scan" | "standalone",
): Promise<void> {
  const { git, revision, hasFile } = repository;
  const identityIndex = (name: string, email: string) => {
    const index = context.identities.findIndex(
      (identity) => identity.email === email,
    );
    if (index !== -1) return index;
    return context.identities.push({ name, email }) - 1;
  };
  const add = (item: Omit<OwnerEvidence, "id">) =>
    addOwnerEvidence(context, item);
  for (const path of new Set(finding.locations.map(({ path }) => path))) {
    const trackedPath = gitTreePath(path);
    if (!hasFile(trackedPath)) {
      context.limitations.push(`Not a regular file at HEAD: ${path}`);
      continue;
    }
    const locations = stale
      ? [{ path }]
      : finding.locations.filter((location) => location.path === path);
    const lineLocations = locations.filter(
      (location) => location.startLine !== undefined,
    );
    if (policy === "scan" && !lineLocations.length) {
      const history = await repository.recentFileHistory(trackedPath);
      for (let i = 0; i + 3 < history.length; i += 4) {
        const [commit, name, email, timestamp] = history.slice(i, i + 4) as [
          string,
          string,
          string,
          string,
        ];
        if (name && email.trim())
          add({
            kind: "history",
            path,
            commit,
            commitTime: Number(timestamp),
            content: "",
            identityIndex: identityIndex(name, email),
          });
      }
      continue;
    }
    const source = await git("cat-file", "blob", `${revision}:${trackedPath}`);
    if (!source || source.includes("\0")) {
      context.limitations.push(`Source is empty or binary: ${path}`);
      continue;
    }
    const lines = source.replace(/\n$/u, "").split("\n");
    for (const location of policy === "scan" ? lineLocations : locations) {
      const start = location.startLine ?? 1;
      if (policy === "scan" && (location.endLine ?? start) > lines.length)
        throw new CodexSecurityError(
          `Finding lines are outside the committed file: ${path}`,
        );
      if (start > lines.length) {
        context.limitations.push(
          `Finding line is outside the committed file: ${path}:${start}`,
        );
        continue;
      }
      // Include surrounding code for the model, but attribute only the affected lines.
      const end = Math.min(
        location.endLine ?? location.startLine ?? lines.length,
        lines.length,
      );
      const excerptStart = Math.max(1, start - 10);
      const excerptEnd = Math.min(lines.length, end + 10);
      if (policy === "standalone")
        add({
          kind: "source",
          path,
          commit: revision,
          startLine: excerptStart,
          endLine: excerptEnd,
          content: lines
            .slice(excerptStart - 1, excerptEnd)
            .map((line, index) => `${excerptStart + index}: ${line}`)
            .join("\n"),
          identityIndex: null,
        });
      const blame = await git(
        "blame",
        "--line-porcelain",
        "--no-textconv",
        "--ignore-revs-file=",
        "-L",
        `${start},${end}`,
        revision,
        "--",
        trackedPath,
      );
      let commit = "",
        name = "",
        email = "",
        line = 0,
        commitTime = 0;
      for (const value of blame.split("\n")) {
        const header = /^([a-f0-9]{40,64}) \d+ (\d+)(?: \d+)?$/u.exec(value);
        if (header) {
          commit = header[1]!;
          line = Number(header[2]);
        } else if (value.startsWith("author ")) name = value.slice(7);
        else if (value.startsWith("author-mail <")) email = value.slice(13, -1);
        else if (value.startsWith("committer-time "))
          commitTime = Number(value.slice(15));
        else if (value.startsWith("\t") && email.trim()) {
          const index = identityIndex(name, email);
          const previous = context.evidence.at(-1);
          if (
            previous?.kind === "blame" &&
            previous.path === path &&
            previous.blameCommit === commit &&
            previous.identityIndex === index &&
            previous.endLine === line - 1
          ) {
            previous.endLine = line;
          } else {
            add({
              kind: "blame",
              path,
              commit: revision,
              blameCommit: commit,
              ...(policy === "scan" && { commitTime }),
              startLine: line,
              endLine: line,
              content: `Authored in ${commit}.`,
              identityIndex: index,
            });
          }
        }
      }
    }
    if (policy === "scan") continue;
    const history = (
      await git(
        "log",
        "--no-use-mailmap",
        "--no-show-signature",
        "--no-notes",
        "--no-decorate",
        "--format=%H%x00%an%x00%ae%x00%aI%x00%s",
        "-z",
        revision,
        "--",
        trackedPath,
      )
    ).split("\0");
    for (let index = 0; index + 4 < history.length; index += 5) {
      const [commit, name, email, date, subject] = history.slice(
        index,
        index + 5,
      ) as [string, string, string, string, string];
      if (email.trim())
        add({
          kind: "history",
          path,
          commit,
          content: `${date}: ${subject}`,
          identityIndex: identityIndex(name, email),
        });
    }
  }
}

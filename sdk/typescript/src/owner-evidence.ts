import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";
import { CodexSecurityError } from "./errors.js";
import type { OwnerFinding } from "./suggest-owners.js";
import { normalizeRepository, validatedGitEnvironment } from "./targets.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execFile = promisify(execFileCallback);

export interface OwnerIdentity {
  name: string;
  email: string;
}

export interface OwnerEvidence {
  id: string;
  kind: "source" | "blame" | "history";
  path: string;
  commit: string;
  startLine?: number;
  endLine?: number;
  content: string;
  identityIndex: number | null;
}

export interface OwnerContext {
  identities: OwnerIdentity[];
  evidence: OwnerEvidence[];
  limitations: string[];
}

/** Read committed objects, so dirty files and source symlinks are never followed. */
export async function ownerRepository(
  repository: string,
  environment: NodeJS.ProcessEnv,
  signal?: AbortSignal,
) {
  repository = await normalizeRepository(repository, signal);
  validatedGitEnvironment(environment);
  const executable = await resolveTrustedExecutable(
    "git",
    environment,
    repository,
  );
  if (executable === null)
    throw new CodexSecurityError("Git is required to suggest owners.");
  const run = async (cwd: string, args: string[]) => {
    signal?.throwIfAborted();
    const { stdout } = await execFile(executable.executable, args, {
      cwd,
      env: { ...executable.environment, GIT_NO_LAZY_FETCH: "1" },
      signal,
      maxBuffer: Infinity,
    });
    return stdout;
  };
  const gitDirectory = (
    await run(repository, ["rev-parse", "--absolute-git-dir"])
  ).trim();
  // Blame otherwise reads an uncommitted .mailmap from the working directory.
  const git = (...args: string[]) =>
    run(gitDirectory, [
      `--git-dir=${gitDirectory}`,
      "--literal-pathspecs",
      "-c",
      "core.bare=true",
      ...args,
    ]);
  const revision = (await git("rev-parse", "--verify", "HEAD^{commit}")).trim();
  const files = new Set(
    (await git("ls-tree", "-r", "-z", "--full-tree", revision))
      .split("\0")
      .filter((record) => /^100(?:644|755) blob /u.test(record))
      .map((record) => record.slice(record.indexOf("\t") + 1)),
  );
  const shallow =
    (await git("rev-parse", "--is-shallow-repository")).trim() === "true";
  return { git, revision, files, shallow };
}

export async function collectOwnerEvidence(
  finding: OwnerFinding,
  repository: Awaited<ReturnType<typeof ownerRepository>>,
): Promise<OwnerContext> {
  const { git, revision, files, shallow } = repository;
  const context: OwnerContext = {
    identities: [],
    evidence: [],
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
  const identityIndex = (name: string, email: string) => {
    const index = context.identities.findIndex(
      (identity) => identity.email === email,
    );
    if (index !== -1) return index;
    return context.identities.push({ name, email }) - 1;
  };
  const add = (item: Omit<OwnerEvidence, "id">) => {
    context.evidence.push({ id: `e${context.evidence.length + 1}`, ...item });
  };
  for (const path of new Set(finding.locations.map(({ path }) => path))) {
    if (!files.has(path)) {
      context.limitations.push(`Not a regular file at HEAD: ${path}`);
      continue;
    }
    const source = await git("cat-file", "blob", `${revision}:${path}`);
    if (!source || source.includes("\0")) {
      context.limitations.push(`Source is empty or binary: ${path}`);
      continue;
    }
    const lines = source.replace(/\n$/u, "").split("\n");
    const locations = stale
      ? [{ path }]
      : finding.locations.filter((location) => location.path === path);
    for (const location of locations) {
      const start = location.startLine ?? 1;
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
        path,
      );
      let commit = "",
        name = "",
        email = "",
        line = 0;
      for (const value of blame.split("\n")) {
        const header = /^([a-f0-9]{40,64}) \d+ (\d+)(?: \d+)?$/u.exec(value);
        if (header) {
          commit = header[1]!;
          line = Number(header[2]);
        } else if (value.startsWith("author ")) name = value.slice(7);
        else if (value.startsWith("author-mail <")) email = value.slice(13, -1);
        else if (value.startsWith("\t") && email.trim()) {
          const index = identityIndex(name, email);
          const previous = context.evidence.at(-1);
          if (
            previous?.kind === "blame" &&
            previous.content === `Authored in ${commit}.` &&
            previous.identityIndex === index &&
            previous.endLine === line - 1
          ) {
            previous.endLine = line;
          } else {
            add({
              kind: "blame",
              path,
              commit: revision,
              startLine: line,
              endLine: line,
              content: `Authored in ${commit}.`,
              identityIndex: index,
            });
          }
        }
      }
    }
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
        path,
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
  return context;
}

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { gitOutput } from "../../sdk/typescript/dist/targets.js";
import type { ReachabilityCase, Repository } from "./cases.mts";

export type Clones = Readonly<Partial<Record<Repository, string>>>;
type Snapshot = Pick<ReachabilityCase, "repository" | "revision" | "stage">;

// The base commit pins the upstream tree. Hash the actual staged overrides
// so two local runs can distinguish fixture edits even before a commit.
export async function snapshotDigest(repo: string, scenario: Snapshot) {
  const files = [];
  for (const { destination } of scenario.stage) {
    const bytes = await readFile(join(repo, destination));
    files.push([destination, createHash("sha256").update(bytes).digest("hex")]);
  }
  return createHash("sha256")
    .update(JSON.stringify([scenario.repository, scenario.revision, files]))
    .digest("hex");
}

// Pinned objects must already exist locally, including in partial clones.
const localGit = { GIT_ALLOW_PROTOCOL: "", GIT_NO_REPLACE_OBJECTS: "1" };

function cloneFor(clones: Clones, repository: Repository, revision: string) {
  if (!/^[a-f0-9]{40}$/u.test(revision))
    throw new Error(`Expected a full commit ID for ${repository}: ${revision}`);
  const clone = clones[repository];
  if (!clone) throw new Error(`Missing local clone for ${repository}`);
  return clone;
}

export async function prepareSnapshot(
  root: string,
  scenario: Snapshot,
  clones: Clones,
  signal?: AbortSignal,
): Promise<string> {
  const clone = cloneFor(clones, scenario.repository, scenario.revision);
  const objects = await gitOutput(
    clone,
    ["rev-parse", "--path-format=absolute", "--git-path", "objects"],
    signal,
    localGit,
  );
  const directory = await mkdtemp(join(root, "case-"));
  const repo = join(directory, "source");
  const metadata = join(directory, "metadata");
  await mkdir(repo);
  await gitOutput(directory, ["init", "--bare", metadata], signal, localGit);
  // The private index reads the caller's objects, leaving their checkout intact.
  // Neither Git history nor the harness lives under the model's source root.
  await writeFile(join(metadata, "objects/info/alternates"), objects + "\n");
  // Materialize committed bytes even if a local smudge filter is installed.
  await mkdir(join(metadata, "info"), { recursive: true });
  await writeFile(
    join(metadata, "info/attributes"),
    "* -filter -ident -text !eol !working-tree-encoding\n",
  );
  const git = (args: string[]) =>
    gitOutput(
      directory,
      [`--git-dir=${metadata}`, `--work-tree=${repo}`, ...args],
      signal,
      localGit,
    );
  await git(["read-tree", scenario.revision]);
  await git(["checkout-index", "--all"]);

  // All overlays live in fresh top-level directories. Never follow a symlink
  // from target source when adding deployed files or dependency evidence.
  const directories = new Set<string>();
  for (const file of scenario.stage) {
    const parts = file.destination.split("/");
    if (
      parts.length < 2 ||
      parts.some((p) => !p || p === "." || p === ".." || /[\\:]/u.test(p))
    )
      throw new Error(`Invalid overlay destination: ${file.destination}`);
    if (!directories.has(parts[0])) {
      await mkdir(join(repo, parts[0]));
      directories.add(parts[0]);
    }
    const destination = join(repo, ...parts);
    await mkdir(dirname(destination), { recursive: true });
    const bytes =
      file.kind === "git"
        ? await gitOutput(
            cloneFor(clones, file.repository, file.revision),
            ["cat-file", "blob", `${file.revision}:${file.source}`],
            signal,
            localGit,
            undefined,
            "buffer",
          )
        : file.kind === "fixture"
          ? await readFile(join(import.meta.dirname, file.source))
          : JSON.stringify(file.value, null, 2) + "\n";
    await writeFile(destination, bytes, { flag: "wx" });
  }
  return repo;
}

import { lstat } from "node:fs/promises";
import { join, posix } from "node:path";
import { inventoryFiles } from "./component-plan.js";
import { readRegularInputFile } from "./prompt-files.js";
import { normalizeRepository } from "./targets.js";

export interface DependencyEvidenceFile {
  path: string;
  lines: { number: number; text: string }[];
}

// The reviewer gets one tool-free turn. Budget the serialized excerpts, including
// line numbers, so a single generated source file or lockfile cannot fill it.
const EVIDENCE_BYTES = 64 * 1024;
const FILE_EVIDENCE_BYTES = EVIDENCE_BYTES / 4;
// Avoid buffering arbitrarily large generated source or lockfiles merely to
// extract a small excerpt; callers must see the resulting coverage gap.
const MAX_SOURCE_BYTES = 16 * 1024 * 1024;
const OMITTED_DIRECTORY =
  /(?:^|\/)(?:\.[^/]+|node_modules|vendor|dist|build|target|coverage|__pycache__|secrets?)(?:\/|$)/iu;
const SOURCE =
  /\.(?:[cm]?[jt]sx?|py|go|rs|java|kt|kts|scala|cs|fs|cpp|cc|c|h|hpp|rb|php|ex|exs|swift|dart)$/iu;
const MANIFEST =
  /^(?:package(?:-lock)?\.json|npm-shrinkwrap\.json|(?:pnpm-lock|pubspec)\.ya?ml|yarn\.lock|bun\.lock|pyproject\.toml|Pipfile(?:\.lock)?|(?:poetry|uv|Cargo|composer|mix|pubspec)\.lock|requirements[^/]*\.txt|setup\.cfg|Cargo\.toml|go\.(?:mod|sum)|Gemfile(?:\.lock)?|pom\.xml|build\.gradle(?:\.kts)?|composer\.json|[^/]+\.(?:csproj|gemspec))$/iu;
const DEPLOYMENT =
  /^(?:(?:docker-)?compose(?:\.[^.]+)*\.ya?ml|Dockerfile(?:\..+)?|Containerfile)$/iu;

function includePath(path: string, directory: boolean): boolean {
  if (OMITTED_DIRECTORY.test(path) || /\.min\.[cm]?js$/iu.test(path))
    return false;
  const name = posix.basename(path);
  return (
    directory ||
    SOURCE.test(name) ||
    MANIFEST.test(name) ||
    DEPLOYMENT.test(name)
  );
}

// Read deployment structure, leaving values in unrelated environment and secret
// sections out of the review. Presence of a descriptor establishes configuration only.
function deploymentLine(path: string, text: string): boolean {
  if (/^(?:Dockerfile|Containerfile)/iu.test(posix.basename(path))) {
    return /^(?:FROM|WORKDIR|COPY|CMD|ENTRYPOINT)\s|^ARG\s+\w+\s*$|^RUN\s+(?:npm|pnpm|yarn|pip|bundle|cargo|go|mvn)\s/iu.test(
      text,
    );
  }
  return /^(?:services\s*:|  [\w.-]+\s*:\s*(?:#.*)?$|    (?:image|build|command|entrypoint|ports)\s*:|      (?:args|context|dockerfile)\s*:)/u.test(
    text,
  );
}

export async function collectDependencyEvidence(
  repository: string,
  packageNames: readonly string[],
  signal?: AbortSignal,
): Promise<{
  files: DependencyEvidenceFile[];
  limitations: string[];
  complete: boolean;
}> {
  const root = await normalizeRepository(repository, signal);
  const names = [
    ...new Set(packageNames.map((name) => name.toLowerCase()).filter(Boolean)),
  ];
  if (!names.length)
    return {
      files: [],
      limitations: ["The advisory has no package name to search for."],
      complete: false,
    };

  let complete = true;
  let skippedVendor = false;
  const paths = await inventoryFiles(
    root,
    signal,
    (path, directory) => {
      if (/(?:^|\/)vendor(?:\/|$)/iu.test(path)) skippedVendor = true;
      const include = includePath(path, directory);
      if (!include) complete = false;
      return include;
    },
    () => {
      complete = false;
    },
  );
  const files: DependencyEvidenceFile[] = [];
  const parents = new Set<string>();
  let remaining = EVIDENCE_BYTES;
  let truncated = false;
  let oversized = 0;
  const [sources, deployments] = [
    paths.filter((path) => !DEPLOYMENT.test(posix.basename(path))),
    paths.filter((path) => DEPLOYMENT.test(posix.basename(path))),
  ];
  for (const path of [...sources, ...deployments]) {
    signal?.throwIfAborted();
    const deployment = DEPLOYMENT.test(posix.basename(path));
    if (deployment && !parents.has(posix.dirname(path))) {
      complete = false;
      continue;
    }
    if (remaining <= 0) {
      truncated = true;
      break;
    }
    const fullPath = join(root, path);
    const metadata = await lstat(fullPath, { bigint: true });
    if (!metadata.isFile()) {
      complete = false;
      continue;
    }
    if (metadata.size > MAX_SOURCE_BYTES) {
      oversized++;
      continue;
    }
    const contents = await readRegularInputFile(fullPath, root, metadata);
    if (contents.includes("\0")) {
      complete = false;
      continue;
    }
    const lines = contents.replace(/\r?\n$/u, "").split(/\r?\n/u);
    const file: DependencyEvidenceFile = { path, lines: [] };
    let budget =
      Math.min(FILE_EVIDENCE_BYTES, remaining) -
      Buffer.byteLength(JSON.stringify(file));
    let last = -1;
    for (const [index, text] of lines.entries()) {
      const selected = deployment
        ? deploymentLine(path, text)
        : names.some((name) => text.toLowerCase().includes(name));
      if (!selected) continue;
      // Keep the lock record or nearby import and call together. Overlapping
      // matches extend the previous excerpt without duplicating source lines.
      const start = Math.max(last + 1, deployment ? index : index - 8);
      last = Math.min(lines.length - 1, deployment ? index : index + 12);
      for (let i = start; i <= last; i++) {
        const line = { number: i + 1, text: lines[i]! };
        const bytes = 1 + Buffer.byteLength(JSON.stringify(line));
        if (bytes > budget) {
          truncated = true;
          continue;
        }
        file.lines.push(line);
        budget -= bytes;
      }
    }
    if (!deployment && last >= 0) {
      for (
        let dir = posix.dirname(path);
        !parents.has(dir);
        dir = posix.dirname(dir)
      ) {
        parents.add(dir);
        if (dir === ".") break;
      }
    }
    if (file.lines.length !== lines.length) complete = false;
    if (file.lines.length) {
      files.push(file);
      remaining -= Buffer.byteLength(JSON.stringify(file)) + 1;
    }
  }
  const limitations: string[] = [];
  if (skippedVendor)
    limitations.push(
      "Vendored sources were excluded; additional or patched copies may be present.",
    );
  if (oversized)
    limitations.push(
      `Skipped ${oversized} candidate files larger than ${MAX_SOURCE_BYTES} bytes.`,
    );
  if (!files.length)
    limitations.push(
      "No matching package references found in the inspected source and manifests.",
    );
  if (truncated)
    limitations.push(
      "Some source evidence was omitted to fit the review input budget.",
    );
  return {
    files,
    limitations,
    complete: complete && files.length > 0 && !limitations.length,
  };
}
